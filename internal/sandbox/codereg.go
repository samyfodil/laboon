//go:build darwin || windows

package sandbox

import (
	"encoding/binary"
	"sync"
)

// Code in memory processes share. A stub runs a page of shared memory as a
// private shadow ("hot": stub/macos/wx.zig, stub/windows/mem.zig), which
// every write to that memory must cool first. A stub's own writes fault into
// it; codeReg carries the rest, a page of memory named the same in every
// process (Darwin: its VM object's id and offset; Windows: its section's key
// and offset):
//   - HOT: a stub about to run a page, unless it is the run's only process,
//     becomes its holder, and every other stub freezes its writable mappings
//     of that memory (codeFreeze) before the page is copied.
//   - COOL: a stub writing through a mapping so frozen has every other
//     holder cool the page first (codeCool).
//   - A stopped stub cannot answer: one being stopped cools its hot pages and
//     heats none until it goes on (codeStop, codeGo), so it holds none; the
//     freezes it misses are owed, and the pages owed cool before it goes on.
//   - The supervisor's own writes to a file a stub maps shared and executable
//     cool its hot pages of the file (codeCoolFile).
// Each request is served on the goroutine of the stub asking, one page's at
// a time: a stub never waits on the registry holding what its own service
// needs to answer it.

// codeOp is a request to a stub's service.
type codeOp int

const (
	codeFreeze   codeOp = iota // page: freeze the writable mappings of it
	codeCool                   // page: cool the hot page of it
	codeCoolFile               // file: cool the hot pages of it
	codeStop                   // cool every hot page, heat none until codeGo
	codeGo
	codeDetachFile // file: let the views of it go, to map again when touched (Windows)
)

// codeLink reaches a stub's service: tell has it serve op with body and
// waits for it to; false if the stub has ended.
type codeLink interface {
	tell(op codeOp, body []byte) bool
}

type objPage struct {
	obj, off uint64
}

func (x objPage) bytes() []byte {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:], x.obj)
	binary.LittleEndian.PutUint64(b[8:], x.off)
	return b[:]
}

// codePage is a page's holders; mu orders its HOTs and COOLs.
type codePage struct {
	mu      sync.Mutex
	holders map[int]bool // guarded by codeReg.mu
}

type codeReg struct {
	mu      sync.Mutex
	live    map[int]codeLink           // the stubs that answer, by pid
	pages   map[objPage]*codePage      // pages some stub holds or held
	stopped map[int]map[objPage]bool   // stopped stubs, with the pages they owe a freeze
	marks   map[[2]uint64]map[int]bool // files mapped shared and executable, by stub
}

func (r *codeReg) page(x objPage) *codePage {
	if r.pages == nil {
		r.pages = map[objPage]*codePage{}
	}
	p := r.pages[x]
	if p == nil {
		p = &codePage{holders: map[int]bool{}}
		r.pages[x] = p
	}
	return p
}

// join makes stub pid one that answers, through l, and returns the pages
// some stub holds as of then, which it must freeze: a HOT after it tells it.
func (r *codeReg) join(pid int, l codeLink) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live == nil {
		r.live = map[int]codeLink{}
	}
	r.live[pid] = l
	var out []byte
	for x, p := range r.pages {
		if len(p.holders) > 0 {
			out = append(out, x.bytes()...)
		}
	}
	return out
}

// leave forgets stub pid, ended: what it held, owed and mapped.
func (r *codeReg) leave(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.live, pid)
	for _, p := range r.pages {
		delete(p.holders, pid)
	}
	delete(r.stopped, pid)
	for k, m := range r.marks {
		if delete(m, pid); len(m) == 0 {
			delete(r.marks, k)
		}
	}
}

// hot makes pid a holder of x, once every other stub has frozen it.
func (r *codeReg) hot(pid int, x objPage) {
	r.mu.Lock()
	p := r.page(x)
	r.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	r.mu.Lock()
	if _, stopped := r.stopped[pid]; stopped {
		r.mu.Unlock()
		return // it heats nothing until it goes on
	}
	p.holders[pid] = true
	var to []int
	for q := range r.live {
		if q == pid {
			continue
		}
		if owe, stopped := r.stopped[q]; stopped {
			owe[x] = true
		} else {
			to = append(to, q)
		}
	}
	r.mu.Unlock()
	r.tellAll(to, codeFreeze, x.bytes())
}

// cool has every holder of x but pid cool it.
func (r *codeReg) cool(pid int, x objPage) {
	r.mu.Lock()
	p := r.page(x)
	r.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	r.mu.Lock()
	var to []int
	for h := range p.holders {
		if h != pid {
			to = append(to, h)
		}
	}
	clear(p.holders)
	r.mu.Unlock()
	r.tellAll(to, codeCool, x.bytes())
}

// stop readies stub pid for a host stop: it cools its hot pages and heats
// none until gone, and the freezes it misses are owed from here. A run's only
// process holds pages it never registered: every stub is asked.
func (r *codeReg) stop(pid int) {
	r.mu.Lock()
	if r.stopped == nil {
		r.stopped = map[int]map[objPage]bool{}
	}
	_, already := r.stopped[pid]
	if !already {
		r.stopped[pid] = map[objPage]bool{}
	}
	r.mu.Unlock()
	if already {
		return
	}
	r.tell(pid, codeStop, nil)
	r.mu.Lock()
	for _, p := range r.pages {
		delete(p.holders, pid)
	}
	r.mu.Unlock()
}

// going readies stub pid to go on, before the host lets it: the pages it owes
// a freeze cool, and from here a HOT waits for its freeze. Whether it was
// stopped.
func (r *codeReg) going(pid int) bool {
	for {
		r.mu.Lock()
		owe, stopped := r.stopped[pid]
		if !stopped {
			r.mu.Unlock()
			return false
		}
		if len(owe) == 0 {
			delete(r.stopped, pid)
			r.mu.Unlock()
			return true
		}
		r.stopped[pid] = map[objPage]bool{}
		r.mu.Unlock()
		for x := range owe {
			r.cool(-1, x)
		}
	}
}

// gone lets stub pid, gone on, heat again.
func (r *codeReg) gone(pid int) { r.tell(pid, codeGo, nil) }

// mark records that stub pid maps file k shared and executable.
func (r *codeReg) mark(pid int, k [2]uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.marks == nil {
		r.marks = map[[2]uint64]map[int]bool{}
	}
	if r.marks[k] == nil {
		r.marks[k] = map[int]bool{}
	}
	r.marks[k][pid] = true
}

// marked reports whether any file is mapped shared and executable.
func (r *codeReg) marked() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.marks) > 0
}

// fileWritten cools the hot pages of file k, named to a stub by body, in
// every stub that maps it shared and executable.
func (r *codeReg) fileWritten(k [2]uint64, body []byte) {
	r.mu.Lock()
	var to []int
	for pid := range r.marks[k] {
		if _, stopped := r.stopped[pid]; !stopped {
			to = append(to, pid)
		}
	}
	r.mu.Unlock()
	r.tellAll(to, codeCoolFile, body)
}

// fileTruncating has every stub that maps file k, named to it by body, and
// answers, serve op first.
func (r *codeReg) fileTruncating(k [2]uint64, body []byte) {
	r.mu.Lock()
	var to []int
	for pid := range r.marks[k] {
		if _, stopped := r.stopped[pid]; !stopped {
			to = append(to, pid)
		}
	}
	r.mu.Unlock()
	r.tellAll(to, codeDetachFile, body)
}

// fork gives stub child the files its parent maps shared and executable,
// which it maps too.
func (r *codeReg) fork(parent, child int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.marks {
		if m[parent] {
			m[child] = true
		}
	}
}

func (r *codeReg) tellAll(pids []int, op codeOp, body []byte) {
	if len(pids) == 1 {
		r.tell(pids[0], op, body)
		return
	}
	var wg sync.WaitGroup
	for _, pid := range pids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.tell(pid, op, body)
		}()
	}
	wg.Wait()
}

func (r *codeReg) tell(pid int, op codeOp, body []byte) bool {
	r.mu.Lock()
	l := r.live[pid]
	r.mu.Unlock()
	return l != nil && l.tell(op, body)
}
