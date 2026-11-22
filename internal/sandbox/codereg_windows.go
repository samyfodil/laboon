//go:build windows

package sandbox

import (
	"encoding/binary"
	"errors"
	"os"

	"github.com/samyfodil/laboon/core"
	"golang.org/x/sys/windows"
)

// Shared code across stubs on Windows (codereg.go): a page of memory is its
// section's key and offset, the same in every stub of the run (a file's
// section takes futexFileKey); a stub asks on its thread's channel (lcHot,
// lcCool), and a service thread of its own, on a slot of its own, serves the
// registry's requests (repCode), a file named to it by its key.

const (
	// lcServiceSlot -> the slot offset a service thread takes; the stub has
	// joined the registry, and the pages held as of then are in the
	// window, args[0] of them, args[1] in all (lcServiceHeld the rest).
	lcServiceSlot = 0x4c43002d
	lcService     = 0x4c43002e // the service thread: serve the registry's requests (repCode)
	lcServiceHeld = 0x4c430034 // (from) -> how many of the held pages from the from-th are in the window
	lcHot         = 0x4c43002f // (key, off)
	lcCool        = 0x4c430032 // (key, off)
	lcCodeFile    = 0x4c430033 // (key): the stub maps that file shared and executable

	// repCode has the service thread serve request args[0] (codeOp) with
	// body args[1:], and reply msgHostRet.
	repCode = 23
)

// winLink reaches a stub's service thread, through the goroutine serving
// its slot; held is what it was given to freeze as it joined.
type winLink struct {
	reqs chan winReq
	done chan struct{} // closed once the stub has ended
	held []byte
}

type winReq struct {
	op   codeOp
	body []byte
	ok   chan bool
}

func (l *winLink) tell(op codeOp, body []byte) bool {
	r := winReq{op, body, make(chan bool, 1)}
	select {
	case l.reqs <- r:
	case <-l.done:
		return false
	}
	select {
	case ok := <-r.ok:
		return ok
	case <-l.done:
		return false
	}
}

// serviceSlot serves lcServiceSlot: a slot of its own for g's stub's service
// thread, which the goroutine serving it hands the registry's requests. The
// stub joins the registry here, before its guest runs on (a fork child's
// included): what is held as of then it freezes from the window; a request
// after it waits for the service thread.
func (g *wguest) serviceSlot(dg *dguest) int64 {
	fs := dg.dfs
	idx := fs.allocSlot()
	if idx < 0 {
		return sErr(lxEAGAIN)
	}
	cch, err := newStubChan(fs, idx, dg.ch.proc, false)
	if err != nil {
		fs.freeSlot(idx)
		return sErr(lxEAGAIN)
	}
	l := &winLink{reqs: make(chan winReq), done: make(chan struct{})}
	l.held = g.run.code.join(dg.ps.ospid, l)
	dg.mp.w.link = l
	fs.wg.Add(1)
	go g.serveService(fs, cch, idx, dg.ps.ospid, l)
	dg.ch.page.args[0], dg.ch.page.args[1] = uint64(g.heldTo(dg, 0)), uint64(len(l.held)/16)
	return int64(idx * slotSize)
}

// heldTo writes the pages held as dg's stub joined, from the from-th on, to
// its window, and returns how many it wrote.
func (g *wguest) heldTo(dg *dguest, from int) int {
	l := dg.mp.w.link
	if l == nil || 16*from >= len(l.held) {
		return 0
	}
	n := copy(dg.window(), l.held[16*from:]) / 16
	return n
}

// serveService hands the service thread, once it checks in, the registry's
// requests until its stub ends.
func (g *wguest) serveService(fs *dfs, c *hostChan, idx, pid int, l *winLink) {
	defer fs.wg.Done()
	defer fs.freeSlot(idx)
	defer c.closeEvents()
	defer close(l.done)
	reg := &g.run.code
	defer reg.leave(pid)
	if err := c.wait(); err != nil || c.page.kind != msgSyscall || c.page.nr != lcService {
		return
	}
	// It ends with its stub, which ends the slot's exchange with it.
	gone := make(chan struct{})
	cur := windows.CurrentProcess()
	var h windows.Handle
	if err := windows.DuplicateHandle(cur, c.proc, cur, &h, windows.SYNCHRONIZE, false, 0); err != nil {
		return
	}
	go func() {
		windows.WaitForSingleObject(h, windows.INFINITE)
		windows.CloseHandle(h)
		close(gone)
	}()
	for {
		var r winReq
		select {
		case r = <-l.reqs:
		case <-gone:
			return
		case <-fs.done:
			return
		}
		c.page.args = [6]uint64{uint64(r.op)}
		for i := 0; i+8 <= len(r.body) && i < 40; i += 8 {
			c.page.args[1+i/8] = binary.LittleEndian.Uint64(r.body[i:])
		}
		c.reply(repCode)
		err := c.wait()
		r.ok <- err == nil && c.page.kind == msgHostRet
		if err != nil {
			return
		}
	}
}

// codeReq serves a stub's lcHot or lcCool of page (key, off).
func (g *wguest) codeReq(dg *dguest, nr, key, off uint64) int64 {
	if nr == lcHot {
		g.run.code.hot(dg.ps.ospid, objPage{key, off})
	} else {
		g.run.code.cool(dg.ps.ospid, objPage{key, off})
	}
	return 0
}

// procCode is the registry p's process is in.
func (sr *sigRun) procCode(p *sigProc) *codeReg {
	sr.fs.mu.Lock()
	defer sr.fs.mu.Unlock()
	if dp := sr.fs.procs[p.tgid]; dp != nil && dp.g != nil && dp.g.mp != nil && dp.g.mp.w != nil {
		return &dp.g.mp.w.run.code
	}
	return nil
}

// codeStop readies p's stub for a host stop (codeReg.stop).
func (sr *sigRun) codeStop(p *sigProc) {
	if r, pid := sr.procCode(p), sr.ospid(p); r != nil && pid > 0 {
		r.stop(pid)
	}
}

// codeGo lets p's stub go on: what it owes cools before cont lets the host
// run it, and it heats again after.
func (sr *sigRun) codeGo(p *sigProc, cont func()) {
	r, pid := sr.procCode(p), sr.ospid(p)
	if r == nil || pid <= 0 {
		cont()
		return
	}
	going := r.going(pid)
	cont()
	if going {
		r.gone(pid)
	}
}

// codeKey marks the file with section key key as mapped shared and
// executable by g's stub.
func (g *dguest) codeKey(key uint64) {
	if w := g.mp.w; w != nil && key != 0 && g.ps.ospid > 0 {
		w.run.code.mark(g.ps.ospid, [2]uint64{key, 0})
	}
}

func (g *dguest) codeFile(fi os.FileInfo) {}

// modified is a write to d's file: inotify hears of it, and the stubs that
// map the file shared and executable cool their hot pages of it.
func (g *dguest) modified(d *dfile) {
	g.notifyFd(d, inModify)
	if fd, ok := d.hostFd(); ok {
		g.handleModified(fd)
	}
}

// fileModified cools the hot pages of f's file in the stubs that map it
// shared and executable.
func (g *dguest) fileModified(f core.File) {
	if fd, ok := hostFdOf(f); ok {
		g.handleModified(fd)
	}
}

func (g *dguest) handleModified(fd int) {
	w := g.mp.w
	if w == nil || !w.run.code.marked() {
		return
	}
	key := futexFileKey(windows.Handle(fd))
	var body [8]byte
	binary.LittleEndian.PutUint64(body[:], key)
	w.run.code.fileWritten([2]uint64{key, 0}, body[:])
}

// mappedShared marks a file a stub maps shared (codeReg.mark), as the second
// word of its name.
const mappedShared = 1

// truncated runs truncate, which cuts or grows the file host names. Windows
// refuses to cut a file a view of it maps: then every stub that maps it shared
// lets its views of it go, to map them again, as far as the file then
// reaches, when they are touched, and truncate runs again.
func (g *dguest) truncated(host func() (int, bool), truncate func() error) error {
	err := truncate()
	w := g.mp.w
	fd, ok := host()
	if !errors.Is(err, windows.ERROR_USER_MAPPED_FILE) || w == nil || !ok {
		return err
	}
	key := futexFileKey(windows.Handle(fd))
	var body [8]byte
	binary.LittleEndian.PutUint64(body[:], key)
	w.run.code.fileTruncating([2]uint64{key, mappedShared}, body[:])
	return truncate()
}
