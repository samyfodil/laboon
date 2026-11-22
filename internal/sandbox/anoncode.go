//go:build windows || darwin

package sandbox

import (
	"bytes"
	"encoding/binary"
	"hash/maphash"
	"slices"
	"sync"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// Code made executable at run time (stub/windows/mem.zig, stub/macos/wx.zig):
// the stub keeps a guest's executable memory that is not code from a file
// unexecutable until a page of it is about to run, freezes the page and asks
// here for its syscall sites (lcAnonSites), which it turns into traps before
// it makes the page executable. A page is analyzed from the instruction
// boundaries it is known to be entered at -- where the thread was about to
// run, and where the code of other pages branches into it -- by descent, then
// swept, as file code is.
//
// The stub puts a page's syscalls back where its traps were before the page
// can change, so a page is analyzed as the guest wrote it. anonCode keeps each
// page's trap sites and the entries other pages give it, with the contents of
// the page each came from, its traps read as the syscalls they were. An entry
// from a page that changed since is dropped, as the boundary it named may be
// gone.
const lcAnonSites = 0x4c430029 // (page, pc[, aside, area, room]) -> n; scratch: the n u32 site offsets, then a u32 count and the u64 pages to rewrite again (then, given an area, anonTramps's patches)

// lcAnonLearn hands over pages the stub made executable without asking: a
// page with no syscall while no page that ran had one, whose analysis could
// only matter for the entries it gives a page with syscalls, and so is done
// once one needs it, as if when it first ran; and, in a fork child, every page
// that runs, which its supervisor has not seen.
const lcAnonLearn = 0x4c43002a // (n): the n (page, pc) u64 pairs in the scratch -> 0; scratch: a u32 count and the u64 pages to rewrite again

type anonCode struct {
	mu    sync.Mutex
	seed  maphash.Seed
	pages map[uint64]*anonPage
}

type anonPage struct {
	hash    uint64  // the page as analyzed; 0 before
	patched []int   // its trap sites
	steal   []uint8 // each one's run a trampoline can take (x86-64), else 0
	stolen  []anonStolen
	entries []anonEntry
}

// anonStolen is an instruction the stub replaced with a jump to a
// trampoline (anonTramps): its bytes, at off, and what took their place.
type anonStolen struct {
	off       int
	orig, new []byte
}

// anonEntry is an instruction boundary in a page that code in another page,
// from, branches to, with the contents from had then.
type anonEntry struct {
	off  int
	from uint64
	hash uint64
}

// sites finds the syscall sites of the ps-byte page at page, which the stub
// has frozen, entered at pc (0: only where other pages enter it), writes them
// and the executable pages it found new entries of to the slot scratch, and
// returns how many sites. read reads guest memory; insnEnd is where the
// instruction at a pc ends, or 0.
func (a *anonCode) sites(dg *dguest, ps, page, pc uint64, read func(addr uint64, b []byte) error, insnEnd func(pc uint64) uint64) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	sites, gained, ok := a.analyze(ps, page, pc, read, insnEnd)
	if !ok {
		return sErr(lxEFAULT)
	}
	var again []uint64
	for _, q := range gained {
		if a.pages[q].hash != 0 {
			again = append(again, q) // already ran: rewritten again with the new entry
		}
	}
	sc := dg.scratch()
	if 4*(len(sites)+1)+8*len(again) > len(sc) {
		return sErr(lxENOMEM)
	}
	for i, off := range sites {
		binary.LittleEndian.PutUint32(sc[4*i:], uint32(off))
	}
	putPages(sc[4*len(sites):], again)
	return int64(len(sites))
}

// learn analyzes the n pages of the scratch's (page, pc) pairs, which run
// unchanged since the stub froze them, until what they branch to among
// themselves is known, and writes the pages that ran analyzed and gained
// entries to the scratch.
func (a *anonCode) learn(dg *dguest, ps uint64, n int, read func(addr uint64, b []byte) error, insnEnd func(pc uint64) uint64) int64 {
	sc := dg.scratch()
	if 16*n > len(sc) {
		return sErr(lxEINVAL)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	pcs := make(map[uint64]uint64, n)
	work := make([]uint64, 0, n)
	for i := range n {
		page := binary.LittleEndian.Uint64(sc[16*i:])
		pcs[page] = binary.LittleEndian.Uint64(sc[16*i+8:])
		work = append(work, page)
	}
	queued := make(map[uint64]bool, n)
	for _, p := range work {
		queued[p] = true
	}
	var again []uint64
	for len(work) > 0 {
		page := work[0]
		work = work[1:]
		queued[page] = false
		_, gained, ok := a.analyze(ps, page, pcs[page], read, insnEnd)
		if !ok {
			continue
		}
		for _, q := range gained {
			if _, in := pcs[q]; in {
				if !queued[q] {
					queued[q] = true
					work = append(work, q)
				}
			} else if a.pages[q].hash != 0 {
				again = append(again, q)
			}
		}
	}
	if 4+8*len(again) > len(sc) {
		return sErr(lxENOMEM)
	}
	putPages(sc, again)
	return 0
}

// analyze finds the syscall sites of the page at page entered at pc, records
// its branches out as entries of the pages they enter, and returns the sites
// and the pages that gained an entry. The lock is held.
func (a *anonCode) analyze(ps, page, pc uint64, read func(addr uint64, b []byte) error, insnEnd func(pc uint64) uint64) ([]int, []uint64, bool) {
	code := make([]byte, ps)
	if read(page, code) != nil {
		return nil, nil, false
	}
	p := a.page(page)
	var entries []int
	switch {
	case pc >= page && pc < page+ps:
		entries = append(entries, int(pc-page))
	case pc != 0 && pc < page:
		// An instruction from the page before runs into this one: what
		// follows it is the first boundary here.
		if end := insnEnd(pc); end > page && end < page+ps {
			entries = append(entries, int(end-page))
		}
	}
	kept := p.entries[:0]
	src := make([]byte, ps)
	for _, e := range p.entries {
		if read(e.from, src) != nil {
			continue
		}
		untrap(src, a.pages[e.from])
		if a.hash(src) == e.hash {
			kept = append(kept, e)
			entries = append(entries, e.off)
		}
	}
	p.entries = kept
	sites, steal, exits := anonAnalyze(code, entries)
	p.hash, p.patched, p.steal, p.stolen = a.hash(code), sites, steal, nil
	var gained []uint64
	for _, x := range exits {
		t := page + uint64(int64(x))
		tp := t &^ (ps - 1)
		if tp == page {
			continue
		}
		q := a.page(tp)
		e := anonEntry{off: int(t - tp), from: page, hash: p.hash}
		known := false
		for i, have := range q.entries {
			if have.off == e.off && have.from == page {
				q.entries[i].hash = e.hash // the same boundary, from page as it is now
				known = true
				break
			}
		}
		if !known {
			q.entries = append(q.entries, e)
			gained = append(gained, tp)
		}
	}
	return sites, gained, true
}

// hash is the page's contents as anonCode compares them: keyed, so no guest
// can make two contents agree.
func (a *anonCode) hash(b []byte) uint64 {
	if a.seed == (maphash.Seed{}) {
		a.seed = maphash.MakeSeed()
	}
	return maphash.Bytes(a.seed, b) | 1
}

// page is what is known of the page at addr.
func (a *anonCode) page(addr uint64) *anonPage {
	if a.pages == nil {
		a.pages = map[uint64]*anonPage{}
	}
	p := a.pages[addr]
	if p == nil {
		p = &anonPage{}
		a.pages[addr] = p
	}
	return p
}

// reset forgets every page, at an exec.
func (a *anonCode) reset() {
	a.mu.Lock()
	a.pages = nil
	a.mu.Unlock()
}

// putPages writes a u32 count and the u64 pages to b.
func putPages(b []byte, pages []uint64) {
	binary.LittleEndian.PutUint32(b, uint32(len(pages)))
	for i, q := range pages {
		binary.LittleEndian.PutUint64(b[4+8*i:], q)
	}
}

// cloneInto copies what is known into b, a fork child's, which runs the same
// pages.
func (a *anonCode) cloneInto(b *anonCode) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b.seed = a.seed
	b.pages = make(map[uint64]*anonPage, len(a.pages))
	for k, p := range a.pages {
		q := *p
		q.patched = slices.Clone(p.patched)
		q.steal = slices.Clone(p.steal)
		q.stolen = slices.Clone(p.stolen)
		q.entries = slices.Clone(p.entries)
		b.pages[k] = &q
	}
}

// untrap puts the syscalls back at p's trap sites in code, a page that may
// run with them trapped.
func untrap(code []byte, p *anonPage) {
	if p == nil {
		return
	}
	for _, off := range p.patched {
		untrapSite(code, off)
	}
	for _, s := range p.stolen {
		if at := code[s.off:]; bytes.HasPrefix(at, s.new) {
			copy(at, s.orig)
		}
	}
}

// runs is the trap sites of the page at page as last analyzed, with the run
// before each a trampoline can take.
func (a *anonCode) runs(page uint64) (sites []int, steal []uint8) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.pages[page]
	if p == nil {
		return nil, nil
	}
	return slices.Clone(p.patched), slices.Clone(p.steal)
}

// stole records the instructions the stub replaced in the page at page.
func (a *anonCode) stole(page uint64, s []anonStolen) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p := a.pages[page]; p != nil {
		p.stolen = s
	}
}

func insnEnd(read func(addr uint64, b []byte) error, pc uint64) uint64 {
	b := make([]byte, 16)
	if read(pc, b) != nil {
		return 0
	}
	if n := rewrite.InsnLen(b); n > 0 {
		return pc + uint64(n)
	}
	return 0
}

// lcInsn: (pc) -> the length of the x86-64 instruction there | where its
// RIP-relative displacement starts << 8 (0 when it has none); 0 when it
// decodes as none. The stub runs a store out of line with it
// (stub/windows/ool.zig, stub/macos/ool.zig).
const lcInsn = 0x4c43002c

func insnAt(read func(addr uint64, b []byte) error, pc uint64) int64 {
	b := make([]byte, 16)
	for len(b) > 0 && read(pc, b) != nil {
		b = b[:len(b)-1] // the instruction ends before an unreadable page
	}
	n, at := rewrite.RipDisp(b)
	return int64(n | at<<8)
}
