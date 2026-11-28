//go:build windows

package sandbox

import (
	"debug/elf"
	"slices"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// x86-64 guests on Windows: syscall sites become trampolines or ud2, %fs
// accesses become islands that read the guest thread pointer from a TEB slot.

const elfMachine = elf.EM_X86_64

const (
	wCloneNr   = 56
	wExit      = 60
	wExitGroup = 231
	wGtod      = 96
	wSetTid    = 218
	wSigAct    = 13
	wSigMask   = 14
	wSigAlt    = 131
	wGetrandom = 318
	wYield     = 24
	wNanosleep = 35
	wTime      = x64Time
)

// codeTrampMax bounds the trampolines sized for a code mapping: they must
// stay in rel32 range of it.
const codeTrampMax = 1 << 30

// toGeneric maps an x86-64 syscall to the shared table's key. poll, select
// and pause have no generic form: the first two have keys of their own
// (poll_windows.go), and pause is a ppoll on nothing.
func toGeneric(nr uint64, a [6]uint64) (uint64, [6]uint64, bool) {
	switch nr {
	case 7:
		return winPoll, a, true
	case 23:
		return winSelect, a, true
	case 34:
		return lxPpoll, [6]uint64{}, true
	}
	return x64Generic(nr, a)
}

func fromGeneric(nr uint64, a [6]uint64, r int64) int64 { return x64Result(nr, a, r) }

type imageRewriter struct {
	g     *wguest
	w     *rewrite.Rewriter
	plan  *rewrite.Plan // the image's sites, at offsets from minbase
	base  uint64
	left  []uint64
	areas int // the areas place was given
}

// rewritesRawSyscalls: an image whose syscalls stay raw (NoRewrite) is left
// as it is.
const rewritesRawSyscalls = false

func (g *wguest) newRewriter(src imageSrc) (*imageRewriter, error) {
	r := &imageRewriter{g: g}
	if !g.cfg.NoRewrite {
		if p, base, err := g.imagePlan(src); err == nil {
			r.plan, r.base = &p, base
		} else {
			g.tracef("[lc] image plan: %v; segments are swept linearly\n", err)
		}
	}
	return r, nil
}

// traps is where the rewrite left traps: the sites, and the restarts in the
// trampolines.
func (r *imageRewriter) traps() []uint64 {
	return append(slices.Clone(r.w.Sites), r.w.Restarts...)
}

// need is the trampoline area the whole image needs, at most.
func (r *imageRewriter) need() uint64 {
	if r.plan == nil {
		return 0
	}
	return r.plan.TrampBytes()
}

// trampReach is how far a site's jmp reaches its trampoline.
const trampReach = 1<<31 - pageSize

// sizingAreas is where codeSize lets the trampolines of the code at
// [addr, addr+n) go: one area at addr, as a jmp reaches all of it.
func (r *imageRewriter) sizingAreas(addr, n uint64) []trampArea {
	return []trampArea{{addr, codeTrampMax}}
}

// place puts the trampolines in the first area, which a rel32 jmp reaches
// from any code a mapping holds; with none, every site traps.
func (r *imageRewriter) place(areas []trampArea) {
	var tramp, size uint64
	if len(areas) > 0 {
		tramp, size = areas[0].base, areas[0].size
	}
	r.areas = len(areas)
	r.w = rewrite.New(tramp, size, r.g.entry)
	r.w.NoStray = r.g.cfg.Trace == nil && !r.g.cfg.StrictRewrite // the scan only feeds the trace and the strict policy
	r.w.SegmentSlot(tebSlotTP)
	if r.g.exitEntry != 0 {
		r.w.ExitStack(tebSlotStk, r.g.exitEntry)
	}
}

// imagePlan is the plan of every executable segment of src, by its file
// identity when it has one, else by its contents, with offsets from the
// lowest PT_LOAD address.
func (g *wguest) imagePlan(src imageSrc) (rewrite.Plan, uint64, error) {
	f, err := elf.NewFile(src.reader())
	if err != nil {
		return rewrite.Plan{}, 0, err
	}
	base := ^uint64(0)
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			base = min(base, p.Vaddr)
		}
	}
	compute := func() (rewrite.Plan, error) { return analyzeImageFS(f, base) }
	if id, ok := src.identity(); ok {
		p, err := g.cache.ByID(imageSalt, id, nil, compute)
		return p, base, err
	}
	data, err := src.bytes()
	if err != nil {
		return rewrite.Plan{}, 0, err
	}
	p, err := g.cache.Memo(imageSalt, data, compute)
	return p, base, err
}

// segment rewrites seg, the bytes at elfVaddr in the file, loaded at vaddr:
// all of an executable segment, or the part of one a code mapping covers.
func (r *imageRewriter) segment(seg []byte, vaddr, elfVaddr uint64) {
	if r.plan == nil {
		r.w.Apply(r.g.cache.Plan(seg), seg, vaddr)
		if !testNoFSIslands {
			r.left = append(r.left, r.w.PatchFS(seg, vaddr, r.g.cache.FS(seg))...)
		}
		return
	}
	lo, hi := elfVaddr-r.base, elfVaddr-r.base+uint64(len(seg))
	var sp rewrite.Plan
	for _, s := range r.plan.Sites {
		if o := uint64(s.Off); o >= lo && o+2 <= hi {
			if o-uint64(s.Steal) < lo {
				s.Steal = 0 // the instruction before it is outside this mapping
			}
			s.Off = uint32(o - lo)
			sp.Sites = append(sp.Sites, s)
		}
	}
	for _, s := range r.plan.FS {
		if o := uint64(s.Off); o >= lo && o+uint64(s.Len) <= hi {
			if o-uint64(s.Steal) < lo {
				s.Steal = 0
			}
			s.Off = uint32(o - lo)
			sp.FS = append(sp.FS, s)
		}
	}
	r.w.Apply(sp, seg, vaddr)
	if !testNoFSIslands {
		r.left = append(r.left, r.w.PatchFS(seg, vaddr, sp.FS)...)
	}
}

// finish returns each area's contents: the first's trampolines, the others
// empty. An %fs site without an island faults (the real FS base is 0); the
// stub's exception handler then loads the guest thread pointer as the FS
// base and re-runs it.
func (r *imageRewriter) finish(lo, hi uint64) ([][]byte, error) {
	for _, a := range r.left {
		r.g.tracef("[lc] %%fs site at %#x left to the fault handler\n", a)
	}
	if err := r.g.strayPolicy(r.w.Stray); err != nil {
		return nil, err
	}
	r.g.tracef("[lc] image %#x-%#x: %d syscall sites (%d fast), %d %%fs islands\n", lo, hi, len(r.w.Sites), r.w.Fast, r.w.FS)
	out := make([][]byte, r.areas)
	if r.areas > 0 {
		out[0] = r.w.Trampolines()
	}
	return out, nil
}
