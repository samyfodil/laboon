//go:build windows

package sandbox

import (
	"debug/elf"
	"fmt"
	"slices"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// arm64 guests on Windows: svc sites become islands or udf, and every
// mrs/msr tpidr_el0 becomes an island over the guest thread pointer in a TEB
// slot, since the stub keeps the TEB in tpidr_el0 (stub/windows/aarch64.zig).
// Syscall numbers are asm-generic already.

const elfMachine = elf.EM_AARCH64

const (
	wCloneNr      = 220
	wExit         = 93
	wExitGroup    = 94
	wGtod         = 169
	wSetTid       = 96
	wSigAct       = 134
	wSigMask      = 135
	wSigAlt       = 132
	wGetrandom    = 278
	wYield        = 124
	wNanosleep    = 101
	wClockGettime = 113
	wTime         = ^uint64(0) // arm64 has no time(2)

	// ctrEL0 is the CTR_EL0 the guest reads: IDC=DIC=0, 64-byte data-cache
	// lines, and the largest instruction-cache line there is (IminLine 15:
	// 128 KiB). A JIT's flush loop steps by that line, so it issues one
	// ic ivau per 128 KiB, each a trap the stub serves by flushing the whole
	// aligned 128 KiB (see the stub's CTR_VALUE): every line is covered,
	// with a trap per block instead of per 64 bytes.
	ctrEL0 = 0x8444c00f
)

// codeTrampMax bounds the trampolines sized for a code mapping: they must
// stay in B range of it.
const codeTrampMax = 64 << 20

func toGeneric(nr uint64, a [6]uint64) (uint64, [6]uint64, bool) { return nr, a, true }

func fromGeneric(_ uint64, _ [6]uint64, r int64) int64 { return r }

type imageRewriter struct {
	g       *wguest
	w       *rewrite.A64Rewriter
	sites   []uint32 // offsets from minbase: svc and system-register sites
	minbase uint64
	left    []uint64
	dcNops  int
}

// traps is where the rewrite left traps: the sites (those given an island
// branch rather than trap, and are never asked about).
func (r *imageRewriter) traps() []uint64 {
	return slices.Clone(r.w.Sites)
}

// need is the trampoline area the image needs beyond the default; the arm64
// islands fit in it.
func (r *imageRewriter) need() uint64 { return 0 }

// trampReach is how far a site's b reaches its island.
const trampReach = 1<<27 - pageSize

// sizingAreas is where codeSize lets the islands of the code at [addr,
// addr+n) go: an area against each end, as the stub places them for code
// wider than a b reaches, each with room for an island per site.
func (r *imageRewriter) sizingAreas(addr, n uint64) []trampArea {
	room := rewrite.A64AreaBytes(len(r.sites))
	return []trampArea{{addr - room, room}, {addr + n, room}}
}

// place puts the islands in areas: each site's goes in the first one its b
// reaches. The stub's syscall entry moves to its own stack, and exit sites
// switch to it before anything is written (see stub/windows/aarch64.zig).
func (r *imageRewriter) place(areas []trampArea) {
	as := make([]rewrite.A64Area, len(areas))
	for i, a := range areas {
		as[i] = rewrite.A64Area{Base: a.base, Size: a.size}
	}
	r.w = rewrite.NewA64Areas(as, r.g.entry)
	r.w.OwnStack()
	if r.g.exitEntry != 0 {
		r.w.ExitStack(tebSlotStk, r.g.exitEntry)
	}
}

func (g *wguest) newRewriter(src imageSrc) (*imageRewriter, error) {
	r := &imageRewriter{g: g}
	if g.cfg.NoRewrite {
		return nil, errNoBackstop
	}
	f, err := elf.NewFile(src.reader())
	if err != nil {
		return nil, err
	}
	r.minbase = ^uint64(0)
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			r.minbase = min(r.minbase, p.Vaddr&^(darwinPage-1))
		}
	}
	r.sites, err = winA64Sites(g.cache, src, r.minbase)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// winA64Salt names winA64Sites's analysis in cache keys; change it whenever
// the analysis would give a different answer for the same file.
const winA64Salt = "windows-a64-sites-3"

// winA64Sites is the svc and system-register sites of src (computeSitesELF, as
// darwin finds them), as offsets from minbase. The result is cached by the
// file's identity when it has one, so a file seen before is not hashed
// (node's 126 MB).
func winA64Sites(c *rewrite.Cache, src imageSrc, minbase uint64) ([]uint32, error) {
	compute := func() ([]uint32, error) {
		f, err := elf.NewFile(src.reader())
		if err != nil {
			return nil, err
		}
		return computeSitesELF(f)
	}
	if id, ok := src.identity(); ok {
		return c.OffsetsByID(winA64Salt, id, compute)
	}
	data, err := src.bytes()
	if err != nil {
		return nil, err
	}
	return c.Offsets(winA64Salt, data, compute)
}

// segment rewrites one executable segment, loaded at vaddr (elfVaddr in the
// file).
func (r *imageRewriter) segment(seg []byte, vaddr, elfVaddr uint64) {
	lo := elfVaddr - r.minbase
	var svc, sys []int
	for _, s := range r.sites {
		o := int64(uint64(s) - lo)
		if uint64(s) < lo || o+4 > int64(len(seg)) {
			continue
		}
		if rewrite.IsA64Sysreg(le32(seg[o:])) {
			sys = append(sys, int(o))
		} else {
			svc = append(svc, int(o))
		}
	}
	r.w.Apply(svc, seg, vaddr)
	r.left = append(r.left, r.w.Sysreg(sys, seg, vaddr, tebSlotTP, ctrEL0)...)
	r.dcNops += nopDataCacheOps(seg)
}

// Windows traps the EL0 cache maintenance a JIT issues after writing code
// (probe 5): dc cvau/cvac/civac/cvap and ic ivau. The stub serves ic ivau
// with NtFlushInstructionCache, which cleans the data cache to the point of
// unification as well, so the data-cache cleans are not needed: they become
// nops here rather than a trap per cache line (a JIT's flush loop issues one
// per line). Their encodings are distinctive enough for a linear scan, as the
// system-register sites are.
const (
	a64DCCVAC  = 0xd50b7a20
	a64DCCVAU  = 0xd50b7b20
	a64DCCVAP  = 0xd50b7c20
	a64DCCVADP = 0xd50b7d20
	a64DCCIVAC = 0xd50b7e20
	a64NOP     = 0xd503201f
)

func nopDataCacheOps(seg []byte) int {
	n := 0
	for o := 0; o+4 <= len(seg); o += 4 {
		switch le32(seg[o:]) &^ 0x1f {
		case a64DCCVAC, a64DCCVAU, a64DCCVAP, a64DCCVADP, a64DCCIVAC:
			put32(seg[o:], a64NOP)
			n++
		}
	}
	return n
}

// finish returns each area's contents. A tpidr_el0 access left in place would
// read the TEB as the guest's thread pointer, so the image is refused.
func (r *imageRewriter) finish(lo, hi uint64) ([][]byte, error) {
	if len(r.left) > 0 {
		return nil, fmt.Errorf("%d system-register sites out of reach of their islands (first at %#x)", len(r.left), r.left[0])
	}
	if err := r.g.strayPolicy(r.w.Stray); err != nil {
		return nil, err
	}
	r.g.tracef("[lc] image %#x-%#x: %d svc sites (%d islands), %d system-register islands, %d data-cache cleans dropped\n", lo, hi, len(r.w.Sites), r.w.Fast, r.w.Sysregs, r.dcNops)
	return r.w.Areas(), nil
}
