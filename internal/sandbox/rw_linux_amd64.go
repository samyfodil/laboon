package sandbox

import (
	"debug/elf"

	"golang.org/x/sys/unix"

	"github.com/samyfodil/laboon/internal/rewrite"
)

const (
	elfMachine   = elf.EM_X86_64
	platform     = "x86_64" // AT_PLATFORM
	unameMachine = "x86_64"
	trampReach   = 1 << 31 // jmp rel32
)

// mapVdso maps a vDSO into the stub process when the guest has unmapped its
// own, as each execve on Linux maps a fresh one: arch_prctl(ARCH_MAP_VDSO_64),
// on the guest's thread, with the kernel choosing where.
func (g *dguest) mapVdso() { g.host(unix.SYS_ARCH_PRCTL, 0x2003, 0) }

// archAuxv returns the auxv entries only this architecture passes.
func archAuxv() []uint64 { return nil }

// Guest syscall sites take the ud2/SIGILL path by default: it is serviced on
// the signal altstack, so no servicing ever runs on the guest's own stack. The
// stealing trampoline instead services on the guest stack, which corrupts a
// guest whose thread stacks are small and adjacently packed with no guard page
// between them -- a nested laboon's Go goroutine stacks -- by underflowing one
// stack's servicing frames into its neighbor. fastTramp lets a test exercise
// the trampoline. The trampoline now services on a per-thread scratch stack
// via the stub's %gs anchor, never the guest's own stack, so it is the default.
var fastTramp = true

func (g *dguest) newRewriter(base, size uint64) codeRewriter {
	// The %gs trampoline anchor is available only to the outermost stub, which
	// owns the real %gs: its trampoline services on a per-thread scratch stack
	// reached through %gs, never the guest's own stack. A nested laboon's stub
	// cannot own %gs (its own %gs is the outer's anchor, and its
	// arch_prctl(ARCH_SET_GS) is virtualized by the outer), so its guests take
	// the trap path, which services on the signal altstack and composes to any
	// depth. Nesting is thus correct everywhere and fast at the top level.
	gs := fastTramp && outermost
	if !gs {
		size = 0
	}
	entry := g.run.entry
	if gs {
		entry = g.run.entryGs
	}
	w := rewrite.New(base, size, entry)
	if gs {
		w.GsAnchor(stubSp, stubScratchTop, stubBusy, stubKicked, g.run.latekick)
	}
	w.NoStray = g.cfg.Trace == nil
	return w
}

// imageSites holds what segment rewriting needs from the whole ELF: function
// entries from the unwind table and from the symbol tables, and where its
// executable sections are.
type imageSites struct {
	eh, sym []uint64
	text    [][2]uint64
}

func analyzeImage(f *elf.File) imageSites {
	eh, sym := rewrite.ELFEntries(f)
	if f.Entry != 0 { // the program's entry point is a guaranteed code boundary
		sym = append(sym, f.Entry)
	}
	return imageSites{eh, sym, rewrite.ExecRanges(f)}
}

// imagePlan is the rewrite plan of all of an image's executable segments,
// with sites at file offsets.
type imagePlan = rewrite.Plan

const imageSalt = "linux-amd64-image-3"

// imagePlan returns pf's plan, by its file identity when it has been seen
// before: then the file is neither analyzed nor hashed.
func (g *dguest) imagePlan(pf *progFile, f *elf.File) imagePlan {
	p, err := g.cfg.Cache.ByID(imageSalt, pf.id, nil, func() (rewrite.Plan, error) {
		var out rewrite.Plan
		var s *imageSites
		for _, p := range f.Progs {
			if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 || p.Off+p.Filesz > uint64(len(pf.data)) {
				continue
			}
			if s == nil {
				a := analyzeImage(f)
				s = &a
			}
			for _, site := range g.segmentPlan(*s, p, pf.data[p.Off:p.Off+p.Filesz]).Sites {
				site.Off += uint32(p.Off)
				out.Sites = append(out.Sites, site)
			}
		}
		return out, nil
	})
	if err != nil {
		return rewrite.Plan{}
	}
	return p
}

// segmentPlan analyzes one executable segment, seg, by recursive descent from
// every known instruction boundary (unwind table + symbols + program entry),
// which decodes only real code and never drifts through data interleaved in the
// text (V8's builtins blob is the motivating case). A linear byte scan is never
// used: it cannot tell code from data, so on any binary that interleaves them it
// rewrites a matching data word and silently corrupts the guest.
//
// The amount of unwind info decides only whether to scavenge for syscalls reached
// only indirectly (function pointers), which descent cannot follow:
//
//   - Dense .eh_frame (a C/C++ binary like node/V8): descent from the entries is
//     complete, so scavenging is off -- it would risk a false positive in a
//     code+data blob.
//   - Sparse/no .eh_frame (musl, Go, stripped): scavenge the unreached remainder
//     under its validity test (a clean instruction stream, landing exactly on the
//     0f 05, near already-decoded code). A syscall neither descent nor scavenge
//     proves is code is left as a raw 0f 05 and caught loudly by seccomp -- never
//     patched into data.
func (g *dguest) segmentPlan(s imageSites, p *elf.Prog, seg []byte) rewrite.Plan {
	var ents []int
	add := func(addrs []uint64) {
		for _, e := range addrs {
			if e >= p.Vaddr && e < p.Vaddr+p.Filesz {
				ents = append(ents, int(e-p.Vaddr))
			}
		}
	}
	add(s.eh)
	add(s.sym)
	return g.cfg.Cache.Entries(seg, ents, rewrite.SegmentRanges(s.text, p.Vaddr, p.Filesz))
}

// rewriteSegment rewrites one executable segment, seg, loaded at vaddr,
// following the image's plan.
func (g *dguest) rewriteSegment(cw codeRewriter, plan imagePlan, p *elf.Prog, seg []byte, vaddr uint64) {
	var sp rewrite.Plan
	for _, s := range plan.Sites {
		if uint64(s.Off) >= p.Off && uint64(s.Off) < p.Off+p.Filesz {
			s.Off -= uint32(p.Off)
			sp.Sites = append(sp.Sites, s)
		}
	}
	cw.(*rewrite.Rewriter).Apply(sp, seg, vaddr)
}

const codeSalt = "linux-amd64-code-3"

// rewriteCode rewrites code made executable at run time, by recursive descent --
// never a linear scan, which cannot tell a JIT's constant pools and jump tables
// from code and would drift into them. Code mapped from a readable file descends
// on the file's .eh_frame (a C++/LLVM .so like librustc_driver.so interleaves
// data in its text); a non-ELF region or a stale/closed fd (a JIT region
// re-protected after its file was closed) descends from the region start and
// scavenges, leaving any syscall it cannot prove is code as a raw 0f 05 for
// seccomp to catch loudly rather than patching a data word. A plan is kept by
// the file's identity, only in memory for an unlinked file (a memfd) or for
// code with no file behind it.
func (g *dguest) rewriteCode(cw codeRewriter, code []byte, addr uint64, src *codeSource) {
	id, ok := src.identity()
	if src != nil && src.r != nil {
		if ef, err := elf.NewFile(src.r); err == nil {
			for _, p := range ef.Progs {
				if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Off == src.off && uint64(len(code)) >= p.Filesz {
					cw.(*rewrite.Rewriter).Apply(g.segmentPlan(analyzeImage(ef), p, code), code, addr)
					return
				}
			}
		}
	}
	plan := func() (rewrite.Plan, error) {
		return g.cfg.Cache.AnonEntries(code, []int{0}, [][2]int{{0, len(code)}}), nil
	}
	var p rewrite.Plan
	if ok {
		p, _ = g.cfg.Cache.ByID(codeSalt, id, []uint64{src.off, uint64(len(code))}, plan)
	} else {
		p, _ = plan()
	}
	cw.(*rewrite.Rewriter).Apply(p, code, addr)
}

// windowSites analyzes ext, the window of an executable range at addr and
// the page after it, from roots, the addresses in it the windows before
// showed start instructions, sweeping spans, the parts the guest wrote; the
// range's first window (not midway) starts with one too. It rewrites the first n bytes, or past them to the next page
// for a syscall that crosses the cut, and returns how many that is and the
// addresses past them the code decoded goes on at.
func (g *dguest) windowSites(ext []byte, n int, addr uint64, roots []uint64, spans [][2]int, midway bool) (windowPlan, int, []uint64) {
	var offs []int
	if !midway {
		offs = append(offs, 0)
	}
	for _, r := range roots {
		offs = append(offs, int(r-addr))
	}
	p, next := rewrite.AnalyzeWindow(ext, offs, spans, midway, n)
	used := n
	for _, s := range p.Sites {
		if int(s.Off) < n && int(s.Off)+2 > n {
			used = min(len(ext), n+int(pageSize))
		}
	}
	var out []uint64
	for _, o := range next {
		if o >= used {
			out = append(out, addr+uint64(o))
		}
	}
	return p, used, out
}

type windowPlan = rewrite.Plan

func applyWindow(cw codeRewriter, p windowPlan, code []byte, addr uint64) {
	cw.(*rewrite.Rewriter).Apply(p, code, addr)
}
