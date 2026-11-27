package sandbox

import (
	"debug/elf"
	"io"
	"slices"
	"sync"

	"github.com/samyfodil/laboon/internal/rewrite"
)

const (
	elfMachine   = elf.EM_AARCH64
	platform     = "aarch64" // AT_PLATFORM
	unameMachine = "aarch64"
	trampReach   = 1 << 27 // b imm26
)

// mapVdso does nothing: arm64 Linux maps a vDSO only at execve, so a guest
// that unmapped its own goes without one, its libc making the calls.
func (g *dguest) mapVdso() {}

// hostAuxv holds the host's AT_HWCAP, AT_HWCAP2 and AT_MINSIGSTKSZ.
var hostAuxv = sync.OnceValue(func() []uint64 { return readHostAuxv(16, 26, 51) })

// archAuxv passes the host's AT_HWCAP and AT_HWCAP2, from which glibc and
// musl pick their string, memory and crypto routines, and AT_MINSIGSTKSZ,
// the signal frame size sysconf(_SC_MINSIGSTKSZ) reports.
func archAuxv() []uint64 { return hostAuxv() }

// Guest syscall sites branch to islands that enter the stub, which services
// them on the slot's own stack (OwnStack, stub lc_syscall_entry): nothing of
// the service runs on the guest's stack, which in a nested laboon's Go
// goroutines is small and packed against its neighbor's. A site without an
// island in reach takes the udf/SIGILL path, serviced on the signal altstack;
// fastTramp false sends every site there, for a test to exercise it.
var fastTramp = true

func (g *dguest) newRewriter(base, size uint64) codeRewriter {
	if !fastTramp {
		size = 0
	}
	w := rewrite.NewA64(base, size, g.run.entry)
	w.OwnStack()
	w.NoStray = g.cfg.Trace == nil
	return w
}

// imageSites are the svc sites of a whole ELF, as offsets from base, its
// lowest PT_LOAD address (so they fit the cache's u32 offsets).
type imageSites struct {
	base uint64
	offs []uint32
}

// linuxSitesSalt names the analysis in cache keys; change it whenever
// rewrite.A64ELFSites would give a different answer for the same file.
const linuxSitesSalt = "linux-a64-sites-4"

// imagePlan is an image's sites.
type imagePlan = imageSites

func (g *dguest) imagePlan(pf *progFile, f *elf.File) imagePlan {
	return g.analyzeImage(pf.id, true, func() ([]byte, error) { return pf.data, nil }, f)
}

// analyzeImage finds the sites of the ELF f, whose contents data returns. A host
// file (hasID) seen before is found by its identity, without reading or hashing
// it; a non-host file (no stable identity) is analyzed by its content, which is
// still memoized by the content's hash.
func (g *dguest) analyzeImage(id rewrite.FileID, hasID bool, data func() ([]byte, error), f *elf.File) imageSites {
	base := ^uint64(0)
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			base = min(base, p.Vaddr)
		}
	}
	byContent := func() ([]uint32, error) {
		b, err := data()
		if err != nil {
			return nil, err
		}
		return g.cfg.Cache.Offsets(linuxSitesSalt, b, func() ([]uint32, error) {
			vs, err := rewrite.A64ELFSites(f)
			if err != nil {
				return nil, err
			}
			out := make([]uint32, len(vs))
			for i, v := range vs {
				out[i] = uint32(v - base)
			}
			return out, nil
		})
	}
	var offs []uint32
	var err error
	if hasID {
		offs, err = g.cfg.Cache.OffsetsByID(linuxSitesSalt, id, byContent)
	} else {
		offs, err = byContent()
	}
	if err != nil {
		// Unrewritten syscalls still meet the seccomp backstop.
		return imageSites{}
	}
	return imageSites{base, offs}
}

// segment returns the sites inside the file-backed part of p, as offsets
// from its start.
func (s imageSites) segment(p *elf.Prog) []int {
	var out []int
	for _, o := range s.offs {
		if va := s.base + uint64(o); va >= p.Vaddr && va < p.Vaddr+p.Filesz {
			out = append(out, int(va-p.Vaddr))
		}
	}
	return out
}

func (g *dguest) rewriteSegment(cw codeRewriter, s imagePlan, p *elf.Prog, seg []byte, vaddr uint64) {
	cw.(*rewrite.A64Rewriter).Apply(s.segment(p), seg, vaddr)
}

// codeSalt names the analysis of anonymous runtime code.
const codeSalt = "linux-a64-code-2"

// rewriteCode rewrites code made executable at run time. Code mapped from an
// ELF file (a shared library) gets the same whole-file analysis as an image;
// anonymous code has no symbols, so descent starts at its first byte and the
// inlined-syscall heuristic covers the rest. Its sites are kept only in memory
// unless a file is behind it.
func (g *dguest) rewriteCode(cw codeRewriter, code []byte, addr uint64, src *codeSource) {
	w := cw.(*rewrite.A64Rewriter)
	if src != nil {
		if sites, ok := g.fileCodeSites(src, uint64(len(code))); ok {
			w.Apply(sites, code, addr)
			return
		}
	}
	memo := g.cfg.Cache.AnonOffsets
	if _, ok := src.identity(); ok {
		memo = g.cfg.Cache.Offsets
	}
	offs, err := memo(codeSalt, code, func() ([]uint32, error) {
		var out []uint32
		for _, o := range rewrite.A64SegmentSites(code, 0, []uint64{0}, 0, uint64(len(code))) {
			out = append(out, uint32(o))
		}
		return out, nil
	})
	if err != nil {
		return
	}
	sites := make([]int, len(offs))
	for i, o := range offs {
		sites[i] = int(o)
	}
	w.Apply(sites, code, addr)
}

// fileCodeSites returns the sites in the n bytes at src, if src is part of an
// executable segment of an ELF file.
func (g *dguest) fileCodeSites(src *codeSource, n uint64) ([]int, bool) {
	if src == nil || src.r == nil {
		return nil, false
	}
	id, ok := src.identity()
	f, err := elf.NewFile(src.r)
	if err != nil || f.Machine != elfMachine {
		return nil, false
	}
	s := g.analyzeImage(id, ok, func() ([]byte, error) {
		return io.ReadAll(io.NewSectionReader(src.r, 0, 1<<62))
	}, f)
	var out []int
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		for _, o := range s.segment(p) {
			if fo := p.Off + uint64(o); fo >= src.off && fo < src.off+n {
				out = append(out, int(fo-src.off))
			}
		}
	}
	return out, true
}

// windowSites analyzes the first n bytes of ext, the window of an executable
// range at addr, from roots, the addresses in it known to start instructions;
// the range's first window (not midway) starts with one. A midway window's
// first word may sit in a literal pool, so it is no root: its svc words are
// taken as the code before them shows they are code. Instructions are fixed
// width, so no window cuts one; what carries to the windows after is the
// targets of branches past its end.
func (g *dguest) windowSites(ext []byte, n int, addr uint64, roots []uint64, spans [][2]int, midway bool) (windowPlan, int, []uint64) {
	funcs := slices.Clone(roots)
	if !midway {
		funcs = append(funcs, addr)
	}
	sites, next := rewrite.A64WindowSites(ext[:n], addr, funcs)
	return sites, n, next
}

type windowPlan = []int

func applyWindow(cw codeRewriter, sites windowPlan, code []byte, addr uint64) {
	cw.(*rewrite.A64Rewriter).Apply(sites, code, addr)
}
