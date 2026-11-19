//go:build darwin || linux || windows

package sandbox

import (
	"bytes"
	"debug/elf"
	"io"
	"os"
	"syscall"

	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/internal/rewrite"
)

// darwinPage is the stub's page size (16 KiB), used to match its minbase
// rounding so site offsets line up with the stub's load bias.
const darwinPage = 0x4000

// computeSites finds every `svc #0` the stub must rewrite in one guest ELF,
// using the shared arm64 analysis (rewrite.A64SegmentSites: recursive descent
// plus the inlined-syscall heuristic) rather than a linear scan: a bare
// 0xd4000001 word in a literal pool or a GOT/reloc table is data, not a
// syscall, and must not be patched. The stub also guards that the word is
// svc #0. It adds the system-register sites only the macOS stub rewrites.
//
// Each returned offset is (vaddr - minbase): the stub maps the image at a
// kernel-picked base with bias = base - minbase, so the instruction sits at
// base + offset regardless of where the kernel placed it.
//
// The analysis takes about half a second for node, so results are cached by
// file content, and in front of that by file identity, so a file seen before
// is neither read nor hashed.
func computeSites(c *rewrite.Cache, elfPath string) ([]uint32, error) {
	f, err := os.Open(elfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return computeSitesFile(c, f)
}

// computeSitesFile is computeSites over an already-open file (a runtime-loaded
// shared library). It does not close f.
func computeSitesFile(c *rewrite.Cache, f *os.File) ([]uint32, error) {
	read := func() ([]uint32, error) {
		b, err := io.ReadAll(io.NewSectionReader(f, 0, 1<<62))
		if err != nil {
			return nil, err
		}
		return computeSitesBytes(c, b)
	}
	fi, err := hostfs.FileStat(f)
	if err != nil {
		return nil, err
	}
	st, ok := hostfs.StatOf(fi)
	if !ok || st.Ino() == 0 {
		return read()
	}
	return c.OffsetsByID(sitesSalt, rewrite.FileID{
		Dev: st.Dev(), Ino: st.Ino(), Size: st.Size(),
		Mtime: TsNano(st.Mtime()), Ctime: TsNano(st.Ctime()),
	}, read)
}

func TsNano(t syscall.Timespec) int64 { return int64(t.Sec)*1e9 + int64(t.Nsec) }

// sitesSalt names this analysis in cache keys. Change it whenever
// computeSitesELF would give a different answer for the same file.
const sitesSalt = "darwin-a64-sites-4"

func computeSitesBytes(c *rewrite.Cache, b []byte) ([]uint32, error) {
	return c.Offsets(sitesSalt, b, func() ([]uint32, error) {
		f, err := elf.NewFile(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return computeSitesELF(f)
	})
}

// imageBase is the page of the lowest PT_LOAD: a site's place in the image is
// its vaddr less this.
func imageBase(f *elf.File) uint64 {
	var minbase uint64 = ^uint64(0)
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			if b := p.Vaddr &^ (darwinPage - 1); b < minbase {
				minbase = b
			}
		}
	}
	if minbase == ^uint64(0) {
		minbase = 0
	}
	return minbase
}

func computeSitesELF(f *elf.File) ([]uint32, error) {
	minbase := imageBase(f)
	funcs := rewrite.A64ELFEntries(f)

	var sites []uint32
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		code := make([]byte, p.Filesz)
		if _, err := io.ReadFull(p.Open(), code); err != nil {
			return nil, err
		}
		base := p.Vaddr - minbase
		tlo, thi := rewrite.A64TextRange(f, p)
		for _, off := range rewrite.A64SegmentSites(code, p.Vaddr, funcs, tlo, thi) {
			sites = append(sites, uint32(base+uint64(off)))
		}

		// System-register sites the stub rewrites: the guest's musl tpidr_el0
		// thread-pointer reads/writes (Darwin clobbers the physical reg on every
		// reschedule) and its ctr_el0 reads (Apple Silicon traps that at EL0).
		// Found by a LINEAR scan, not descent: descent misses the many sites
		// behind indirect branches in a big C++ binary -- node has ~550 tpidr
		// reads, 166 of them unreachable by descent, and a single un-rewritten one
		// reads clobbered CPU-info and corrupts the guest. The scan is NEON-
		// vectorized on arm64 (rewrite.A64SysregSites). Confined to [.text): a
		// word in .rodata/.got packed into the executable segment that happens to
		// match one of these encodings is data, never an instruction, so rewriting
		// it would silently corrupt the guest; a real sysreg access is in code and
		// so inside .text, so confinement drops only false matches.
		for _, off := range rewrite.A64SysregSites(code) {
			if va := p.Vaddr + uint64(off); va < tlo || va >= thi {
				continue
			}
			sites = append(sites, uint32(base+uint64(off)))
		}
	}
	return sites, nil
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// writeSites marshals site offsets to a temp file in dir (little-endian u32 each) for
// the stub to read, returning the path and a cleanup func. An empty slice still
// writes a (zero-length) file so the stub always has a path to open.
func writeSites(dir string, sites []uint32) (string, func(), error) {
	buf := make([]byte, 4*len(sites))
	for i, s := range sites {
		put32(buf[i*4:], s)
	}
	f, err := os.CreateTemp(dir, "lc-sites-*")
	if err != nil {
		return "", nil, err
	}
	path := f.Name()
	cleanup := func() { os.Remove(path) }
	if _, err := f.Write(buf); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}
