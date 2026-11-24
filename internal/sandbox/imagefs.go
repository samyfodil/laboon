//go:build darwin || windows

package sandbox

import (
	"debug/elf"
	"errors"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// imageSalt names the image analysis in cache keys; change it whenever
// analyzeImageFS would give a different plan for the same file.
const imageSalt = "x86-image-fs-4"

// analyzeImageFS plans f's executable segments: recursive descent from its
// function entries, so data in its text (V8's embedded builtins, a
// .rodata sharing the segment) is never decoded as code, then a sweep of its
// executable sections for the syscalls of functions no entry names
// (rewrite.AnalyzeEntriesFS). %fs sites in code that only an indirect branch
// reaches are left to the stub's fault handler.
func analyzeImageFS(f *elf.File, base uint64) (rewrite.Plan, error) {
	var out rewrite.Plan
	var eh, sym []uint64
	var text [][2]uint64
	entries := false
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 || p.Filesz == 0 {
			continue
		}
		if p.Vaddr+p.Filesz-base >= 1<<32 {
			return rewrite.Plan{}, errors.New("image too large for a plan")
		}
		seg := make([]byte, p.Filesz)
		if _, err := p.ReadAt(seg, 0); err != nil {
			return rewrite.Plan{}, err
		}
		if !entries {
			eh, sym = rewrite.ELFEntries(f)
			if f.Entry != 0 {
				sym = append(sym, f.Entry)
			}
			text = rewrite.ExecRanges(f)
			entries = true
		}
		var ents []int
		for _, e := range append(eh, sym...) {
			if e >= p.Vaddr && e < p.Vaddr+p.Filesz {
				ents = append(ents, int(e-p.Vaddr))
			}
		}
		sp := rewrite.AnalyzeEntriesFS(seg, ents, rewrite.SegmentRanges(text, p.Vaddr, p.Filesz))
		d := uint32(p.Vaddr - base)
		for _, s := range sp.Sites {
			s.Off += d
			out.Sites = append(out.Sites, s)
		}
		for _, s := range sp.FS {
			s.Off += d
			out.FS = append(out.FS, s)
		}
	}
	return out, nil
}
