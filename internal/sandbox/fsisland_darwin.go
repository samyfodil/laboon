//go:build darwin

package sandbox

import (
	"cmp"
	"slices"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// lcFsIsland: (pc, island, tp) -> the length n of what takes the place of the
// x86-64 %fs-relative instruction at pc | the length of its island << 8, 0
// when it cannot have one; scratch: the n bytes, then the island at 16. The
// island, at island, reads the guest thread pointer from %gs:tp. The stub
// patches an %fs access that faults once, rather than emulating it at every
// run (stub/macos/fsmem.zig).
const lcFsIsland = 0x4c430038

// lcFsPatch: (text, len, file off, guest fd, area, area len | tp << 32) ->
// the bytes of area used. It moves the %fs-relative instructions of the
// library text just mapped at text, from the file d's offset off and not yet
// run, to islands in area that read the guest thread pointer from %gs:tp, as
// PatchFS does a Windows image. Done before the text first runs, it reaches
// the sites lcFsIsland cannot: one too short for a jmp moves into its island
// with the instructions before it, which no thread can be part way through.
const lcFsPatch = 0x4c430039

// fsRoomUnits is the stub's islands (ISLAND_SIZE, 64 bytes) of room an %fs
// site's island may take: the island itself and a run moved into it.
const fsRoomUnits = 2

func init() {
	regSys(lcFsIsland, func(g *dguest, a [6]uint64) int64 {
		if g.run == nil || !g.run.x64 {
			return 0
		}
		code := make([]byte, 15)
		for len(code) > 0 && g.getBuf(a[0], code) != nil {
			code = code[:len(code)-1]
		}
		patch, isl, ok := rewrite.FSIsland(code, a[0], a[1], uint32(a[2]))
		sc := g.scratch()
		if !ok || len(patch) > 16 || 16+len(isl) > len(sc) {
			return 0
		}
		copy(sc, patch)
		copy(sc[16:], isl)
		return int64(len(patch) | len(isl)<<8)
	})
	regSys(lcFsPatch, func(g *dguest, a [6]uint64) int64 {
		if g.run == nil || !g.run.x64 {
			return 0
		}
		d, ok := g.ft.get(int(int32(a[3])))
		if !ok {
			return 0
		}
		sites := libFSSites(g.cfg.Cache, a[1], a[2], d)
		if len(sites) == 0 {
			return 0
		}
		text, area := a[0], a[4]
		slices.SortFunc(sites, func(x, y rewrite.FSSite) int { return cmp.Compare(x.Off, y.Off) })
		w := rewrite.New(area, a[5]&0xffffffff, 0)
		w.SegmentSlot(uint32(a[5] >> 32))
		buf, orig := make([]byte, fsWindow), make([]byte, fsWindow)
		written := 0
		for i := 0; i < len(sites); {
			lo, hi := fsSpan(sites[i], a[1])
			j := i + 1
			for ; j < len(sites); j++ {
				l, h := fsSpan(sites[j], a[1])
				if max(hi, h)-min(lo, l) > fsWindow {
					break
				}
				lo, hi = min(lo, l), max(hi, h)
			}
			code, was := buf[:hi-lo], orig[:hi-lo]
			if g.getBuf(text+lo, code) != nil {
				return 0
			}
			copy(was, code)
			in := slices.Clone(sites[i:j])
			for k := range in {
				in[k].Off -= uint32(lo)
			}
			w.PatchFS(code, text+lo, in)
			if tr := w.Trampolines(); len(tr) > written {
				if g.putBuf(area+uint64(written), tr[written:]) != nil {
					return 0
				}
				written = len(tr)
			}
			for k := 0; k < len(code); {
				if code[k] == was[k] {
					k++
					continue
				}
				m := k
				for m < len(code) && code[m] != was[m] {
					m++
				}
				if g.putBuf(text+lo+uint64(k), code[k:m]) != nil {
					return 0
				}
				k = m
			}
			i = j
		}
		if w.FS == 0 {
			return 0
		}
		return int64(len(w.Trampolines()))
	})
}

// fsWindow bounds the library text lcFsPatch holds at once: the sites are
// patched in runs, each read with the bytes its patches touch.
const fsWindow = 1 << 20

// fsSpan is the part of a text n bytes long that patching s may touch: the
// run before it, the instruction, and its cave.
func fsSpan(s rewrite.FSSite, n uint64) (lo, hi uint64) {
	l, h := int64(s.Off)-int64(s.Steal), int64(s.Off)+int64(s.Len)
	if s.Cave != 0 {
		l, h = min(l, int64(s.Off)+int64(s.Cave)), max(h, int64(s.Off)+int64(s.Cave)+5)
	}
	return uint64(max(l, 0)), uint64(min(h, int64(n)))
}
