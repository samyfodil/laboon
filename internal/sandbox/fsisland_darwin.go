//go:build darwin

package sandbox

import "github.com/samyfodil/laboon/internal/rewrite"

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
		if a[1] > maxCodeRead {
			return 0
		}
		code := make([]byte, a[1])
		if g.getBuf(text, code) != nil {
			return 0
		}
		orig := append([]byte(nil), code...)
		w := rewrite.New(area, a[5]&0xffffffff, 0)
		w.SegmentSlot(uint32(a[5] >> 32))
		w.PatchFS(code, text, sites)
		if w.FS == 0 || g.putBuf(area, w.Trampolines()) != nil {
			return 0
		}
		for i := 0; i < len(code); {
			if code[i] == orig[i] {
				i++
				continue
			}
			j := i
			for j < len(code) && code[j] != orig[j] {
				j++
			}
			if g.putBuf(text+uint64(i), code[i:j]) != nil {
				return 0
			}
			i = j
		}
		return int64(len(w.Trampolines()))
	})
}
