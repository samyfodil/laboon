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
}
