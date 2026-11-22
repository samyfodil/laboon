//go:build darwin

package sandbox

// anonInsnEnd is where the instruction at pc ends, for one that may run from
// one page into the next: x86-64's; an arm64 instruction never does.
func (g *dguest) anonInsnEnd(pc uint64) uint64 {
	if g.run == nil || !g.run.x64 {
		return 0
	}
	return insnEnd(g.getBuf, pc)
}

func init() {
	regSys(lcAnonSites, func(g *dguest, a [6]uint64) int64 {
		return g.mp.anon.sites(g, uint64(g.guestPageSize()), a[0], a[1], g.getBuf, g.anonInsnEnd)
	})
	regSys(lcAnonLearn, func(g *dguest, a [6]uint64) int64 {
		return g.mp.anon.learn(g, uint64(g.guestPageSize()), int(a[0]), g.getBuf, g.anonInsnEnd)
	})
	regSys(lcInsn, func(g *dguest, a [6]uint64) int64 { return insnAt(g.getBuf, a[0]) })
}
