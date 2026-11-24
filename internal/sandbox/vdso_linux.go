package sandbox

import "golang.org/x/sys/unix"

// The kernel's special mappings in the stub process -- [vvar], [vvar_vclock]
// and [vdso], which the guest has for its own (AT_SYSINFO_EHDR) -- outlive the
// guest unmapping or mapping over them: they move aside, into the stub's
// window, where the guest can neither reach nor see them, and come back at
// its next execve, which on Linux maps a fresh vDSO. Linux lets a process move
// them (mremap; CRIU does), and they keep their places relative to each other,
// which the vDSO's code relies on.

// specialPark is where they wait, an offset in the stub's window that
// stub.zig leaves free.
const specialPark = 0x16800000000

// specialMap is one special mapping: where it is, and off, where it sits in
// their block.
type specialMap struct {
	lo, hi, off uint64
	kind        uint64 // mapVdso, mapVvar or mapVvarVclock
	parked      bool
	moved       bool // by the guest (mremap), anywhere its next image may map
}

// noteSpecial records the stub process's special mappings.
func (g *dguest) noteSpecial() {
	es, ok := g.hostMaps()
	if !ok {
		return
	}
	m := g.mp
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range es {
		if k := e.attr >> 8; k == mapVdso || k == mapVvar || k == mapVvarVclock {
			m.special = append(m.special, specialMap{lo: e.lo, hi: e.hi, kind: k})
		}
	}
	for i := range m.special {
		m.special[i].off = m.special[i].lo - m.special[0].lo
	}
}

// parkSpecial moves aside each special mapping wholly inside [lo, hi), which
// the guest is about to unmap or map over. One only partly inside stays: the
// host refuses to split it, as Linux does. g.mp.mu held.
func (g *dguest) parkSpecial(lo, hi uint64) {
	for i := range g.mp.special {
		s := &g.mp.special[i]
		if !s.parked && s.lo >= lo && s.hi <= hi && g.moveSpecial(s, stubLo+specialPark+s.off) {
			s.parked = true
		}
	}
}

// movedSpecial follows a special mapping the guest remapped itself, from old
// to at, and reports whether [old, old+n) was one: the kernel's, which stays
// out of the guest's own record. g.mp.mu held.
func (g *dguest) movedSpecial(old, n, at uint64) bool {
	for i := range g.mp.special {
		if s := &g.mp.special[i]; !s.parked && s.lo == old && s.hi-s.lo == alignUp(n) {
			s.moved = s.moved || at != old
			s.lo, s.hi = at, at+alignUp(n)
			return true
		}
	}
	return false
}

// parkMoved moves aside, before an execve clears the old image, each special
// mapping the guest moved to where the new image may map over it.
// g.mp.mu held.
func (g *dguest) parkMoved() {
	for i := range g.mp.special {
		if s := &g.mp.special[i]; s.moved && !s.parked && g.moveSpecial(s, stubLo+specialPark+s.off) {
			s.parked = true
		}
	}
}

// restoreSpecial brings back, with the rest of their block, the special
// mappings the guest's last image unmapped or mapped over, where an mmap
// would go: the place is claimed with a placeholder first, so they replace
// nothing but it. g.mp.mu held.
func (g *dguest) restoreSpecial() {
	var n uint64
	parked := false
	for _, s := range g.mp.special {
		parked = parked || s.parked
		n = max(n, s.off+s.hi-s.lo)
	}
	if !parked {
		return
	}
	r := g.mapAt(0, n, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, false, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, n, unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|fixed, ^uint64(0), 0)
	})
	if r < 0 {
		return
	}
	base := uint64(r)
	g.untrack(base, n)
	end := base
	for i := range g.mp.special {
		s := &g.mp.special[i]
		if at := base + s.off; at > end {
			g.host(unix.SYS_MUNMAP, end, at-end) // a gap between them: the placeholder's
		}
		if g.moveSpecial(s, base+s.off) {
			s.parked, s.moved = false, false
		}
		end = max(end, s.hi)
	}
	if end < base+n {
		g.host(unix.SYS_MUNMAP, end, base+n-end)
	}
}

// moveSpecial moves s to at, replacing whatever is there. g.mp.mu held.
func (g *dguest) moveSpecial(s *specialMap, at uint64) bool {
	sz := s.hi - s.lo
	if r := g.host(unix.SYS_MREMAP, s.lo, sz, sz, unix.MREMAP_MAYMOVE|unix.MREMAP_FIXED, at); r < 0 || uint64(r) != at {
		return false
	}
	s.lo, s.hi = at, at+sz
	return true
}

// vdso is where the guest's vDSO is, or 0 if it has none in place.
func (g *dguest) vdso() uint64 {
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	for _, s := range g.mp.special {
		if s.kind == mapVdso && !s.parked {
			return s.lo
		}
	}
	return 0
}
