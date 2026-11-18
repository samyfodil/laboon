package sandbox

// Tracking of a guest address space's MAP_SHARED mappings of non-host files, so
// the per-vnode backing (sharedback.go) can be written back and released once
// nothing maps it any more, rather than living for the whole run.
//
// The kernel owns the real VMAs (the guest is a real process; laboon reads
// /proc/<pid>/maps), so this is a small side table: one entry per shared mapping
// segment, keyed to the backing it maps. Each backing counts its live mapped
// pages across all address spaces; the last page removed evicts it. A mapping's
// pages are reserved under fs.shMu when it is made (sharedBacking), so the count
// can never reach zero while a mapping is being established. All of these run
// under g.mp.mu, which the mmap/munmap/mremap/fork/execve paths already hold.

// shMap is one MAP_SHARED mapping of a non-host file in an address space.
type shMap struct {
	lo, hi uint64
	sb     *shBacking
}

// addShMap records [lo, hi) as mapping sb, after dropping any shared mapping the
// range replaces (a MAP_FIXED mapping lands on top of what was there). The
// caller has already reserved sb's pages for this mapping.
func (m *memProc) addShMap(lo, hi uint64, sb *shBacking, fs *dfs) {
	if lo >= hi {
		return
	}
	m.removeShMap(lo, hi, fs)
	m.shMaps = append(m.shMaps, shMap{lo, hi, sb})
}

// removeShMap drops [lo, hi) from the shared mappings, releasing the pages each
// overlapped mapping loses (splitting one that is only partly covered); a
// backing that loses its last mapped page is written back and released.
func (m *memProc) removeShMap(lo, hi uint64, fs *dfs) {
	if lo >= hi || len(m.shMaps) == 0 {
		return
	}
	kept := m.shMaps[:0]
	var freed []shMap // released after the slice is rebuilt, so a re-map during eviction is consistent
	for _, s := range m.shMaps {
		if s.hi <= lo || s.lo >= hi { // no overlap
			kept = append(kept, s)
			continue
		}
		ol, oh := max(lo, s.lo), min(hi, s.hi) // the covered part
		if s.lo < ol {
			kept = append(kept, shMap{s.lo, ol, s.sb})
		}
		if oh < s.hi {
			kept = append(kept, shMap{oh, s.hi, s.sb})
		}
		freed = append(freed, shMap{ol, oh, s.sb})
	}
	m.shMaps = kept
	for _, f := range freed {
		fs.release(f.sb, int64((f.hi-f.lo)/pageSize))
	}
}

// shMapAt returns the backing mapped at addr, or nil: used by mremap to carry a
// shared mapping to its new address.
func (m *memProc) shMapAt(addr uint64) *shBacking {
	for _, s := range m.shMaps {
		if addr >= s.lo && addr < s.hi {
			return s.sb
		}
	}
	return nil
}

// dropShMaps releases every shared mapping of this address space (execve's
// teardown and process exit), evicting each backing that nothing else maps.
func (m *memProc) dropShMaps(fs *dfs) {
	if len(m.shMaps) == 0 {
		return
	}
	freed := m.shMaps
	m.shMaps = nil
	for _, s := range freed {
		fs.release(s.sb, int64((s.hi-s.lo)/pageSize))
	}
}

// forkShMaps copies the parent's shared mappings into a fork child (which
// inherits the mappings) and reserves their pages on each backing, so a backing
// the parent later unmaps is not evicted while the child still maps it. The
// child's m.mu is not yet shared, so no lock is taken here. fs.shMu is taken per
// backing to make the reservation race-free against eviction.
func (c *memProc) forkShMaps(parent *memProc, fs *dfs) {
	if len(parent.shMaps) == 0 {
		return
	}
	c.shMaps = append([]shMap(nil), parent.shMaps...)
	fs.shMu.Lock()
	for _, s := range c.shMaps {
		s.sb.reserve(int64((s.hi - s.lo) / pageSize))
	}
	fs.shMu.Unlock()
}
