//go:build linux

package sandbox

import (
	"slices"
	"sync/atomic"
)

// siteSnap is the set of trap sites a process's code holds. A loaded image's
// sites never change, so they are kept as the image's sorted list, shared
// with forks and with later loads of the same image. Code made executable at
// run time adds sorted runs of the process's own, each under half the length
// of the one before it: an addition merges into a new run only the runs not
// much longer than what it carries, so a site is copied a logarithmic number
// of times, and a lookup searches a logarithmic number of runs. A siteSnap is
// never changed once published: a change makes a new one, so a trap is
// checked without the process's memory lock.
type siteSnap struct {
	lists [][]uint64 // sorted
	more  [][]uint64 // sorted, shrinking by more than half
}

func (s *siteSnap) has(a uint64) bool {
	if s == nil {
		return false
	}
	for _, l := range s.lists {
		if _, ok := slices.BinarySearch(l, a); ok {
			return true
		}
	}
	for _, l := range s.more {
		if _, ok := slices.BinarySearch(l, a); ok {
			return true
		}
	}
	return false
}

// siteSet holds a process's published siteSnap. Its changes are made with the
// memProc lock held.
type siteSet struct{ p atomic.Pointer[siteSnap] }

func (s *siteSet) load() *siteSnap { return s.p.Load() }

func (s *siteSet) reset() { s.p.Store(&siteSnap{}) }

// share publishes another process's sites, as a fork's child starts with.
func (s *siteSet) share(o *siteSet) { s.p.Store(o.p.Load()) }

// edit publishes a copy of the set with f applied.
func (s *siteSet) edit(f func(*siteSnap)) {
	var n siteSnap
	if c := s.p.Load(); c != nil {
		n = siteSnap{lists: slices.Clip(c.lists), more: c.more}
	}
	f(&n)
	s.p.Store(&n)
}

// addList adds sorted, immutable sites.
func (s *siteSet) addList(l []uint64) {
	if len(l) > 0 {
		s.edit(func(n *siteSnap) { n.lists = append(n.lists, l) })
	}
}

func (s *siteSet) add(a []uint64) {
	if len(a) == 0 {
		return
	}
	r := slices.Clone(a)
	slices.Sort(r)
	r = slices.Compact(r)
	s.edit(func(n *siteSnap) {
		k := len(n.more)
		for ; k > 0 && len(n.more[k-1]) <= 2*len(r); k-- {
			r = mergeSites(n.more[k-1], r)
		}
		n.more = append(n.more[:k:k], r)
	})
}

// mergeSites is the sorted union of sorted a and b.
func mergeSites(a, b []uint64) []uint64 {
	m := make([]uint64, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		switch {
		case a[0] < b[0]:
			m, a = append(m, a[0]), a[1:]
		case b[0] < a[0]:
			m, b = append(m, b[0]), b[1:]
		default:
			m, a, b = append(m, a[0]), a[1:], b[1:]
		}
	}
	return append(append(m, a...), b...)
}
