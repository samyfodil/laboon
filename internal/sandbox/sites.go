//go:build linux

package sandbox

import (
	"slices"
	"sync/atomic"
)

// siteSnap is the set of trap sites a process's code holds. A loaded image's
// sites never change, so they are kept as the image's sorted list, shared
// with forks and with later loads of the same image; code made executable at
// run time adds to a sorted list of the process's own. A siteSnap is never
// changed once published: a change makes a new one, so a trap is checked
// without the process's memory lock.
type siteSnap struct {
	lists [][]uint64 // sorted
	more  []uint64   // sorted
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
	_, ok := slices.BinarySearch(s.more, a)
	return ok
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
	s.edit(func(n *siteSnap) {
		m := slices.Concat(n.more, a)
		slices.Sort(m)
		n.more = slices.Compact(m)
	})
}
