//go:build linux

package sandbox

import "testing"

// A published siteSnap never changes: a reader holding one, as a trap check
// does without the lock, sees the set as it was, and a fork's copy grows
// apart from its parent's.
func TestSiteSetSnapshots(t *testing.T) {
	var s siteSet
	s.addList([]uint64{10, 20})
	s.add([]uint64{3, 1})
	old := s.load()
	s.add([]uint64{2})
	s.addList([]uint64{30})
	if old.has(2) || old.has(30) || !old.has(1) || !old.has(20) {
		t.Fatal("a published snapshot changed")
	}
	for _, a := range []uint64{1, 2, 3, 10, 20, 30} {
		if !s.load().has(a) {
			t.Fatalf("site %d lost", a)
		}
	}
	var c siteSet
	c.share(&s)
	c.addList([]uint64{40})
	s.addList([]uint64{50})
	if s.load().has(40) || c.load().has(50) || !c.load().has(30) {
		t.Fatal("a fork's sites are not its own")
	}
	s.reset()
	if s.load().has(1) || !c.load().has(1) {
		t.Fatal("reset reached the fork")
	}
}

// Sites added one call at a time stay findable while the runs that hold
// them stay few: each is under half the length of the one before it.
func TestSiteSetRuns(t *testing.T) {
	var s siteSet
	const n = 5000
	for i := range n {
		s.add([]uint64{uint64(i*7919%n) * 2})
		if i%3 == 0 {
			s.add([]uint64{uint64(i*7919%n) * 2})
		}
	}
	m := s.load().more
	for k := 1; k < len(m); k++ {
		if len(m[k]) > len(m[k-1])/2 {
			t.Fatalf("run %d holds %d sites after one of %d", k, len(m[k]), len(m[k-1]))
		}
	}
	for i := range uint64(n) {
		if !s.load().has(2*i) || s.load().has(2*i+1) {
			t.Fatalf("site lookup wrong around %d", 2*i)
		}
	}
}
