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
