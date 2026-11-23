package sandbox

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestExecNotWritable(t *testing.T) {
	ps := int(pageSize)
	m, err := unix.Mmap(-1, 0, 3*ps, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(m)
	if err := unix.Mprotect(m[:2*ps], unix.PROT_READ|unix.PROT_EXEC); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mprotect(m[ps:2*ps], unix.PROT_EXEC); err != nil {
		t.Fatal(err)
	}
	base := uint64(uintptr(unsafe.Pointer(&m[0])))
	g := &dguest{mp: newMemProc(os.Getpid())}
	for _, c := range []struct {
		off, n uint64
		want   bool
	}{
		{0, pageSize, true},
		{0, 2 * pageSize, true},
		{pageSize, pageSize, true},
		{pageSize, 2 * pageSize, false},
		{2 * pageSize, pageSize, false},
	} {
		if got := g.execNotWritable(base+c.off, c.n); got != c.want {
			t.Errorf("[%#x, +%#x): got %v, want %v", c.off, c.n, got, c.want)
		}
	}
}

// A fork child must not share the parent's mutable rewrite bookkeeping:
// both keep recording sites and reserving trampoline chunks afterwards.
func TestForkCopyOwnsBookkeeping(t *testing.T) {
	m := newMemProc(1)
	m.sites.add([]uint64{1})
	m.reserved = make([]run, 1, 8)
	g := &dguest{mp: m}
	c := &dguest{mp: m.forkCopy(&dfs{})}
	c.reserve(0x1000, 0x1000)
	g.reserve(0x5000, 0x1000)
	if c.mp.reserved[1].lo != 0x1000 {
		t.Fatalf("parent's reservation overwrote the child's: %+v", c.mp.reserved)
	}
	c.mp.sites.add([]uint64{2})
	if g.mp.sites.has(2) || !c.mp.sites.has(1) {
		t.Fatal("the child's sites are not its own copy of the parent's")
	}
}

// madvise, msync and mincore must not reach the stub's ranges: madvise could
// otherwise discard (MADV_DONTNEED) or punch out (MADV_REMOVE) the stub's
// pages, such as the host-op request page its hop thread trusts.
func TestAdviseSkipsReserved(t *testing.T) {
	g := &dguest{mp: newMemProc(1)}
	g.reserve(0x5000, 0x1000)
	for _, nr := range []uintptr{unix.SYS_MADVISE, unix.SYS_MSYNC, unix.SYS_MINCORE} {
		for _, r := range [][2]uint64{{0x5000, 0x1000}, {0x4000, 0x1001}, {0x5fff, 1}} {
			if got := g.advise(nr, [6]uint64{r[0], r[1], unix.MADV_REMOVE}); got != sErr(lxENOMEM) {
				t.Errorf("nr %d on [%#x, +%#x): got %d, want ENOMEM", nr, r[0], r[1], got)
			}
		}
	}
}

// A thread's stack, unmapped as it ran on it, goes when the thread does,
// except what the guest has mapped there meanwhile.
func TestUnmapOwnStackSparesRemaps(t *testing.T) {
	ps := uint64(pageSize)
	m, err := unix.Mmap(-1, 0, int(4*ps), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(m)
	base := uint64(uintptr(unsafe.Pointer(&m[0])))
	var unmapped [][2]uint64
	g := &dguest{mp: newMemProc(os.Getpid())}
	g.mp.ownStack[g.pid] = run{lo: base, hi: base + 4*ps}
	g.mp.vm.add(base+ps, base+2*ps, true) // mapped again since
	g.unmapOwnStackWith(func(a, n uint64) { unmapped = append(unmapped, [2]uint64{a - base, n}) })
	want := [][2]uint64{{0, ps}, {2 * ps, 2 * ps}}
	if len(unmapped) != len(want) || unmapped[0] != want[0] || unmapped[1] != want[1] {
		t.Fatalf("unmapped %v, want %v", unmapped, want)
	}
	if _, held := g.mp.ownStack[g.pid]; held {
		t.Fatal("the held range was kept")
	}
}

// A stack its thread unmapped is still the host's until the thread is gone,
// so no mapping is placed there meanwhile.
func TestPlaceAvoidsOwnStack(t *testing.T) {
	m := newMemProc(1)
	m.lay = mmapLayout{base: 0x7f0000000000, legacyBase: 0x10000000, norand: true}
	at, ok := m.place(0, 0x3000, 0, true)
	if !ok {
		t.Fatal("no room")
	}
	m.ownStack[2] = run{lo: at - 0x200000, hi: at + 0x3000}
	got, ok := m.place(0, 0x3000, 0, true)
	if !ok || got+0x3000 > at-0x200000 && got < at+0x3000 {
		t.Fatalf("placed at %#x, inside the exiting stack [%#x, %#x)", got, at-0x200000, at+0x3000)
	}
	if h, ok := m.place(at, 0x3000, 0, true); !ok || h == at {
		t.Fatalf("a hint into the exiting stack was taken: %#x", h)
	}
}

// The set of guest mappings merges, splits and counts as mappings come and go.
func TestVmaSet(t *testing.T) {
	var s vmaSet
	if n := s.add(0x10000, 0x20000, true); n != 0x10000 {
		t.Fatalf("add counted %#x", n)
	}
	if n := s.add(0x20000, 0x30000, true); n != 0x10000 || len(s.r) != 1 {
		t.Fatalf("adjacent add: %#x, runs %v", n, s.r)
	}
	if n := s.add(0x18000, 0x28000, false); n != 0 || len(s.r) != 3 {
		t.Fatalf("overlapping add of another kind: %#x, runs %v", n, s.r)
	}
	if n := s.sub(0x14000, 0x2c000); n != 0x18000 {
		t.Fatalf("sub removed %#x", n)
	}
	want := []vmaRun{{0x10000, 0x14000, true}, {0x2c000, 0x30000, true}}
	if len(s.r) != 2 || s.r[0] != want[0] || s.r[1] != want[1] || s.total() != 0x8000 {
		t.Fatalf("runs %v, want %v", s.r, want)
	}
}

// Mappings are placed as Linux places them: top-down below mmap_base, a freed
// gap used again, a free hint honoured, a whole number of huge pages huge-page
// aligned, bottom-up with the legacy layout.
func TestPlace(t *testing.T) {
	ps, huge := uint64(pageSize), hugePage()
	base := uint64(0x7d0000000000)
	m := newMemProc(1)
	m.lay = mmapLayout{base: base, legacyBase: 0x2aaaaaaab000}
	take := func(hint, n uint64, anon bool) uint64 {
		a, ok := m.place(hint, n, 0, anon)
		if !ok {
			t.Fatalf("no room for %#x", n)
		}
		m.vm.add(a, a+n, anon)
		return a
	}
	a := take(0, 16*ps, false)
	b := take(0, 16*ps, false)
	if a != base-16*ps || b != a-16*ps {
		t.Fatalf("top-down: %#x then %#x below %#x", a, b, base)
	}
	m.vm.sub(b, b+16*ps)
	if c := take(0, 8*ps, false); c != a-8*ps {
		t.Fatalf("freed gap not used again: %#x", c)
	}
	if h := take(0x600000000000, ps, false); h != 0x600000000000 {
		t.Fatalf("free hint not honoured: %#x", h)
	}
	if h := take(a, ps, false); h == a {
		t.Fatal("taken hint honoured")
	}
	if g := take(0, 2*huge, true); g%huge != 0 {
		t.Fatalf("anonymous huge-page multiple at %#x", g)
	}
	m.lay.legacy = true
	l1 := take(0, ps, false)
	l2 := take(0, ps, false)
	if l1 != m.lay.legacyBase || l2 != l1+ps {
		t.Fatalf("legacy layout: %#x then %#x", l1, l2)
	}
}
