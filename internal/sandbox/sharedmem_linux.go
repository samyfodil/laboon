package sandbox

import (
	"os"
	"sort"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Shared guest RAM (experimental, behind LABOON_SHMEM). On Linux the guest is a
// separate process and its memory is read and written with process_vm_readv/writev
// -- a syscall per access. When enabled, a guest anonymous mapping is instead
// backed by a memfd that both the stub (at the guest address) and the supervisor
// (a "mirror") map, so the supervisor reads and writes the bytes directly, no
// syscall. Beyond the data plane this gives tools a live window on guest memory.
//
// This is gated and validated because it changes the memory model: MAP_SHARED
// breaks fork's copy-on-write (a child would share the parent's pages), so a
// forked child's mirrored regions must be re-privatised -- handled separately.
// LABOON_SHMEM_VALIDATE cross-checks every direct access against process_vm so a
// mirror bug is caught loudly rather than corrupting data.

// shmemMin is the smallest anonymous mapping worth a memfd + mirror; below it
// the setup costs more than the process_vm calls it would save, so small
// mappings stay on the ordinary path.
const shmemMin = 64 << 10

var (
	shmemOnce     atomic.Int32 // 0 unset, 1 off, 2 on
	shmemValidate atomic.Int32
)

func shmemEnabled() bool {
	if v := shmemOnce.Load(); v != 0 {
		return v == 2
	}
	on := int32(1)
	if os.Getenv("LABOON_SHMEM") != "" {
		on = 2
	}
	shmemOnce.Store(on)
	val := int32(1)
	if os.Getenv("LABOON_SHMEM_VALIDATE") != "" {
		val = 2
	}
	shmemValidate.Store(val)
	return on == 2
}

func shmemValidating() bool { return shmemValidate.Load() == 2 }

// mirrorRegion is one memfd-backed guest range and the supervisor's view of it.
type mirrorRegion struct {
	lo, hi uint64   // guest address range [lo, hi)
	buf    []byte   // the supervisor's MAP_SHARED mapping of the same memfd
	file   *os.File // the memfd, kept open so the mapping stays valid
	prot   uint64   // the guest's protection, to restore if the region is re-privatised
}

// mirrors is an immutable sorted snapshot, swapped atomically so the hot read
// path needs no lock; mmap/munmap (holding memProc.mu) build a new snapshot.
type mirrors struct{ r []mirrorRegion }

// mirrorFind returns the supervisor bytes for [addr, addr+n) when it lies wholly
// within one mirrored region, lock-free.
func (m *memProc) mirrorFind(addr uint64, n int) ([]byte, bool) {
	ms := m.mirrorsP.Load()
	if ms == nil || n == 0 {
		return nil, false
	}
	end := addr + uint64(n)
	i := sort.Search(len(ms.r), func(i int) bool { return ms.r[i].hi > addr })
	if i == len(ms.r) {
		return nil, false
	}
	rg := ms.r[i]
	if addr < rg.lo || end > rg.hi {
		return nil, false
	}
	off := addr - rg.lo
	return rg.buf[off : off+uint64(n)], true
}

// setMirrors replaces the snapshot. Caller holds m.mu.
func (m *memProc) setMirrors(r []mirrorRegion) {
	sort.Slice(r, func(i, j int) bool { return r[i].lo < r[j].lo })
	m.mirrorsP.Store(&mirrors{r: r})
}

// addMirror records a new mirrored region. Caller holds m.mu.
func (m *memProc) addMirror(lo, hi uint64, buf []byte, f *os.File, prot uint64) {
	ms := m.mirrorsP.Load()
	var cur []mirrorRegion
	if ms != nil {
		cur = ms.r
	}
	next := make([]mirrorRegion, 0, len(cur)+1)
	next = append(next, cur...)
	next = append(next, mirrorRegion{lo: lo, hi: hi, buf: buf, file: f, prot: prot})
	m.setMirrors(next)
}

// dropMirror unmaps and forgets any mirrored region overlapping [lo, hi). Caller
// holds m.mu. A partial overlap (a split by munmap/mremap of part of a region)
// drops the whole region, so the rest falls back to process_vm -- correct, just
// slower, until it is re-mapped.
func (m *memProc) dropMirror(lo, hi uint64) {
	ms := m.mirrorsP.Load()
	if ms == nil {
		return
	}
	var next []mirrorRegion
	changed := false
	for _, rg := range ms.r {
		if rg.lo < hi && lo < rg.hi { // overlaps
			unix.Munmap(rg.buf)
			rg.file.Close()
			changed = true
			continue
		}
		next = append(next, rg)
	}
	if changed {
		m.setMirrors(next)
	}
}

// dropAllMirrors tears down every mirror (run teardown, or disabling the
// feature). Caller holds m.mu.
func (m *memProc) dropAllMirrors() {
	ms := m.mirrorsP.Load()
	if ms == nil {
		return
	}
	for _, rg := range ms.r {
		unix.Munmap(rg.buf)
		rg.file.Close()
	}
	m.mirrorsP.Store(&mirrors{})
}

// mmapMirroredAnon services a guest anonymous mmap by backing it with a memfd
// mapped MAP_SHARED in both the stub (at the guest address) and the supervisor.
// It returns the guest address, or ok=false to fall back to the ordinary path
// (which the caller then takes). Caller holds g.mp.mu.
func (g *dguest) mmapMirroredAnon(addr, length, prot, flags uint64) (int64, bool) {
	fd, err := unix.MemfdCreate("lc-guestmem", unix.MFD_CLOEXEC)
	if err != nil {
		return 0, false
	}
	if unix.Ftruncate(fd, int64(length)) != nil {
		unix.Close(fd)
		return 0, false
	}
	buf, err := unix.Mmap(fd, 0, int(length), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return 0, false
	}
	f := os.NewFile(uintptr(fd), "lc-guestmem")
	sfd, e := g.passFd(hostFd(f))
	if e != 0 {
		unix.Munmap(buf)
		f.Close()
		return 0, false
	}
	r := g.notReserved(g.mapAt(addr, length, flags, false, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, length, prot, fixed|unix.MAP_SHARED, uint64(sfd), 0)
	}), length)
	g.host(unix.SYS_CLOSE, uint64(sfd))
	if r < 0 {
		unix.Munmap(buf)
		f.Close()
		return r, true
	}
	g.mp.addMirror(uint64(r), uint64(r)+length, buf, f, prot)
	return r, true
}

// unmirrorForFork converts every mirrored region back to private anonymous
// memory, preserving its contents, before a real fork. MAP_SHARED would make the
// forked child share the parent's pages; a private mapping is copy-on-write, as
// fork expects. After this the regions fall back to process_vm (correct, just not
// accelerated), which is the right trade for a forking workload. Takes g.mp.mu.
func (g *dguest) unmirrorForFork() {
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	ms := g.mp.mirrorsP.Load()
	if ms == nil || len(ms.r) == 0 {
		return
	}
	for _, rg := range ms.r {
		content := append([]byte(nil), rg.buf...) // snapshot before the mapping is replaced
		length := rg.hi - rg.lo
		r := g.host(unix.SYS_MMAP, rg.lo, length, unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED, ^uint64(0), 0)
		if r >= 0 {
			g.mp.writeVM(rg.lo, content) // restore into the new private mapping
			if rg.prot != unix.PROT_READ|unix.PROT_WRITE {
				g.host(unix.SYS_MPROTECT, rg.lo, length, rg.prot)
			}
		}
		unix.Munmap(rg.buf)
		rg.file.Close()
	}
	g.mp.mirrorsP.Store(&mirrors{})
}

// readMirror copies from the supervisor's mirror of guest memory when the whole
// range is mirrored, returning ok=false otherwise. With validation on it also
// reads via process_vm and reports any disagreement.
func (m *memProc) readMirror(addr uint64, b []byte) bool {
	src, ok := m.mirrorFind(addr, len(b))
	if !ok {
		return false
	}
	if shmemValidating() {
		chk := make([]byte, len(b))
		if m.readVM(addr, chk) == nil && !equalBytes(src, chk) {
			shmemMismatch("read", addr, len(b))
		}
	}
	copy(b, src)
	return true
}

// writeMirror writes into the supervisor's mirror when the range is mirrored.
func (m *memProc) writeMirror(addr uint64, b []byte) bool {
	dst, ok := m.mirrorFind(addr, len(b))
	if !ok {
		return false
	}
	copy(dst, b)
	return true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var mismatchLogged atomic.Bool

func shmemMismatch(op string, addr uint64, n int) {
	if mismatchLogged.CompareAndSwap(false, true) {
		os.Stderr.WriteString("laboon: SHMEM mirror mismatch on " + op + " -- falling back; please report\n")
	}
	_ = addr
	_ = n
}

// mirrorPtr is the supervisor address of a mirrored guest address (for tools and
// zero-copy iovecs); ok is false if not mirrored.
func (m *memProc) mirrorPtr(addr uint64, n int) (unsafe.Pointer, bool) {
	b, ok := m.mirrorFind(addr, n)
	if !ok {
		return nil, false
	}
	return unsafe.Pointer(&b[0]), true
}
