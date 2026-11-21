package sandbox

import (
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

// A writable MAP_SHARED mapping of a non-host file (here an in-memory memFS file)
// is coherent and written back generically: one host backing per vnode, so two
// independent opens map the same object and see each other's writes, and msync
// flushes the content back to the core.File. The guest proves cross-open coherence;
// the test proves write-back by reading the memFS file afterward.
func TestMmapSharedNonHost(t *testing.T) {
	exe := guestPath(t, "mmapshared")
	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "f", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	runMmapGuest(t, exe, mem, "MMAP-SHARED-OK")
	if got := memReadAt(t, mem, "f", 0, 14); string(got) != "SHARED-WRITTEN" {
		t.Fatalf("memFS file after run = %q, want the shared-mapping write SHARED-WRITTEN", got)
	}
}

// While a file is shared-mapped its per-vnode backing is the authoritative copy,
// so a store through the mapping is visible to a plain read() with no msync and a
// write() is visible through the mapping (no clobber); both reach the memFS.
func TestMmapCacheCoherence(t *testing.T) {
	exe := guestPath(t, "mmapcache")
	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "f", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	runMmapGuest(t, exe, mem, "MMAP-CACHE-OK")
	if got := memReadAt(t, mem, "f", 0, 10); string(got) != "MMAP-STORE" {
		t.Fatalf("offset 0 = %q, want the mapping store MMAP-STORE written back", got)
	}
	if got := memReadAt(t, mem, "f", 100, 10); string(got) != "WRITE-DATA" {
		t.Fatalf("offset 100 = %q, want the write() WRITE-DATA written back", got)
	}
	if sz := memSize(t, mem, "f"); sz != 4096 {
		t.Fatalf("file size = %d, want 4096 (unchanged)", sz)
	}
}

// A MAP_SHARED mapping that runs past the end of a short file must not grow the
// file: only [0, EOF) is written back, stores past the end are dropped.
func TestMmapSharedNoEOFExtend(t *testing.T) {
	exe := guestPath(t, "mmapeof")
	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "f", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	runMmapGuest(t, exe, mem, "MMAP-EOF-OK")
	if sz := memSize(t, mem, "f"); sz != 100 {
		t.Fatalf("file size = %d, want 100 (a past-EOF mapping must not extend it)", sz)
	}
	if got := memReadAt(t, mem, "f", 0, 2); string(got) != "IN" {
		t.Fatalf("offset 0 = %q, want the in-bounds store IN", got)
	}
}

// An explicit munmap of a shared mapping writes the backing back to the file and
// releases it; the stores reach the memFS even with no msync and before teardown.
func TestMmapEvictWriteBack(t *testing.T) {
	exe := guestPath(t, "mmapevict")
	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "f", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	runMmapGuest(t, exe, mem, "MMAP-EVICT-OK")
	if got := memReadAt(t, mem, "f", 0, 11); string(got) != "EVICT-WRITE" {
		t.Fatalf("offset 0 = %q, want EVICT-WRITE written back on munmap", got)
	}
}

// A MAP_SHARED mapping of a non-host file is coherent across fork, and the
// backing survives while a child still maps it; both processes' stores reach the
// memFS.
func TestMmapForkCoherent(t *testing.T) {
	exe := guestPath(t, "mmapfork")
	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "f", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	runMmapGuest(t, exe, mem, "MMAP-FORK-OK")
	if got := memReadAt(t, mem, "f", 0, 6); string(got) != "PARENT" {
		t.Fatalf("offset 0 = %q, want PARENT", got)
	}
	if got := memReadAt(t, mem, "f", 100, 5); string(got) != "CHILD" {
		t.Fatalf("offset 100 = %q, want the fork child's store CHILD", got)
	}
}

// runMmapGuest, memReadAt and memSize are shared with the cross-platform test in
// mmapcross_test.go.
