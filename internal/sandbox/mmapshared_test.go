//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

// A writable MAP_SHARED mapping of a non-host file (here an in-memory memFS file)
// is coherent and written back generically: one host backing per vnode, so two
// independent opens map the same object and see each other's writes, and msync
// flushes the content back to the core.File. The guest proves cross-open coherence;
// the test proves write-back by reading the memFS file afterward.
func TestMmapSharedNonHost(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "mmapshared")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mmapshared.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}

	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "f", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{
		Args:   []string{exe},
		RootFS: HostRoot("/"),
		Mounts: []Mount{{Guest: "/data", FS: mem}},
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), "MMAP-SHARED-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}

	// Write-back: the guest's shared-mapping write reached the core.File.
	n, err := mem.Lookup(mem.Root(), "f")
	if err != nil {
		t.Fatal(err)
	}
	f, err := n.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, 14)
	if _, err := f.ReadAt(b, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(b) != "SHARED-WRITTEN" {
		t.Fatalf("memFS file after run = %q, want the shared-mapping write SHARED-WRITTEN", b)
	}
}

// While a file is shared-mapped its per-vnode backing is the authoritative copy,
// so a store through the mapping is visible to a plain read() with no msync and a
// write() is visible through the mapping (no clobber); both reach the memFS.
func TestMmapCacheCoherence(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "mmapcache")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mmapcache.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
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
	exe := filepath.Join(t.TempDir(), "mmapeof")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mmapeof.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
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
	exe := filepath.Join(t.TempDir(), "mmapevict")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mmapevict.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
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
	exe := filepath.Join(t.TempDir(), "mmapfork")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mmapfork.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
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
