package sandbox

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/internal/vfs"
)

// Writable MAP_SHARED of a non-host file works on every backend: cross-open
// coherence, a mapping store visible to read() with no msync, a write() visible
// through the mapping, and write-back to the composed filesystem. The guest is a
// Go program built for linux/<host arch>, so the same test runs on Linux and on
// macOS (where it exercises the darwin host-file backing) with no C toolchain.
func TestMmapSharedCrossPlatform(t *testing.T) {
	// The guest must be PIE: a non-PIE ET_EXEC forces the hypervisor backend on
	// arm64 macOS, which copies file mappings into VM RAM instead of sharing
	// them. LC_MMAP_BIN, when set, is a prebuilt static-PIE guest for this arch
	// (testdata/mmapguest.c, `gcc -static-pie`); the gate provides it on macOS,
	// where a dynamic-PIE Go build would need a Linux loader the host root lacks.
	// Otherwise, on Linux, the Go form is built -buildmode=pie and the host
	// provides the loader.
	exe := os.Getenv("LC_MMAP_BIN")
	if exe == "" {
		if runtime.GOOS != "linux" {
			t.Skip("set LC_MMAP_BIN to a static-PIE guest for this arch (testdata/mmapguest.c)")
		}
		exe = filepath.Join(t.TempDir(), "mmapguest")
		cmd := exec.Command("go", "build", "-buildmode=pie", "-o", exe, "../../testdata/mmapguest.go")
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("cross build unavailable: %v\n%s", err, b)
		}
	}
	mem := vfs.NewMemFS()
	if _, err := mem.(vfs.WriteFileSystem).WriteFile(mem.Root(), "f", vfs.CreateSpec{Kind: vfs.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	runMmapGuest(t, exe, mem, "MMAP-OK")
	if got := memReadAt(t, mem, "f", 0, 14); string(got) != "SHARED-WRITTEN" {
		t.Fatalf("offset 0 = %q, want SHARED-WRITTEN written back", got)
	}
	if got := memReadAt(t, mem, "f", 100, 5); string(got) != "WROTE" {
		t.Fatalf("offset 100 = %q, want the write() WROTE written back", got)
	}
}

// runMmapGuest runs exe with mem mounted at /data and host root, requiring want
// in its output.
func runMmapGuest(t *testing.T, exe string, mem vfs.FileSystem, want string) {
	t.Helper()
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
	if err != nil || code != 0 || !strings.Contains(out.String(), want) {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

func memReadAt(t *testing.T, mem vfs.FileSystem, name string, off int64, n int) []byte {
	t.Helper()
	node, err := mem.Lookup(mem.Root(), name)
	if err != nil {
		t.Fatal(err)
	}
	f, err := node.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return b
}

func memSize(t *testing.T, mem vfs.FileSystem, name string) int64 {
	t.Helper()
	node, err := mem.Lookup(mem.Root(), name)
	if err != nil {
		t.Fatal(err)
	}
	a, err := node.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return a.Size
}
