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

	"github.com/samyfodil/laboon/internal/vfs"
)

// A writable MAP_SHARED mapping of a non-host file (here an in-memory memFS file)
// is coherent and written back generically: one host backing per vnode, so two
// independent opens map the same object and see each other's writes, and msync
// flushes the content back to the vfs.File. The guest proves cross-open coherence;
// the test proves write-back by reading the memFS file afterward.
func TestMmapSharedNonHost(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "mmapshared")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mmapshared.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}

	mem := vfs.NewMemFS()
	if _, err := mem.(vfs.WriteFileSystem).WriteFile(mem.Root(), "f", vfs.CreateSpec{Kind: vfs.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
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

	// Write-back: the guest's shared-mapping write reached the vfs.File.
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
