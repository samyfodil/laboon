//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/internal/vfs"
)

// TestCopyUpModeCheckpoint guards the metadata checkpoint against the gap the old
// per-syscall mirror had: a lower file copied up by a content write (no chmod)
// keeps a mode the host file cannot hold (0400) only in the inode side table. The
// kept upper's captured layer must still report 0400, because close() projects
// that table onto the path-keyed override.
func TestCopyUpModeCheckpoint(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	for _, d := range []string{lower, upper} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "secret"), []byte("old"), 0o400); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(lower, "copyupmode")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/copyupmode.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}

	var out bytes.Buffer
	code, err := Run(context.Background(), "/copyupmode", Config{
		Args: []string{"/copyupmode"}, Root: lower, Upper: upper,
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 {
		t.Fatalf("copyupmode code %d err %v\n%s", code, err, out.String())
	}

	// The captured layer: 0400 preserved though no chmod ever ran, content rewritten.
	l, err := vfs.LayerFromDir(upper)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := l.Stat("secret"); !ok || a.Mode&0o7777 != 0o400 {
		t.Fatalf("secret mode = %+v ok=%v, want 0400", a, ok)
	}
	if b, err := l.ReadFile("secret"); err != nil || string(b) != "changed" {
		t.Fatalf("secret body = %q, %v", b, err)
	}
}
