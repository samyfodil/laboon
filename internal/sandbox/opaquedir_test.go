//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestOverlayOpaqueRecreate guards the overlay against whiteout markers leaking
// into a directory listing or blocking a host rmdir: a guest empties a lower
// directory (files and a subdir of files), removes it and recreates it, and the
// recreated directory must be opaque. This is the linux-side regression test
// for the mac gate's fstest.c t_dirs case.
func TestOverlayOpaqueRecreate(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	if err := os.MkdirAll(filepath.Join(lower, "d", "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(upper, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"d/world", "d/repositories", "d/arch", "d/keys/a.pub", "d/keys/b.pub"} {
		if err := os.WriteFile(filepath.Join(lower, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(lower, "opaquedir")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/opaquedir.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}

	var out bytes.Buffer
	code, err := Run(context.Background(), "/opaquedir", Config{
		Args: []string{"/opaquedir"}, Root: lower, Upper: upper,
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 {
		t.Fatalf("opaquedir code %d err %v\n%s", code, err, out.String())
	}
}
