//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestProcTaskNlink runs testdata/proctask.c: /proc/<pid>/task must report
// st_nlink of 2 + the thread count, which Chromium's sandbox CHECKs (>= 3) to
// confirm single-threadedness before entering the GPU process.
func TestProcTaskNlink(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "proctask")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-pthread", "-o", bin, "../../testdata/proctask.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"proctask"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot("/"),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d (testdata/proctask.c line) err %v\n%s", code, err, out.String())
	}
}
