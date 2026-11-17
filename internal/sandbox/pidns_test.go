//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPidNamespace runs testdata/pidns.c: a clone(CLONE_NEWPID) child is pid 1
// in its namespace with an invisible parent, its own child is pid 2, and the
// outer parent reaps it by the pid clone returned — the pid translation
// Chromium's zygote relies on.
func TestPidNamespace(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "pidns")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/pidns.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"pidns"},
		Stdout: &out, Stderr: &out, Root: "/",
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
