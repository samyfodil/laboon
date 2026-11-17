//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestUTSNamespace runs testdata/utsns.c: a child in a new UTS namespace changes
// its hostname and the change does not reach the parent.
func TestUTSNamespace(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "utsns")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/utsns.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"utsns"},
		Stdout: &out, Stderr: &out, Root: "/",
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
