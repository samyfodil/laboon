package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A bind mount must show the source subtree through the target, resolving via
// the vfs like any other mount.
func TestMountBind(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "mountbind")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mountbind.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "BIND-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
