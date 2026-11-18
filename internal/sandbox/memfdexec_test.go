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

// Executing a memfd through /proc/self/fd/<n> must run the in-descriptor image,
// not fail on the memfd's pathless name. Container runtimes (and laboon's own
// stub launch) rely on it.
func TestMemfdExec(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "memfdexec")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/memfdexec.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "MEMFD-EXEC-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
