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

// TestProcessVM checks process_vm_readv/writev move bytes correctly: a plain
// copy, a multi-iovec scatter, a writev, and a short count. The guest targets
// itself (same address space), which every host serves -- directly on Linux and
// Windows, through the caller's channel on macOS.
func TestProcessVM(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "procvm")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/procvm.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "PROCVM-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
