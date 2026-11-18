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

// TestPtraceSetRegs checks PTRACE_SETREGSET write-back: the tracer overwrites
// the child's getpid result at its syscall-exit stop, and the child must then
// see the edited value. Covers amd64 and arm64 (linux, and the macOS and
// Windows VMs through their gates).
func TestPtraceSetRegs(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "setregs")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/ptracesetregs.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "SETREGS-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
