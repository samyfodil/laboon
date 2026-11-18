package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestSingleStep checks PTRACE_SINGLESTEP (x86 trap flag): the tracer steps the
// child one instruction at a time from a syscall stop and sees rip advance by
// one byte over a NOP, with a TRAP_TRACE SIGTRAP each step. x86-64 only (arm64
// cannot single-step from EL0). Linux, and the Windows x64 VM through its gate.
func TestSingleStep(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x86 trap-flag single-step")
	}
	exe := filepath.Join(t.TempDir(), "singlestep")
	if b, err := exec.Command("gcc", "-O0", "-static", "-o", exe, "../../testdata/singlestep.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "SINGLESTEP-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
