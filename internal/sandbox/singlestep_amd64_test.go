package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestSingleStep checks PTRACE_SINGLESTEP (x86 trap flag): the tracer steps the
// child one instruction at a time from a syscall stop and sees rip advance by
// one byte over a NOP, with a TRAP_TRACE SIGTRAP each step. x86-64 only (arm64
// cannot single-step from EL0). Linux, and the Windows x64 VM through its gate.
func TestSingleStep(t *testing.T) {
	root, exe := guestRoot(t, "singlestep_amd64")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "SINGLESTEP-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
