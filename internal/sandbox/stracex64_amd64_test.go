package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestStraceX64 runs an x86-64 ptrace tracer (testdata/stracex64_amd64.c) under
// laboon: it traces a child to a write(42) syscall and reads its registers with
// PTRACE_GETREGSET(NT_PRSTATUS). It covers the syscall-entry stop, register
// publishing and PTRACE_CONT on amd64 (linux and, through its VM, windows).
func TestStraceX64(t *testing.T) {
	root, exe := guestRoot(t, "stracex64_amd64")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "STRACE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
