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

// TestStraceX64 runs an x86-64 ptrace tracer (testdata/stracex64.c) under
// laboon: it traces a child to a write(42) syscall and reads its registers with
// PTRACE_GETREGSET(NT_PRSTATUS). It covers the syscall-entry stop, register
// publishing and PTRACE_CONT on amd64 (linux and, through its VM, windows).
func TestStraceX64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64 register set")
	}
	exe := filepath.Join(t.TempDir(), "stracex64")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/stracex64.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "STRACE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
