package sandbox

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// TestWindowsNoRewriteKilled runs busybox with syscall rewriting disabled, so
// its first syscall is a raw stray. The stub's instrumentation-callback
// backstop (stub/windows/instrcb.zig) catches it — a syscall returning outside
// ntdll — and kills the guest: ErrKilled. (On Linux the trap backstop services
// such a stray instead; see TestNoRewriteRunsViaTrap.)
func TestWindowsNoRewriteKilled(t *testing.T) {
	var out, errb bytes.Buffer
	_, err := Run(context.Background(), "/bin/busybox", Config{
		RootFS:    HostRoot(busyboxRoot(t)),
		Args:      []string{"busybox", "true"},
		Env:       []string{"PATH=/bin"},
		Stdin:     strings.NewReader(""),
		Stdout:    &out,
		Stderr:    &errb,
		NoRewrite: true,
	})
	if !errors.Is(err, ErrKilled) {
		t.Fatalf("err = %v, want ErrKilled (stray syscall killed by the backstop)", err)
	}
}

// TestWindowsFSFault runs busybox with no %fs islands, so every thread-pointer
// access goes through the stub's fault handler.
func TestWindowsFSFault(t *testing.T) {
	testNoFSIslands = true
	defer func() { testNoFSIslands = false }()
	if code, out, errs := winRun(t, busyboxRoot(t), "sh", "-c", "echo a; echo b >&2; exit 3"); code != 3 || out != "a\n" || errs != "b\n" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}
