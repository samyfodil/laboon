package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestStubJumpKilled: a guest that branches into the stub's own syscall
// instructions to make a call the supervisor would mediate (here an mmap) is
// killed, not served.
func TestStubJumpKilled(t *testing.T) {
	root, out := guestRoot(t, "stubjump")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"stubjump"}, Stdout: &o, Stderr: &o})
	if !errors.Is(err, ErrKilled) || !strings.Contains(o.String(), "gadget at") || strings.Contains(o.String(), "ESCAPED") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestStubSignalScoped: the stub's kick signal, the one signal a guest can
// send by branching into the stub, does not reach a process outside the
// sandbox: the guest thread's filter admits it only to the stub's own
// process, on any kernel, so the guest is killed.
func TestStubSignalScoped(t *testing.T) {
	root, out := guestRoot(t, "stubjump")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"stubjump", "signal", strconv.Itoa(os.Getpid())}, Stdout: &o, Stderr: &o})
	if !errors.Is(err, ErrKilled) || !strings.Contains(o.String(), "gadget at") || strings.Contains(o.String(), "ESCAPED") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}
