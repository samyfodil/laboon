package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestStraceLocalArm64 traces a child to a syscall the sandbox serves in-guest
// (getrandom) rather than posting to the supervisor, and confirms it still
// appears at a ptrace syscall-entry stop. Without reporting in-guest-served
// syscalls for their stops, such a call is invisible to a tracer; this guards
// that path on arm64 (linux, and through the gate, darwin).
func TestStraceLocalArm64(t *testing.T) {
	root, exe := guestRoot(t, "stracelocal_arm64")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "LOCALTRACE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
