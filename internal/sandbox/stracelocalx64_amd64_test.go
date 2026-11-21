package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestStraceLocalX64 traces a child to a syscall the sandbox serves in-guest
// (getrandom) rather than posting to the supervisor, and confirms it still
// appears at a ptrace syscall-entry stop. This guards the in-guest-served
// trace path on amd64 (linux, and through its VM, windows).
func TestStraceLocalX64(t *testing.T) {
	root, exe := guestRoot(t, "stracelocalx64_amd64")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "LOCALTRACE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
