package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestStraceArm64 runs a minimal arm64 ptrace tracer (testdata/stracearm_arm64.c)
// under laboon: it traces a child to a write(42) syscall and reads its
// registers with PTRACE_GETREGSET(NT_PRSTATUS). This covers the syscall-entry
// stop, register publishing and PTRACE_CONT on arm64 (linux and, through the
// gate, darwin), where single-step and breakpoints do not apply.
func TestStraceArm64(t *testing.T) {
	root, exe := guestRoot(t, "stracearm_arm64")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "STRACE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
