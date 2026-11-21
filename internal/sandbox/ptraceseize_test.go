package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestPtraceSeize checks PTRACE_SEIZE, PTRACE_INTERRUPT and PTRACE_LISTEN,
// and attaching to a task stopped by job control, one thread of several
// included, as Linux has them.
func TestPtraceSeize(t *testing.T) {
	root, exe := guestRoot(t, "ptraceseize")
	for _, args := range [][]string{{exe}, {exe, "stopped-mt"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		var out bytes.Buffer
		code, err := Run(ctx, exe, Config{Args: args, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
		cancel()
		if err != nil || code != 0 || !strings.Contains(out.String(), "ptraceseize fails=0") {
			t.Fatalf("%v: code=%d err=%v out=%q", args[1:], code, err, out.String())
		}
	}
}
