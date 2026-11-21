package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestPtraceFollow checks that a tracer follows its tracee through exec and
// fork, and that PTRACE_ATTACH stops a running process and PTRACE_DETACH lets
// it go on.
func TestPtraceFollow(t *testing.T) {
	root, exe := guestRoot(t, "ptracefollow")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "ptracefollow fails=0") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
