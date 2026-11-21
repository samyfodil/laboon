package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestPtraceThreads checks a tracer follows a traced process's threads: a
// clone event and a start stop for each, and each one's end.
func TestPtraceThreads(t *testing.T) {
	root, exe := guestRoot(t, "ptracethreads")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "ptracethreads fails=0") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
