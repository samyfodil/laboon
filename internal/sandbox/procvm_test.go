package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestProcessVM checks process_vm_readv/writev move bytes correctly: a plain
// copy, a multi-iovec scatter, a writev, and a short count. The guest targets
// itself (same address space), which every host serves -- directly on Linux and
// Windows, through the caller's channel on macOS.
func TestProcessVM(t *testing.T) {
	root, exe := guestRoot(t, "procvm")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "PROCVM-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
