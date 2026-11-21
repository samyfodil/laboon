package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// Executing a memfd through /proc/self/fd/<n> must run the in-descriptor image,
// not fail on the memfd's pathless name. Container runtimes (and laboon's own
// stub launch) rely on it.
func TestMemfdExec(t *testing.T) {
	root, exe := guestRoot(t, "memfdexec")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "MEMFD-EXEC-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
