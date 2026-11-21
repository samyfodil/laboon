package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// A bind mount must show the source subtree through the target, resolving via
// the vfs like any other mount.
func TestMountBind(t *testing.T) {
	root, exe := guestRoot(t, "mountbind")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "BIND-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
