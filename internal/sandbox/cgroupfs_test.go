package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// The virtual cgroup v2 hierarchy supports mkdir, recorded control-file writes,
// nesting, and rmdir (with ENOTEMPTY) — what a container runtime needs.
func TestCgroupFS(t *testing.T) {
	root, exe := guestRoot(t, "cgroupfs")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "CGROUPFS-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
