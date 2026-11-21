package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// get_robust_list must round-trip what set_robust_list stored (podman's shm
// lock manager probes robust-mutex support and fails on ENOSYS).
func TestRobustList(t *testing.T) {
	root, exe := guestRoot(t, "robustlist")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "ROBUST-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
