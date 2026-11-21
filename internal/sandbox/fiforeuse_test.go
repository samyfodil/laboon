package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// A regular file that reuses a removed fifo's inode must stat as regular, not
// inherit the fifo type from stale per-inode metadata.
func TestFifoReuse(t *testing.T) {
	root, exe := guestRoot(t, "fiforeuse")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "FIFOREUSE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
