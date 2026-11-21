package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// fchmod on a socket or pipe descriptor must act on the descriptor, not resolve
// a path (conmon relies on this for its console socket and stderr pipe).
func TestFchmodSocketPipe(t *testing.T) {
	root, exe := guestRoot(t, "fchmodsock")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "FCHMOD-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
