package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// A persisted network-namespace bind-mount: unlink is refused while bound
// (EBUSY), umount releases it, and setns through it rejoins the pinned netns
// (a loopback listener living there becomes reachable only after the join).
func TestNsBind(t *testing.T) {
	root, exe := guestRoot(t, "nsbind")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Net: true, Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "NSBIND-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
