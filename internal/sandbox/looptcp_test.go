package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// A TCP client and server on 127.0.0.1 inside an isolated netns talk over vnet.
func TestLoopTCP(t *testing.T) {
	root, exe := guestRoot(t, "looptcp")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Net: true, Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "LOOPTCP-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
