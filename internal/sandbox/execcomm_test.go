package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// An exec names the task after the path the caller gave (a symlink's name, a
// /proc/self/fd link's number), as Linux does, not after the resolved file.
func TestExecComm(t *testing.T) {
	root, exe := guestRoot(t, "execcomm")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "EXECCOMM-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
