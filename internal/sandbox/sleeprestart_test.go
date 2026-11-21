package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestSleepRestart checks a sleep a signal interrupts goes on or fails as on
// Linux: through a tracer's stop and a job-control stop it finishes, resumed
// by restart_syscall; a handler, even with SA_RESTART, ends it with EINTR.
func TestSleepRestart(t *testing.T) {
	root, exe := guestRoot(t, "sleeprestart")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "sleeprestart fails=0") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
