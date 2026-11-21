package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// A rtnetlink RTM_NEWLINK with NLM_F_ACK (a runtime bringing lo up in its netns)
// is answered with an NLMSG_ERROR ack, read back with recvfrom — including from
// an isolated network namespace.
func TestNlAck(t *testing.T) {
	root, exe := guestRoot(t, "nlack")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "NLACK-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
