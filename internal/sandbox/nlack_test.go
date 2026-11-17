package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A rtnetlink RTM_NEWLINK with NLM_F_ACK (a runtime bringing lo up in its netns)
// is answered with an NLMSG_ERROR ack, read back with recvfrom — including from
// an isolated network namespace.
func TestNlAck(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "nlack")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/nlack.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "NLACK-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
