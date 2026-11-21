package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestKillCred checks the signal and process_vm credential gates: a same-uid
// signal is allowed, but a process that dropped to a different uid can neither
// signal nor read the memory of the (root) process it no longer owns. The guest
// runs as root (Config.User nil), so the child can setuid away.
func TestKillCred(t *testing.T) {
	root, exe := guestRoot(t, "killcred")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	s := out.String()
	if err != nil || code != 0 || !strings.Contains(s, "KILLCRED-DONE") {
		t.Fatalf("probe code=%d err=%v out=%q", code, err, s)
	}
	t.Logf("killcred output:\n%s", s)
	const eperm = "Operation not permitted"
	if !strings.Contains(s, "same-uid-kill rc=0") {
		t.Errorf("same-uid kill should be allowed: %q", s)
	}
	if !strings.Contains(s, "xuid-kill rc=-1 errno="+eperm) {
		t.Errorf("cross-uid kill should be EPERM: %q", s)
	}
	if !strings.Contains(s, "xuid-procvm rc=-1 errno="+eperm) {
		t.Errorf("cross-uid process_vm should be EPERM: %q", s)
	}
}
