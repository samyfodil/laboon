package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// execveat(O_PATH fd, AT_EMPTY_PATH) must run the pinned file even after its
// name is unlinked — the fexecve / bind-mount-ro re-exec a container runtime uses.
func TestOPathExec(t *testing.T) {
	root, exe := guestRoot(t, "opathexec")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "OPATH-EXEC-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
