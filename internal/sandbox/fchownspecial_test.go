package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// fchown of /dev/null and a pipe must succeed (a container runtime chowns the
// std streams it points there), not fail resolving a nonexistent path.
func TestFchownSpecial(t *testing.T) {
	root, exe := guestRoot(t, "fchownspecial")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "FCHOWN-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
