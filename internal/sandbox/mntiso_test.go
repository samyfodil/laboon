package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestMountNamespaceIsolation checks a mount(2) in one mount namespace is not
// visible in another: a child unshares CLONE_NEWNS, mounts a tmpfs + marker, and
// the root-namespace parent must not see it.
func TestMountNamespaceIsolation(t *testing.T) {
	groot, exe := guestRoot(t, "mntiso")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(groot), Stdout: &out, Stderr: &out})
	s := out.String()
	if err != nil || code != 0 || !strings.Contains(s, "MNTISO-DONE") {
		t.Fatalf("code=%d err=%v out=%q", code, err, s)
	}
	t.Logf("mntiso output:\n%s", s)
	if !strings.Contains(s, "child-sees-own-mount=1") {
		t.Errorf("child should see its own mount: %q", s)
	}
	if !strings.Contains(s, "parent-sees-child-mount=0") {
		t.Errorf("a child mount namespace's mount must not be visible to the root namespace: %q", s)
	}
}
