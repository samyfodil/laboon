package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// A tmpfs mount must behave like any vfs mount: a file written under it reads
// back, and the mount is isolated from the rootfs path it covered.
func TestMountTmpfs(t *testing.T) {
	root, exe := guestRoot(t, "mounttmpfs")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "TMPFS-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
