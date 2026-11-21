package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/filesystems/memfs"
)

// A memFS-backed tmpfs file supports a private mmap (its bytes read back through
// the mapping) and its directory fstats as a directory.
func TestTmpfsMmap(t *testing.T) {
	root, exe := guestRoot(t, "tmpfsmmap")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "TMPFSMMAP-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

// A FileSystem the host mounts (WithFS, here an in-memory one) serves the guest's
// open/write/read/stat under its mount point.
func TestWithFSMem(t *testing.T) {
	root, exe := guestRoot(t, "fsrw")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{
		Args:   []string{exe},
		RootFS: HostRoot(root),
		Mounts: []Mount{{Guest: "/data", FS: memfs.NewMemFS()}},
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), "FSRW-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
