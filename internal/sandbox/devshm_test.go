package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A hard link within /dev/shm must succeed: both names live in the one
// overlay-backed filesystem behind the /dev mount. Regression for the devFS
// Link wrapper handing the overlay a /dev-wrapped node (reported EXDEV, which
// broke Python multiprocessing's sem_open).
func TestDevShmLink(t *testing.T) {
	root, exe := guestRoot(t, "shmlink")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.HasSuffix(out.String(), "OK\n") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

// /dev/shm is a sticky world-writable directory even when the root has no
// /dev: it is made in the writable layer, through the Namespace.
func TestDevShmProvisioned(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "devshm")
	copyGuest(t, exe, "devshm")
	upper := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, "/devshm", Config{Args: []string{"/devshm"}, RootFS: HostRoot(root), Upper: upper, Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || out.String() != "OK\n" {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
	if _, err := os.Stat(filepath.Join(root, "dev")); !os.IsNotExist(err) {
		t.Fatalf("lower layer gained /dev: %v", err)
	}
}
