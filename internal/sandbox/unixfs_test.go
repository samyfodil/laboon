package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/filesystems/memfs"
)

// TestUnixSocketFS runs testdata/unixfs.c: AF_UNIX sockets named in the
// overlay's writable layer, in an in-memory mount (which holds no host
// sockets) and under /dev, and in a directory whose host path overruns
// sun_path.
func TestUnixSocketFS(t *testing.T) {
	bin := guestPath(t, "unixfs")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "w"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unixfs"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, "/unixfs", Config{
		Args:   []string{"/unixfs", "/w", "/m", "/dev"},
		RootFS: HostRoot(root),
		Upper:  t.TempDir(),
		Mounts: []Mount{{Guest: "/m", FS: memfs.NewMemFS()}},
		Stdout: &o, Stderr: &o,
	})
	t.Log(strings.TrimSpace(o.String()))
	if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
		t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
	}
}
