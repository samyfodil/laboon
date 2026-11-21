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

// The kernel filesystems answer by the mount over a path, so a guest mount over
// /proc or a cgroup2 at another path behaves as on Linux
// (testdata/mountdispatch.c).
func TestMountDispatch(t *testing.T) {
	bin := guestPath(t, "mountdispatch")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "mountdispatch"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, "/mountdispatch", Config{
		Args: []string{"/mountdispatch"}, RootFS: HostRoot(root), Upper: t.TempDir(),
		Stdout: &o, Stderr: &o,
	})
	t.Log(strings.TrimSpace(o.String()))
	if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
		t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
	}
}
