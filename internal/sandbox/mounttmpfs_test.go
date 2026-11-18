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

// A tmpfs mount must behave like any vfs mount: a file written under it reads
// back, and the mount is isolated from the rootfs path it covered.
func TestMountTmpfs(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "mounttmpfs")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mounttmpfs.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "TMPFS-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
