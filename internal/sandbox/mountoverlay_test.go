//go:build linux

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

// TestMountOverlay runs testdata/mountoverlay.c: a guest mounts an overlay (as a
// container runtime's overlay storage driver does), and the union must merge the
// lower layer and copy writes up into the upper layer. This is what lets podman
// run on its default overlay driver without the --storage-driver vfs workaround.
func TestMountOverlay(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "mountoverlay")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mountoverlay.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "OVERLAY-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
