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

// A persisted network-namespace bind-mount: unlink is refused while bound
// (EBUSY), umount releases it, and setns through it rejoins the pinned netns
// (a loopback listener living there becomes reachable only after the join).
func TestNsBind(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "nsbind")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", exe, "../../testdata/nsbind.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Net: true, Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "NSBIND-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
