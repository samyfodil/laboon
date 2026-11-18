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

// get_robust_list must round-trip what set_robust_list stored (podman's shm
// lock manager probes robust-mutex support and fails on ENOSYS).
func TestRobustList(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "robustlist")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/robustlist.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "ROBUST-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
