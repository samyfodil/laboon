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

// The virtual cgroup v2 hierarchy supports mkdir, recorded control-file writes,
// nesting, and rmdir (with ENOTEMPTY) — what a container runtime needs.
func TestCgroupFS(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "cgroupfs")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/cgroupfs.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "CGROUPFS-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
