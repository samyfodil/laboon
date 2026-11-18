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

// Pseudo mounts report their real statfs f_type (cgroup2 for /sys/fs/cgroup,
// proc for /proc) rather than the overlay's — a container runtime checks this.
func TestFsMagic(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "fsmagic")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/fsmagic.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "FSMAGIC-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
