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

func runC(t *testing.T, csrc, marker string) {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "t")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/"+csrc).CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), marker) {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

// umount of a mount point succeeds once then reports EINVAL (so a runtime's
// unmount-until-failure loop terminates rather than spinning).
func TestUmountSeq(t *testing.T) { runC(t, "umountseq.c", "UMOUNTSEQ-OK") }

// bpf fakes the cgroup device controller: attach is a no-op, others ENOSYS.
func TestBpfDev(t *testing.T) { runC(t, "bpfdev.c", "BPFDEV-OK") }
