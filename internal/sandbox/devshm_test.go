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

// A hard link within /dev/shm must succeed: both names live in the one
// overlay-backed filesystem behind the /dev mount. Regression for the devFS
// Link wrapper handing the overlay a /dev-wrapped node (reported EXDEV, which
// broke Python multiprocessing's sem_open).
func TestDevShmLink(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "shmlink")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/shmlink.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.HasSuffix(out.String(), "OK\n") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
