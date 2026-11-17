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

// A char device mknod'd inside a tmpfs mount must report its real type and
// number (char 1:3) on both path-stat and fstat — a container runtime (crun's
// reopen-dev-null) compares /dev/null's rdev against the stdio fds, and a
// device that looked like a plain rdev-0 file made it clobber the stdout pipe.
func TestTmpfsDevRdev(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "tmpfsdev")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/tmpfsdev.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	got := out.String()
	if err != nil || code != 0 ||
		!strings.Contains(got, "path-stat: ischr=1 rdev=1:3") ||
		!strings.Contains(got, "fstat: ischr=1 rdev=1:3") {
		t.Fatalf("code=%d err=%v out=%q", code, err, got)
	}
}
