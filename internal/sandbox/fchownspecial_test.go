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

// fchown of /dev/null and a pipe must succeed (a container runtime chowns the
// std streams it points there), not fail resolving a nonexistent path.
func TestFchownSpecial(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "fchownspecial")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/fchownspecial.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "FCHOWN-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
