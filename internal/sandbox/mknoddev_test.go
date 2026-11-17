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

// Root can mknod the standard character devices; they stat as char specials
// with the right number and open to the host device's behavior.
func TestMknodDev(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "mknoddev")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/mknoddev.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "MKNODDEV-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
