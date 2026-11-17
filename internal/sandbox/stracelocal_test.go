package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestStraceLocalArm64 traces a child to a syscall the sandbox serves in-guest
// (getrandom) rather than posting to the supervisor, and confirms it still
// appears at a ptrace syscall-entry stop. Without reporting in-guest-served
// syscalls for their stops, such a call is invisible to a tracer; this guards
// that path on arm64 (linux, and through the gate, darwin).
func TestStraceLocalArm64(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("arm64 register set")
	}
	exe := filepath.Join(t.TempDir(), "stracelocal")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/stracelocal.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "LOCALTRACE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
