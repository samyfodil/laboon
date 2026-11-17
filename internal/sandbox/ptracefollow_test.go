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

// TestPtraceFollow checks that a tracer follows its tracee through exec and
// fork, and that PTRACE_ATTACH stops a running process and PTRACE_DETACH lets
// it go on.
func TestPtraceFollow(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "ptracefollow")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/ptracefollow.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "ptracefollow fails=0") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
