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

// TestPtraceSeize checks PTRACE_SEIZE, PTRACE_INTERRUPT and PTRACE_LISTEN,
// and attaching to a task stopped by job control, one thread of several
// included, as Linux has them.
func TestPtraceSeize(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "ptraceseize")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", exe, "../../testdata/ptraceseize.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	for _, args := range [][]string{{exe}, {exe, "stopped-mt"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		var out bytes.Buffer
		code, err := Run(ctx, exe, Config{Args: args, Root: "/", Stdout: &out, Stderr: &out})
		cancel()
		if err != nil || code != 0 || !strings.Contains(out.String(), "ptraceseize fails=0") {
			t.Fatalf("%v: code=%d err=%v out=%q", args[1:], code, err, out.String())
		}
	}
}
