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

// execveat(O_PATH fd, AT_EMPTY_PATH) must run the pinned file even after its
// name is unlinked — the fexecve / bind-mount-ro re-exec a container runtime uses.
func TestOPathExec(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "opathexec")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/opathexec.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "OPATH-EXEC-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
