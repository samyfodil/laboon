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

// After an exec from an O_PATH fd whose name was unlinked, /proc/self/exe must
// still open the exec'd inode and read back with " (deleted)" (crun re-reads
// its own exe after re-execing itself this way).
func TestProcExe(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "procexe")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/procexe.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "PROCEXE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
