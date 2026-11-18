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

// A TCP client and server on 127.0.0.1 inside an isolated netns talk over vnet.
func TestLoopTCP(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "looptcp")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", exe, "../../testdata/looptcp.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Net: true, Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "LOOPTCP-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
