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

// Two containers in separate network namespaces reach each other over the
// shared virtual network (cross-netns vnet routing).
func TestXNetns(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "xnetns")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", exe, "../../testdata/xnetns.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Net: true, Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "XNETNS-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
