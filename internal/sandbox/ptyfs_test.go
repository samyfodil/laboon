//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Terminals resolve as devices through the Namespace (testdata/ptyfs.c).
func TestPtyFS(t *testing.T) {
	bin := guestBin(t, "ptyfs")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ptyfs"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, "/ptyfs", Config{
		Args: []string{"/ptyfs"}, RootFS: HostRoot(root), Upper: t.TempDir(),
		Stdout: &o, Stderr: &o,
	})
	t.Log(strings.TrimSpace(o.String()))
	if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
		t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
	}
}
