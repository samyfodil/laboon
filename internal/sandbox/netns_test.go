//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestNetNamespace runs testdata/netns.c with networking enabled: a new network
// namespace (as a sandbox gives a renderer) cuts the process off from the host
// network even though -net is on, while AF_UNIX still works.
func TestNetNamespace(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "netns")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/netns.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"netns"},
		Stdout: &out, Stderr: &out, Root: "/", Net: true,
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
