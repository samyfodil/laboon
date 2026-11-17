//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEpollEt runs testdata/epollet.c: edge-triggered epoll must hold back a
// ready fd that does not fit a wait's maxevents rather than lose its edge.
func TestEpollEt(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "epollet")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/epollet.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{Args: []string{"epollet"}, Stdout: &out, Stderr: &out, Root: "/"})
	if err != nil || code != 0 {
		t.Fatalf("code %d (testdata/epollet.c line) err %v\n%s", code, err, out.String())
	}
}
