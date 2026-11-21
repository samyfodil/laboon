package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
)

// An image root has no /proc or /sys; the CPU files must still be there.
func TestCPUFilesInEmptyRoot(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "cpuinfo")
	copyGuest(t, exe, "cpuinfo")
	var out bytes.Buffer
	code, err := Run(context.Background(), "/cpuinfo", Config{Args: []string{"cpuinfo"}, Stdout: &out, Stderr: &out, RootFS: HostRoot(root)})
	if err != nil || code != 0 {
		t.Fatalf("code = %d, err = %v, output %q", code, err, out.String())
	}
	n := runtime.NumCPU()
	if want := fmt.Sprintf("stat=%d cpuinfo=%d online=%s\n", n, n, cpuList(n)); out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
}
