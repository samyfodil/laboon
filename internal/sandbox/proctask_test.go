package sandbox

import (
	"bytes"
	"context"
	"testing"
)

// TestProcTaskNlink runs testdata/proctask.c: /proc/<pid>/task must report
// st_nlink of 2 + the thread count, which Chromium's sandbox CHECKs (>= 3) to
// confirm single-threadedness before entering the GPU process.
func TestProcTaskNlink(t *testing.T) {
	root, bin := guestRoot(t, "proctask")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"proctask"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d (testdata/proctask.c line) err %v\n%s", code, err, out.String())
	}
}
