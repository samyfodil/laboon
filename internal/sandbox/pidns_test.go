package sandbox

import (
	"bytes"
	"context"
	"testing"
)

// TestPidNamespace runs testdata/pidns.c: a clone(CLONE_NEWPID) child is pid 1
// in its namespace with an invisible parent, its own child is pid 2, and the
// outer parent reaps it by the pid clone returned — the pid translation
// Chromium's zygote relies on.
func TestPidNamespace(t *testing.T) {
	root, bin := guestRoot(t, "pidns")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"pidns"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
