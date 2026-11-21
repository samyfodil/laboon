package sandbox

import (
	"bytes"
	"context"
	"testing"
)

// TestUTSNamespace runs testdata/utsns.c: a child in a new UTS namespace changes
// its hostname and the change does not reach the parent.
func TestUTSNamespace(t *testing.T) {
	root, bin := guestRoot(t, "utsns")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"utsns"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
