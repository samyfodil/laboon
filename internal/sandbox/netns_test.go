package sandbox

import (
	"bytes"
	"context"
	"testing"
)

// TestNetNamespace runs testdata/netns.c with networking enabled: a new network
// namespace (as a sandbox gives a renderer) cuts the process off from the host
// network even though -net is on, while AF_UNIX still works.
func TestNetNamespace(t *testing.T) {
	root, bin := guestRoot(t, "netns")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"netns"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root), Net: true,
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
