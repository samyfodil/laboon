package sandbox

import (
	"bytes"
	"context"
	"testing"
)

// TestEpollEt runs testdata/epollet.c: edge-triggered epoll must hold back a
// ready fd that does not fit a wait's maxevents rather than lose its edge.
func TestEpollEt(t *testing.T) {
	root, bin := guestRoot(t, "epollet")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{Args: []string{"epollet"}, Stdout: &out, Stderr: &out, RootFS: HostRoot(root)})
	if err != nil || code != 0 {
		t.Fatalf("code %d (testdata/epollet.c line) err %v\n%s", code, err, out.String())
	}
}
