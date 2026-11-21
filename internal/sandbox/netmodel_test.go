package sandbox

import (
	"bytes"
	"context"
	"testing"
)

// TestNetModelEndToEnd runs testdata/netmodel.c: in a freshly unshared network
// namespace the guest adds an address with RTM_NEWADDR and getifaddrs must then
// report it. This fails under an ack-and-fake netlink (which would show only the
// host's loopback), so it guards that a non-host netns is really modelled.
func TestNetModelEndToEnd(t *testing.T) {
	root, bin := guestRoot(t, "netmodel")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"netmodel"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root), Net: true,
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}

// TestNetModelHostEndToEnd runs testdata/netmodelhost.c in the host network
// namespace: a created bridge (a runtime's, via RTM_NEWLINK) must appear in a
// link dump alongside the real host loopback, i.e. the host netns is a live view
// of the real interfaces with the guest's own additions layered on.
func TestNetModelHostEndToEnd(t *testing.T) {
	root, bin := guestRoot(t, "netmodelhost")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"netmodelhost"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root), Net: true,
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
