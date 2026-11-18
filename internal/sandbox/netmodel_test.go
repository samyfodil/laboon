//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestNetModelEndToEnd runs testdata/netmodel.c: in a freshly unshared network
// namespace the guest adds an address with RTM_NEWADDR and getifaddrs must then
// report it. This fails under an ack-and-fake netlink (which would show only the
// host's loopback), so it guards that a non-host netns is really modelled.
func TestNetModelEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "netmodel")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/netmodel.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"netmodel"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot("/"), Net: true,
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
	dir := t.TempDir()
	bin := filepath.Join(dir, "netmodelhost")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/netmodelhost.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"netmodelhost"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot("/"), Net: true,
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
