package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestUnixAddrContained runs testdata/unixsock.c with the host as the image
// and checks that nothing the guest bound reached the host.
func TestUnixAddrContained(t *testing.T) {
	// The host directory is in the guest's image, at /host.
	root, bin := guestRoot(t, "unixsock")
	host := filepath.Join(root, "host")
	if err := os.Mkdir(host, 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(host, "host.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	name := fmt.Sprintf("lc-host-abstract-%d", os.Getpid())
	// A host abstract socket the guest must not reach, where the host has the
	// abstract namespace (Darwin has none: "@" would name a file here).
	if runtime.GOOS != "darwin" {
		abs, err := net.Listen("unix", "@"+name)
		if err != nil {
			t.Fatal(err)
		}
		defer abs.Close()
	}
	// With networking too: the guest's sockets are host sockets either way.
	for _, netOn := range []bool{true, false} {
		var out bytes.Buffer
		code, err := Run(context.Background(), bin, Config{
			Args:   []string{"unixsock", "/host", "/host/host.sock", name},
			Stdout: &out, Stderr: &out, RootFS: HostRoot(root), Net: netOn,
		})
		if err != nil || code != 0 {
			t.Fatalf("net %v: code %d (testdata/unixsock.c line) err %v\n%s", netOn, code, err, out.String())
		}
	}
	ents, err := os.ReadDir(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() != "host.sock" {
			t.Errorf("the guest's %s reached the host", e.Name())
		}
	}
}
