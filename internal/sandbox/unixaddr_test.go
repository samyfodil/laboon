//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestUnixAddrContained runs testdata/unixsock.c with the host as the image
// and checks that nothing the guest bound reached the host.
func TestUnixAddrContained(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "unixsock")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/unixsock.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	host := t.TempDir()
	ln, err := net.Listen("unix", filepath.Join(host, "host.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	abs, err := net.Listen("unix", "@lc-host-abstract-"+filepath.Base(host))
	if err != nil {
		t.Fatal(err)
	}
	defer abs.Close()
	// With networking too: the guest's sockets are host sockets either way.
	for _, netOn := range []bool{true, false} {
		var out bytes.Buffer
		code, err := Run(context.Background(), bin, Config{
			Args:   []string{"unixsock", host, filepath.Join(host, "host.sock"), "lc-host-abstract-" + filepath.Base(host)},
			Stdout: &out, Stderr: &out, RootFS: HostRoot("/"), Net: netOn,
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
