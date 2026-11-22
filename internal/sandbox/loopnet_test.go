package sandbox

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
)

// TestLoopbackWithoutNet runs testdata/loopnet.c without networking,
// where the guest has loopback only; with NoNet, where it has no INET socket
// at all; and with networking, under an egress allowlist or not, where its
// loopback is its own and the host's is out of reach.
func TestLoopbackWithoutNet(t *testing.T) {
	dir := t.TempDir() // the guest's root: the program is all it needs
	bin := filepath.Join(dir, "loopnet")
	copyGuest(t, bin, "loopnet")
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostPort := strconv.Itoa(host.Addr().(*net.TCPAddr).Port)
	for _, c := range []struct {
		args       []string
		noNet, net bool
		allow      []string
	}{
		{[]string{"loopback"}, false, false, nil},
		{[]string{"none"}, true, false, nil},
		{[]string{"local", hostPort}, false, true, nil},
		{[]string{"local", hostPort, "dns"}, false, true, []string{"example.com"}},
	} {
		var out bytes.Buffer
		code, err := Run(context.Background(), "/loopnet", Config{
			Args:   append([]string{"loopnet"}, c.args...),
			Stdout: &out, Stderr: &out, RootFS: HostRoot(dir), NoNet: c.noNet,
			Net: c.net, AllowDomains: c.allow,
		})
		if err != nil || code != 0 {
			t.Errorf("%v: code %d err %v\n%s", c.args, code, err, out.String())
		}
	}
}
