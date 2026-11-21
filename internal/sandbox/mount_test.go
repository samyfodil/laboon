package sandbox

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// TestMountSocket runs testdata/x11sock.c against a host AF_UNIX listener under
// /tmp/.X11-unix/: a socket bind lets the guest reach it; without one the
// connect is refused, as a host socket in the rootfs is.
func TestMountSocket(t *testing.T) {
	const sockPath = "/tmp/.X11-unix/X231"
	// The host's X socket lives in the guest's rootfs, as /tmp/.X11-unix would.
	root, bin := guestRoot(t, "x11sock")
	sockDir := filepath.Join(root, "tmp", ".X11-unix")
	if err := os.Mkdir(sockDir, 0o777); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(sockDir, "X231"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.CopyN(io.Discard, c, 4)
				c.Write([]byte("pong"))
				c.Close()
			}()
		}
	}()

	run := func(mounts []Mount) (int, string) {
		var out bytes.Buffer
		code, err := Run(context.Background(), bin, Config{
			Args:   []string{"x11sock", sockPath},
			RootFS: HostRoot(root), Mounts: mounts,
			Stdout: &out, Stderr: &out,
		})
		if err != nil {
			t.Fatalf("run: %v\n%s", err, out.String())
		}
		return code, out.String()
	}

	// With the bind, the guest reaches the host socket.
	if code, out := run([]Mount{{Guest: "/tmp/.X11-unix", FS: hostfs.Dir(sockDir)}}); code != 0 {
		t.Fatalf("with mount: code %d (testdata/x11sock.c line)\n%s", code, out)
	}
	// Without it, a host socket in the rootfs is refused.
	if code, _ := run(nil); code == 0 {
		t.Errorf("without mount: connect to a host socket should be refused, got success")
	}
}
