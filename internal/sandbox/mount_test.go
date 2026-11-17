//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMountSocket runs testdata/x11sock.c against a host AF_UNIX listener under
// /tmp/.X11-unix/: a socket bind lets the guest reach it; without one the
// connect is refused, as a host socket in the rootfs is.
func TestMountSocket(t *testing.T) {
	const sockPath = "/tmp/.X11-unix/X231" // an unused display number
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("listen %s: %v", sockPath, err)
	}
	defer ln.Close()
	defer os.Remove(sockPath)
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

	dir := t.TempDir()
	bin := filepath.Join(dir, "x11sock")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/x11sock.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}

	run := func(mounts []Mount) (int, string) {
		var out bytes.Buffer
		code, err := Run(context.Background(), bin, Config{
			Args: []string{"x11sock", sockPath},
			Root: "/", Mounts: mounts,
			Stdout: &out, Stderr: &out,
		})
		if err != nil {
			t.Fatalf("run: %v\n%s", err, out.String())
		}
		return code, out.String()
	}

	// With the bind, the guest reaches the host socket.
	if code, out := run([]Mount{{Host: "/tmp/.X11-unix", Guest: "/tmp/.X11-unix"}}); code != 0 {
		t.Fatalf("with mount: code %d (testdata/x11sock.c line)\n%s", code, out)
	}
	// Without it, a host socket in the rootfs is refused.
	if code, _ := run(nil); code == 0 {
		t.Errorf("without mount: connect to a host socket should be refused, got success")
	}
}
