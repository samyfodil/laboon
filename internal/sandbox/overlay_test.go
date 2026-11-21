package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runBusybox runs a busybox shell script over a root holding only busybox.
func runBusybox(t *testing.T, script string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code, err := Run(context.Background(), "/bin/busybox", Config{
		Args:   []string{"sh", "-c", "/bin/busybox --install -s /bin; " + script},
		Env:    []string{"PATH=/bin"},
		Stdout: &out,
		Stderr: &out,
		RootFS: HostRoot(busyboxRoot(t)),
	})
	if err != nil {
		t.Fatalf("run: %v (output %q)", err, out.String())
	}
	return code, out.String()
}

// The root of the overlay exists in the upper layer from the start, so a
// listing must merge in the lower layer rather than show only the upper.
func TestListMergesOverlayLayers(t *testing.T) {
	code, out := runBusybox(t, "ls /; mkdir /lc-new; echo x > /tmp/lc-file; ls / /tmp; rmdir /lc-new; ls /")
	if code != 0 {
		t.Fatalf("code = %d, output %q", code, out)
	}
	lines := strings.Split(out, "\n")
	count := func(name string) int {
		n := 0
		for _, l := range lines {
			if l == name {
				n++
			}
		}
		return n
	}
	if count("bin") != 3 || count("lc-new") != 1 || count("lc-file") != 1 {
		t.Fatalf("output %q", out)
	}
}

// TestFsOps runs testdata/fsops.c, built against glibc and musl, over a host
// directory image: file attributes, links, FIFOs, locks, vectored I/O, copies,
// shared mappings and fd ioctls.
func TestFsOps(t *testing.T) {
	for _, name := range []string{"fsops", "fsops+musl"} {
		// The probe works on a lower /etc/passwd and runs /usr/bin/env.
		root, prog := guestRoot(t, name)
		withBusybox(t, root)
		for _, d := range []string{"etc", "usr/bin"} {
			if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		copyFile(t, filepath.Join(root, "bin", "busybox"), filepath.Join(root, "usr", "bin", "env"))
		var o bytes.Buffer
		code, err := Run(context.Background(), prog, Config{Args: []string{"fsops"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
		if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
			t.Errorf("%s: code=%d err=%v\n%s", name, code, err, o.String())
		}
	}
}
