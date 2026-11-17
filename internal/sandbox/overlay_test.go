//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runBusybox runs a busybox shell script with the host as the read-only root.
func runBusybox(t *testing.T, script string) (int, string) {
	t.Helper()
	bb, err := exec.LookPath("busybox")
	if err != nil {
		t.Skip("busybox unavailable")
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bb, Config{
		Args:   []string{"sh", "-c", script},
		Stdout: &out,
		Stderr: &out,
		Root:   "/",
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
	if count("usr") != 3 || count("lc-new") != 1 || count("lc-file") != 1 {
		t.Fatalf("output %q", out)
	}
}

// TestFsOps runs testdata/fsops.c, built against glibc and musl, with the
// host root as the image: file attributes, links, FIFOs, locks, vectored
// I/O, copies, shared mappings and fd ioctls.
func TestFsOps(t *testing.T) {
	dir := t.TempDir()
	builds := map[string][]string{
		"glibc": {"gcc", "-O2", "-static", "-w", "-pthread", "-o", filepath.Join(dir, "glibc"), "../../testdata/fsops.c"},
	}
	if z := zigCC(); z != "" {
		target := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-linux-musl"
		builds["musl"] = []string{z, "cc", "-target", target, "-O2", "-static", "-o", filepath.Join(dir, "musl"), "../../testdata/fsops.c"}
	}
	for libc, c := range builds {
		if b, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Skipf("build: %v\n%s", err, b)
		}
		var o bytes.Buffer
		code, err := Run(context.Background(), filepath.Join(dir, libc), Config{Args: []string{"fsops"}, Stdout: &o, Stderr: &o, Root: "/"})
		if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
			t.Errorf("%s: code=%d err=%v\n%s", libc, code, err, o.String())
		}
	}
}
