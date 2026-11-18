//go:build !windows

package oci

import (
	"os"
	"path/filepath"
	"testing"
)

// LookPath follows a rootfs's symlinks as the guest sees them: busybox
// applets are absolute links, which must resolve inside the rootfs.
func TestLookPathSymlinks(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"bin", "usr/bin", "sbin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "bin/busybox"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/data"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"bin/cat":     "/bin/busybox",            // absolute, as in alpine
		"usr/bin/env": "../../bin/busybox",       // relative
		"sbin/up":     "../../../../bin/busybox", // ".." stops at the top
		"bin/loop":    "/bin/loop",
		"bin/data2":   "data",
		"bin/host":    "/etc/passwd", // the host's, not the rootfs's
	}
	for l, target := range links {
		if err := os.Symlink(target, filepath.Join(root, l)); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"PATH=/usr/bin:/bin:/sbin"}
	for name, want := range map[string]string{"cat": "/bin/cat", "env": "/usr/bin/env", "up": "/sbin/up", "busybox": "/bin/busybox"} {
		if p, err := LookPath(root, name, env); err != nil || p != want {
			t.Errorf("LookPath(%s) = %q, %v; want %q", name, p, err, want)
		}
	}
	for _, name := range []string{"loop", "data", "data2", "host", "missing"} {
		if p, err := LookPath(root, name, env); err == nil {
			t.Errorf("LookPath(%s) = %q, want an error", name, p)
		}
	}
}
