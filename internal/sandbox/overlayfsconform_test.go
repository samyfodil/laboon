package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
	"github.com/samyfodil/laboon/internal/namespace"
)

// TestOverlayFSConformance proves the vfs overlay backend, resolved through a
// Namespace, reconstructs exactly what a real guest produced over the live
// sandbox overlay. It is the equivalence the eventual hot-path routing relies
// on: run vfsmutate (new file, sub-0600 mode, nested dir, symlink, a deleted
// lower file, a rewritten lower file, a chmod'd lower file), then open the same
// lower+upper as an overlayFS and assert the merged view matches — modes,
// symlink target, whiteout, content.
func TestOverlayFSConformance(t *testing.T) {
	// The run resolves its root canonically (macOS's /var is a symlink), and
	// the confined backend opened here does no resolution of its own.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	for _, d := range []string{lower, upper} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"keep.txt": "keep", "gone.txt": "x", "mod.txt": "orig"} {
		if err := os.WriteFile(filepath.Join(lower, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(lower, "vfsmutate")
	copyGuest(t, bin, "vfsmutate")

	var out bytes.Buffer
	code, err := Run(context.Background(), "/vfsmutate", Config{
		Args: []string{"/vfsmutate"}, RootFS: HostRoot(lower), Upper: upper, Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 {
		t.Fatalf("vfsmutate code %d err %v\n%s", code, err, out.String())
	}

	// Reopen the run's lower and kept upper as a union overlay over the REAL
	// platform backend (hostfs.HostDirFS), with the kept upper's metadata sidecar loaded
	// into the shared store — the composition the live routing uses.
	lo := hostfs.NewHostDirFS(lower, hostfs.NewHostFS(lower, "", ""))
	up := hostfs.NewHostDirFS(upper, hostfs.NewHostFS(upper, "", ""))
	ofs := overlayfs.OverlayFS(lo, up)
	up.LoadSidecar() // the upper leaf owns its metadata now
	ns := namespace.NewNamespace(ofs)

	stat := func(p string) core.Attr {
		t.Helper()
		loc, err := ns.Resolve(p, false)
		if err != nil {
			t.Fatalf("resolve %s: %v", p, err)
		}
		a, _ := loc.Node.Stat()
		return a
	}
	body := func(p string) string {
		t.Helper()
		loc, err := ns.Resolve(p, true)
		if err != nil {
			t.Fatalf("resolve %s: %v", p, err)
		}
		f, err := loc.Node.Open(os.O_RDONLY)
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}
		b := make([]byte, 64)
		n, _ := f.ReadAt(b, 0)
		f.Close()
		return string(b[:n])
	}

	if body("/new.txt") != "hello" {
		t.Error("new.txt content")
	}
	if a := stat("/ro.txt"); a.Mode&0o7777 != 0o400 {
		t.Errorf("ro.txt mode = %o, want 0400 (sub-floor via overlay meta)", a.Mode&0o7777)
	}
	if body("/sub/f.txt") != "nested" {
		t.Error("sub/f.txt content")
	}
	if a := stat("/sl"); a.Kind != core.Symlink || a.Target != "/keep.txt" {
		t.Errorf("sl = %+v", a)
	}
	if _, err := ns.Resolve("/gone.txt", false); err == nil {
		t.Error("gone.txt should be whiteouted in the overlay view")
	}
	if body("/mod.txt") != "changed" {
		t.Error("mod.txt content (copy-up)")
	}
	if a := stat("/keep.txt"); a.Mode&0o7777 != 0o640 {
		t.Errorf("keep.txt mode = %o, want 0640", a.Mode&0o7777)
	}
}
