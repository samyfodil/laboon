//go:build linux || darwin

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// A guest-issued `mount -t overlay` names its layer directories; overlayLayerHost
// maps each to a host directory read raw. A guest with CAP_SYS_ADMIN must not be
// able to name a layer that resolves outside the backing tree — via ".." or a
// symlink whose target is a host path — and have it mounted, which would expose
// an arbitrary part of the host. This checks the confinement directly, and that
// a legitimate in-tree symlink layer (podman names lower layers through symlinks)
// is still accepted.
func TestOverlayLayerHostConfinement(t *testing.T) {
	base := t.TempDir()
	upper, err := filepath.EvalSymlinks(base) // canonical, as the real upperAbs is
	if err != nil {
		t.Fatal(err)
	}
	diff := filepath.Join(upper, "l1", "diff")
	if err := os.MkdirAll(diff, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(diff, filepath.Join(upper, "link")); err != nil { // in-tree symlink layer
		t.Fatal(err)
	}
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(upper, "evil")); err != nil { // symlink out of the tree
		t.Fatal(err)
	}

	fs := &dfs{rootAbs: upper, upperAbs: upper}

	for _, c := range []struct{ gp, want string }{
		{"/l1/diff", diff},
		{"/link", diff}, // resolves through the in-tree symlink, stays inside
	} {
		h, ok := fs.overlayLayerHost(c.gp)
		if !ok {
			t.Fatalf("overlayLayerHost(%q) refused a legitimate in-tree layer", c.gp)
		}
		if h != c.want {
			t.Fatalf("overlayLayerHost(%q) = %q, want %q", c.gp, h, c.want)
		}
	}

	for _, gp := range []string{
		"/../../../../../../etc",       // ".." ladder out of the tree
		"/evil",                        // symlink whose target is outside the tree
		"/l1/../../../../../../../tmp", // ".." after an in-tree component
	} {
		if h, ok := fs.overlayLayerHost(gp); ok {
			t.Fatalf("overlayLayerHost(%q) = %q, ok — escape was not refused", gp, h)
		}
	}
}
