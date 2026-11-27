package overlayfs

import (
	"os"
	"testing"

	. "github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

// TestGenOnlyOnNameChange checks the overlay's generation moves on a change to
// what a path resolves to (a copy-up, create, link, remove, rename) and not on
// one that leaves every name resolving to the same nodes (a writable open, an
// attribute change, of a file already in the top).
func TestGenOnlyOnNameChange(t *testing.T) {
	lower, top := memfs.NewMemFS(), memfs.NewMemFS()
	writeInto(t, lower, lower.Root(), "low", "L", CreateSpec{Mode: 0o644})
	ov := OverlayFS(lower, top)
	g := ov.(Generational)
	up := writeInto(t, ov, ov.Root(), "up", "U", CreateSpec{Mode: 0o644})

	same := func(what string, f func() error) {
		t.Helper()
		before := g.Gen()
		if err := f(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if g.Gen() != before {
			t.Errorf("%s bumped the generation", what)
		}
	}
	moved := func(what string, f func() error) {
		t.Helper()
		before := g.Gen()
		if err := f(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if g.Gen() == before {
			t.Errorf("%s left the generation unchanged", what)
		}
	}
	mode := uint32(0o600)

	same("writable open of a top file", func() error {
		f, err := up.Open(os.O_RDWR)
		if err != nil {
			return err
		}
		return f.Close()
	})
	same("chmod of a top file", func() error { return up.SetAttr(AttrUpdate{Mode: &mode}) })
	moved("writable open of a lower file", func() error {
		f, err := lookupPath(t, ov, "low").Open(os.O_WRONLY)
		if err != nil {
			return err
		}
		return f.Close()
	})
	moved("create", func() error {
		_, err := ov.Create(ov.Root(), "new", CreateSpec{Kind: Reg, Mode: 0o644})
		return err
	})
	moved("link", func() error {
		_, err := ov.Link(ov.Root(), "hard", lookupPath(t, ov, "new"))
		return err
	})
	moved("rename", func() error { return ov.Rename(ov.Root(), "new", ov.Root(), "moved") })
	moved("remove", func() error { return ov.Remove(ov.Root(), "moved", false) })
}
