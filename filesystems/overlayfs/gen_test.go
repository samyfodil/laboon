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

// TestDirGen checks a change bumps the version of the directories whose names
// it changed, and only theirs: a copy-up the parent of the copied path, a move
// both directories.
func TestDirGen(t *testing.T) {
	lower, top := memfs.NewMemFS(), memfs.NewMemFS()
	for _, d := range []string{"a", "b", "c"} {
		if _, err := lower.Create(lower.Root(), d, CreateSpec{Kind: Dir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	al, _ := lower.Lookup(lower.Root(), "a")
	writeInto(t, lower, al, "f", "F", CreateSpec{Mode: 0o644})
	ov := OverlayFS(lower, top)
	g := ov.(DirGenerational)
	check := func(what string, f func() error, want ...string) {
		t.Helper()
		before := map[string]uint64{}
		for _, d := range []string{"", "a", "b", "c"} {
			before[d] = g.DirGen(d)
		}
		e0 := g.Epoch()
		if err := f(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		for d, v := range before {
			bumped := g.DirGen(d) != v
			wanted := false
			for _, w := range want {
				wanted = wanted || w == d
			}
			if bumped != wanted {
				t.Errorf("%s: directory %q bumped=%v, want %v", what, d, bumped, wanted)
			}
		}
		if g.Epoch() != e0 {
			t.Errorf("%s moved the epoch", what)
		}
	}
	check("first write into a lower dir", func() error {
		f, err := lookupPath(t, ov, "a/f").Open(os.O_WRONLY)
		if err != nil {
			return err
		}
		return f.Close()
	}, "", "a")
	check("create", func() error {
		_, err := ov.Create(lookupPath(t, ov, "a"), "g", CreateSpec{Kind: Reg, Mode: 0o644})
		return err
	}, "a")
	check("rewrite", func() error {
		f, err := lookupPath(t, ov, "a/f").Open(os.O_WRONLY)
		if err != nil {
			return err
		}
		return f.Close()
	})
	check("rename into a lower dir", func() error {
		return ov.Rename(lookupPath(t, ov, "a"), "g", lookupPath(t, ov, "b"), "g")
	}, "", "a", "b")
	check("remove", func() error { return ov.Remove(lookupPath(t, ov, "b"), "g", false) }, "b")
	before := g.Epoch()
	ov.(Generational).Touch()
	if g.Epoch() == before {
		t.Error("Touch left the epoch unchanged")
	}
}
