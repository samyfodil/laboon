package vfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOverlayFS drives the copy-on-write backend through the Namespace: a read
// comes from the lower layer, a write copies the path up into the top layer and
// leaves the lower untouched, a removal of a lower path whites it out, and a new
// file lands in the top.
func TestOverlayFS(t *testing.T) {
	lowerDir, upperDir := t.TempDir(), t.TempDir()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(os.MkdirAll(filepath.Join(lowerDir, "etc"), 0o755))
	must(os.WriteFile(filepath.Join(lowerDir, "etc/base"), []byte("base"), 0o644))
	must(os.WriteFile(filepath.Join(lowerDir, "gone"), []byte("x"), 0o644))
	ofs := NewOverlayFS(newTestDirFS(lowerDir), newTestDirFS(upperDir))
	ns := NewNamespace(ofs)
	read := func(p string) string {
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

	if read("/etc/base") != "base" {
		t.Fatal("lower read through overlay")
	}

	// A writable open copies the path up: write into the top, lower untouched.
	loc, _ := ns.Resolve("/etc/base", true)
	f, err := loc.Node.Open(os.O_RDWR | os.O_TRUNC)
	must(err)
	f.WriteAt([]byte("changed"), 0)
	f.Close()
	if read("/etc/base") != "changed" {
		t.Fatal("copy-up write not visible")
	}
	if b, _ := os.ReadFile(filepath.Join(lowerDir, "etc/base")); string(b) != "base" {
		t.Fatalf("lower mutated by copy-up: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(upperDir, "etc/base")); string(b) != "changed" {
		t.Fatalf("top layer missing the copied-up change: %q", b)
	}

	// Removing a lower path whites it out of the merged view.
	root, _ := ns.Resolve("/", true)
	must(ofs.Remove(root.Node, "gone", false))
	if _, err := ns.Resolve("/gone", true); err == nil {
		t.Fatal("removed lower path still resolves")
	}

	// A new file lands in the top and reads back.
	if _, err := ofs.(WriteFileSystem).WriteFile(root.Node, "new", CreateSpec{Kind: Reg, Mode: 0o644}, []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if read("/new") != "fresh" {
		t.Fatal("new file in top")
	}

	// Emptying a lower directory fills its top copy with whiteout markers; the
	// now-empty merged directory must still rmdir (Remove drops the top copy and
	// its markers), and stay gone.
	must(os.MkdirAll(filepath.Join(lowerDir, "d"), 0o755))
	must(os.WriteFile(filepath.Join(lowerDir, "d/a"), []byte("x"), 0o644))
	must(os.WriteFile(filepath.Join(lowerDir, "d/b"), []byte("y"), 0o644))
	ofs2 := NewOverlayFS(newTestDirFS(lowerDir), newTestDirFS(upperDir))
	ns2 := NewNamespace(ofs2)
	dloc, _ := ns2.Resolve("/d", true)
	must(ofs2.Remove(dloc.Node, "a", false))
	must(ofs2.Remove(dloc.Node, "b", false))
	r2, _ := ns2.Resolve("/", true)
	if err := ofs2.Remove(r2.Node, "d", true); err != nil {
		t.Fatalf("rmdir of a marker-filled merged dir: %v", err)
	}
	if _, err := ns2.Resolve("/d", true); err == nil {
		t.Fatal("rmdir'd dir still resolves")
	}

	// Recreating the removed directory makes it opaque: the lower layer's entries
	// (a, b) were deleted and must stay hidden under the fresh empty dir.
	if _, err := ofs2.Create(r2.Node, "d", CreateSpec{Kind: Dir, Mode: 0o755}); err != nil {
		t.Fatalf("recreate removed dir: %v", err)
	}
	dloc2, err := ns2.Resolve("/d", true)
	if err != nil {
		t.Fatalf("recreated dir does not resolve: %v", err)
	}
	if ents, _ := ofs2.ReadDir(dloc2.Node); len(ents) != 0 {
		t.Fatalf("recreated dir not opaque: %d entries, want 0", len(ents))
	}
}
