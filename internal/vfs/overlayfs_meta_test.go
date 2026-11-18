package vfs

import "testing"

// TestOverlayFSInodeMeta checks the overlay backend keys the host-uncarryable
// metadata by node identity: a sub-floor mode and a non-root owner are shared
// between two hardlinks (one inode, one record) and survive a rename (the inode
// does not change). This is what the Stack's path-keyed metadata could not do.
func TestOverlayFSInodeMeta(t *testing.T) {
	f := NewOverlayFS(newTestDirFS(t.TempDir()), newTestDirFS(t.TempDir()))
	root := f.Root()

	a, err := f.Create(root, "secret", CreateSpec{Kind: Reg, Mode: 0o400, Uid: 1000, Gid: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Link(root, "alias", a); err != nil {
		t.Fatal(err)
	}
	check := func(name string, mode uint32, uid uint32) {
		t.Helper()
		n, err := f.Lookup(root, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		at, _ := n.Stat()
		if at.Mode&0o7777 != mode || at.Uid != uid {
			t.Fatalf("%s: mode=%o uid=%d, want %o %d", name, at.Mode&0o7777, at.Uid, mode, uid)
		}
	}
	// The create's sub-floor mode and non-root owner show on both names.
	check("secret", 0o400, 1000)
	check("alias", 0o400, 1000)

	// Changing one hardlink's mode shows on the other (shared inode, one record).
	na, _ := f.Lookup(root, "secret")
	m444 := uint32(0o444)
	if err := na.SetAttr(AttrUpdate{Mode: &m444}); err != nil {
		t.Fatal(err)
	}
	check("secret", 0o444, 1000)
	check("alias", 0o444, 1000)

	// A rename keeps the metadata: the inode is unchanged.
	if err := f.Rename(root, "secret", root, "moved"); err != nil {
		t.Fatal(err)
	}
	check("moved", 0o444, 1000)
	check("alias", 0o444, 1000)
}

// windowFS is a top layer that, once it has made the object name, runs at
// before returning: the moment the object exists on the host but the overlay
// has not yet recorded its guest metadata.
type windowFS struct {
	FileSystem
	name string
	at   func()
}

func (w *windowFS) Create(dir Node, name string, spec CreateSpec) (Node, error) {
	n, err := w.FileSystem.Create(dir, name, spec)
	if err == nil && name == w.name {
		w.at()
	}
	return n, err
}

// TestOverlayFSCreateWindow checks no Stat of a new object's path can run
// between its creation on the host and the recording of its guest owner and
// mode: one would see the host's defaults (owner root), and a process that
// found the directory made by another would be refused writing in it.
func TestOverlayFSCreateWindow(t *testing.T) {
	top := &windowFS{FileSystem: newTestDirFS(t.TempDir()), name: "d"}
	f := NewOverlayFS(newTestDirFS(t.TempDir()), top).(*overlayFS)
	top.at = func() {
		if l := f.makingLock("d"); l.TryRLock() {
			l.RUnlock()
			t.Error("a Stat of the path could run before its metadata is recorded")
		}
	}
	if _, err := f.Create(f.Root(), "d", CreateSpec{Kind: Dir, Mode: 0o700, Uid: 70, Gid: 70}); err != nil {
		t.Fatal(err)
	}
	n, err := f.Lookup(f.Root(), "d")
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := n.Stat(); a.Uid != 70 || a.Mode&0o7777 != 0o700 {
		t.Fatalf("uid=%d mode=%o, want 70 0700", a.Uid, a.Mode&0o7777)
	}
}
