package vfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestMemFSFileIO(t *testing.T) {
	f := NewMemFS()
	root := f.Root()

	n, err := f.Create(root, "hello", CreateSpec{Kind: Reg, Mode: 0o644})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n.Kind() != Reg {
		t.Fatalf("kind = %v, want Reg", n.Kind())
	}

	h, err := n.Open(os.O_RDWR)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := h.WriteAt([]byte("hello world"), 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Overwrite the middle, then read the whole thing back.
	if _, err := h.WriteAt([]byte("WORLD"), 6); err != nil {
		t.Fatalf("write2: %v", err)
	}
	buf := make([]byte, 11)
	if m, err := h.ReadAt(buf, 0); err != nil || m != 11 || string(buf) != "hello WORLD" {
		t.Fatalf("read = %q n=%d err=%v, want %q", buf[:m], m, err, "hello WORLD")
	}
	// A read past the end returns what it can plus EOF.
	over := make([]byte, 20)
	if m, err := h.ReadAt(over, 0); err != io.EOF || m != 11 {
		t.Fatalf("read over = n=%d err=%v, want 11, EOF", m, err)
	}

	if a, _ := n.Stat(); a.Size != 11 || a.Nlink != 1 || a.Mode != 0o644 {
		t.Fatalf("stat = %+v, want size 11 nlink 1 mode 0644", a)
	}
	if err := h.Truncate(5); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if a, _ := n.Stat(); a.Size != 5 {
		t.Fatalf("size after truncate = %d, want 5", a.Size)
	}

	if _, err := f.Create(root, "hello", CreateSpec{Kind: Reg}); err != syscall.EEXIST {
		t.Fatalf("recreate err = %v, want EEXIST", err)
	}
	if _, err := f.Lookup(root, "nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lookup missing err = %v, want ErrNotExist", err)
	}
}

func TestMemFSDirs(t *testing.T) {
	f := NewMemFS()
	root := f.Root()

	d, err := f.Create(root, "sub", CreateSpec{Kind: Dir, Mode: 0o755})
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := f.Create(d, "a", CreateSpec{Kind: Reg}); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if _, err := f.Create(d, "b", CreateSpec{Kind: Dir}); err != nil {
		t.Fatalf("create b: %v", err)
	}
	ents, err := f.ReadDir(d)
	if err != nil || len(ents) != 2 {
		t.Fatalf("readdir = %v (%d), want 2 entries", ents, len(ents))
	}
	// A directory's link count is 2 plus its subdirectories.
	if a, _ := d.Stat(); a.Nlink != 3 {
		t.Fatalf("dir nlink = %d, want 3", a.Nlink)
	}

	if err := f.Remove(d, "b", false); err != syscall.EISDIR {
		t.Fatalf("unlink dir err = %v, want EISDIR", err)
	}
	if err := f.Remove(d, "a", true); err != ErrNotDir {
		t.Fatalf("rmdir file err = %v, want ErrNotDir", err)
	}
	if err := f.Remove(root, "sub", true); err != syscall.ENOTEMPTY {
		t.Fatalf("rmdir non-empty err = %v, want ENOTEMPTY", err)
	}
	if err := f.Remove(d, "a", false); err != nil {
		t.Fatalf("unlink a: %v", err)
	}
	if err := f.Remove(d, "b", true); err != nil {
		t.Fatalf("rmdir b: %v", err)
	}
	if err := f.Remove(root, "sub", true); err != nil {
		t.Fatalf("rmdir sub: %v", err)
	}
}

func TestMemFSLinks(t *testing.T) {
	f := NewMemFS()
	root := f.Root()

	// Symlink round-trips its target.
	sl, err := f.Create(root, "link", CreateSpec{Kind: Symlink, Target: "/target"})
	if err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if tgt, err := sl.Readlink(); err != nil || tgt != "/target" {
		t.Fatalf("readlink = %q, %v", tgt, err)
	}

	// Hardlink shares content and bumps nlink.
	a, _ := f.Create(root, "a", CreateSpec{Kind: Reg})
	ha, _ := a.Open(os.O_RDWR)
	ha.WriteAt([]byte("shared"), 0)
	b, err := f.Link(root, "b", a)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if b.ID() != a.ID() {
		t.Fatalf("hardlink ID %v != %v", b.ID(), a.ID())
	}
	hb, _ := b.Open(os.O_RDONLY)
	buf := make([]byte, 6)
	if n, _ := hb.ReadAt(buf, 0); string(buf[:n]) != "shared" {
		t.Fatalf("hardlink content = %q, want shared", buf[:n])
	}
	if st, _ := a.Stat(); st.Nlink != 2 {
		t.Fatalf("nlink after link = %d, want 2", st.Nlink)
	}
	if err := f.Remove(root, "b", false); err != nil {
		t.Fatalf("unlink b: %v", err)
	}
	if st, _ := a.Stat(); st.Nlink != 1 {
		t.Fatalf("nlink after unlink = %d, want 1", st.Nlink)
	}

	// Hardlink across filesystems is rejected.
	g := NewMemFS()
	if _, err := f.Link(root, "c", g.Root()); !errors.Is(err, ErrCrossDevice) {
		t.Fatalf("cross-fs link err = %v, want ErrCrossDevice", err)
	}
}

func TestMemFSRename(t *testing.T) {
	f := NewMemFS()
	root := f.Root()
	f.Create(root, "a", CreateSpec{Kind: Reg})
	d, _ := f.Create(root, "d", CreateSpec{Kind: Dir})
	sub, _ := f.Create(d, "sub", CreateSpec{Kind: Dir})

	if err := f.Rename(root, "a", d, "a2"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := f.Lookup(root, "a"); err == nil {
		t.Fatal("old name still present after rename")
	}
	if _, err := f.Lookup(d, "a2"); err != nil {
		t.Fatalf("new name missing after rename: %v", err)
	}
	// A directory cannot be renamed into its own subtree.
	if err := f.Rename(root, "d", sub, "loop"); err != syscall.EINVAL {
		t.Fatalf("rename into subtree err = %v, want EINVAL", err)
	}
}

func TestMemFSStatFS(t *testing.T) {
	f := NewMemFS().(StatFSer)
	st, err := f.StatFS(nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Type != 0x01021994 { // TMPFS_MAGIC
		t.Fatalf("statfs type = %#x, want tmpfs magic", st.Type)
	}
	if st.Bavail == 0 {
		t.Fatal("statfs reports no available space")
	}
}

func TestHardenFS(t *testing.T) {
	h := HardenFS(NewMemFS(), WithNoSymLink(), WithNoHardLink(), WithNoDevice(), WithNoSocket(), WithNoFifo())
	root := h.Root()

	// A regular file and a directory are still allowed.
	reg, err := h.Create(root, "ok", CreateSpec{Kind: Reg})
	if err != nil {
		t.Fatalf("create reg: %v", err)
	}
	if _, err := h.Create(root, "okdir", CreateSpec{Kind: Dir}); err != nil {
		t.Fatalf("create dir: %v", err)
	}

	for _, tc := range []struct {
		name string
		spec CreateSpec
	}{
		{"symlink", CreateSpec{Kind: Symlink, Target: "/x"}},
		{"chardev", CreateSpec{Kind: Chardev}},
		{"blockdev", CreateSpec{Kind: Blockdev}},
		{"socket", CreateSpec{Kind: Socket}},
		{"fifo", CreateSpec{Kind: Fifo}},
	} {
		if _, err := h.Create(root, tc.name, tc.spec); err != syscall.EPERM {
			t.Fatalf("create %s err = %v, want EPERM", tc.name, err)
		}
	}
	if _, err := h.Link(root, "hard", reg); err != syscall.EPERM {
		t.Fatalf("hardlink err = %v, want EPERM", err)
	}

	// Without the options, the same operations pass through.
	plain := HardenFS(NewMemFS())
	if _, err := plain.Create(plain.Root(), "sym", CreateSpec{Kind: Symlink, Target: "/y"}); err != nil {
		t.Fatalf("plain harden create symlink: %v", err)
	}
}

// TestConfinedLinks checks that a confined mount resolves its symlinks within its
// own root, while an ordinary mount keeps Linux semantics (absolute targets reach
// the namespace root).
func TestConfinedLinks(t *testing.T) {
	root := NewMemFS()
	// A file at the namespace root a symlink might try to escape to.
	root.Create(root.Root(), "escape", CreateSpec{Kind: Reg})

	build := func(confined bool) FileSystem {
		m := NewMemFS()
		m.Create(m.Root(), "escape", CreateSpec{Kind: Reg}) // the in-instance target
		m.Create(m.Root(), "abs", CreateSpec{Kind: Symlink, Target: "/escape"})
		m.Create(m.Root(), "rel", CreateSpec{Kind: Symlink, Target: "../../escape"})
		if confined {
			return HardenFS(m, WithConfinedLinks())
		}
		return m
	}

	confinedNS := NewNamespace(root)
	confinedNS.MountShadow("/data", build(true))
	for _, link := range []string{"/data/abs", "/data/rel"} {
		loc, err := confinedNS.Resolve(link, true)
		if err != nil {
			t.Fatalf("resolve %s (confined): %v", link, err)
		}
		if loc.Path != "/data/escape" {
			t.Fatalf("confined %s resolved to %q, want /data/escape", link, loc.Path)
		}
	}

	openNS := NewNamespace(root)
	openNS.MountShadow("/data", build(false))
	loc, err := openNS.Resolve("/data/abs", true)
	if err != nil {
		t.Fatalf("resolve /data/abs (open): %v", err)
	}
	if loc.Path != "/escape" {
		t.Fatalf("unconfined absolute symlink resolved to %q, want /escape (namespace root)", loc.Path)
	}
}
