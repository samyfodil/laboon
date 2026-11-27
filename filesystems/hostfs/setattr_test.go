package hostfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/core"
)

// TestFileSetAttrOwnObject: a change through an open file is recorded for that
// file alone, and setting one of its times leaves the other as it was.
func TestFileSetAttrOwnObject(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := Dir(dir)
	open := func(name string) core.File {
		n, err := fs.Lookup(fs.Root(), name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := n.Open(os.O_RDWR)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	attr := func(f core.File) core.Attr {
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		return fi.Attr()
	}
	a, b := open("a"), open("b")
	before := attr(b)
	uid := uint32(4242)
	if err := a.SetAttr(core.AttrUpdate{Uid: &uid}); err != nil {
		t.Fatal(err)
	}
	if got := attr(a).Uid; got != uid {
		t.Errorf("a's uid = %d, want %d", got, uid)
	}
	if got := attr(b).Uid; got != before.Uid {
		t.Errorf("b's uid = %d after a chown of a, was %d", got, before.Uid)
	}
	mtime := before.Mtime - 3600e9
	if err := b.SetAttr(core.AttrUpdate{Mtime: &mtime}); err != nil {
		t.Fatal(err)
	}
	after := attr(b)
	if after.Mtime != mtime {
		t.Errorf("mtime = %d, want %d", after.Mtime, mtime)
	}
	if after.Atime != before.Atime {
		t.Errorf("atime = %d after setting only mtime, was %d", after.Atime, before.Atime)
	}
}
