package namespace

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"

	. "github.com/samyfodil/laboon/core"
)

// testDirFS is a host-directory FileSystem for the vfs package's own tests only.
// The production host-directory backend lives in the hostfs subpackage (which
// imports vfs, so a package-internal test cannot), and keeping a copy here lets
// these tests exercise the overlay and resolver over a real host tree without the
// production vfs package depending on the host OS.
type testDirFS struct{ root string }

func newTestDirFS(root string) FileSystem {
	os.MkdirAll(root, 0o755)
	return &testDirFS{root: root}
}

func (f *testDirFS) hp(p string) string { return filepath.Join(f.root, filepath.FromSlash(p)) }

type testDirNode struct {
	fs   *testDirFS
	p    string
	kind Kind
	id   NodeID
}

func testKind(fi os.FileInfo) Kind {
	switch m := fi.Mode(); {
	case m.IsDir():
		return Dir
	case m&os.ModeSymlink != 0:
		return Symlink
	case m&os.ModeNamedPipe != 0:
		return Fifo
	case m&os.ModeSocket != 0:
		return Socket
	case m&os.ModeCharDevice != 0:
		return Chardev
	case m&os.ModeDevice != 0:
		return Blockdev
	}
	return Reg
}

func (f *testDirFS) node(p string) (Node, error) {
	p = clean(p)
	fi, err := os.Lstat(f.hp(p))
	if err != nil {
		return nil, &fs.PathError{Op: "lookup", Path: p, Err: fs.ErrNotExist}
	}
	id, _ := StatID(fi)
	return &testDirNode{fs: f, p: p, kind: testKind(fi), id: id}, nil
}

func (f *testDirFS) Root() Node { n, _ := f.node(""); return n }
func (f *testDirFS) Lookup(dir Node, name string) (Node, error) {
	return f.node(path.Join(dir.(*testDirNode).p, name))
}
func (f *testDirFS) ReadDir(dir Node) ([]Dirent, error) {
	ents, err := os.ReadDir(f.hp(dir.(*testDirNode).p))
	if err != nil {
		return nil, err
	}
	out := make([]Dirent, 0, len(ents))
	for _, e := range ents {
		fi, _ := e.Info()
		out = append(out, Dirent{Name: e.Name(), Kind: testKind(fi)})
	}
	return out, nil
}
func (f *testDirFS) Create(dir Node, name string, spec CreateSpec) (Node, error) {
	p := path.Join(dir.(*testDirNode).p, name)
	hp := f.hp(p)
	os.MkdirAll(filepath.Dir(hp), 0o755)
	var err error
	switch spec.Kind {
	case Dir:
		err = os.Mkdir(hp, os.FileMode(spec.Mode&0o777)|0o700)
	case Symlink:
		err = os.Symlink(spec.Target, hp)
	default:
		var file *os.File
		if file, err = os.OpenFile(hp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(spec.Mode&0o777)|0o600); file != nil {
			file.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	return f.node(p)
}
func (f *testDirFS) WriteFile(dir Node, name string, spec CreateSpec, data []byte) (Node, error) {
	p := path.Join(dir.(*testDirNode).p, name)
	hp := f.hp(p)
	os.MkdirAll(filepath.Dir(hp), 0o755)
	if err := os.WriteFile(hp, data, os.FileMode(spec.Mode&0o777)|0o600); err != nil {
		return nil, err
	}
	return f.node(p)
}
func (f *testDirFS) Link(dir Node, name string, target Node) (Node, error) {
	p := path.Join(dir.(*testDirNode).p, name)
	if err := os.Link(f.hp(target.(*testDirNode).p), f.hp(p)); err != nil {
		return nil, err
	}
	return f.node(p)
}
func (f *testDirFS) Remove(dir Node, name string, isDir bool) error {
	return os.Remove(f.hp(path.Join(dir.(*testDirNode).p, name)))
}
func (f *testDirFS) Rename(fromDir Node, from string, toDir Node, to string) error {
	return os.Rename(f.hp(path.Join(fromDir.(*testDirNode).p, from)), f.hp(path.Join(toDir.(*testDirNode).p, to)))
}

func (n *testDirNode) ID() NodeID { return n.id }
func (n *testDirNode) Kind() Kind { return n.kind }
func (n *testDirNode) Stat() (Attr, error) {
	fi, err := os.Lstat(n.fs.hp(n.p))
	if err != nil {
		return Attr{}, err
	}
	a := Attr{Kind: testKind(fi), Mode: uint32(fi.Mode().Perm()), Size: fi.Size(), Mtime: fi.ModTime().UnixNano()}
	if _, nlink, ok := FileID(fi); ok {
		a.Nlink = nlink
	}
	if a.Kind == Symlink {
		a.Target, _ = os.Readlink(n.fs.hp(n.p))
	}
	return a, nil
}
func (n *testDirNode) SetAttr(u AttrUpdate) error {
	hp := n.fs.hp(n.p)
	if u.Mode != nil {
		if err := os.Chmod(hp, os.FileMode(*u.Mode&0o777)); err != nil {
			return err
		}
	}
	if u.Atime != nil || u.Mtime != nil {
		at, mt := time.Now(), time.Now()
		if u.Atime != nil {
			at = time.Unix(0, *u.Atime)
		}
		if u.Mtime != nil {
			mt = time.Unix(0, *u.Mtime)
		}
		if err := os.Chtimes(hp, at, mt); err != nil {
			return err
		}
	}
	return nil
}
func (n *testDirNode) Readlink() (string, error) { return os.Readlink(n.fs.hp(n.p)) }
func (n *testDirNode) Open(flags int) (File, error) {
	of, err := os.OpenFile(n.fs.hp(n.p), flags, 0)
	if err != nil {
		return nil, err
	}
	return &testDirFile{File: of, n: n}, nil
}

// testDirFile answers fstat through the node, so the open handle reports the
// backend-agnostic Info a guest stat is built from (core.File.Stat), not the raw
// os.FileInfo an *os.File would.
type testDirFile struct {
	*os.File
	n *testDirNode
}

func (f *testDirFile) Stat() (Info, error) {
	a, err := f.n.Stat()
	if err != nil {
		return nil, err
	}
	return FileInfo(path.Base(f.n.p), a, f.n.id), nil
}

func (f *testDirFile) SetAttr(u AttrUpdate) error { return f.n.SetAttr(u) }
