// Package hostfs holds core.FileSystem backends and layers that are implemented
// over the host OS (a host directory tree, the copy-up layer's on-disk sidecar
// and whiteouts). It is kept out of the core vfs package so that package has no
// direct host-OS interaction: vfs defines the abstraction (the resolver, the
// overlay, the interfaces, the in-memory backend), and the host is reached only
// through a backend that lives here.
package hostfs

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/samyfodil/laboon/core"
)

// clean is the backend-local path cleaner (vfs has its own); a guest path is
// cleaned to a root-relative form with no leading or trailing slash.
func clean(p string) string { return strings.Trim(path.Clean("/"+p), "/") }

// dirFS is a plain host-directory FileSystem over os: a directory tree with no
// overlay semantics of its own. It reports entries raw (a ".wh." name is just a
// file here), so the union overlayFS layered above it is the one that interprets
// whiteouts. It is the generic backend for the build and tests; the live sandbox
// uses its platform equivalent (hostDirFS). The homogeneity is the FileSystem
// interface they share.
type dirFS struct{ root string }

// NewDirFS presents the host directory root as a plain FileSystem.
func NewDirFS(root string) core.FileSystem {
	os.MkdirAll(root, 0o755)
	return &dirFS{root: root}
}

func (f *dirFS) hp(p string) string { return filepath.Join(f.root, filepath.FromSlash(p)) }

type dirNode struct {
	fs   *dirFS
	p    string
	kind core.Kind
	id   core.NodeID
}

func (f *dirFS) node(p string) (core.Node, error) {
	p = clean(p)
	fi, err := os.Lstat(f.hp(p))
	if err != nil {
		return nil, &fs.PathError{Op: "lookup", Path: p, Err: fs.ErrNotExist}
	}
	id, _ := core.StatID(fi)
	return &dirNode{fs: f, p: p, kind: kindOf2(fi), id: id}, nil
}

func (f *dirFS) Root() core.Node { n, _ := f.node(""); return n }

func (f *dirFS) Lookup(dir core.Node, name string) (core.Node, error) {
	return f.node(path.Join(dir.(*dirNode).p, name))
}

func (f *dirFS) ReadDir(dir core.Node) ([]core.Dirent, error) {
	ents, err := os.ReadDir(f.hp(dir.(*dirNode).p))
	if err != nil {
		return nil, err
	}
	out := make([]core.Dirent, 0, len(ents))
	for _, e := range ents {
		out = append(out, core.Dirent{Name: e.Name(), Kind: kindOfDirEntry(e)})
	}
	return out, nil
}

func (f *dirFS) Create(dir core.Node, name string, spec core.CreateSpec) (core.Node, error) {
	p := path.Join(dir.(*dirNode).p, name)
	hp := f.hp(p)
	os.MkdirAll(filepath.Dir(hp), 0o755)
	var err error
	switch spec.Kind {
	case core.Dir:
		err = os.Mkdir(hp, os.FileMode(spec.Mode&0o777)|0o700)
	case core.Symlink:
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

func (f *dirFS) WriteFile(dir core.Node, name string, spec core.CreateSpec, data []byte) (core.Node, error) {
	p := path.Join(dir.(*dirNode).p, name)
	hp := f.hp(p)
	os.MkdirAll(filepath.Dir(hp), 0o755)
	if err := os.WriteFile(hp, data, os.FileMode(spec.Mode&0o777)|0o600); err != nil {
		return nil, err
	}
	return f.node(p)
}

func (f *dirFS) Link(dir core.Node, name string, target core.Node) (core.Node, error) {
	p := path.Join(dir.(*dirNode).p, name)
	if err := os.Link(f.hp(target.(*dirNode).p), f.hp(p)); err != nil {
		return nil, err
	}
	return f.node(p)
}

func (f *dirFS) Remove(dir core.Node, name string, isDir bool) error {
	return os.Remove(f.hp(path.Join(dir.(*dirNode).p, name)))
}

func (f *dirFS) Rename(fromDir core.Node, from string, toDir core.Node, to string) error {
	return os.Rename(f.hp(path.Join(fromDir.(*dirNode).p, from)), f.hp(path.Join(toDir.(*dirNode).p, to)))
}

func (n *dirNode) ID() core.NodeID { return n.id }
func (n *dirNode) Kind() core.Kind { return n.kind }

func (n *dirNode) Stat() (core.Attr, error) {
	fi, err := os.Lstat(n.fs.hp(n.p))
	if err != nil {
		return core.Attr{}, err
	}
	a := core.Attr{Kind: kindOf2(fi), Mode: uint32(fi.Mode().Perm()), Size: fi.Size(), Mtime: fi.ModTime().UnixNano()}
	if _, nlink, ok := core.FileID(fi); ok {
		a.Nlink = nlink
	}
	if a.Nlink == 0 { // a host that carries no link count (NTFS via os.Lstat): a live file has at least one
		a.Nlink = 1
	}
	if a.Kind == core.Symlink {
		a.Target, _ = os.Readlink(n.fs.hp(n.p))
	}
	return a, nil
}

func (n *dirNode) SetAttr(u core.AttrUpdate) error {
	hp := n.fs.hp(n.p)
	if u.Mode != nil {
		if err := os.Chmod(hp, os.FileMode(*u.Mode&0o777)); err != nil {
			return err
		}
	}
	if u.Uid != nil || u.Gid != nil {
		uid, gid := -1, -1
		if u.Uid != nil {
			uid = int(*u.Uid)
		}
		if u.Gid != nil {
			gid = int(*u.Gid)
		}
		if err := os.Lchown(hp, uid, gid); err != nil {
			return err
		}
	}
	if u.Atime != nil || u.Mtime != nil {
		at, mt, err := n.times(u)
		if err != nil {
			return err
		}
		if err := os.Chtimes(hp, at, mt); err != nil {
			return err
		}
	}
	return nil
}

// times resolves the (atime, mtime) to set, filling an unspecified one from the
// node's current times.
func (n *dirNode) times(u core.AttrUpdate) (time.Time, time.Time, error) {
	var at, mt time.Time
	if u.Atime == nil || u.Mtime == nil {
		fi, err := os.Lstat(n.fs.hp(n.p))
		if err != nil {
			return at, mt, err
		}
		at, mt = fi.ModTime(), fi.ModTime()
	}
	if u.Atime != nil {
		at = time.Unix(0, *u.Atime)
	}
	if u.Mtime != nil {
		mt = time.Unix(0, *u.Mtime)
	}
	return at, mt, nil
}

func (n *dirNode) Readlink() (string, error) { return os.Readlink(n.fs.hp(n.p)) }

func (n *dirNode) Open(flags int) (core.File, error) {
	f, err := os.OpenFile(n.fs.hp(n.p), flags, 0)
	if err != nil {
		return nil, err
	}
	return hostFile{File: f}, nil
}

func kindOf2(fi os.FileInfo) core.Kind {
	switch m := fi.Mode(); {
	case m.IsDir():
		return core.Dir
	case m&os.ModeSymlink != 0:
		return core.Symlink
	case m&os.ModeNamedPipe != 0:
		return core.Fifo
	case m&os.ModeSocket != 0:
		return core.Socket
	case m&os.ModeCharDevice != 0:
		return core.Chardev
	case m&os.ModeDevice != 0:
		return core.Blockdev
	}
	return core.Reg
}

func kindOfDirEntry(e os.DirEntry) core.Kind {
	if fi, err := e.Info(); err == nil {
		return kindOf2(fi)
	}
	return core.Reg
}
