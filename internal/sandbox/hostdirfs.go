//go:build darwin || linux || windows

package sandbox

import (
	"io/fs"
	"os"
	"path"
	"syscall"

	"github.com/samyfodil/laboon/core"
)

// hostDirFS presents a host directory tree as a core.FileSystem, doing its I/O
// through the sandbox's platform host access (linuxFS/darwinFS/winFS). It is how
// the guest's real root enters the homogeneous vfs namespace — a filesystem
// mounted on /, uniform with the overlay, proc and the rest — while the platform
// specifics (winFS reparse symlinks, darwin O_NOFOLLOW_ANY, the confined openat2)
// stay inside this backend, not threaded through the generic vfs layer.
type hostDirFS struct {
	root    string // host directory this filesystem is rooted at
	h       hostFS // platform host operations
	confine bool   // the guest can mutate this tree (the writable upper): reach an
	// object through an fd opened without following a symlink, defeating a
	// dir→symlink swap. A read-only lower (or the rootless host) needs no such care.
	// meta holds the device-node kind and number the host placeholder cannot
	// carry, for a standalone mount (a guest tmpfs); nil when this backend is an
	// overlay layer, whose own MetaStore records it instead.
	meta *core.MetaStore
}

func newHostDirFS(root string, h hostFS) *hostDirFS { return &hostDirFS{root: root, h: h} }

// hp is the host path of the backend-relative guest path p. It goes through the
// platform hostPath so names NTFS cannot hold are escaped (winfs); on unix
// hostPath is a plain join.
func (f *hostDirFS) hp(p string) string { return hostPath(f.root, p) }

type hostNode struct {
	fs   *hostDirFS
	p    string // clean, no leading slash ("" is the root)
	kind core.Kind
	id   core.NodeID
}

// idStater is a hostFS that answers a lookup's lstat, which reads only the
// kind and the device and inode, from a cache.
type idStater interface {
	hLstatID(p string) (os.FileInfo, error)
}

func (f *hostDirFS) node(p string) (core.Node, error) {
	p = path.Clean("/" + p)[1:]
	lstat := f.h.hLstat
	if c, ok := f.h.(idStater); ok {
		lstat = c.hLstatID
	}
	fi, err := lstat(f.hp(p))
	if err != nil {
		return nil, &fs.PathError{Op: "lookup", Path: p, Err: fs.ErrNotExist}
	}
	dev, ino := hostDevIno(fi)
	return &hostNode{fs: f, p: p, kind: hostKind(fi), id: core.NodeID{Dev: dev, Ino: ino}}, nil
}

func (f *hostDirFS) Root() core.Node { n, _ := f.node(""); return n }

// StatFS reports the statfs of the host filesystem backing n (its own directory,
// or its parent when n is not one, since the host call opens a directory).
func (f *hostDirFS) StatFS(n core.Node) (core.StatFS, error) {
	hn := n.(*hostNode)
	p := hn.p
	if hn.kind != core.Dir {
		p = path.Dir(p)
	}
	s, err := f.h.hStatfs(f.hp(p))
	if err != nil {
		return core.StatFS{}, err
	}
	return core.StatFS{Bsize: s.bsize, Blocks: s.blocks, Bfree: s.bfree, Bavail: s.bavail, Files: s.files, Ffree: s.ffree, Fsid: s.fsid, Type: s.ftype}, nil
}

func (f *hostDirFS) Lookup(dir core.Node, name string) (core.Node, error) {
	return f.node(path.Join(dir.(*hostNode).p, name))
}

func (f *hostDirFS) ReadDir(dir core.Node) ([]core.Dirent, error) {
	infos, err := f.h.hReadDir(f.hp(dir.(*hostNode).p))
	if err != nil {
		return nil, err
	}
	out := make([]core.Dirent, 0, len(infos))
	for _, fi := range infos {
		_, ino := hostDevIno(fi)
		out = append(out, core.Dirent{Name: fi.Name(), Kind: hostKind(fi), Ino: ino})
	}
	return out, nil
}

func (f *hostDirFS) Create(dir core.Node, name string, spec core.CreateSpec) (core.Node, error) {
	p := path.Join(dir.(*hostNode).p, name)
	hp := f.hp(p)
	var err error
	switch spec.Kind {
	case core.Dir:
		err = f.h.hMkdir(hp, spec.Mode)
	case core.Symlink:
		err = f.h.hSymlink(spec.Target, hp)
	case core.Fifo:
		err = f.h.hMkfifo(hp, spec.Mode)
	case core.Socket:
		err = f.h.hMksock(hp, spec.Mode)
	default:
		var file *os.File
		if file, err = f.h.hOpen(hp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(spec.Mode&0o777)); file != nil {
			file.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	n, err := f.node(p)
	if err == nil && f.meta != nil && (spec.Kind == core.Chardev || spec.Kind == core.Blockdev) {
		// A device is a placeholder file on the host; record its kind and number
		// so Stat reports them (a container runtime matches /dev/null's rdev).
		f.meta.Update(n.ID(), func(o *core.Override) {
			o.Special, o.Kind, o.Rdev = true, spec.Kind, spec.Rdev
		})
	}
	return n, err
}

func (f *hostDirFS) Link(dir core.Node, name string, target core.Node) (core.Node, error) {
	p := path.Join(dir.(*hostNode).p, name)
	if err := f.h.hLink(f.hp(target.(*hostNode).p), f.hp(p)); err != nil {
		return nil, err
	}
	return f.node(p)
}

func (f *hostDirFS) Remove(dir core.Node, name string, isDir bool) error {
	return f.h.hUnlink(f.hp(path.Join(dir.(*hostNode).p, name)), isDir)
}

func (f *hostDirFS) Rename(fromDir core.Node, from string, toDir core.Node, to string) error {
	return f.h.hRename(f.hp(path.Join(fromDir.(*hostNode).p, from)), f.hp(path.Join(toDir.(*hostNode).p, to)), false)
}

func (f *hostDirFS) RenameExchange(fromDir core.Node, from string, toDir core.Node, to string) error {
	return f.h.hRename(f.hp(path.Join(fromDir.(*hostNode).p, from)), f.hp(path.Join(toDir.(*hostNode).p, to)), true)
}

func (n *hostNode) ID() core.NodeID { return n.id }
func (n *hostNode) Kind() core.Kind {
	if n.fs.meta != nil {
		if o, ok := n.fs.meta.Get(n.id); ok && o.Special {
			return o.Kind
		}
	}
	return n.kind
}

func (n *hostNode) Stat() (core.Attr, error) {
	fi, err := n.fs.h.hLstat(n.fs.hp(n.p))
	if err != nil {
		return core.Attr{}, err
	}
	a := core.Attr{Kind: hostKind(fi), Mode: uint32(fi.Mode().Perm())}
	if st, ok := statOf(fi); ok {
		a.Mode = st.mode & 0o7777 // perm + setuid/setgid/sticky, which Perm() drops
		a.Uid, a.Gid, a.Rdev = st.uid, st.gid, st.rdev
		a.Size, a.Nlink, a.Blocks, a.Blksize = st.size, uint64(st.nlink), st.blocks, int64(st.blksize)
		a.Atime, a.Mtime, a.Ctime, a.Btime = tsNano(st.atime), tsNano(st.mtime), tsNano(st.ctime), tsNano(st.btime)
	}
	if a.Kind == core.Symlink {
		a.Target, _ = n.fs.h.hReadlink(n.fs.hp(n.p))
	}
	if n.fs.meta != nil {
		if o, ok := n.fs.meta.Get(n.id); ok && o.Special {
			a.Kind, a.Rdev = o.Kind, o.Rdev
		}
	}
	return a, nil
}

func (n *hostNode) SetAttr(u core.AttrUpdate) error {
	hp := n.fs.hp(n.p)
	if u.Mode != nil {
		if err := n.fs.h.hChmod(hp, *u.Mode); err != nil {
			return err
		}
	}
	// A non-root guest owner the host cannot hold is the overlay's MetaStore to
	// keep, so u.Uid/u.Gid are not applied to the host file here.
	if u.Atime != nil || u.Mtime != nil {
		at, mt := u.Atime, u.Mtime
		if at == nil || mt == nil {
			// Keep the unspecified time at its current value — the real atime for
			// atime (ModTime is only mtime, so it cannot fill an omitted atime).
			fi, err := n.fs.h.hLstat(hp)
			if err != nil {
				return err
			}
			ca, cm := fi.ModTime().UnixNano(), fi.ModTime().UnixNano()
			if st, ok := statOf(fi); ok {
				ca, cm = tsNano(st.atime), tsNano(st.mtime)
			}
			if at == nil {
				at = &ca
			}
			if mt == nil {
				mt = &cm
			}
		}
		return n.fs.h.hUtimes(hp, syscall.NsecToTimespec(*at), syscall.NsecToTimespec(*mt))
	}
	return nil
}

func (n *hostNode) Readlink() (string, error) { return n.fs.h.hReadlink(n.fs.hp(n.p)) }

func (n *hostNode) Open(flags int) (core.File, error) {
	// Open is for existing content; a nonzero mode without O_CREATE is EINVAL.
	return n.fs.h.hOpen(n.fs.hp(n.p), flags, 0)
}

func hostKind(fi os.FileInfo) core.Kind {
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
