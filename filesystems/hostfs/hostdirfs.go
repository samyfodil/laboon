//go:build darwin || linux || windows

package hostfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/samyfodil/laboon/core"
)

// HostDirFS presents a host directory tree as a core.FileSystem, doing its I/O
// through the sandbox's platform host access (LinuxFS/DarwinFS/WinFS). It is how
// the guest's real root enters the homogeneous vfs namespace — a filesystem
// mounted on /, uniform with the overlay, proc and the rest — while the platform
// specifics (WinFS reparse symlinks, darwin O_NOFOLLOW_ANY, the confined openat2)
// stay inside this backend, not threaded through the generic vfs layer.
type HostDirFS struct {
	root    string // host directory this filesystem is rooted at
	h       HostFS // platform host operations
	confine bool   // the guest can mutate this tree (the writable upper): reach an
	// object through an fd opened without following a symlink, defeating a
	// dir→symlink swap. A read-only lower (or the rootless host) needs no such care.
	// meta holds the device-node kind and number the host placeholder cannot
	// carry, for a standalone mount (a guest tmpfs); nil when this backend is an
	// overlay layer, whose own MetaStore records it instead.
	meta *core.MetaStore
	// making holds a lookup of a name back while a create of it runs: the host
	// object exists before its guest metadata is recorded, and until then it
	// would read as root's. One lock per path hash.
	making [64]sync.RWMutex
}

func (f *HostDirFS) makingLock(p string) *sync.RWMutex {
	h := uint32(2166136261)
	for i := 0; i < len(p); i++ {
		h = (h ^ uint32(p[i])) * 16777619
	}
	return &f.making[h%uint32(len(f.making))]
}

func NewHostDirFS(root string, h HostFS) *HostDirFS {
	return &HostDirFS{root: root, h: h, meta: core.NewMetaStore()}
}

// Dir presents the host directory root as a confined, writable FileSystem backed
// by the live sandbox host layer: symlink resolution stays inside the subtree
// (a dir→symlink swap cannot escape it), guest owner/mode/special-node metadata
// a host file cannot hold lives in a store, and an AF_UNIX connect under it
// reaches the host socket there (how an X server is shared). Mount it with
// WithMount: at "/" it is the guest root (the host tree as a read-only image
// with an ephemeral writable upper), elsewhere a writable host bind. Wrap it with
// ReadOnly for a read-only bind.
func Dir(root string) core.FileSystem {
	// Resolve the root's own symlinks: the confined backend opens every path
	// below it with no-symlink resolution, which refuses a root whose own
	// components include a symlink (/tmp on macOS, a /data->/mnt bind). A root
	// that does not exist yet is left as-is; the open fails later either way.
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	d := NewHostDirFS(root, NewRawHostFS(root))
	d.SetConfine(true)
	return d
}

// RootDir is the host directory f is rooted at, which the sandbox recovers to
// set up a host-directory guest root (its ephemeral upper and darwin exec).
func (f *HostDirFS) RootDir() string { return f.root }

// hp is the host path of the backend-relative guest path p. It goes through the
// platform HostPath so names NTFS cannot hold are escaped (winfs); on unix
// HostPath is a plain join.
func (f *HostDirFS) hp(p string) string { return HostPath(f.root, p) }

type HostNode struct {
	fs   *HostDirFS
	p    string // clean, no leading slash ("" is the root)
	kind core.Kind
	id   core.NodeID
}

// idStater is a HostFS that answers a lookup's lstat, which reads only the
// kind and the device and inode, from a cache.
type idStater interface {
	hLstatID(p string) (os.FileInfo, error)
}

func (f *HostDirFS) node(p string) (core.Node, error) {
	p = path.Clean("/" + p)[1:]
	lstat := f.h.hLstat
	if c, ok := f.h.(idStater); ok {
		lstat = c.hLstatID
	}
	fi, err := lstat(f.hp(p))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil, core.NotExist("lookup", p)
		}
		return nil, core.MaybeNotExist("lookup", p, err)
	}
	dev, ino := HostDevIno(fi)
	return &HostNode{fs: f, p: p, kind: HostKind(fi), id: core.NodeID{Dev: dev, Ino: ino}}, nil
}

func (f *HostDirFS) Root() core.Node { n, _ := f.node(""); return n }

// StatFS reports the statfs of the host filesystem backing n (its own directory,
// or its parent when n is not one, since the host call opens a directory).
func (f *HostDirFS) StatFS(n core.Node) (core.StatFS, error) {
	hn := n.(*HostNode)
	p := hn.p
	if hn.kind != core.Dir {
		if p = path.Dir(p); p == "." {
			p = ""
		}
	}
	s, err := f.h.hStatfs(f.hp(p))
	if err != nil {
		return core.StatFS{}, err
	}
	return s, nil
}

func (f *HostDirFS) Lookup(dir core.Node, name string) (core.Node, error) {
	p := path.Join(dir.(*HostNode).p, name)
	l := f.makingLock(p)
	l.RLock()
	defer l.RUnlock()
	return f.node(p)
}

func (f *HostDirFS) ReadDir(dir core.Node) ([]core.Dirent, error) {
	infos, err := f.h.hReadDir(f.hp(dir.(*HostNode).p))
	if err != nil {
		return nil, err
	}
	out := make([]core.Dirent, 0, len(infos))
	for _, fi := range infos {
		_, ino := HostDevIno(fi)
		out = append(out, core.Dirent{Name: fi.Name(), Kind: HostKind(fi), Ino: ino})
	}
	return out, nil
}

func (f *HostDirFS) Create(dir core.Node, name string, spec core.CreateSpec) (core.Node, error) {
	p := path.Join(dir.(*HostNode).p, name)
	l := f.makingLock(p)
	l.Lock()
	defer l.Unlock()
	hp := f.hp(p)
	hm := uint32(core.HostMode(spec.Mode, spec.Kind == core.Dir)) // keep the host file owner-writable
	var err error
	switch spec.Kind {
	case core.Dir:
		err = f.h.hMkdir(hp, hm)
	case core.Symlink:
		err = f.h.hSymlink(spec.Target, hp)
	case core.Fifo:
		err = f.h.hMkfifo(hp, hm)
	case core.Socket:
		err = f.h.hMksock(hp, hm)
	case core.Chardev, core.Blockdev:
		// An unprivileged host cannot mknod a device; keep a placeholder file and
		// record its kind and number so Stat reports them.
		var file *os.File
		if file, err = f.h.hOpen(hp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); file != nil {
			file.Close()
		}
	default:
		var file *os.File
		if file, err = f.h.hOpen(hp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(hm&0o777)); file != nil {
			file.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	n, err := f.node(p)
	if err == nil {
		f.record(n.ID(), spec)
	}
	return n, err
}

// record keeps, for the new node, the guest metadata a host file cannot hold: a
// non-root owner, a sub-floor mode, and a device node's kind/number.
func (f *HostDirFS) record(id core.NodeID, spec core.CreateSpec) {
	if f.meta == nil {
		return
	}
	sub := uint32(core.HostMode(spec.Mode, spec.Kind == core.Dir))&0o7777 != spec.Mode&0o7777
	dev := spec.Kind == core.Chardev || spec.Kind == core.Blockdev
	owner := spec.Uid != 0 || spec.Gid != 0
	if !sub && !dev && !owner {
		f.meta.Delete(id)
		return
	}
	f.meta.Update(id, func(o *core.Override) {
		o.Mode, o.HasMode = spec.Mode&0o7777, sub
		o.Uid, o.Gid, o.HasOwner = spec.Uid, spec.Gid, owner
		if dev {
			o.Special, o.Kind, o.Rdev = true, spec.Kind, spec.Rdev
		} else {
			o.Special, o.Kind, o.Rdev = false, 0, 0
		}
	})
}

func (f *HostDirFS) Link(dir core.Node, name string, target core.Node) (core.Node, error) {
	p := path.Join(dir.(*HostNode).p, name)
	if err := f.h.hLink(f.hp(target.(*HostNode).p), f.hp(p)); err != nil {
		return nil, err
	}
	return f.node(p)
}

func (f *HostDirFS) Remove(dir core.Node, name string, isDir bool) error {
	return f.h.hUnlink(f.hp(path.Join(dir.(*HostNode).p, name)), isDir)
}

func (f *HostDirFS) Rename(fromDir core.Node, from string, toDir core.Node, to string) error {
	return f.h.hRename(f.hp(path.Join(fromDir.(*HostNode).p, from)), f.hp(path.Join(toDir.(*HostNode).p, to)), false)
}

func (f *HostDirFS) RenameExchange(fromDir core.Node, from string, toDir core.Node, to string) error {
	return f.h.hRename(f.hp(path.Join(fromDir.(*HostNode).p, from)), f.hp(path.Join(toDir.(*HostNode).p, to)), true)
}

func (n *HostNode) ID() core.NodeID { return n.id }

func (n *HostNode) Kind() core.Kind {
	if n.fs.meta != nil {
		if o, ok := n.fs.meta.Get(n.id); ok && o.Special {
			return o.Kind
		}
	}
	return n.kind
}

func (n *HostNode) Stat() (core.Attr, error) {
	fi, err := n.fs.h.hLstat(n.fs.hp(n.p))
	if err != nil {
		return core.Attr{}, err
	}
	a := core.Attr{Kind: HostKind(fi), Mode: uint32(fi.Mode().Perm())}
	if st, ok := StatOf(fi); ok {
		a = attrFromHostStat(st)
	}
	if a.Kind == core.Symlink {
		a.Target, _ = n.fs.h.hReadlink(n.fs.hp(n.p))
	}
	applyMeta(&a, n.fs.meta, n.id)
	return a, nil
}

// attrFromHostStat maps a normalized host stat to a backend-agnostic Attr (guest
// overrides are a separate step, applyMeta). Kind comes from the S_IFMT bits so
// the fstat path, which has no lstat FileInfo, classifies the object the same
// way the lstat path does. A symlink's mode is 0777, as Linux has no other
// (Darwin keeps the umask it was made under).
func attrFromHostStat(st HostStat) core.Attr {
	mode := st.mode & 0o7777 // perm + setuid/setgid/sticky, which Perm() drops
	if kindOfMode(st.mode) == core.Symlink {
		mode = 0o777
	}
	return core.Attr{
		Kind:    kindOfMode(st.mode),
		Mode:    mode,
		Uid:     st.uid,
		Gid:     st.gid,
		Rdev:    st.rdev,
		Size:    st.size,
		Nlink:   uint64(st.nlink),
		Blocks:  st.blocks,
		Blksize: int64(st.blksize),
		Atime:   TsNano(st.atime),
		Mtime:   TsNano(st.mtime),
		Ctime:   TsNano(st.ctime),
		Btime:   TsNano(st.btime),
	}
}

func kindOfMode(m uint32) core.Kind {
	switch m & 0o170000 {
	case 0o040000:
		return core.Dir
	case 0o120000:
		return core.Symlink
	case 0o010000:
		return core.Fifo
	case 0o140000:
		return core.Socket
	case 0o020000:
		return core.Chardev
	case 0o060000:
		return core.Blockdev
	}
	return core.Reg
}

// applyMeta overlays the guest owner, sub-floor mode and special-node kind the
// host file cannot itself carry, from the backend's per-inode store keyed by id.
// When a MetaStore is present the backend is a guest's vfs layer: the host file's
// own uid/gid are the unprivileged supervisor's, never the guest's view, so the
// guest owner is the recorded override or root (0) when none — never the raw host
// owner that attrFromHostStat read. A standalone backend (no MetaStore) keeps the
// host owner and mode as they are.
func applyMeta(a *core.Attr, meta *core.MetaStore, id core.NodeID) {
	if meta == nil {
		return
	}
	a.Uid, a.Gid = 0, 0
	o, ok := meta.Get(id)
	if !ok {
		return
	}
	if o.HasMode {
		a.Mode = o.Mode
	}
	if o.HasOwner {
		a.Uid, a.Gid = o.Uid, o.Gid
	}
	if o.Special {
		a.Kind, a.Rdev = o.Kind, o.Rdev
	}
}

func (n *HostNode) SetAttr(u core.AttrUpdate) error {
	hp := n.fs.hp(n.p)
	if u.Mode != nil {
		hm := uint32(core.HostMode(*u.Mode, n.kind == core.Dir))
		if err := n.fs.h.hChmod(hp, hm); err != nil {
			return err
		}
		if n.fs.meta != nil {
			sub := hm&0o7777 != *u.Mode&0o7777
			n.fs.meta.Update(n.id, func(o *core.Override) {
				if sub {
					o.Mode, o.HasMode = *u.Mode&0o7777, true
				} else {
					o.HasMode = false
				}
			})
		}
	}
	// A non-root guest owner the host cannot hold is recorded in the leaf's own
	// store, not applied to the host file.
	if (u.Uid != nil || u.Gid != nil) && n.fs.meta != nil {
		n.fs.meta.Update(n.id, func(o *core.Override) {
			if u.Uid != nil {
				o.Uid = *u.Uid
			}
			if u.Gid != nil {
				o.Gid = *u.Gid
			}
			o.HasOwner = o.Uid != 0 || o.Gid != 0
		})
	}
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
			if st, ok := StatOf(fi); ok {
				ca, cm = TsNano(st.atime), TsNano(st.mtime)
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

func (n *HostNode) Readlink() (string, error) { return n.fs.h.hReadlink(n.fs.hp(n.p)) }

func (n *HostNode) Open(flags int) (core.File, error) {
	// Open is for existing content; a nonzero mode without O_CREATE is EINVAL.
	f, err := n.fs.h.hOpen(n.fs.hp(n.p), flags, 0)
	if err != nil {
		return nil, err
	}
	return hostFile{File: f, meta: n.fs.meta, name: n.p}, nil
}

// hostFile is a host file opened through a Node, as a core.File. The descriptor
// is kept unexported so a caller reaches it only through the File interface
// (Stat is fstat on the handle) and never by asserting the concrete type past
// the interface. What needs the host object itself (mmap, poll, the stub) takes
// the bare descriptor through HostFd — the one deliberate escape hatch. meta is
// the backend's guest-metadata authority, for Stat's overrides.
type hostFile struct {
	*os.File
	meta *core.MetaStore
	name string
}

// Stat is the open handle's attributes in Linux terms, as a core.Info: an fstat
// on the descriptor, platform-normalized, with the backend's guest overrides
// applied. Identity (dev/ino) comes from the opened object, so it stays correct
// after a rename or unlink. This is never the raw os.File.Stat an embedded
// *os.File would promote — that is not a Linux stat on darwin or windows.
func (h hostFile) Stat() (core.Info, error) {
	st, err := FstatOf(h.File)
	if err != nil {
		return nil, err
	}
	a := attrFromHostStat(st)
	id := core.NodeID{Dev: st.dev, Ino: st.ino}
	applyMeta(&a, h.meta, id)
	return core.FileInfo(h.name, a, id), nil
}

// SetAttr changes the open file's metadata on the descriptor itself — the
// fd-level twin of HostNode.SetAttr (which works by path). The mode goes on the
// host file to the owner-rw floor; bits the host cannot hold and a non-root owner
// are recorded in the shared MetaStore under the open object's identity, the same
// key Stat reads back. A standalone backend (no MetaStore) keeps only what the
// host file itself can hold.
func (h hostFile) SetAttr(u core.AttrUpdate) error {
	fi, err := h.File.Stat()
	if err != nil {
		return err
	}
	st, _ := StatOf(fi)
	id := core.NodeID{Dev: st.Dev(), Ino: st.Ino()}
	if u.Mode != nil {
		hm := uint32(core.HostMode(*u.Mode, fi.IsDir()))
		if err := FchmodOf(h.File, hm); err != nil {
			return err
		}
		if h.meta != nil {
			sub := hm&0o7777 != *u.Mode&0o7777
			h.meta.Update(id, func(o *core.Override) {
				if sub {
					o.Mode, o.HasMode = *u.Mode&0o7777, true
				} else {
					o.HasMode = false
				}
			})
		}
	}
	if (u.Uid != nil || u.Gid != nil) && h.meta != nil {
		h.meta.Update(id, func(o *core.Override) {
			if u.Uid != nil {
				o.Uid = *u.Uid
			}
			if u.Gid != nil {
				o.Gid = *u.Gid
			}
			o.HasOwner = o.Uid != 0 || o.Gid != 0
		})
	}
	if u.Atime != nil || u.Mtime != nil {
		ats, mts := st.Atime(), st.Mtime()
		if u.Atime != nil {
			ats = syscall.NsecToTimespec(*u.Atime)
		}
		if u.Mtime != nil {
			mts = syscall.NsecToTimespec(*u.Mtime)
		}
		return FutimesOf(h.File, ats, mts)
	}
	return nil
}

// Append writes p at the end of the file. On a descriptor opened (or set by
// F_SETFL) O_APPEND the host appends atomically; the seek to the end first
// serves one that is not. The kernel offset it moves is laboon's alone: guest
// reads and writes are positional.
func (h hostFile) Append(p []byte) (int, int64, error) {
	if _, err := h.File.Seek(0, io.SeekEnd); err != nil {
		return 0, 0, err
	}
	n, err := h.File.Write(p)
	end, serr := h.File.Seek(0, io.SeekCurrent)
	if err == nil {
		err = serr
	}
	return n, end, err
}

// Dup is a second handle on the same open file, for another description of it
// (a reopen through /proc/<pid>/fd of a file whose name is gone). Offsets are
// the caller's, so the two share no position.
func (h hostFile) Dup() (core.File, error) {
	f, err := dupOf(h.File)
	if err != nil {
		return nil, err
	}
	return hostFile{File: f, meta: h.meta, name: h.name}, nil
}

// HostFd is the host descriptor behind h, borrowed: h keeps owning it and closes
// it on Close. It is for what only the host object can do (map it, poll it,
// lend it to the stub); bytes and metadata go through the File interface.
func (h hostFile) HostFd() uintptr { return fdOf(h.File) }

func HostKind(fi os.FileInfo) core.Kind {
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

// SetMeta makes store the backend's guest-metadata authority (shared with the
// sandbox so one store serves both leaf and live ops). SetConfine marks the
// tree guest-mutable, so objects are reached through an fd opened without
// following a symlink.
func (f *HostDirFS) SetMeta(store *core.MetaStore) { f.meta = store }
func (f *HostDirFS) SetConfine(b bool)             { f.confine = b }

// LoadSidecar reads the metadata sidecar at the root of f's tree (the owners,
// modes and special kinds an image's host files cannot hold) into f's store,
// keyed by each file's identity as f's own nodes report it.
func (f *HostDirFS) LoadSidecar() {
	h, err := f.h.hOpen(f.hp(core.MetaFileName), os.O_RDONLY, 0)
	if err != nil {
		return
	}
	b, err := io.ReadAll(h)
	h.Close()
	if err != nil {
		return
	}
	core.DecodeMeta(b, func(p string, o core.Override) {
		if o.Special && o.Kind == core.Symlink {
			// A placeholder holding a symlink's target, where the host keeps no
			// symlinks: the host backend types it, and serves it as one.
			t, ok := f.h.(interface{ hTypeSymlink(string) error })
			if ok && t.hTypeSymlink(f.hp(p)) == nil {
				o.Special, o.Kind = false, 0
			}
		}
		n, err := f.node(p)
		if err != nil {
			return
		}
		if o.HasMode || o.HasOwner || o.Special {
			f.meta.Update(n.ID(), func(d *core.Override) { *d = o })
		}
	})
}

// Persist records in the layer's sidecar what store holds for each file of its
// tree, keyed by the file's identity, so a kept layer carries the guest owners,
// modes and fifos past the run.
func (l *Layer) Persist(store *core.MetaStore) error {
	return filepath.WalkDir(l.dir, func(hp string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(l.dir, hp)
		if err != nil || rel == "." {
			return err
		}
		if core.Internal(filepath.Base(hp)) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		gp := "/" + filepath.ToSlash(rel)
		dev, ino := pathDevIno(hp, fi)
		o, ok := store.Get(core.NodeID{Dev: dev, Ino: ino})
		if t, typed := hostTyped(hp); typed && !(ok && o.Special) {
			perm := t & 0o7777
			if ok && o.HasMode {
				perm = o.Mode
			}
			switch t & 0o170000 {
			case 0o120000:
				l.mu.Lock()
				l.markSymlinkLocked(gp)
				l.mu.Unlock()
			case 0o010000:
				l.Special(gp, core.Fifo, 0, perm)
			case 0o140000:
				l.Special(gp, core.Socket, 0, perm)
			default:
				l.SetMode(gp, perm)
			}
		} else if fi.Mode()&os.ModeNamedPipe != 0 {
			perm := uint32(fi.Mode().Perm())
			if ok && o.HasMode {
				perm = o.Mode
			}
			l.Special(gp, core.Fifo, 0, perm)
		} else if ok && o.HasMode {
			l.SetMode(gp, o.Mode)
		}
		if ok && o.HasOwner {
			l.SetOwner(gp, o.Uid, o.Gid)
		}
		return nil
	})
}
