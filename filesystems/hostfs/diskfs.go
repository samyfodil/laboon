package hostfs

import (
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/samyfodil/laboon/core"
)

// DiskFS is a writable host-directory FileSystem that is faithful to guest
// metadata a host file cannot itself hold: a non-root owner, a sub-floor mode
// (e.g. 0400 the unprivileged host owner must still be able to write), and a
// special-node kind (device, fifo, socket). Those are kept in an override map
// DiskFS owns, keyed by the layer-relative path and persisted to an on-disk
// sidecar, so Stat is authoritative and a kept directory reloads them. Entries
// are reported raw -- a ".wh." name is just a file -- so a copy-on-write overlay
// above interprets the whiteout convention. It is the writable top of an image
// composition: OverlayFS(TarFS(layers)..., NewDiskFS(upper)).
type DiskFS struct {
	root string
	mu   sync.Mutex
	over map[string]*core.Override
}

// NewDiskFS presents the host directory root as a faithful writable FileSystem,
// loading any metadata sidecar it already holds.
func NewDiskFS(root string) *DiskFS {
	os.MkdirAll(root, 0o755)
	d := &DiskFS{root: root, over: map[string]*core.Override{}}
	core.DecodeMeta(readSidecar(root), func(p string, o core.Override) {
		oc := o
		d.over[p] = &oc
	})
	return d
}

func readSidecar(root string) []byte {
	b, _ := os.ReadFile(filepath.Join(root, core.MetaFileName))
	return b
}

// Save writes the metadata sidecar so a kept upper reloads the guest owners,
// sub-floor modes and special-node kinds its host files cannot carry.
func (d *DiskFS) Save() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	b := core.EncodeMeta(d.over)
	if len(b) == 0 {
		return nil
	}
	return os.WriteFile(filepath.Join(d.root, core.MetaFileName), b, 0o600)
}

func (d *DiskFS) hp(p string) string { return filepath.Join(d.root, filepath.FromSlash(clean(p))) }

func (d *DiskFS) ov(p string) *core.Override {
	p = clean(p)
	o := d.over[p]
	if o == nil {
		o = &core.Override{}
		d.over[p] = o
	}
	return o
}

func (d *DiskFS) gc(p string) {
	p = clean(p)
	if o := d.over[p]; o != nil && !o.HasMode && !o.HasOwner && !o.Special {
		delete(d.over, p)
	}
}

type diskNode struct {
	fs   *DiskFS
	p    string
	kind core.Kind
	id   core.NodeID
}

func (d *DiskFS) node(p string) (core.Node, error) {
	p = clean(p)
	fi, err := os.Lstat(d.hp(p))
	if err != nil {
		return nil, core.NotExist("lookup", p)
	}
	id, _ := core.StatID(fi)
	k := kindOf2(fi)
	d.mu.Lock()
	if o := d.over[p]; o != nil && o.Special {
		k = o.Kind
	}
	d.mu.Unlock()
	return &diskNode{fs: d, p: p, kind: k, id: id}, nil
}

func (d *DiskFS) Root() core.Node { n, _ := d.node(""); return n }

func (d *DiskFS) Lookup(dir core.Node, name string) (core.Node, error) {
	return d.node(path.Join(dir.(*diskNode).p, name))
}

func (d *DiskFS) ReadDir(dir core.Node) ([]core.Dirent, error) {
	ents, err := os.ReadDir(d.hp(dir.(*diskNode).p))
	if err != nil {
		return nil, err
	}
	out := make([]core.Dirent, 0, len(ents))
	for _, e := range ents {
		if e.Name() == core.MetaFileName {
			continue // the sidecar is internal, not a guest entry
		}
		out = append(out, core.Dirent{Name: e.Name(), Kind: kindOfDirEntry(e)})
	}
	return out, nil
}

func (d *DiskFS) Create(dir core.Node, name string, spec core.CreateSpec) (core.Node, error) {
	p := path.Join(dir.(*diskNode).p, name)
	hp := d.hp(p)
	os.MkdirAll(filepath.Dir(hp), 0o755)
	var err error
	switch spec.Kind {
	case core.Dir:
		err = os.Mkdir(hp, os.FileMode(core.HostMode(spec.Mode, true))&0o7777)
	case core.Symlink:
		err = os.Symlink(spec.Target, hp)
	case core.Fifo, core.Chardev, core.Blockdev, core.Socket:
		// An unprivileged host cannot mknod; keep a placeholder file and record
		// the real kind and device number so Stat reports them.
		err = os.WriteFile(hp, nil, 0o600)
	default:
		var file *os.File
		if file, err = os.OpenFile(hp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(core.HostMode(spec.Mode, false))&0o777); file != nil {
			file.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	d.record(p, spec)
	return d.node(p)
}

func (d *DiskFS) WriteFile(dir core.Node, name string, spec core.CreateSpec, data []byte) (core.Node, error) {
	p := path.Join(dir.(*diskNode).p, name)
	hp := d.hp(p)
	os.MkdirAll(filepath.Dir(hp), 0o755)
	if err := os.WriteFile(hp, data, os.FileMode(core.HostMode(spec.Mode, false))&0o777); err != nil {
		return nil, err
	}
	spec.Kind = core.Reg
	d.record(p, spec)
	return d.node(p)
}

// record keeps, for the path, the guest metadata the host file cannot hold: a
// sub-floor mode, a non-root owner, a special-node kind.
func (d *DiskFS) record(p string, spec core.CreateSpec) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := clean(p)
	sub := uint32(core.HostMode(spec.Mode, spec.Kind == core.Dir))&0o7777 != spec.Mode&0o7777
	special := spec.Kind >= core.Fifo
	if !sub && spec.Uid == 0 && spec.Gid == 0 && !special {
		delete(d.over, cp)
		return
	}
	o := d.ov(p)
	o.Mode, o.HasMode = spec.Mode&0o7777, sub
	o.Uid, o.Gid, o.HasOwner = spec.Uid, spec.Gid, spec.Uid != 0 || spec.Gid != 0
	if special {
		o.Special, o.Kind, o.Rdev = true, spec.Kind, spec.Rdev
	} else {
		o.Special, o.Kind, o.Rdev = false, 0, 0
	}
}

func (d *DiskFS) Link(dir core.Node, name string, target core.Node) (core.Node, error) {
	p := path.Join(dir.(*diskNode).p, name)
	if err := os.Link(d.hp(target.(*diskNode).p), d.hp(p)); err != nil {
		return nil, err
	}
	return d.node(p)
}

func (d *DiskFS) Remove(dir core.Node, name string, isDir bool) error {
	p := path.Join(dir.(*diskNode).p, name)
	if err := os.Remove(d.hp(p)); err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.over, clean(p))
	d.mu.Unlock()
	return nil
}

func (d *DiskFS) Rename(fromDir core.Node, from string, toDir core.Node, to string) error {
	fp := path.Join(fromDir.(*diskNode).p, from)
	tp := path.Join(toDir.(*diskNode).p, to)
	if err := os.Rename(d.hp(fp), d.hp(tp)); err != nil {
		return err
	}
	d.mu.Lock()
	if o := d.over[clean(fp)]; o != nil {
		delete(d.over, clean(fp))
		d.over[clean(tp)] = o
	}
	d.mu.Unlock()
	return nil
}

func (n *diskNode) ID() core.NodeID { return n.id }
func (n *diskNode) Kind() core.Kind { return n.kind }

// HostPath is the node's real path on the host, for a consumer that must reach
// the concrete file (an AF_UNIX bind needs a real socket path).
func (n *diskNode) HostPath() string { return n.fs.hp(n.p) }

func (n *diskNode) Stat() (core.Attr, error) {
	fi, err := os.Lstat(n.fs.hp(n.p))
	if err != nil {
		return core.Attr{}, err
	}
	a := core.Attr{Kind: kindOf2(fi), Mode: uint32(fi.Mode().Perm()), Size: fi.Size(), Mtime: fi.ModTime().UnixNano()}
	if _, nlink, ok := core.FileID(fi); ok {
		a.Nlink = nlink
	}
	if a.Kind == core.Symlink {
		a.Target, _ = os.Readlink(n.fs.hp(n.p))
	}
	n.fs.mu.Lock()
	if o := n.fs.over[clean(n.p)]; o != nil {
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
	n.fs.mu.Unlock()
	return a, nil
}

func (n *diskNode) SetAttr(u core.AttrUpdate) error {
	hp := n.fs.hp(n.p)
	if u.Mode != nil {
		floored := uint32(core.HostMode(*u.Mode, n.kind == core.Dir)) & 0o7777
		if err := os.Chmod(hp, os.FileMode(floored)); err != nil {
			return err
		}
		n.fs.mu.Lock()
		if floored != *u.Mode&0o7777 {
			o := n.fs.ov(n.p)
			o.Mode, o.HasMode = *u.Mode&0o7777, true
		} else if o := n.fs.over[clean(n.p)]; o != nil {
			o.HasMode = false
			n.fs.gc(n.p)
		}
		n.fs.mu.Unlock()
	}
	if u.Uid != nil || u.Gid != nil {
		// A guest owner the unprivileged host cannot set is recorded, not chowned.
		n.fs.mu.Lock()
		o := n.fs.ov(n.p)
		if u.Uid != nil {
			o.Uid = *u.Uid
		}
		if u.Gid != nil {
			o.Gid = *u.Gid
		}
		o.HasOwner = o.Uid != 0 || o.Gid != 0
		n.fs.gc(n.p)
		n.fs.mu.Unlock()
	}
	if u.Atime != nil || u.Mtime != nil {
		at, mt, err := statTimes(hp, u)
		if err != nil {
			return err
		}
		if err := os.Chtimes(hp, at, mt); err != nil {
			return err
		}
	}
	return nil
}

func (n *diskNode) Readlink() (string, error) { return os.Readlink(n.fs.hp(n.p)) }

func (n *diskNode) Open(flags int) (core.File, error) {
	return os.OpenFile(n.fs.hp(n.p), flags, 0)
}

func statTimes(hp string, u core.AttrUpdate) (time.Time, time.Time, error) {
	var at, mt time.Time
	if u.Atime == nil || u.Mtime == nil {
		fi, err := os.Lstat(hp)
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
