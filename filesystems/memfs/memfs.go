package memfs

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	. "github.com/samyfodil/laboon/core"
)

// memFS is an in-memory FileSystem: directories, regular files, symlinks,
// hardlinks and special nodes live in Go memory, and file content is served
// through the File interface rather than a host path, so it composes with the
// host and overlay backends uniformly. It is volatile — nothing persists past
// the process — which makes it both the backing for a guest tmpfs and the
// in-memory backend an embedder mounts directly (WithMount). It is safe for
// concurrent use: one RWMutex guards the whole tree and every node's content,
// which is ample for the small, memcpy-cheap trees it holds.
type memFS struct {
	dev  uint64
	mu   sync.RWMutex
	ino  uint64 // last inode assigned, under mu (or at construction)
	root *memNode
}

// memDevSeq hands each memFS a distinct device id, so a node's (dev, ino) is
// unique across instances as well as within one.
var memDevSeq uint64

// NewMemFS makes an empty in-memory FileSystem whose root is a directory
// (mode 0755). Mount it with WithMount, or wrap it with ReadOnly or HardenFS.
func NewMemFS() FileSystem {
	f := &memFS{dev: atomic.AddUint64(&memDevSeq, 1)}
	f.root = f.newNode(Dir, 0o755)
	return f
}

type memNode struct {
	fs   *memFS
	ino  uint64
	kind Kind
	mode uint32 // permission bits, 07777
	uid  uint32
	gid  uint32
	rdev uint64 // device number for Chardev/Blockdev
	tgt  string // symlink target

	atime, mtime, ctime int64 // unix nanoseconds

	kids  map[string]*memNode // directory entries
	data  []byte              // regular-file content
	nlink uint32              // names pointing here (for non-directories)
}

func memNow() int64 { return time.Now().UnixNano() }

// newNode allocates a node; the caller holds f.mu (or is constructing f).
func (f *memFS) newNode(k Kind, mode uint32) *memNode {
	f.ino++
	t := memNow()
	n := &memNode{fs: f, ino: f.ino, kind: k, mode: mode & 0o7777, nlink: 1, atime: t, mtime: t, ctime: t}
	if k == Dir {
		n.kids = map[string]*memNode{}
	}
	return n
}

func (f *memFS) Root() Node { return f.root }

func (f *memFS) Lookup(dir Node, name string) (Node, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d := dir.(*memNode)
	if d.kind != Dir {
		return nil, ErrNotDir
	}
	c, ok := d.kids[name]
	if !ok {
		return nil, NotExist("lookup", name)
	}
	return c, nil
}

func (f *memFS) ReadDir(dir Node) ([]Dirent, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d := dir.(*memNode)
	if d.kind != Dir {
		return nil, ErrNotDir
	}
	out := make([]Dirent, 0, len(d.kids))
	for name, c := range d.kids {
		out = append(out, Dirent{Name: name, Kind: c.kind, Ino: c.ino})
	}
	return out, nil
}

func (f *memFS) Create(dir Node, name string, spec CreateSpec) (Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := dir.(*memNode)
	if d.kind != Dir {
		return nil, ErrNotDir
	}
	if _, ok := d.kids[name]; ok {
		return nil, syscall.EEXIST
	}
	n := f.newNode(spec.Kind, spec.Mode)
	n.uid, n.gid = spec.Uid, spec.Gid
	switch spec.Kind {
	case Symlink:
		n.tgt = spec.Target
	case Chardev, Blockdev, Fifo, Socket:
		n.rdev = spec.Rdev
	}
	d.kids[name] = n
	d.touch()
	return n, nil
}

// WriteFile creates (or overwrites) a regular file with data in one step, for an
// importer that has the bytes in hand (WriteFileSystem).
func (f *memFS) WriteFile(dir Node, name string, spec CreateSpec, data []byte) (Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := dir.(*memNode)
	if d.kind != Dir {
		return nil, ErrNotDir
	}
	n, ok := d.kids[name]
	if !ok {
		n = f.newNode(Reg, spec.Mode)
		n.uid, n.gid = spec.Uid, spec.Gid
		d.kids[name] = n
		d.touch()
	} else if n.kind != Reg {
		return nil, syscall.EEXIST
	}
	n.data = append(n.data[:0], data...)
	n.mtime, n.ctime = memNow(), memNow()
	return n, nil
}

func (f *memFS) Link(dir Node, name string, target Node) (Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := dir.(*memNode)
	t, ok := target.(*memNode)
	if !ok || t.fs != f {
		return nil, ErrCrossDevice
	}
	if d.kind != Dir {
		return nil, ErrNotDir
	}
	if t.kind == Dir {
		return nil, syscall.EPERM // hardlink to a directory, as Linux refuses
	}
	if _, ok := d.kids[name]; ok {
		return nil, syscall.EEXIST
	}
	t.nlink++
	t.ctime = memNow()
	d.kids[name] = t
	d.touch()
	return t, nil
}

func (f *memFS) Remove(dir Node, name string, isDir bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := dir.(*memNode)
	if d.kind != Dir {
		return ErrNotDir
	}
	c, ok := d.kids[name]
	if !ok {
		return NotExist("remove", name)
	}
	if isDir {
		if c.kind != Dir {
			return ErrNotDir
		}
		if len(c.kids) > 0 {
			return syscall.ENOTEMPTY
		}
	} else if c.kind == Dir {
		return syscall.EISDIR
	}
	delete(d.kids, name)
	if c.kind != Dir && c.nlink > 0 {
		c.nlink--
		c.ctime = memNow()
	}
	d.touch()
	return nil
}

func (f *memFS) Rename(fromDir Node, from string, toDir Node, to string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fd, td := fromDir.(*memNode), toDir.(*memNode)
	if td.fs != f {
		return ErrCrossDevice
	}
	if fd.kind != Dir || td.kind != Dir {
		return ErrNotDir
	}
	src, ok := fd.kids[from]
	if !ok {
		return NotExist("rename", from)
	}
	// A directory cannot be moved into its own subtree, which would detach it.
	if src.kind == Dir && (src == td || descends(src, td)) {
		return syscall.EINVAL
	}
	if dst, ok := td.kids[to]; ok {
		if dst == src {
			return nil // same object under both names: a no-op
		}
		switch {
		case dst.kind == Dir && src.kind != Dir:
			return syscall.EISDIR
		case dst.kind != Dir && src.kind == Dir:
			return ErrNotDir
		case dst.kind == Dir && len(dst.kids) > 0:
			return syscall.ENOTEMPTY
		}
		if dst.kind != Dir && dst.nlink > 0 {
			dst.nlink--
		}
	}
	delete(fd.kids, from)
	td.kids[to] = src
	fd.touch()
	td.touch()
	return nil
}

// StatFS reports a tmpfs-shaped statfs: the magic a guest expects for tmpfs and
// generous synthetic space (the memory ceiling is the host's, not a fixed quota).
func (f *memFS) StatFS(Node) (StatFS, error) {
	const tmpfsMagic = 0x01021994
	return StatFS{
		Bsize:  4096,
		Blocks: 1 << 21, Bfree: 1 << 21, Bavail: 1 << 21, // ~8 GiB nominal
		Files: 1 << 20, Ffree: 1 << 20,
		Type: tmpfsMagic,
	}, nil
}

// descends reports whether n is reachable below the directory anc.
func descends(anc, n *memNode) bool {
	for _, c := range anc.kids {
		if c == n || (c.kind == Dir && descends(c, n)) {
			return true
		}
	}
	return false
}

// touch updates a directory's modification time after a change to its entries.
// The caller holds fs.mu.
func (n *memNode) touch() { t := memNow(); n.mtime, n.ctime = t, t }

func (n *memNode) ID() NodeID { return NodeID{Dev: n.fs.dev, Ino: n.ino} }
func (n *memNode) Kind() Kind { return n.kind }

func (n *memNode) Stat() (Attr, error) {
	n.fs.mu.RLock()
	defer n.fs.mu.RUnlock()
	a := Attr{
		Kind: n.kind, Mode: n.mode, Uid: n.uid, Gid: n.gid, Rdev: n.rdev,
		Target: n.tgt, Blksize: 4096,
		Atime: n.atime, Mtime: n.mtime, Ctime: n.ctime,
	}
	switch n.kind {
	case Reg:
		a.Size = int64(len(n.data))
		a.Blocks = (a.Size + 511) / 512
		a.Nlink = uint64(n.nlink)
	case Dir:
		sub := uint64(0)
		for _, c := range n.kids {
			if c.kind == Dir {
				sub++
			}
		}
		a.Nlink = 2 + sub // ".", "..", and each subdirectory's ".."
	default:
		a.Nlink = uint64(n.nlink)
	}
	return a, nil
}

func (n *memNode) SetAttr(u AttrUpdate) error {
	n.fs.mu.Lock()
	defer n.fs.mu.Unlock()
	if u.Mode != nil {
		n.mode = *u.Mode & 0o7777
	}
	if u.Uid != nil {
		n.uid = *u.Uid
	}
	if u.Gid != nil {
		n.gid = *u.Gid
	}
	if u.Atime != nil {
		n.atime = *u.Atime
	}
	if u.Mtime != nil {
		n.mtime = *u.Mtime
	}
	n.ctime = memNow()
	return nil
}

func (n *memNode) Readlink() (string, error) {
	if n.kind != Symlink {
		return "", syscall.EINVAL
	}
	return n.tgt, nil
}

func (n *memNode) Open(flags int) (File, error) {
	n.fs.mu.Lock()
	defer n.fs.mu.Unlock()
	if n.kind == Dir {
		return nil, ErrNoHostFile // a directory is read through ReadDir, not a File
	}
	if n.kind != Reg {
		return nil, syscall.EINVAL // a special node has no byte content to open here
	}
	if flags&os.O_TRUNC != 0 && flags&(os.O_WRONLY|os.O_RDWR) != 0 {
		n.data = n.data[:0]
		n.mtime, n.ctime = memNow(), memNow()
	}
	return &memFile{n: n}, nil
}

// memFile is an open handle to a memNode's content. Offsets are the caller's, as
// the File contract requires; the node's data slice is the shared backing store,
// guarded by the filesystem mutex.
type memFile struct{ n *memNode }

func (h *memFile) Stat() (Info, error) {
	a, err := h.n.Stat()
	if err != nil {
		return nil, err
	}
	return FileInfo("", a, h.n.ID()), nil
}

func (h *memFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, syscall.EINVAL
	}
	n := h.n
	n.fs.mu.RLock()
	defer n.fs.mu.RUnlock()
	if off >= int64(len(n.data)) {
		return 0, io.EOF
	}
	c := copy(p, n.data[off:])
	if c < len(p) {
		return c, io.EOF
	}
	return c, nil
}

func (h *memFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, syscall.EINVAL
	}
	n := h.n
	n.fs.mu.Lock()
	defer n.fs.mu.Unlock()
	end := off + int64(len(p))
	if end > int64(len(n.data)) {
		n.data = grow(n.data, int(end))
	}
	copy(n.data[off:end], p)
	n.mtime, n.ctime = memNow(), memNow()
	return len(p), nil
}

// grow returns b extended to length n with the new bytes zeroed, enlarging
// capacity geometrically so repeated extends are amortized O(1) rather than a
// full reallocation each time (a file written in sequential chunks would
// otherwise be O(n^2)). The gap a sparse write leaves past the old end reads as
// zero, as on a real filesystem.
func grow(b []byte, n int) []byte {
	if n <= cap(b) {
		old := len(b)
		b = b[:n]
		clear(b[old:])
		return b
	}
	c := cap(b) * 2
	if c < n {
		c = n
	}
	nb := make([]byte, n, c)
	copy(nb, b)
	return nb
}

// Append writes p at the end of the file, atomically with every other write.
func (h *memFile) Append(p []byte) (int, int64, error) {
	n := h.n
	n.fs.mu.Lock()
	defer n.fs.mu.Unlock()
	off := int64(len(n.data))
	n.data = grow(n.data, int(off)+len(p))
	copy(n.data[off:], p)
	n.mtime, n.ctime = memNow(), memNow()
	return len(p), off + int64(len(p)), nil
}

func (h *memFile) Truncate(size int64) error {
	if size < 0 {
		return syscall.EINVAL
	}
	n := h.n
	n.fs.mu.Lock()
	defer n.fs.mu.Unlock()
	if size <= int64(len(n.data)) {
		n.data = n.data[:size]
	} else {
		n.data = grow(n.data, int(size))
	}
	n.mtime, n.ctime = memNow(), memNow()
	return nil
}

// SetAttr changes the open file's metadata on its node, the in-memory inode the
// handle is a view of.
func (h *memFile) SetAttr(u AttrUpdate) error { return h.n.SetAttr(u) }

func (h *memFile) Close() error { return nil }

// Dup is a second handle on the file.
func (h *memFile) Dup() (File, error) { return &memFile{n: h.n}, nil }
