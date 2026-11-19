package tarfs

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"syscall"

	. "github.com/samyfodil/laboon/core"
)

// TarFS presents one layer tar as a read-only FileSystem without extracting it.
// It indexes the archive once -- reading headers and skipping over file data --
// keeping only the directory tree and each regular file's (offset, size) within
// the backing. Content is served on demand with ReadAt into ra, so no file bytes
// are held in memory. ra must give random access to the *uncompressed* tar; size
// is its length. Whiteout entries (.wh.*) are kept verbatim as ordinary files,
// for the overlay above to interpret.
func TarFS(ra io.ReaderAt, size int64) (FileSystem, error) {
	f := &tarFS{ra: ra, dev: atomic.AddUint64(&tarDevSeq, 1)}
	f.root = f.newNode(Dir, 0o755)
	// A plain counting reader (not a Seeker) forces tar.Reader to skip data by
	// reading through it, so cr.n tracks the exact stream position: right after
	// Next returns, it is the current entry's data offset.
	cr := &countReader{r: io.NewSectionReader(ra, 0, size)}
	tr := tar.NewReader(cr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		dataOff := cr.n
		name := path.Clean("/" + hdr.Name)
		if name == "/" {
			applyMeta(f.root, hdr)
			continue
		}
		dir, base := path.Split(name)
		parent, err := f.mkdirp(path.Clean(dir))
		if err != nil {
			return nil, err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			applyMeta(f.ensureDir(parent, base), hdr)
		case tar.TypeReg:
			n := f.newNode(Reg, modeOf(hdr))
			applyMeta(n, hdr)
			n.off, n.size = dataOff, hdr.Size
			parent.kids[base] = n
		case tar.TypeSymlink:
			n := f.newNode(Symlink, modeOf(hdr))
			applyMeta(n, hdr)
			n.tgt = hdr.Linkname
			parent.kids[base] = n
		case tar.TypeLink:
			tn, ok := f.resolve(path.Clean("/" + hdr.Linkname))
			if !ok {
				return nil, fmt.Errorf("tarfs: hardlink %q to missing %q", name, hdr.Linkname)
			}
			tn.nlink++
			parent.kids[base] = tn
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			k := Fifo
			if hdr.Typeflag == tar.TypeChar {
				k = Chardev
			} else if hdr.Typeflag == tar.TypeBlock {
				k = Blockdev
			}
			n := f.newNode(k, modeOf(hdr))
			applyMeta(n, hdr)
			n.rdev = mkdev(uint64(hdr.Devmajor), uint64(hdr.Devminor))
			parent.kids[base] = n
		}
	}
	return f, nil
}

var tarDevSeq uint64

type tarFS struct {
	ra   io.ReaderAt
	dev  uint64
	ino  uint64
	root *tarNode
}

type tarNode struct {
	fs             *tarFS
	ino            uint64
	kind           Kind
	mode, uid, gid uint32
	rdev           uint64
	tgt            string
	mtime          int64
	off, size      int64               // regular-file data region in fs.ra
	kids           map[string]*tarNode // directory entries
	nlink          uint32
}

func (f *tarFS) newNode(k Kind, mode uint32) *tarNode {
	f.ino++
	n := &tarNode{fs: f, ino: f.ino, kind: k, mode: mode & 0o7777, nlink: 1}
	if k == Dir {
		n.kids = map[string]*tarNode{}
	}
	return n
}

// mkdirp returns the directory node at absolute path p, creating any missing
// ancestors as plain 0755 directories (a later explicit entry sets their mode).
func (f *tarFS) mkdirp(p string) (*tarNode, error) {
	n := f.root
	for _, name := range strings.Split(strings.Trim(p, "/"), "/") {
		if name == "" {
			continue
		}
		c, ok := n.kids[name]
		if !ok {
			c = f.newNode(Dir, 0o755)
			n.kids[name] = c
		} else if c.kind != Dir {
			return nil, syscall.ENOTDIR
		}
		n = c
	}
	return n, nil
}

func (f *tarFS) ensureDir(parent *tarNode, name string) *tarNode {
	if c, ok := parent.kids[name]; ok && c.kind == Dir {
		return c
	}
	c := f.newNode(Dir, 0o755)
	parent.kids[name] = c
	return c
}

func (f *tarFS) resolve(p string) (*tarNode, bool) {
	n := f.root
	for _, name := range strings.Split(strings.Trim(p, "/"), "/") {
		if name == "" {
			continue
		}
		c, ok := n.kids[name]
		if !ok {
			return nil, false
		}
		n = c
	}
	return n, true
}

func modeOf(hdr *tar.Header) uint32 { return uint32(hdr.Mode) & 0o7777 }

func applyMeta(n *tarNode, hdr *tar.Header) {
	n.mode = modeOf(hdr)
	n.uid, n.gid = uint32(hdr.Uid), uint32(hdr.Gid)
	n.mtime = hdr.ModTime.UnixNano()
}

// mkdev encodes a Linux dev_t from major and minor (glibc makedev), so a device
// node from a layer reports the st_rdev the guest expects.
func mkdev(major, minor uint64) uint64 {
	return ((major & 0xfffff000) << 32) | ((major & 0xfff) << 8) |
		((minor & 0xffffff00) << 12) | (minor & 0xff)
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n += int64(k)
	return k, err
}

func (f *tarFS) Root() Node { return f.root }

func (f *tarFS) Lookup(dir Node, name string) (Node, error) {
	d := dir.(*tarNode)
	if d.kind != Dir {
		return nil, ErrNotDir
	}
	c, ok := d.kids[name]
	if !ok {
		return nil, NotExist("lookup", name)
	}
	return c, nil
}

func (f *tarFS) ReadDir(dir Node) ([]Dirent, error) {
	d := dir.(*tarNode)
	if d.kind != Dir {
		return nil, ErrNotDir
	}
	out := make([]Dirent, 0, len(d.kids))
	for name, c := range d.kids {
		out = append(out, Dirent{Name: name, Kind: c.kind, Ino: c.ino})
	}
	return out, nil
}

func (*tarFS) Create(Node, string, CreateSpec) (Node, error) { return nil, syscall.EROFS }
func (*tarFS) Link(Node, string, Node) (Node, error)         { return nil, syscall.EROFS }
func (*tarFS) Remove(Node, string, bool) error               { return syscall.EROFS }
func (*tarFS) Rename(Node, string, Node, string) error       { return syscall.EROFS }

func (n *tarNode) ID() NodeID { return NodeID{Dev: n.fs.dev, Ino: n.ino} }
func (n *tarNode) Kind() Kind { return n.kind }

func (n *tarNode) Stat() (Attr, error) {
	a := Attr{
		Kind: n.kind, Mode: n.mode, Uid: n.uid, Gid: n.gid, Rdev: n.rdev,
		Target: n.tgt, Blksize: 4096, Mtime: n.mtime, Atime: n.mtime, Ctime: n.mtime,
	}
	switch n.kind {
	case Reg:
		a.Size = n.size
		a.Blocks = (n.size + 511) / 512
		a.Nlink = uint64(n.nlink)
	case Dir:
		sub := uint64(0)
		for _, c := range n.kids {
			if c.kind == Dir {
				sub++
			}
		}
		a.Nlink = 2 + sub
	default:
		a.Nlink = uint64(n.nlink)
	}
	return a, nil
}

func (*tarNode) SetAttr(AttrUpdate) error { return syscall.EROFS }

func (n *tarNode) Readlink() (string, error) {
	if n.kind != Symlink {
		return "", syscall.EINVAL
	}
	return n.tgt, nil
}

func (n *tarNode) Open(flags int) (File, error) {
	if flags&(os.O_WRONLY|os.O_RDWR) != 0 {
		return nil, syscall.EROFS
	}
	if n.kind == Dir {
		return nil, ErrNoHostFile
	}
	if n.kind != Reg {
		return nil, syscall.EINVAL
	}
	return &tarFile{fs: n.fs, off: n.off, size: n.size}, nil
}

type tarFile struct {
	fs        *tarFS
	off, size int64
}

func (h *tarFile) ReadAt(p []byte, at int64) (int, error) {
	if at < 0 {
		return 0, syscall.EINVAL
	}
	if at >= h.size {
		return 0, io.EOF
	}
	short := false
	if int64(len(p)) > h.size-at {
		p = p[:h.size-at]
		short = true
	}
	n, err := h.fs.ra.ReadAt(p, h.off+at)
	if err == nil && short {
		err = io.EOF
	}
	return n, err
}

func (*tarFile) WriteAt([]byte, int64) (int, error) { return 0, syscall.EROFS }
func (*tarFile) Truncate(int64) error               { return syscall.EROFS }
func (*tarFile) Close() error                       { return nil }

func (*tarFS) ReadOnlyMount() {}
