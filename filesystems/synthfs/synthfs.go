package synthfs

import (
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"path"

	. "github.com/samyfodil/laboon/core"
)

// SynthNode is one node of a synthetic filesystem tree. Children and Content are
// computed on access, so a dynamic tree (a /proc with a directory per live pid,
// files whose bytes reflect current state) is expressed by returning different
// results over time. A directory sets Children; a regular file sets Content; a
// symlink sets Target.
type SynthNode struct {
	Name     string
	Kind     Kind
	Mode     uint32
	Target   string
	Content  func() []byte
	Children func() []*SynthNode
}

// synthFS is a read-only synthetic FileSystem built from a SynthNode tree — the
// shape /proc, /sys and /dev take as backends mounted in the Namespace. Writes
// are rejected; it composes uniformly with the host and overlay backends.
type synthFS struct{ root *SynthNode }

// NewSynthFS presents a SynthNode tree as a read-only FileSystem.
func NewSynthFS(root *SynthNode) FileSystem { return &synthFS{root: root} }

type synthNode struct {
	fs *synthFS
	p  string
	n  *SynthNode
}

func synthIno(p string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(p))
	return h.Sum64() | 1 // never 0
}

func (f *synthFS) Root() Node { return &synthNode{fs: f, p: "", n: f.root} }

func (f *synthFS) child(parent *synthNode, name string) (*SynthNode, bool) {
	if parent.n.Children == nil {
		return nil, false
	}
	for _, c := range parent.n.Children() {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

func (f *synthFS) Lookup(dir Node, name string) (Node, error) {
	d := dir.(*synthNode)
	c, ok := f.child(d, name)
	if !ok {
		return nil, NotExist("lookup", path.Join(d.p, name))
	}
	return &synthNode{fs: f, p: path.Join(d.p, name), n: c}, nil
}

func (f *synthFS) ReadDir(dir Node) ([]Dirent, error) {
	d := dir.(*synthNode)
	if d.n.Children == nil {
		return nil, nil
	}
	cs := d.n.Children()
	out := make([]Dirent, 0, len(cs))
	for _, c := range cs {
		out = append(out, Dirent{Name: c.Name, Kind: c.Kind, Ino: synthIno(path.Join(d.p, c.Name))})
	}
	return out, nil
}

func (f *synthFS) Create(Node, string, CreateSpec) (Node, error) { return nil, errROFS("create") }
func (f *synthFS) Link(Node, string, Node) (Node, error)         { return nil, errROFS("link") }
func (f *synthFS) Remove(Node, string, bool) error               { return errROFS("remove") }
func (f *synthFS) Rename(Node, string, Node, string) error       { return errROFS("rename") }

func errROFS(op string) error { return &fs.PathError{Op: op, Path: "", Err: fs.ErrPermission} }

func (n *synthNode) ID() NodeID { return NodeID{Ino: synthIno(n.p)} }
func (n *synthNode) Kind() Kind { return n.n.Kind }

func (n *synthNode) Stat() (Attr, error) {
	a := Attr{Kind: n.n.Kind, Mode: n.n.Mode, Nlink: 1, Target: n.n.Target}
	if n.n.Kind == Reg && n.n.Content != nil {
		a.Size = int64(len(n.n.Content()))
	}
	return a, nil
}

func (n *synthNode) SetAttr(AttrUpdate) error  { return errROFS("setattr") }
func (n *synthNode) Readlink() (string, error) { return n.n.Target, nil }

func (n *synthNode) Open(flags int) (File, error) {
	if flags&(os.O_WRONLY|os.O_RDWR) != 0 {
		return nil, errROFS("open")
	}
	var data []byte
	if n.n.Content != nil {
		data = n.n.Content()
	}
	return &bytesFile{n: n, data: data}, nil
}

// bytesFile is a read-only in-memory File for synthetic content.
type bytesFile struct {
	n    *synthNode
	data []byte
}

func (b *bytesFile) Stat() (Info, error) {
	a, err := b.n.Stat()
	if err != nil {
		return nil, err
	}
	return FileInfo("", a, b.n.ID()), nil
}

func (b *bytesFile) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n := copy(p, b.data[off:])
	return n, nil
}
func (b *bytesFile) WriteAt([]byte, int64) (int, error) { return 0, errROFS("write") }
func (b *bytesFile) Truncate(int64) error               { return errROFS("truncate") }
func (b *bytesFile) SetAttr(AttrUpdate) error            { return errROFS("setattr") }
func (b *bytesFile) Close() error                       { return nil }
