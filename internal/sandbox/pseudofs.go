//go:build darwin || linux || windows

package sandbox

import (
	"io/fs"
	"path"

	"github.com/samyfodil/laboon/core"
)

// pnodeFS exposes a synthetic pnode tree (/proc, /sys, /dev) as a core.FileSystem
// so the Namespace resolves those paths like any other mount. It serves
// RESOLUTION only — Lookup/ReadDir/Stat/Readlink over the pnode structure, which
// is reader-independent metadata. A pseudo file's content (generated on read,
// applied on write), device opens and fd objects are richer than core.File, so
// Open is left to the sandbox's pseudoOpen with the reading guest, the way exec
// and bind resolve through the Namespace but act in the sandbox. The tree itself
// is a per-reader view (pid-namespace-relative), so each guest mounts its own.
type pnodeFS struct {
	root  *pnode
	dev   uint64 // the mount's device number (devProc/devSys/devDevtmp)
	base  string // the mount's guest path ("/proc"), for inode hashing
	magic uint64 // f_type statfs reports (PROC_SUPER_MAGIC, ...); 0 = derive from base
}

func newPnodeFS(root *pnode, dev, magic uint64, base string) *pnodeFS {
	return &pnodeFS{root: root, dev: dev, base: base, magic: magic}
}

type pnodeNode struct {
	fs *pnodeFS
	p  string // guest path
	n  *pnode
}

// errPseudoOpen marks a pseudo node whose open the sandbox must perform (its
// file semantics exceed core.File).
var errPseudoOpen = &fs.PathError{Op: "open", Path: "pseudo", Err: fs.ErrInvalid}

func pkindToVfs(k pkind) core.Kind {
	switch k {
	case pDir:
		return core.Dir
	case pLink, pFdObj:
		return core.Symlink
	case pDev:
		return core.Chardev
	}
	return core.Reg
}

func (f *pnodeFS) node(p string, n *pnode) *pnodeNode {
	n.dev, n.ino = f.dev, pino(p)
	if n.kind == pLink && magicTarget(n.target) {
		n.ino = pino(n.target)
	}
	return &pnodeNode{fs: f, p: p, n: n}
}

func (f *pnodeFS) Root() core.Node { return f.node(f.base, f.root) }

func (f *pnodeFS) Lookup(dir core.Node, name string) (core.Node, error) {
	d := dir.(*pnodeNode)
	if d.n.kind != pDir {
		return nil, &fs.PathError{Op: "lookup", Path: path.Join(d.p, name), Err: fs.ErrNotExist}
	}
	c := d.n.child(name)
	if c == nil {
		return nil, &fs.PathError{Op: "lookup", Path: path.Join(d.p, name), Err: fs.ErrNotExist}
	}
	return f.node(path.Join(d.p, name), c), nil
}

func (f *pnodeFS) ReadDir(dir core.Node) ([]core.Dirent, error) {
	d := dir.(*pnodeNode)
	if d.n.kind != pDir || d.n.kids == nil {
		return nil, nil
	}
	cs := d.n.kids()
	out := make([]core.Dirent, 0, len(cs))
	for _, c := range cs {
		out = append(out, core.Dirent{Name: c.name, Kind: pkindToVfs(c.n.kind), Ino: pino(path.Join(d.p, c.name))})
	}
	return out, nil
}

func pseudoROFS(op string) error { return &fs.PathError{Op: op, Path: "pseudo", Err: fs.ErrPermission} }

func (f *pnodeFS) Create(core.Node, string, core.CreateSpec) (core.Node, error) {
	return nil, pseudoROFS("create")
}
func (f *pnodeFS) Link(core.Node, string, core.Node) (core.Node, error) {
	return nil, pseudoROFS("link")
}
func (f *pnodeFS) Remove(core.Node, string, bool) error              { return pseudoROFS("remove") }
func (f *pnodeFS) Rename(core.Node, string, core.Node, string) error { return pseudoROFS("rename") }

func (n *pnodeNode) ID() core.NodeID { return core.NodeID{Dev: n.n.dev, Ino: n.n.ino} }
func (n *pnodeNode) Kind() core.Kind { return pkindToVfs(n.n.kind) }

func (n *pnodeNode) Stat() (core.Attr, error) {
	a := core.Attr{
		Kind:  pkindToVfs(n.n.kind),
		Mode:  n.n.perm & 0o7777,
		Nlink: 1,
		Rdev:  n.n.rdev,
	}
	if n.n.kind == pDir && n.n.nlink != nil {
		a.Nlink = uint64(n.n.nlink())
	}
	if n.n.kind == pLink || n.n.kind == pFdObj {
		a.Target = n.n.target
		a.Size = int64(len(n.n.target))
	}
	return a, nil
}

func (n *pnodeNode) SetAttr(core.AttrUpdate) error { return pseudoROFS("setattr") }
func (n *pnodeNode) Readlink() (string, error)     { return n.n.target, nil }
func (n *pnodeNode) Open(int) (core.File, error)   { return nil, errPseudoOpen }

// devFS is the /dev mount: a union of the synthetic device nodes (null, zero,
// pts, ...) over the overlay's own /dev (console, shm, whatever the guest made
// there). A synthetic name wins; every other name comes from the overlay. Like
// the other pseudo mounts it serves resolution; a synthetic node's Open returns
// the pseudo sentinel, while an overlay node opens normally.
type devFS struct {
	syn   *pnode          // synthetic /dev root (per-guest: pts needs the guest)
	ovFS  core.FileSystem // the overlay, for Lookup/ReadDir/Create under /dev
	ovDev core.Node       // the overlay's own /dev node (nil if it has none)
	dev   uint64          // devDevtmp, for synthetic node identity
}

type devNodeU struct {
	fs  *devFS
	p   string
	syn *pnode    // set when this node is a synthetic device
	ov  core.Node // set when it comes from the overlay
}

func (f *devFS) synNode(p string, n *pnode) *devNodeU {
	n.dev, n.ino = f.dev, pino(p)
	return &devNodeU{fs: f, p: p, syn: n}
}

func (f *devFS) Root() core.Node {
	f.syn.dev, f.syn.ino = f.dev, pino("/dev")
	return &devNodeU{fs: f, p: "/dev", syn: f.syn, ov: f.ovDev}
}

func (f *devFS) Lookup(dir core.Node, name string) (core.Node, error) {
	d := dir.(*devNodeU)
	if d.syn != nil && d.syn.kind == pDir {
		if c := d.syn.child(name); c != nil {
			return f.synNode(path.Join(d.p, name), c), nil
		}
	}
	if d.ov != nil {
		if c, err := f.ovFS.Lookup(d.ov, name); err == nil {
			return &devNodeU{fs: f, p: path.Join(d.p, name), ov: c}, nil
		}
	}
	return nil, &fs.PathError{Op: "lookup", Path: path.Join(d.p, name), Err: fs.ErrNotExist}
}

func (f *devFS) ReadDir(dir core.Node) ([]core.Dirent, error) {
	d := dir.(*devNodeU)
	seen := map[string]bool{}
	var out []core.Dirent
	if d.syn != nil && d.syn.kids != nil {
		for _, c := range d.syn.kids() {
			seen[c.name] = true
			out = append(out, core.Dirent{Name: c.name, Kind: pkindToVfs(c.n.kind), Ino: pino(path.Join(d.p, c.name))})
		}
	}
	if d.ov != nil {
		ents, _ := f.ovFS.ReadDir(d.ov)
		for _, e := range ents {
			if !seen[e.Name] {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (f *devFS) Create(dir core.Node, name string, spec core.CreateSpec) (core.Node, error) {
	d := dir.(*devNodeU)
	if d.ov != nil { // a new /dev entry lands in the overlay, not the synthetic set
		return f.ovFS.Create(d.ov, name, spec)
	}
	return nil, pseudoROFS("create")
}
func (f *devFS) Link(dir core.Node, name string, t core.Node) (core.Node, error) {
	d := dir.(*devNodeU)
	if d.ov != nil {
		if tu, ok := t.(*devNodeU); ok && tu.ov != nil {
			t = tu.ov // the overlay links its own node, not the /dev wrapper
		}
		n, err := f.ovFS.Link(d.ov, name, t)
		if err != nil {
			return nil, err
		}
		return &devNodeU{fs: f, p: path.Join(d.p, name), ov: n}, nil
	}
	return nil, pseudoROFS("link")
}
func (f *devFS) Remove(dir core.Node, name string, isDir bool) error {
	d := dir.(*devNodeU)
	if d.syn != nil && d.syn.child(name) != nil {
		return pseudoROFS("remove") // a synthetic device cannot be removed
	}
	if d.ov != nil {
		return f.ovFS.Remove(d.ov, name, isDir)
	}
	return pseudoROFS("remove")
}
func (f *devFS) Rename(fromDir core.Node, from string, toDir core.Node, to string) error {
	fd, td := fromDir.(*devNodeU), toDir.(*devNodeU)
	if fd.ov != nil && td.ov != nil {
		return f.ovFS.Rename(fd.ov, from, td.ov, to)
	}
	return pseudoROFS("rename")
}

// BindSocket and ReachSocket pass a socket under /dev (a syslog /dev/log) to
// the overlay, which holds every non-synthetic name there.
func (f *devFS) BindSocket(dir core.Node, name string, bind func(addr string) error) (core.Node, error) {
	d := dir.(*devNodeU)
	s, ok := f.ovFS.(core.SocketFS)
	if d.ov == nil || !ok {
		return nil, core.ErrSocketUnsupported
	}
	n, err := s.BindSocket(d.ov, name, bind)
	if err != nil {
		return nil, err
	}
	return &devNodeU{fs: f, p: path.Join(d.p, name), ov: n}, nil
}

func (f *devFS) ReachSocket(n core.Node, op func(addr string) error) error {
	u := n.(*devNodeU)
	s, ok := f.ovFS.(core.SocketFS)
	if u.ov == nil || !ok {
		return core.ErrSocketUnsupported
	}
	return s.ReachSocket(u.ov, op)
}

func (n *devNodeU) ID() core.NodeID {
	if n.syn != nil {
		return core.NodeID{Dev: n.syn.dev, Ino: n.syn.ino}
	}
	return n.ov.ID()
}
func (n *devNodeU) Kind() core.Kind {
	if n.syn != nil {
		return pkindToVfs(n.syn.kind)
	}
	return n.ov.Kind()
}
func (n *devNodeU) Stat() (core.Attr, error) {
	if n.syn != nil {
		return (&pnodeNode{n: n.syn}).Stat()
	}
	return n.ov.Stat()
}
func (n *devNodeU) SetAttr(u core.AttrUpdate) error {
	if n.ov != nil {
		return n.ov.SetAttr(u)
	}
	// A synthetic device (null, zero, ...) has fixed identity, but root may
	// chown and chmod it — a container runtime does this to the std streams it
	// points at /dev/null. Accept the change as a virtualized no-op rather than
	// refusing it with EPERM.
	return nil
}
func (n *devNodeU) Readlink() (string, error) {
	if n.syn != nil {
		return n.syn.target, nil
	}
	return n.ov.Readlink()
}
func (n *devNodeU) Open(flags int) (core.File, error) {
	if n.syn != nil {
		return nil, errPseudoOpen // a synthetic device opens via pseudoOpen
	}
	return n.ov.Open(flags)
}
