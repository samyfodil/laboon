package overlayfs

import (
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	. "github.com/samyfodil/laboon/core"
)

// overlay is a copy-on-write union of FileSystems: reads merge the layers (the
// top-most wins), a write copies the path up into the top layer, and a removed
// lower path is hidden by a .wh. whiteout marker written in the top. It is a
// FileSystem itself, so it composes uniformly beside any other backend. It owns
// only the union convention (whiteout/opaque, copy-up); it holds no metadata of
// its own and reaches nothing on the host. A layer that must carry guest
// metadata a host file cannot hold (a non-root owner, a sub-floor mode, a
// special kind) does so inside itself and reports it from Stat, so copy-up just
// passes the full CreateSpec down and the destination layer is authoritative.
type overlay struct {
	layers []FileSystem  // lowest first; the last is the writable top
	mutGen atomic.Uint64 // bumped on every mutation; the Namespace resolve cache keys on it
	// making serializes the materialization of one overlay path in the top layer,
	// so two threads in a CLONE_FILES group copying the same shared path up do not
	// race to create it twice. One lock per path hash.
	making [256]sync.RWMutex
}

// OverlayFS unions layers (lowest first, writable top last) into a copy-on-write
// FileSystem. It takes the layers at construction and composes them; it keeps no
// metadata store and touches no host state.
func OverlayFS(layers ...FileSystem) FileSystem { return &overlay{layers: layers} }

func (f *overlay) makingLock(p string) *sync.RWMutex {
	p = strings.TrimLeft(p, "/")
	h := uint32(2166136261)
	for i := 0; i < len(p); i++ {
		h = (h ^ uint32(p[i])) * 16777619
	}
	return &f.making[h%uint32(len(f.making))]
}

// touch records that the overlay changed, so any cached path resolution taken
// before now is treated as stale (generational). gen is the current generation.
func (f *overlay) Touch()      { f.mutGen.Add(1) }
func (f *overlay) Gen() uint64 { return f.mutGen.Load() }

func (f *overlay) top() FileSystem { return f.layers[len(f.layers)-1] }

// Layer is the layer that owns n and n's node there.
func (f *overlay) Layer(n Node) (FileSystem, Node) {
	on := n.(*overlayNode)
	return f.layers[on.owner], on.nodes[on.owner]
}

// overlayNode carries, for its overlay path, the backing node in each layer (nil
// where absent); the owner is the top-most layer that has it.
type overlayNode struct {
	fs    *overlay
	p     string
	nodes []Node
	owner int
	kind  Kind
}

func (f *overlay) Root() Node {
	nodes := make([]Node, len(f.layers))
	for i, L := range f.layers {
		nodes[i] = L.Root()
	}
	return &overlayNode{fs: f, p: "", nodes: nodes, owner: len(f.layers) - 1, kind: Dir}
}

func (f *overlay) Lookup(dir Node, name string) (Node, error) {
	d := dir.(*overlayNode)
	nodes := make([]Node, len(f.layers))
	owner := -1
	for i := len(f.layers) - 1; i >= 0; i-- {
		dn := d.nodes[i]
		if dn == nil {
			continue
		}
		L := f.layers[i]
		// The whiteout/opaque probes only matter to stop the descent to lower
		// layers, so they are pointless on the bottom layer.
		whited := i > 0 && present(L, dn, WhiteoutPrefix+name)
		if c, err := L.Lookup(dn, name); err == nil {
			nodes[i] = c
			if owner < 0 {
				owner = i
			}
		}
		if whited || (i > 0 && present(L, dn, OpaqueMarker)) {
			break
		}
	}
	if owner < 0 {
		return nil, NotExist("lookup", path.Join(d.p, name))
	}
	return &overlayNode{fs: f, p: path.Join(d.p, name), nodes: nodes, owner: owner, kind: nodes[owner].Kind()}, nil
}

func (f *overlay) ReadDir(dir Node) ([]Dirent, error) {
	d := dir.(*overlayNode)
	seen := map[string]bool{}
	whited := map[string]bool{}
	var out []Dirent
	for i := len(f.layers) - 1; i >= 0; i-- {
		dn := d.nodes[i]
		if dn == nil {
			continue
		}
		ents, err := f.layers[i].ReadDir(dn)
		if err != nil {
			continue
		}
		opaque := false
		for _, e := range ents {
			if e.Name == OpaqueMarker {
				opaque = true
			} else if strings.HasPrefix(e.Name, WhiteoutPrefix) {
				whited[e.Name[len(WhiteoutPrefix):]] = true
			}
		}
		for _, e := range ents {
			if Internal(e.Name) || seen[e.Name] || whited[e.Name] {
				continue
			}
			seen[e.Name] = true
			out = append(out, e)
		}
		if opaque {
			break
		}
	}
	return out, nil
}

// topDir ensures the directory at overlay path p exists in the top layer,
// copying ancestors up from the layer that provides them, and returns its node.
func (f *overlay) topDir(p string) (Node, error) {
	if p == "" || p == "." || p == "/" {
		return f.top().Root(), nil
	}
	if n, ok := layerNode(f.top(), p); ok {
		return n, nil
	}
	parent := path.Dir(p)
	if parent == "." {
		parent = ""
	}
	pn, err := f.topDir(parent)
	if err != nil {
		return nil, err
	}
	a := Attr{Kind: Dir, Mode: 0o755}
	if sn, err := f.resolve(p); err == nil {
		if sa, e := sn.Stat(); e == nil {
			a = sa
		}
	}
	l := f.makingLock(p)
	l.Lock()
	c, err := f.top().Create(pn, path.Base(p), CreateSpec{Kind: Dir, Mode: a.Mode, Uid: a.Uid, Gid: a.Gid})
	if err != nil {
		l.Unlock()
		// Another goroutine copying the same shared parent up may have created it
		// first (concurrent writes under a CLONE_FILES thread group); take theirs.
		if n, ok := layerNode(f.top(), p); ok {
			return n, nil
		}
		return nil, err
	}
	l.Unlock()
	return c, nil
}

// copyUp makes the overlay path p present and writable in the top layer: a
// lower-only object is copied up with its contents and metadata.
func (f *overlay) copyUp(n *overlayNode) (Node, error) {
	defer f.Touch()
	if tn := n.nodes[len(f.layers)-1]; tn != nil {
		return tn, nil // already in the top
	}
	src := n.nodes[n.owner]
	a, err := src.Stat()
	if err != nil {
		return nil, err
	}
	pdir, err := f.topDir(path.Dir(n.p))
	if err != nil {
		return nil, err
	}
	base := path.Base(n.p)
	l := f.makingLock(n.p)
	l.Lock()
	defer l.Unlock()
	if tn, ok := layerNode(f.top(), n.p); ok {
		n.nodes[len(f.layers)-1] = tn
		n.owner = len(f.layers) - 1
		return tn, nil
	}
	var tn Node
	switch a.Kind {
	case Dir:
		tn, err = f.top().Create(pdir, base, CreateSpec{Kind: Dir, Mode: a.Mode, Uid: a.Uid, Gid: a.Gid})
	case Symlink:
		tn, err = f.top().Create(pdir, base, CreateSpec{Kind: Symlink, Target: a.Target, Mode: a.Mode, Uid: a.Uid, Gid: a.Gid})
	case Reg:
		tn, err = f.copyUpReg(pdir, base, a, src)
	default:
		tn, err = f.top().Create(pdir, base, CreateSpec{Kind: a.Kind, Rdev: a.Rdev, Mode: a.Mode, Uid: a.Uid, Gid: a.Gid})
	}
	if err != nil {
		return nil, err
	}
	// Preserve the source's times on the copy (a content write set them to now);
	// a symlink's own times are not meaningful to set.
	if a.Kind != Symlink && (a.Atime != 0 || a.Mtime != 0) {
		tn.SetAttr(AttrUpdate{Atime: &a.Atime, Mtime: &a.Mtime})
	}
	n.nodes[len(f.layers)-1] = tn
	n.owner = len(f.layers) - 1
	return tn, nil
}

// copyUpReg copies a regular file up into the top layer, streaming its contents
// in fixed chunks so a large file is not buffered whole, and propagating read
// and write errors instead of silently truncating.
func (f *overlay) copyUpReg(pdir Node, name string, a Attr, src Node) (Node, error) {
	r, err := src.Open(os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	tn, err := f.top().Create(pdir, name, CreateSpec{Kind: Reg, Mode: a.Mode, Uid: a.Uid, Gid: a.Gid})
	if err != nil {
		return nil, err
	}
	w, err := tn.Open(os.O_WRONLY | os.O_TRUNC)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 1<<20)
	for off := int64(0); ; {
		n, rerr := r.ReadAt(buf, off)
		if n > 0 {
			if _, werr := w.WriteAt(buf[:n], off); werr != nil {
				w.Close()
				return nil, werr
			}
			off += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			w.Close()
			return nil, rerr
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return tn, nil
}

func (f *overlay) writeTop(pdir Node, name string, spec CreateSpec, data []byte) (Node, error) {
	if w, ok := f.top().(WriteFileSystem); ok {
		return w.WriteFile(pdir, name, spec, data)
	}
	n, err := f.top().Create(pdir, name, spec)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		wf, err := n.Open(os.O_WRONLY | os.O_TRUNC)
		if err != nil {
			return nil, err
		}
		_, err = wf.WriteAt(data, 0)
		wf.Close()
		if err != nil {
			return nil, err
		}
	}
	return n, nil
}

// unwhiteout removes a .wh.name marker from the top directory node, if present.
func (f *overlay) unwhiteout(topDir Node, name string) {
	if c, err := f.top().Lookup(topDir, WhiteoutPrefix+name); err == nil {
		f.top().Remove(topDir, WhiteoutPrefix+name, c.Kind() == Dir)
	}
}

func (f *overlay) Create(dir Node, name string, spec CreateSpec) (Node, error) {
	defer f.Touch()
	d := dir.(*overlayNode)
	topDir, err := f.topDir(d.p)
	if err != nil {
		return nil, err
	}
	whited := present(f.top(), topDir, WhiteoutPrefix+name)
	f.unwhiteout(topDir, name)
	p := join(d.p, name)
	l := f.makingLock(p)
	l.Lock()
	var c Node
	if spec.Kind == Reg {
		c, err = f.writeTop(topDir, name, spec, nil)
	} else {
		c, err = f.top().Create(topDir, name, spec)
	}
	if err != nil {
		l.Unlock()
		return nil, err
	}
	if whited && spec.Kind == Dir {
		// A directory recreated over a whiteout is opaque: the lower layer's
		// entries at this path were removed and must stay hidden.
		f.top().Create(c, OpaqueMarker, CreateSpec{Kind: Reg})
	}
	l.Unlock()
	return f.resolve(p) // fresh: dir may hold a stale top node from the copy-up
}

func (f *overlay) WriteFile(dir Node, name string, spec CreateSpec, data []byte) (Node, error) {
	defer f.Touch()
	d := dir.(*overlayNode)
	topDir, err := f.topDir(d.p)
	if err != nil {
		return nil, err
	}
	f.unwhiteout(topDir, name)
	p := join(d.p, name)
	l := f.makingLock(p)
	l.Lock()
	spec.Kind = Reg
	if _, err := f.writeTop(topDir, name, spec, data); err != nil {
		l.Unlock()
		return nil, err
	}
	l.Unlock()
	return f.resolve(p)
}

func (f *overlay) Link(dir Node, name string, target Node) (Node, error) {
	defer f.Touch()
	t, ok := target.(*overlayNode)
	d, okd := dir.(*overlayNode)
	if !ok || !okd {
		return nil, ErrCrossDevice // a node from another filesystem (a mount)
	}
	tn, err := f.copyUp(t)
	if err != nil {
		return nil, err
	}
	topDir, err := f.topDir(d.p)
	if err != nil {
		return nil, err
	}
	f.unwhiteout(topDir, name)
	if _, err := f.top().Link(topDir, name, tn); err != nil {
		return nil, err
	}
	return f.resolve(join(d.p, name))
}

func (f *overlay) Remove(dir Node, name string, isDir bool) error {
	defer f.Touch()
	d := dir.(*overlayNode)
	child, err := f.Lookup(dir, name)
	if err != nil {
		return err
	}
	c := child.(*overlayNode)
	top := len(f.layers) - 1
	if c.nodes[top] != nil {
		topDir, _ := layerNode(f.top(), d.p)
		if topDir != nil {
			if isDir {
				// The merged dir is empty, but its top copy can still hold whiteout
				// and opaque markers for lower entries now hidden, so a plain rmdir
				// would fail; drop the top dir and everything in it (RemoveAll).
				f.dropTopDir(topDir, name)
			} else {
				f.top().Remove(topDir, name, false)
			}
		}
	}
	// A lower layer still shows it: hide it with a whiteout in the top.
	lowerShows := false
	for i := 0; i < top; i++ {
		if c.nodes[i] != nil {
			lowerShows = true
		}
	}
	if lowerShows {
		topDir, err := f.topDir(d.p)
		if err != nil {
			return err
		}
		if _, err := f.top().Create(topDir, WhiteoutPrefix+name, CreateSpec{Kind: Reg}); err != nil {
			return err
		}
	}
	return nil
}

// dropTopDir removes name (a directory) and everything under it from the top
// layer (RemoveAll), so a top copy holding only whiteout/opaque markers can be
// rmdir'd.
func (f *overlay) dropTopDir(parent Node, name string) error {
	L := f.top()
	dn, err := L.Lookup(parent, name)
	if err != nil {
		return nil // nothing in the top layer
	}
	ents, _ := L.ReadDir(dn)
	for _, e := range ents {
		if e.Kind == Dir {
			if err := f.dropTopDir(dn, e.Name); err != nil {
				return err
			}
		} else if err := L.Remove(dn, e.Name, false); err != nil {
			return err
		}
	}
	return L.Remove(parent, name, true)
}

// deepCopyUp copies n up into the top layer, and for a directory recursively
// copies its merged children up first, so a merged directory is fully
// materialized in the top layer before it is renamed.
func (f *overlay) deepCopyUp(n *overlayNode) error {
	if _, err := f.copyUp(n); err != nil {
		return err
	}
	if n.kind != Dir {
		return nil
	}
	ents, err := f.ReadDir(n)
	if err != nil {
		return err
	}
	for _, e := range ents {
		c, err := f.Lookup(n, e.Name)
		if err != nil {
			return err
		}
		if err := f.deepCopyUp(c.(*overlayNode)); err != nil {
			return err
		}
	}
	return nil
}

func (f *overlay) Rename(fromDir Node, from string, toDir Node, to string) error {
	defer f.Touch()
	src, err := f.Lookup(fromDir, from)
	if err != nil {
		return err
	}
	if err := f.deepCopyUp(src.(*overlayNode)); err != nil {
		return err
	}
	fTop, err := f.topDir(fromDir.(*overlayNode).p)
	if err != nil {
		return err
	}
	tTop, err := f.topDir(toDir.(*overlayNode).p)
	if err != nil {
		return err
	}
	f.unwhiteout(tTop, to)
	if err := f.top().Rename(fTop, from, tTop, to); err != nil {
		return err
	}
	// Hide the old name if a lower layer still shows it.
	for i := 0; i < len(f.layers)-1; i++ {
		if src.(*overlayNode).nodes[i] != nil {
			f.top().Create(fTop, WhiteoutPrefix+from, CreateSpec{Kind: Reg})
			break
		}
	}
	return nil
}

// RenameExchange swaps from and to atomically. Both are deep-copied up so a
// merged directory is fully materialized in the top, then the top layer swaps
// them; no whiteout is needed, since each path keeps a top entry that shadows
// its lower.
func (f *overlay) RenameExchange(fromDir Node, from string, toDir Node, to string) error {
	defer f.Touch()
	src, err := f.Lookup(fromDir, from)
	if err != nil {
		return err
	}
	dst, err := f.Lookup(toDir, to)
	if err != nil {
		return err
	}
	if err := f.deepCopyUp(src.(*overlayNode)); err != nil {
		return err
	}
	if err := f.deepCopyUp(dst.(*overlayNode)); err != nil {
		return err
	}
	fTop, err := f.topDir(fromDir.(*overlayNode).p)
	if err != nil {
		return err
	}
	tTop, err := f.topDir(toDir.(*overlayNode).p)
	if err != nil {
		return err
	}
	xr, ok := f.top().(ExchangeRenamer)
	if !ok {
		return &fs.PathError{Op: "renameexchange", Path: from, Err: fs.ErrInvalid}
	}
	return xr.RenameExchange(fTop, from, tTop, to)
}

func (f *overlay) resolve(p string) (*overlayNode, error) {
	n := f.Root()
	p = clean(p)
	if p == "" {
		return n.(*overlayNode), nil
	}
	for _, name := range strings.Split(p, "/") {
		c, err := f.Lookup(n, name)
		if err != nil {
			return nil, err
		}
		n = c
	}
	return n.(*overlayNode), nil
}

// StatFS forwards to the layer that owns n, so statfs reports the filesystem
// actually backing the node rather than the union abstraction.
func (f *overlay) StatFS(n Node) (StatFS, error) {
	on := n.(*overlayNode)
	sf, ok := f.layers[on.owner].(StatFSer)
	if !ok {
		return StatFS{}, &fs.PathError{Op: "statfs", Path: on.p, Err: fs.ErrInvalid}
	}
	return sf.StatFS(on.nodes[on.owner])
}

// Getxattr/Listxattr read from the layer that owns n; Setxattr/Removexattr copy
// n up first so the change lands in the writable top.
func (n *overlayNode) Getxattr(name string) ([]byte, error) {
	xn, ok := n.nodes[n.owner].(XattrNode)
	if !ok {
		return nil, ErrXattrUnsupported
	}
	return xn.Getxattr(name)
}

func (n *overlayNode) Listxattr() ([]byte, error) {
	xn, ok := n.nodes[n.owner].(XattrNode)
	if !ok {
		return nil, ErrXattrUnsupported
	}
	return xn.Listxattr()
}

func (n *overlayNode) Setxattr(name string, value []byte, flags int) error {
	defer n.fs.Touch()
	tn, err := n.fs.copyUp(n)
	if err != nil {
		return err
	}
	xn, ok := tn.(XattrNode)
	if !ok {
		return ErrXattrUnsupported
	}
	return xn.Setxattr(name, value, flags)
}

func (n *overlayNode) Removexattr(name string) error {
	defer n.fs.Touch()
	tn, err := n.fs.copyUp(n)
	if err != nil {
		return err
	}
	xn, ok := tn.(XattrNode)
	if !ok {
		return ErrXattrUnsupported
	}
	return xn.Removexattr(name)
}

// ID is the node's lowest layer's identity, not the owner's: a copy-up adds a
// top node but the lowest (origin) id never changes, so a consumer keying on it
// (a file lock, a directory pin) sees one identity across copy-up and needs no
// separate origin map.
func (n *overlayNode) ID() NodeID {
	for i := 0; i < len(n.nodes); i++ {
		if n.nodes[i] != nil {
			return n.nodes[i].ID()
		}
	}
	return n.nodes[n.owner].ID()
}
func (n *overlayNode) Kind() Kind { return n.kind }

func (n *overlayNode) Stat() (Attr, error) {
	a, err := n.nodes[n.owner].Stat()
	if err != nil {
		return Attr{}, err
	}
	if a.Kind == Dir {
		// A merged directory's link count is unknown (entries come from several
		// layers), so report 1, as Linux overlayfs does.
		a.Nlink = 1
	}
	return a, nil
}

func (n *overlayNode) SetAttr(u AttrUpdate) error {
	defer n.fs.Touch()
	tn, err := n.fs.copyUp(n)
	if err != nil {
		return err
	}
	return tn.SetAttr(u)
}

func (n *overlayNode) Readlink() (string, error) { return n.nodes[n.owner].Readlink() }

func (n *overlayNode) Open(flags int) (File, error) {
	// Only a regular file's content is copied up on a writable open. A special
	// node (fifo, device, socket) is opened in place.
	if flags&(os.O_WRONLY|os.O_RDWR) != 0 && n.kind == Reg {
		tn, err := n.fs.copyUp(n)
		if err != nil {
			return nil, err
		}
		return tn.Open(flags)
	}
	return n.nodes[n.owner].Open(flags)
}

// CloneNode returns an independent copy, so a resolver cache hit never shares a
// node that copy-up may rewrite in place.
func (n *overlayNode) CloneNode() Node {
	return &overlayNode{fs: n.fs, p: n.p, nodes: append([]Node(nil), n.nodes...), owner: n.owner, kind: n.kind}
}
