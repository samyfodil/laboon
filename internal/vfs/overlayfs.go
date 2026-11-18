package vfs

import (
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
)

// overlayFS is a copy-on-write union of FileSystems: reads merge the layers
// (the top-most wins), a write copies the path up into the top layer, and a
// removed lower path is hidden by a .wh. whiteout marker written in the top. It
// is a FileSystem itself, so it composes uniformly in the Namespace beside the
// host-dir and synthetic backends — the homogeneous model. The layers are plain
// FileSystems (they report entries raw); overlayFS is the one that interprets
// the whiteout/opaque convention and owns copy-up. Host-uncarryable metadata (a
// sub-floor mode, a non-root owner, a special kind) lives in a shared MetaStore,
// keyed by the top node's identity, so hardlinks share it and renames keep it.
type overlayFS struct {
	layers []FileSystem // lowest first; the last is the writable top
	meta   *MetaStore
	mutGen atomic.Uint64 // bumped on every mutation; the Namespace resolve cache keys on it
	// making covers the time a new top-layer object exists on the host but
	// its guest metadata (owner, sub-floor mode, special kind) is not yet
	// recorded: a Stat of the path waits it out, so another process never
	// sees the object with the host's defaults. One lock per path hash.
	making [256]sync.RWMutex
}

// makingLock is the lock covering the creation of overlay path p (with or
// without its leading slash).
func (f *overlayFS) makingLock(p string) *sync.RWMutex {
	p = strings.TrimLeft(p, "/")
	h := uint32(2166136261)
	for i := 0; i < len(p); i++ {
		h = (h ^ uint32(p[i])) * 16777619
	}
	return &f.making[h%uint32(len(f.making))]
}

// touch records that the overlay changed, so any cached path resolution taken
// before now is treated as stale. Over-invalidation (bumping when nothing
// actually changed) is safe; missing a bump is not, so every mutating method
// defers this.
func (f *overlayFS) touch() { f.mutGen.Add(1) }

// gen is the current mutation generation, for the resolve cache (generational).
func (f *overlayFS) gen() uint64 { return f.mutGen.Load() }

// NewOverlayFS unions layers (lowest first, writable top last) with its own
// metadata store.
func NewOverlayFS(layers ...FileSystem) FileSystem {
	return NewOverlayFSWithMeta(NewMetaStore(), layers...)
}

// NewOverlayFSWithMeta is NewOverlayFS sharing an existing metadata store, so a
// caller (the live sandbox) and the backend are one metadata authority.
func NewOverlayFSWithMeta(meta *MetaStore, layers ...FileSystem) FileSystem {
	return &overlayFS{layers: layers, meta: meta}
}

func (f *overlayFS) top() FileSystem { return f.layers[len(f.layers)-1] }

// ovNode carries, for its overlay path, the backing node in each layer (nil
// where absent); the owner is the top-most layer that has it.
type ovNode struct {
	fs    *overlayFS
	p     string
	nodes []Node
	owner int
	kind  Kind
}

func notExist(op, p string) error { return &fs.PathError{Op: op, Path: p, Err: fs.ErrNotExist} }

// Whiteouted reports whether the merged view hides a lower layer at gp: gp or an
// ancestor carries a whiteout marker in the top layer. It reads the on-disk
// markers (the backend's single source of truth), so a caller stays consistent
// with whiteouts the backend writes, no in-memory mirror needed.
func (f *overlayFS) Whiteouted(gp string) bool {
	top := f.top()
	dn := top.Root()
	for _, name := range strings.Split(strings.Trim(gp, "/"), "/") {
		if name == "" {
			continue
		}
		if present(top, dn, WhiteoutPrefix+name) {
			return true
		}
		c, err := top.Lookup(dn, name)
		if err != nil {
			return false // top lacks this component, so no whiteout lies below it
		}
		dn = c
	}
	return false
}

func (f *overlayFS) Root() Node {
	nodes := make([]Node, len(f.layers))
	for i, L := range f.layers {
		nodes[i] = L.Root()
	}
	return &ovNode{fs: f, p: "", nodes: nodes, owner: len(f.layers) - 1, kind: Dir}
}

// present reports whether L's directory dn contains name.
func present(L FileSystem, dn Node, name string) bool {
	_, err := L.Lookup(dn, name)
	return err == nil
}

func (f *overlayFS) Lookup(dir Node, name string) (Node, error) {
	d := dir.(*ovNode)
	nodes := make([]Node, len(f.layers))
	owner := -1
	for i := len(f.layers) - 1; i >= 0; i-- {
		dn := d.nodes[i]
		if dn == nil {
			continue
		}
		L := f.layers[i]
		// A whiteout of name or an opaque dir only matters to stop the descent to
		// the layers below, so the two marker probes are pointless on the bottom
		// layer — nothing is beneath it. Skipping them there halves the host
		// lstats per component on the common lower-only resolve path.
		whited := i > 0 && present(L, dn, WhiteoutPrefix+name)
		if c, err := L.Lookup(dn, name); err == nil {
			nodes[i] = c
			if owner < 0 {
				owner = i
			}
		}
		if whited || (i > 0 && present(L, dn, OpaqueMarker)) {
			break // a whiteout of name, or an opaque dir, hides the lower layers
		}
	}
	if owner < 0 {
		return nil, notExist("lookup", path.Join(d.p, name))
	}
	return &ovNode{fs: f, p: path.Join(d.p, name), nodes: nodes, owner: owner, kind: nodes[owner].Kind()}, nil
}

func (f *overlayFS) ReadDir(dir Node) ([]Dirent, error) {
	d := dir.(*ovNode)
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
				continue // a whiteout/opaque marker or the metadata sidecar, not an entry
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

// layerNode resolves an overlay path within one layer, from its root.
func layerNode(L FileSystem, p string) (Node, bool) {
	n := L.Root()
	if p == "" {
		return n, true
	}
	for _, name := range strings.Split(p, "/") {
		c, err := L.Lookup(n, name)
		if err != nil {
			return nil, false
		}
		n = c
	}
	return n, true
}

// topDir ensures the directory at overlay path p exists in the top layer,
// copying ancestors up from the layer that provides them, and returns its node.
func (f *overlayFS) topDir(p string) (Node, error) {
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
	var srcID NodeID
	var haveSrc bool
	if sn, err := f.resolve(p); err == nil {
		if sa, e := sn.Stat(); e == nil {
			a = sa
		}
		srcID, haveSrc = sn.ID(), true
	}
	l := f.makingLock(p)
	l.Lock()
	c, err := f.top().Create(pn, path.Base(p), CreateSpec{Kind: Dir, Mode: a.Mode})
	if err != nil {
		l.Unlock()
		// Another goroutine copying the same shared parent up may have created it
		// first (concurrent writes under a CLONE_FILES thread group); take theirs.
		if n, ok := layerNode(f.top(), p); ok {
			return n, nil
		}
		return nil, err
	}
	f.recordMeta(c, a)
	l.Unlock()
	if haveSrc && srcID != c.ID() {
		f.meta.SetOrigin(c.ID(), srcID) // keep identity across the copy-up, as copyUp does
	}
	return c, nil
}

// copyUp makes the overlay path p present and writable in the top layer: a
// lower-only object is copied up with its contents and metadata.
func (f *overlayFS) copyUp(n *ovNode) (Node, error) {
	defer f.touch()
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
		// Another process copied it up while this one waited.
		n.nodes[len(f.layers)-1] = tn
		n.owner = len(f.layers) - 1
		return tn, nil
	}
	var tn Node
	switch a.Kind {
	case Dir:
		tn, err = f.top().Create(pdir, base, CreateSpec{Kind: Dir, Mode: a.Mode})
	case Symlink:
		tn, err = f.top().Create(pdir, base, CreateSpec{Kind: Symlink, Target: a.Target})
	case Reg:
		tn, err = f.copyUpReg(pdir, base, a, src)
	default:
		tn, err = f.top().Create(pdir, base, CreateSpec{Kind: a.Kind, Rdev: a.Rdev, Mode: a.Mode})
	}
	if err != nil {
		return nil, err
	}
	f.recordMeta(tn, a)
	// Preserve the source's times on the copy (a content write set them to now);
	// a symlink's own times are not meaningful to set.
	if a.Kind != Symlink && (a.Atime != 0 || a.Mtime != 0) {
		tn.SetAttr(AttrUpdate{Atime: &a.Atime, Mtime: &a.Mtime})
	}
	if src.ID() != tn.ID() {
		f.meta.SetOrigin(tn.ID(), src.ID()) // keep lock identity across the copy-up
	}
	n.nodes[len(f.layers)-1] = tn
	n.owner = len(f.layers) - 1
	return tn, nil
}

// copyUpReg copies a regular file up into the top layer, streaming its contents
// in fixed chunks so a large file (a multi-hundred-MB binary) is not buffered
// whole, and propagating read and write errors instead of silently truncating
// to an empty or partial file.
func (f *overlayFS) copyUpReg(pdir Node, name string, a Attr, src Node) (Node, error) {
	r, err := src.Open(os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// Create with the writable floored mode, not the guest mode: a sub-floor mode
	// (e.g. 0400) would leave the fresh file unwritable to the unprivileged host
	// owner, so the content copy below could not open it. recordMeta restores the
	// floor and records any sub-floor override after.
	tn, err := f.top().Create(pdir, name, CreateSpec{Kind: Reg, Mode: uint32(HostMode(a.Mode, false)) & 0o777})
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

func (f *overlayFS) writeTop(pdir Node, name string, a Attr, data []byte) (Node, error) {
	if w, ok := f.top().(WriteFileSystem); ok {
		return w.WriteFile(pdir, name, CreateSpec{Kind: Reg, Mode: a.Mode}, data)
	}
	n, err := f.top().Create(pdir, name, CreateSpec{Kind: Reg, Mode: a.Mode})
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

// recordMeta floors the top file's host mode and keeps the guest-uncarryable
// bits (sub-floor mode, non-root owner, special kind) in the shared store.
func (f *overlayFS) recordMeta(n Node, a Attr) {
	floored := uint32(HostMode(a.Mode, a.Kind == Dir)) & 0o7777
	n.SetAttr(AttrUpdate{Mode: &floored})
	f.meta.Update(n.ID(), func(o *Override) {
		if floored != a.Mode&0o7777 {
			o.Mode, o.HasMode = a.Mode&0o7777, true
		} else {
			o.HasMode = false
		}
		// Exactly a's owner, so a stale one an earlier file with this inode
		// left goes too.
		o.Uid, o.Gid, o.HasOwner = a.Uid, a.Gid, a.Uid != 0 || a.Gid != 0
		switch a.Kind {
		case Fifo, Chardev, Blockdev, Socket:
			o.Special, o.Kind, o.Rdev = true, a.Kind, a.Rdev
		default:
			// Clear any special-node metadata left on this inode: it may have
			// been reused from a removed device or fifo, and a regular file,
			// directory or symlink must not inherit that type (a stale Fifo
			// here sent a regular file into the FIFO-open rendezvous and hung).
			o.Special, o.Kind, o.Rdev = false, 0, 0
		}
	})
}

// unwhiteout removes a .wh.name marker from the top directory node, if present.
func (f *overlayFS) unwhiteout(topDir Node, name string) {
	if c, err := f.top().Lookup(topDir, WhiteoutPrefix+name); err == nil {
		f.top().Remove(topDir, WhiteoutPrefix+name, c.Kind() == Dir)
	}
}

func (f *overlayFS) Create(dir Node, name string, spec CreateSpec) (Node, error) {
	defer f.touch()
	d := dir.(*ovNode)
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
		c, err = f.writeTop(topDir, name, Attr{Kind: Reg, Mode: spec.Mode}, nil)
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
	f.recordMeta(c, Attr{Kind: spec.Kind, Mode: spec.Mode, Uid: spec.Uid, Gid: spec.Gid, Rdev: spec.Rdev})
	l.Unlock()
	return f.resolve(p) // fresh: dir may hold a stale top node from the copy-up
}

func (f *overlayFS) WriteFile(dir Node, name string, spec CreateSpec, data []byte) (Node, error) {
	defer f.touch()
	d := dir.(*ovNode)
	topDir, err := f.topDir(d.p)
	if err != nil {
		return nil, err
	}
	f.unwhiteout(topDir, name)
	p := join(d.p, name)
	l := f.makingLock(p)
	l.Lock()
	c, err := f.writeTop(topDir, name, Attr{Kind: Reg, Mode: spec.Mode}, data)
	if err != nil {
		l.Unlock()
		return nil, err
	}
	f.recordMeta(c, Attr{Kind: Reg, Mode: spec.Mode, Uid: spec.Uid, Gid: spec.Gid})
	l.Unlock()
	return f.resolve(p) // fresh: dir may hold a stale top node from the copy-up
}

func (f *overlayFS) Link(dir Node, name string, target Node) (Node, error) {
	defer f.touch()
	t, ok := target.(*ovNode)
	d, okd := dir.(*ovNode)
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
	return f.resolve(join(dir.(*ovNode).p, name)) // fresh: dir may hold a stale top node from the copy-up
}

func (f *overlayFS) Remove(dir Node, name string, isDir bool) error {
	defer f.touch()
	d := dir.(*ovNode)
	child, err := f.Lookup(dir, name)
	if err != nil {
		return err
	}
	c := child.(*ovNode)
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
// layer — the FileSystem-interface equivalent of os.RemoveAll — so a top copy
// holding only whiteout/opaque markers can be rmdir'd.
func (f *overlayFS) dropTopDir(parent Node, name string) error {
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
// copies its merged children up first, so a merged directory (whose entries
// come partly from a lower layer) is fully materialized in the top layer before
// it is renamed — otherwise the lower-only entries would be left behind at the
// old path and lost from the new one.
func (f *overlayFS) deepCopyUp(n *ovNode) error {
	if _, err := f.copyUp(n); err != nil { // the dir first, so children copy up into it
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
		if err := f.deepCopyUp(c.(*ovNode)); err != nil {
			return err
		}
	}
	return nil
}

func (f *overlayFS) Rename(fromDir Node, from string, toDir Node, to string) error {
	defer f.touch()
	src, err := f.Lookup(fromDir, from)
	if err != nil {
		return err
	}
	if err := f.deepCopyUp(src.(*ovNode)); err != nil {
		return err
	}
	fTop, err := f.topDir(fromDir.(*ovNode).p)
	if err != nil {
		return err
	}
	tTop, err := f.topDir(toDir.(*ovNode).p)
	if err != nil {
		return err
	}
	f.unwhiteout(tTop, to)
	if err := f.top().Rename(fTop, from, tTop, to); err != nil {
		return err
	}
	// Hide the old name if a lower layer still shows it.
	for i := 0; i < len(f.layers)-1; i++ {
		if src.(*ovNode).nodes[i] != nil {
			f.top().Create(fTop, WhiteoutPrefix+from, CreateSpec{Kind: Reg})
			break
		}
	}
	return nil
}

// ExchangeRenamer is the optional capability of a FileSystem that can swap two
// entries atomically (RENAME_EXCHANGE). Both names must exist.
type ExchangeRenamer interface {
	RenameExchange(fromDir Node, from string, toDir Node, to string) error
}

// RenameExchange swaps from and to atomically. Both are deep-copied up so a
// merged directory is fully materialized in the top, then the top layer swaps
// them; no whiteout is needed, since each path keeps a top entry (the other's
// old content) that shadows its lower.
func (f *overlayFS) RenameExchange(fromDir Node, from string, toDir Node, to string) error {
	defer f.touch()
	src, err := f.Lookup(fromDir, from)
	if err != nil {
		return err
	}
	dst, err := f.Lookup(toDir, to)
	if err != nil {
		return err
	}
	if err := f.deepCopyUp(src.(*ovNode)); err != nil {
		return err
	}
	if err := f.deepCopyUp(dst.(*ovNode)); err != nil {
		return err
	}
	fTop, err := f.topDir(fromDir.(*ovNode).p)
	if err != nil {
		return err
	}
	tTop, err := f.topDir(toDir.(*ovNode).p)
	if err != nil {
		return err
	}
	xr, ok := f.top().(ExchangeRenamer)
	if !ok {
		return &fs.PathError{Op: "renameexchange", Path: from, Err: fs.ErrInvalid}
	}
	return xr.RenameExchange(fTop, from, tTop, to)
}

// stat returns the merged attributes of an overlay path (for internal copy-up).
func (f *overlayFS) stat(p string) (Attr, bool) {
	n, err := f.resolve(p)
	if err != nil {
		return Attr{}, false
	}
	a, err := n.Stat()
	return a, err == nil
}

func (f *overlayFS) resolve(p string) (*ovNode, error) {
	n := f.Root()
	p = clean(p)
	if p == "" {
		return n.(*ovNode), nil
	}
	for _, name := range strings.Split(p, "/") {
		c, err := f.Lookup(n, name)
		if err != nil {
			return nil, err
		}
		n = c
	}
	return n.(*ovNode), nil
}

// StatFS forwards to the layer that owns n, so statfs reports the host
// filesystem actually backing the node rather than the union abstraction.
func (f *overlayFS) StatFS(n Node) (StatFS, error) {
	on := n.(*ovNode)
	sf, ok := f.layers[on.owner].(StatFSer)
	if !ok {
		return StatFS{}, &fs.PathError{Op: "statfs", Path: on.p, Err: fs.ErrInvalid}
	}
	return sf.StatFS(on.nodes[on.owner])
}

// Getxattr/Listxattr read from the layer that owns n; Setxattr/Removexattr copy
// n up first so the change lands in the writable top, like any other mutation.
func (n *ovNode) Getxattr(name string) ([]byte, error) {
	xn, ok := n.nodes[n.owner].(XattrNode)
	if !ok {
		return nil, ErrXattrUnsupported
	}
	return xn.Getxattr(name)
}

func (n *ovNode) Listxattr() ([]byte, error) {
	xn, ok := n.nodes[n.owner].(XattrNode)
	if !ok {
		return nil, ErrXattrUnsupported
	}
	return xn.Listxattr()
}

func (n *ovNode) Setxattr(name string, value []byte, flags int) error {
	defer n.fs.touch()
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

func (n *ovNode) Removexattr(name string) error {
	defer n.fs.touch()
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

// Underlying is the node of the layer that currently owns n, for a consumer
// that must reach the concrete backend — e.g. the supervisor's AF_UNIX bind,
// which needs a real host socket path. WritableUnderlying first copies n up, so
// the path is in the writable top.
func (n *ovNode) Underlying() Node { return n.nodes[n.owner] }

func (n *ovNode) WritableUnderlying() (Node, error) { return n.fs.copyUp(n) }

func (n *ovNode) ID() NodeID { return n.nodes[n.owner].ID() }
func (n *ovNode) Kind() Kind { return n.kind }

func (n *ovNode) Stat() (Attr, error) {
	if n.owner == len(n.fs.layers)-1 {
		l := n.fs.makingLock(n.p)
		l.RLock()
		defer l.RUnlock()
	}
	a, err := n.nodes[n.owner].Stat()
	if err != nil {
		return Attr{}, err
	}
	if a.Kind == Dir {
		// A merged directory's link count is unknown (entries come from several
		// layers), so report 1, as Linux overlayfs does.
		a.Nlink = 1
	}
	// Apply the guest metadata overrides by the node's own inode, so the overlay is
	// the single authority for them: a top-layer file's guest chown/chmod and a
	// lower layer's owner/mode/special sidecar both resolve here, rather than a
	// lower file's owner being post-processed by the sandbox above the vfs. The
	// store is inode-keyed and each layer's node IDs are distinct, so a node only
	// ever matches an override recorded for itself.
	if o, ok := n.fs.meta.Get(n.ID()); ok {
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
	return a, nil
}

func (n *ovNode) SetAttr(u AttrUpdate) error {
	defer n.fs.touch()
	tn, err := n.fs.copyUp(n)
	if err != nil {
		return err
	}
	if u.Mode != nil {
		floored := uint32(HostMode(*u.Mode, n.kind == Dir)) & 0o7777
		if err := tn.SetAttr(AttrUpdate{Mode: &floored}); err != nil {
			return err
		}
		guest := *u.Mode & 0o7777
		sub := floored != guest
		n.fs.meta.Update(tn.ID(), func(o *Override) {
			if sub {
				o.Mode, o.HasMode = guest, true
			} else {
				o.HasMode = false
			}
		})
	}
	if u.Uid != nil || u.Gid != nil {
		var uid, gid uint32
		if u.Uid != nil {
			uid = *u.Uid
		}
		if u.Gid != nil {
			gid = *u.Gid
		}
		n.fs.meta.Update(tn.ID(), func(o *Override) {
			o.Uid, o.Gid, o.HasOwner = uid, gid, uid != 0 || gid != 0
		})
	}
	if u.Atime != nil || u.Mtime != nil {
		if err := tn.SetAttr(AttrUpdate{Atime: u.Atime, Mtime: u.Mtime}); err != nil {
			return err
		}
	}
	return nil
}

func (n *ovNode) Readlink() (string, error) { return n.nodes[n.owner].Readlink() }

func (n *ovNode) Open(flags int) (File, error) {
	// Only a regular file's content is copied up on a writable open. A special
	// node (fifo, device, socket) is opened in place: writing it does not change
	// the file, so there is nothing to copy up.
	if flags&(os.O_WRONLY|os.O_RDWR) != 0 && n.kind == Reg {
		tn, err := n.fs.copyUp(n)
		if err != nil {
			return nil, err
		}
		return tn.Open(flags)
	}
	return n.nodes[n.owner].Open(flags)
}
