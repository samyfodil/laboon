package namespace

import (
	"errors"
	"io/fs"
	"path"
	"strings"
	"sync"

	. "github.com/samyfodil/laboon/core"
)

// A Namespace is the mount tree and the path resolver over it. It is the one
// place that turns a multi-component path into a node: it walks the path one
// component at a time, follows symlinks, crosses mount points and stays confined
// to its root, so no FileSystem implementation has to. This mirrors the Linux
// split between the mount namespace and the individual filesystems.
type Namespace struct {
	root   FileSystem
	mounts map[string]FileSystem // clean absolute mount point ("/x/y") -> filesystem
	policy Policy

	// Path resolution is a hot path (every stat/open walks every component
	// through both overlay layers). When the root reports a mutation generation
	// (generational), cache the walked location per (path, followLast) and reuse
	// it while the generation is unchanged. Any mutation bumps the generation and
	// so invalidates every entry; Mount clears the cache since mounts are not
	// part of the overlay's generation.
	genOf   func() uint64 // nil if the root does not report a generation
	touch   func()        // bumps the root's generation, for Invalidate
	cacheMu sync.Mutex
	cache   map[resolveKey]resolveEnt
}

type resolveKey struct {
	p          string
	followLast bool
}

// resolveEnt caches a successful resolution. Only successes are cached, so there
// is no error field. loc.Node is a private pristine node; a hit returns a clone.
type resolveEnt struct {
	gen uint64
	loc Loc
}

// resolveCacheMax bounds the cache; at the limit it is dropped whole (the next
// resolutions refill it), which is simpler than an LRU and fine for a cache
// whose entries are cheap to recompute.
const resolveCacheMax = 1 << 14

// Policy decides what operation op may do at the resolved absolute path:
//   - return ("", nil) to allow it,
//   - return a non-nil error to deny it (resolution fails with that error),
//   - return (other, nil) to redirect the operation to the path other instead.
//
// It is the agent-sandbox chokepoint: every operation that resolves through the
// Namespace passes its fully-resolved path here, so a symlink or ".." cannot
// smuggle an access past it. op is "" for a bare Resolve; routed syscalls name
// theirs ("open", "unlink", ...).
type Policy func(op, path string) (redirect string, err error)

// SetPolicy installs (or clears, with nil) the policy consulted on every
// resolution.
func (ns *Namespace) SetPolicy(p Policy) { ns.policy = p }

// Whiteouted reports whether the namespace's root filesystem hides a lower layer
// at gp — an overlay whiteout on gp or an ancestor. It is false for a root that
// is not an overlay (nothing to hide).
func (ns *Namespace) Whiteouted(gp string) bool {
	if o, ok := ns.root.(interface{ Whiteouted(string) bool }); ok {
		return o.Whiteouted(gp)
	}
	return false
}

// NewNamespace starts a namespace whose root ("/") is root.
func NewNamespace(root FileSystem) *Namespace {
	ns := &Namespace{root: root, mounts: map[string]FileSystem{}}
	if g, ok := root.(Generational); ok {
		ns.genOf = g.Gen
		ns.touch = g.Touch
	}
	return ns
}

// Invalidate marks the resolve cache stale, for a mutation made to the
// underlying filesystem outside the overlay's own methods (e.g. a whiteout
// written straight to the top layer). It bumps the root's generation, so every
// cached resolution taken before now is discarded.
func (ns *Namespace) Invalidate() {
	if ns.touch != nil {
		ns.touch()
	}
}

// cloneNode returns an independent copy of an overlay node, so a cache hit never
// hands out a node another caller might mutate in place (copy-up rewrites a
// node's layer and owner). It returns nil for any other node type, which tells
// the caller the result is not cacheable.
func cloneNode(n Node) Node {
	if c, ok := n.(Cloner); ok {
		return c.CloneNode()
	}
	return nil
}

// Mount attaches fs at the absolute directory at, which must already resolve to
// a directory. A later resolution that reaches at enters fs at its root.
func (ns *Namespace) Mount(at string, mfs FileSystem) error {
	at = "/" + clean(at)
	if _, err := ns.Resolve(at, true); err != nil {
		return err
	}
	ns.mounts[at] = mfs
	ns.cacheMu.Lock()
	ns.cache = nil // mounts changed; mounts are not in the root's generation
	ns.cacheMu.Unlock()
	return nil
}

// MountShadow attaches fs at the absolute directory at without requiring at to
// already resolve: the mount shadows whatever is (or is not) at that path, so a
// bind the embedder declares works even where the backing filesystem has no
// such directory. walk enters the mount by path, so no mount point is needed.
func (ns *Namespace) MountShadow(at string, mfs FileSystem) {
	at = "/" + clean(at)
	ns.mounts[at] = mfs
	ns.cacheMu.Lock()
	ns.cache = nil
	ns.cacheMu.Unlock()
}

// Unmount removes the mount at the given point and reports whether one was
// there. A path that is not a mount point is left untouched.
func (ns *Namespace) Unmount(at string) bool {
	at = "/" + clean(at)
	if _, ok := ns.mounts[at]; !ok {
		return false
	}
	delete(ns.mounts, at)
	ns.cacheMu.Lock()
	ns.cache = nil
	ns.cacheMu.Unlock()
	return true
}

// Loc is a resolved location: the filesystem reached and the node within it,
// plus the absolute path it resolved to (for "..", cwd and mount crossing).
type Loc struct {
	FS   FileSystem
	Node Node
	Path string // clean absolute, no trailing slash ("" means "/")
}

const maxSymlinkHops = 40

// Resolve walks p from the namespace root to a location. followLast controls
// whether a trailing symlink is followed (stat follows, lstat/readlink/unlink do
// not). An absolute symlink target restarts at the namespace root, never the
// host root, so resolution cannot escape the namespace.
func (ns *Namespace) Resolve(p string, followLast bool) (Loc, error) {
	return ns.ResolveOp("", p, followLast)
}

// ResolveOp is Resolve naming the operation for the policy hook: it resolves p,
// then (if a policy is set) consults it with the fully-resolved path, so the
// check sees the real target, not the symlink or "." / ".." the caller passed.
func (ns *Namespace) ResolveOp(op, p string, followLast bool) (Loc, error) {
	loc, err := ns.resolve(p, followLast, 0)
	if err != nil {
		return Loc{}, err
	}
	if ns.policy != nil {
		redirect, err := ns.policy(op, loc.Path)
		if err != nil {
			return Loc{}, err
		}
		if redirect != "" && redirect != loc.Path {
			// Resolve the redirect target once; the policy is not re-applied to it,
			// so a redirect cannot loop.
			return ns.resolve(redirect, followLast, 0)
		}
	}
	return loc, nil
}

// resolve is walk with a result cache, consulted only for a top-level call
// (hops == 0) so the cache key need not carry the symlink-hop budget. A cached
// entry is reused only while the root's mutation generation is unchanged; a
// result that raced a concurrent mutation (generation moved during the walk) is
// not stored. Only a success or a not-exist miss is cached.
func (ns *Namespace) resolve(p string, followLast bool, hops int) (Loc, error) {
	if ns.genOf == nil || hops != 0 {
		var crossed bool
		return ns.walk(p, followLast, hops, &crossed, "", nil)
	}
	g := ns.genOf()
	key := resolveKey{p: p, followLast: followLast}
	ns.cacheMu.Lock()
	if e, ok := ns.cache[key]; ok && e.gen == g {
		loc := e.loc
		loc.Node = cloneNode(loc.Node) // a fresh node per hit: copy-up mutates the node in place, so hits must not share one
		ns.cacheMu.Unlock()
		return loc, nil
	}
	ns.cacheMu.Unlock()
	var crossed bool
	loc, err := ns.walk(p, followLast, 0, &crossed, "", nil)
	// Cache only a success that stayed within the versioned overlay root. Skip
	// it if the walk crossed a mount (a dynamic fs like /proc is not covered by
	// the overlay's generation, and a /proc/self/fd link can resolve back into
	// the overlay), or if a mutation bumped the generation during the walk.
	// Errors are never cached: a lower-layer lstat failure is masked as
	// ErrNotExist, so a transient error must not stick as a permanent miss.
	if err == nil && !crossed && ns.genOf() == g {
		if cn := cloneNode(loc.Node); cn != nil {
			stored := loc
			stored.Node = cn
			ns.cacheMu.Lock()
			if ns.cache == nil || len(ns.cache) >= resolveCacheMax {
				ns.cache = make(map[resolveKey]resolveEnt)
			}
			ns.cache[key] = resolveEnt{gen: g, loc: stored}
			ns.cacheMu.Unlock()
		}
	}
	return loc, err
}

// A Walk is how a process resolves a path: under its root, from a starting
// directory, within the limits openat2 can ask for. Walk.Path resolves with it.
type Walk struct {
	Root       string // the process root: ".." stops there and an absolute path or symlink restarts there ("/" if empty)
	Start      string // the directory a relative path starts from (Root if empty)
	InRoot     bool   // resolve as if Start were the root (RESOLVE_IN_ROOT)
	Beneath    bool   // fail with ErrCrossDevice on leaving Start (RESOLVE_BENEATH)
	NoSymlinks bool   // fail with ErrLoop on any symlink (RESOLVE_NO_SYMLINKS)
	NoMagic    bool   // fail with ErrLoop on a magic link (RESOLVE_NO_MAGICLINKS)
	FollowLast bool   // follow a symlink in the final component
}

// walkOpts carries a Walk into walk; a nil one is a plain Resolve.
type walkOpts struct {
	root       string // clean absolute, "" for the namespace root
	scoped     bool   // root is an openat2 scope: magic links are refused
	beneath    bool
	noSymlinks bool
	noMagic    bool
	missingOK  bool // a missing final component ends the walk at its path
}

// Path resolves p as w says and returns the symlink-free absolute path it
// names, "/" for the root. The final component need not exist (its path is
// returned for a create); every directory before it must. A procfs magic link
// resolves to the object it names: a path in the namespace whatever the root,
// or the link itself.
func (w Walk) Path(ns *Namespace, p string) (string, error) {
	root := strings.TrimSuffix("/"+clean(w.Root), "/")
	start := root
	if w.Start != "" {
		start = strings.TrimSuffix("/"+clean(w.Start), "/")
	}
	o := &walkOpts{root: root, noSymlinks: w.NoSymlinks, noMagic: w.NoMagic, missingOK: true}
	if w.InRoot || w.Beneath {
		o.root, o.scoped, o.beneath = start, true, w.Beneath
	}
	p = strings.TrimRight(p, "/")
	if path.IsAbs(p) {
		if o.beneath {
			return "", &fs.PathError{Op: "resolve", Path: p, Err: ErrCrossDevice}
		}
		start = o.root
	}
	if !o.scoped && o.root == "" && !o.noSymlinks && !o.noMagic && path.IsAbs(p) {
		// The common case, an unchrooted absolute path: the cached Resolve
		// answers whenever the path exists.
		if loc, err := ns.resolve(p, w.FollowLast, 0); err == nil {
			return absPath(loc.Path), nil
		}
	}
	var crossed bool
	loc, err := ns.walk(start+"/"+p, w.FollowLast, 0, &crossed, "", o)
	if err != nil {
		return "", err
	}
	return absPath(loc.Path), nil
}

func absPath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func (ns *Namespace) walk(p string, followLast bool, hops int, crossed *bool, floor string, o *walkOpts) (Loc, error) {
	cur := ns.at("")
	// Split raw, not cleaned: path.Clean collapses "a/link/.." to "a" lexically,
	// which skips following link. POSIX resolves ".." against the symlink target,
	// so the walk must see each "." / ".." / "" component (handled below) rather
	// than a pre-cleaned path.
	parts := strings.Split(p, "/")
	last := len(parts) - 1
	for last > 0 && parts[last] == "" {
		last-- // a trailing slash leaves the final name the last component
	}
	for i, name := range parts {
		switch name {
		case "", ".":
			continue
		case "..":
			if o != nil && cur.Path == o.root {
				if o.beneath {
					return Loc{}, &fs.PathError{Op: "resolve", Path: p, Err: ErrCrossDevice}
				}
				continue // ".." at the process root stays there
			}
			par := parent(cur.Path)
			if floor != "" && len(par) < len(floor) {
				par = floor // a confined symlink's "../" cannot climb above the instance root
			}
			cur = ns.at(par)
			if cur.FS != ns.root {
				*crossed = true // ".." landed in a mounted (unversioned) filesystem
			}
			continue
		}
		childPath := fastJoin(cur.Path, name)
		// A mount point shadows whatever is at its path: enter the mounted
		// filesystem's root without requiring the point to exist underneath, so
		// a bind at a path the backing fs lacks still resolves (a mount point
		// that does exist ends up here too, with the same result).
		if mfs, ok := ns.mounts[childPath]; ok {
			*crossed = true
			cur = Loc{FS: mfs, Node: mfs.Root(), Path: childPath}
			continue
		}
		if cur.Node.Kind() != Dir {
			return Loc{}, &fs.PathError{Op: "resolve", Path: p, Err: ErrNotDir}
		}
		child, err := cur.FS.Lookup(cur.Node, name)
		if err != nil {
			if o != nil && o.missingOK && i >= last && errors.Is(err, fs.ErrNotExist) {
				return Loc{FS: cur.FS, Path: childPath}, nil
			}
			return Loc{}, err
		}
		isLast := i >= last
		if child.Kind() == Symlink && (!isLast || followLast) {
			if o != nil && o.noSymlinks {
				return Loc{}, &fs.PathError{Op: "resolve", Path: p, Err: ErrLoop}
			}
			if hops++; hops > maxSymlinkHops {
				return Loc{}, &fs.PathError{Op: "resolve", Path: p, Err: ErrLoop}
			}
			// A magic link names an object (an absolute target, or a token); a
			// relative target on a MagicLinker is an ordinary symlink (/proc/self).
			if m, ok := child.(MagicLinker); ok && o != nil {
				if tgt, isPath := m.MagicLink(); !isPath || path.IsAbs(tgt) {
					switch {
					case o.noMagic:
						return Loc{}, &fs.PathError{Op: "resolve", Path: p, Err: ErrLoop}
					case o.scoped:
						return Loc{}, &fs.PathError{Op: "resolve", Path: p, Err: ErrCrossDevice}
					case !isPath:
						if !isLast {
							return Loc{}, &fs.PathError{Op: "resolve", Path: p, Err: ErrNotDir}
						}
						cur = Loc{FS: cur.FS, Node: child, Path: childPath}
						continue
					}
					next, err := ns.walk(tgt, true, hops, crossed, "", o.forLink(isLast))
					if err != nil {
						return Loc{}, err
					}
					cur = next
					continue
				}
			}
			tgt, err := child.Readlink()
			if err != nil {
				return Loc{}, err
			}
			// A confined filesystem (HardenFS with WithConfinedLinks) is a symlink
			// boundary: its links resolve relative to its own mount point, so an
			// absolute target restarts there and "../" cannot climb out. Any other
			// filesystem keeps Linux semantics — an absolute target restarts at the
			// process root — which is what a guest tmpfs needs.
			symFloor := floor
			if c, ok := cur.FS.(Confined); ok && c.Confined() {
				symFloor = ns.mountPointOf(cur.Path)
			}
			base := cur.Path
			if path.IsAbs(tgt) {
				switch {
				case symFloor != "":
					base = symFloor
				case o != nil && o.beneath:
					return Loc{}, &fs.PathError{Op: "resolve", Path: p, Err: ErrCrossDevice}
				case o != nil:
					base = o.root
				default:
					base = ""
				}
			}
			target := join(base, tgt)
			if symFloor != "" || o != nil {
				// Confined, or under a process root: walk the uncleaned path so the
				// walk's clamped "../" handling resolves it, instead of join
				// collapsing "../" lexically — which would let a relative target
				// escape the root.
				target = base + "/" + tgt
			}
			// Resolve the target with walk, not resolve: hops>0 never caches, and
			// passing crossed through propagates a mount a symlink target traverses
			// (e.g. a /proc/self/fd link) so the outer result is not cached.
			next, err := ns.walk(target, true, hops, crossed, symFloor, o.forLink(isLast))
			if err != nil {
				return Loc{}, err
			}
			cur = next
			continue
		}
		cur = Loc{FS: cur.FS, Node: child, Path: childPath}
	}
	return cur, nil
}

// forLink is o for the walk of a symlink's target: its final component may be
// missing only when the link was the path's last (a create through a dangling
// link makes the target).
func (o *walkOpts) forLink(last bool) *walkOpts {
	if o == nil || !o.missingOK || last {
		return o
	}
	c := *o
	c.missingOK = false
	return &c
}

// MountOf returns the mount point covering the clean absolute path p (the
// longest at or above it, "/" for the root) and the filesystem mounted there.
func (ns *Namespace) MountOf(p string) (string, FileSystem) {
	best, bestFS := "/", ns.root
	for mp, mfs := range ns.mounts {
		if (p == mp || strings.HasPrefix(p, mp+"/")) && len(mp) > len(best) {
			best, bestFS = mp, mfs
		}
	}
	return best, bestFS
}

// at returns the location for an absolute path already known to resolve, used
// for "/" and ".." where no lookup or symlink handling is needed.
func (ns *Namespace) at(abs string) Loc {
	abs = "/" + clean(abs)
	best, bestFS := ns.MountOf(abs)
	// Walk from bestFS root to abs without symlink/mount handling (callers use
	// this only for "/" and parent of an already-resolved path).
	cur := Loc{FS: bestFS, Node: bestFS.Root(), Path: strings.TrimSuffix(best, "/")}
	for _, name := range splitPath(strings.TrimPrefix(abs, best)) {
		if name == "" || name == "." {
			continue
		}
		child, err := cur.FS.Lookup(cur.Node, name)
		if err != nil {
			return cur // best effort; parent of a resolved path exists
		}
		cur = Loc{FS: cur.FS, Node: child, Path: fastJoin(cur.Path, name)}
	}
	return cur
}

// mountPointOf returns the longest mount point at or above the absolute path p,
// or "" if p is in the root filesystem. It is the instance root a confined mount
// confines its symlinks to.
func (ns *Namespace) mountPointOf(p string) string {
	best := ""
	for mp := range ns.mounts {
		if (p == mp || strings.HasPrefix(p, mp+"/")) && len(mp) > len(best) {
			best = mp
		}
	}
	return best
}

func splitPath(p string) []string { return strings.Split(clean(p), "/") }

func parent(abs string) string {
	if i := strings.LastIndexByte(abs, '/'); i > 0 {
		return abs[:i]
	}
	return ""
}

func join(base, name string) string { return "/" + clean(base+"/"+name) }

// fastJoin appends one already-clean component to a clean absolute base (""
// means root), skipping the path.Clean that join does. The caller guarantees
// base is clean with no trailing slash and name is a single component — not "",
// ".", ".." and no "/". The resolve walk meets that for every component and is
// the hot path, so this drops a path.Clean per component. For base "/a" and
// name "b" it yields "/a/b", matching join; for base "" it yields "/b".
func fastJoin(base, name string) string { return base + "/" + name }

func clean(p string) string { return strings.Trim(path.Clean("/"+p), "/") }
