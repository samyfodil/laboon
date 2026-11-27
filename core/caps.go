package core

import "errors"

// This file holds the optional capability interfaces a FileSystem or Node may
// implement. They live in core so a consumer (the resolver, the sandbox) can
// type-assert for them without importing any concrete filesystem, and a
// filesystem in another package can satisfy them with exported methods.

// ErrNoHostFile is returned by Open for a node with no byte content to open as a
// host file (a directory, a special node).
var ErrNoHostFile = errors.New("vfs: node has no host file")

// ExchangeRenamer is a FileSystem that can swap two entries atomically
// (RENAME_EXCHANGE). Both names must exist.
type ExchangeRenamer interface {
	RenameExchange(fromDir Node, from string, toDir Node, to string) error
}

// Confined is a FileSystem that confines its symlinks to its own mount point: an
// absolute target restarts there and "../" cannot climb out. The resolver asks
// this to decide a symlink's floor.
type Confined interface {
	Confined() bool
}

// Generational is a FileSystem that reports a monotonic counter bumped on every
// mutation and lets an outside mutator bump it, so the resolver's path cache can
// tell when a cached walk is still valid. A copy-on-write union implements it;
// an immutable or simple filesystem need not.
type Generational interface {
	Gen() uint64
	Touch()
}

// DirGenerational is a Generational FileSystem that also places its mutations:
// DirGen(dir) moves whenever a name in the directory dir (a path from the
// root, "" or "/" for the root) may resolve differently, and Epoch moves on a
// Touch, a mutation it cannot place. A counter may be shared by several
// directories, which only makes it move more often.
type DirGenerational interface {
	Generational
	Epoch() uint64
	DirGen(dir string) uint64
}

// Cloner is a Node that can return an independent copy of itself, so a resolver
// cache never hands out a node another caller might mutate in place (a copy-up
// rewrites a union node's layer and owner). A node that cannot be cloned safely
// does not implement it, and such results are not cached.
type Cloner interface {
	CloneNode() Node
}

// ReadOnlyFS marks a FileSystem whose namespace is immutable, so a caller can
// refuse a write-mode open before attempting it. A filesystem that is read-only
// of itself implements it directly; the readonly wrapper adds it to any other.
type ReadOnlyFS interface{ ReadOnlyMount() }

// IsReadOnly reports whether fs is marked read-only.
func IsReadOnly(fs FileSystem) bool { _, ok := fs.(ReadOnlyFS); return ok }

// Layered is a union FileSystem that can name the layer holding one of its
// nodes: that layer's own filesystem and node, with the union's conventions
// (whiteout and opaque markers) left as written. A union assembled over a
// directory of this one (a guest's overlay mount) reads its layers there, so the
// markers it writes stay visible to it.
type Layered interface {
	Layer(n Node) (FileSystem, Node)
}

// MagicLinker is a symlink Node whose target names an object rather than a
// path under the reader's root, as procfs's fd, cwd and exe links do. When
// isPath, the target is a path in the namespace and resolves there whatever
// root the reader has; otherwise (a "net:[4026531840]" token) the link resolves
// to itself.
type MagicLinker interface {
	MagicLink() (target string, isPath bool)
}
