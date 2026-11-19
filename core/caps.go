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

// Cloner is a Node that can return an independent copy of itself, so a resolver
// cache never hands out a node another caller might mutate in place (a copy-up
// rewrites a union node's layer and owner). A node that cannot be cloned safely
// does not implement it, and such results are not cached.
type Cloner interface {
	CloneNode() Node
}

// Underlying is a Node of a union filesystem that can hand back the concrete
// backing node a consumer must reach -- e.g. an AF_UNIX bind that asks the disk
// leaf for its real host socket path. WritableUnderlying first copies the node up
// so the backing node is in the writable top layer.
type Underlying interface {
	Underlying() Node
	WritableUnderlying() (Node, error)
}

// ReadOnlyFS marks a FileSystem whose namespace is immutable, so a caller can
// refuse a write-mode open before attempting it. A filesystem that is read-only
// of itself implements it directly; the readonly wrapper adds it to any other.
type ReadOnlyFS interface{ ReadOnlyMount() }

// IsReadOnly reports whether fs is marked read-only.
func IsReadOnly(fs FileSystem) bool { _, ok := fs.(ReadOnlyFS); return ok }
