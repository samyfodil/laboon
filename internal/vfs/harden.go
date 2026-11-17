package vfs

import "syscall"

// HardenFS wraps fs and removes capabilities an embedder does not want a mounted
// filesystem to carry, each denied with EPERM and the rest passing through. It
// composes with the other wrappers (ReadOnly, the backends), so a mount can be
// assembled from independent, orthogonal properties:
//
//	HardenFS(NewMemFS(), WithNoSymLink(), WithNoDevice(), WithNoSocket())
//
// WithConfinedLinks additionally makes symlinks resolve relative to this
// filesystem's own root rather than the namespace root (see Confined), so a
// symlink inside the instance cannot name a path outside it.
func HardenFS(fs FileSystem, opts ...HardenOption) FileSystem {
	h := &hardenFS{FileSystem: fs}
	for _, o := range opts {
		o(h)
	}
	return h
}

// A HardenOption turns off one capability of a HardenFS.
type HardenOption func(*hardenFS)

// WithNoHardLink denies hardlink creation (link → EPERM).
func WithNoHardLink() HardenOption { return func(h *hardenFS) { h.noHardLink = true } }

// WithNoSymLink denies symlink creation (symlink → EPERM).
func WithNoSymLink() HardenOption { return func(h *hardenFS) { h.noSymLink = true } }

// WithNoDevice denies device-node creation (mknod of a char/block device → EPERM).
func WithNoDevice() HardenOption { return func(h *hardenFS) { h.noDevice = true } }

// WithNoSocket denies filesystem-socket creation (mknod of a socket → EPERM).
func WithNoSocket() HardenOption { return func(h *hardenFS) { h.noSocket = true } }

// WithNoFifo denies named-pipe creation (mknod of a fifo → EPERM).
func WithNoFifo() HardenOption { return func(h *hardenFS) { h.noFifo = true } }

// WithConfinedLinks makes the resolver treat this filesystem as a symlink
// confinement boundary (see Confined).
func WithConfinedLinks() HardenOption { return func(h *hardenFS) { h.confined = true } }

type hardenFS struct {
	FileSystem
	noHardLink bool
	noSymLink  bool
	noDevice   bool
	noSocket   bool
	noFifo     bool
	confined   bool
}

func (h *hardenFS) Create(dir Node, name string, spec CreateSpec) (Node, error) {
	switch spec.Kind {
	case Symlink:
		if h.noSymLink {
			return nil, syscall.EPERM
		}
	case Chardev, Blockdev:
		if h.noDevice {
			return nil, syscall.EPERM
		}
	case Socket:
		if h.noSocket {
			return nil, syscall.EPERM
		}
	case Fifo:
		if h.noFifo {
			return nil, syscall.EPERM
		}
	}
	return h.FileSystem.Create(dir, name, spec)
}

func (h *hardenFS) Link(dir Node, name string, target Node) (Node, error) {
	if h.noHardLink {
		return nil, syscall.EPERM
	}
	return h.FileSystem.Link(dir, name, target)
}

// Confined reports whether the resolver should treat this filesystem as a
// symlink boundary: a symlink read from it resolves relative to the filesystem's
// own mount point, so an absolute target restarts at that root (not the
// namespace root) and "../" cannot climb above it. Navigation into and out of
// the mount by path is unaffected — only symlink targets are confined. This is a
// hardening choice an embedder opts into (WithConfinedLinks); a guest tmpfs is
// deliberately not confined, so it keeps exact Linux symlink semantics.
func (h *hardenFS) Confined() bool { return h.confined }

// Confined is the optional capability namespace resolution honors for symlink
// confinement; see hardenFS.Confined.
type Confined interface {
	Confined() bool
}
