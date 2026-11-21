package readonly

import (
	"syscall"

	. "github.com/samyfodil/laboon/core"
)

// ReadOnly wraps fs so every namespace mutation — create, link, remove, rename
// — fails with EROFS, while lookups and reads pass through. File content is not
// written through the FileSystem interface (the host file is opened directly),
// so the open path refuses a write-mode open under a read-only mount; IsReadOnly
// lets it tell.
func ReadOnly(fs FileSystem) FileSystem { return &readOnlyFS{FileSystem: fs} }

type readOnlyFS struct{ FileSystem }

func (*readOnlyFS) ReadOnlyMount() {}

func (*readOnlyFS) Create(Node, string, CreateSpec) (Node, error) { return nil, syscall.EROFS }
func (*readOnlyFS) Link(Node, string, Node) (Node, error)         { return nil, syscall.EROFS }
func (*readOnlyFS) Remove(Node, string, bool) error               { return syscall.EROFS }
func (*readOnlyFS) Rename(Node, string, Node, string) error       { return syscall.EROFS }

// BindSocket refuses a new name; ReachSocket passes through, so a host socket
// under a read-only bind (an X server's) stays reachable.
func (r *readOnlyFS) BindSocket(Node, string, func(string) error) (Node, error) {
	return nil, syscall.EROFS
}

func (r *readOnlyFS) ReachSocket(n Node, op func(addr string) error) error {
	s, ok := r.FileSystem.(SocketFS)
	if !ok {
		return ErrSocketUnsupported
	}
	return s.ReachSocket(n, op)
}
