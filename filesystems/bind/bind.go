package bind

import (
	"errors"
	"syscall"

	. "github.com/samyfodil/laboon/core"
)

// Bind presents the subtree rooted at root (a node of fs) as its own
// FileSystem, for a bind mount. Its root is root and every operation under it
// runs on fs with fs's own nodes — the nodes are forwarded unwrapped, so a
// backend that checks a node's concrete type (the overlay's hardlink) still
// sees its own. It is mounted in a Namespace like any other FileSystem, so a
// path under the bind resolves through the same walk and policy hook.
type bindFS struct {
	fs   FileSystem
	root Node
}

// Bind makes a FileSystem presenting fs's subtree at root.
func Bind(fs FileSystem, root Node) FileSystem { return &bindFS{fs: fs, root: root} }

func (b *bindFS) Root() Node                                 { return b.root }
func (b *bindFS) Lookup(dir Node, name string) (Node, error) { return b.fs.Lookup(dir, name) }
func (b *bindFS) ReadDir(dir Node) ([]Dirent, error)         { return b.fs.ReadDir(dir) }
func (b *bindFS) Create(dir Node, name string, spec CreateSpec) (Node, error) {
	return b.fs.Create(dir, name, spec)
}
func (b *bindFS) Link(dir Node, name string, target Node) (Node, error) {
	return b.fs.Link(dir, name, target)
}
func (b *bindFS) Remove(dir Node, name string, isDir bool) error {
	return b.fs.Remove(dir, name, isDir)
}
func (b *bindFS) Rename(fromDir Node, from string, toDir Node, to string) error {
	return b.fs.Rename(fromDir, from, toDir, to)
}

// The optional capabilities forward to fs, answering as an absent capability
// would when fs lacks one.

func (b *bindFS) StatFS(n Node) (StatFS, error) {
	s, ok := b.fs.(StatFSer)
	if !ok {
		return StatFS{}, errors.ErrUnsupported
	}
	return s.StatFS(n)
}

func (b *bindFS) RenameExchange(fromDir Node, from string, toDir Node, to string) error {
	x, ok := b.fs.(ExchangeRenamer)
	if !ok {
		return syscall.EINVAL
	}
	return x.RenameExchange(fromDir, from, toDir, to)
}

func (b *bindFS) BindSocket(dir Node, name string, bind func(addr string) error) (Node, error) {
	s, ok := b.fs.(SocketFS)
	if !ok {
		return nil, ErrSocketUnsupported
	}
	return s.BindSocket(dir, name, bind)
}

func (b *bindFS) ReachSocket(n Node, op func(addr string) error) error {
	s, ok := b.fs.(SocketFS)
	if !ok {
		return ErrSocketUnsupported
	}
	return s.ReachSocket(n, op)
}
