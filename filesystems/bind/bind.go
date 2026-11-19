package bind

import . "github.com/samyfodil/laboon/core"

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
