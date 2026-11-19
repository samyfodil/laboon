package core

import "errors"

// ErrXattrUnsupported is returned by a node whose backend cannot carry extended
// attributes (a synthetic one). Callers map it to the platform's EOPNOTSUPP.
var ErrXattrUnsupported = errors.New("vfs: extended attributes unsupported")

// XattrNode is the optional capability of a Node whose backend carries POSIX
// extended attributes. A host backend does the real xattr I/O; a union forwards
// reads to the layer that owns the node and writes to a copied-up top node. The
// flags of Setxattr are the platform's XATTR_CREATE/REPLACE, passed through.
type XattrNode interface {
	Getxattr(name string) ([]byte, error)
	Setxattr(name string, value []byte, flags int) error
	Listxattr() ([]byte, error)
	Removexattr(name string) error
}
