package vfs

import "io"

// This file is the vfs abstraction's contract, modeled on the Linux VFS: names,
// objects, mounts and open files are separate concerns. A FileSystem owns
// objects and the operations on them, addressed by a parent node and a single
// name component. A Namespace (namespace.go) owns the mount tree and the
// resolver that walks multi-component paths, follows symlinks and crosses mount
// points, so a FileSystem never sees a path. Metadata and content belong to the
// backend that owns the node, keyed by the node's own identity, so they follow
// a rename or a hardlink. The copy-on-write overlay is one implementation
// (overlayfs.go); a synthetic or read-only filesystem is another, and the
// OCI image format is a consumer of these primitives, built on top, not inside.

// NodeID is a backend-local object identity — the host inode for a disk-backed
// filesystem — unique within one FileSystem instance. The resolver and callers
// treat it as opaque; it exists so two names for one object (a hardlink) are
// known to be the same object.
type NodeID struct{ Dev, Ino uint64 }

// A File is an open handle to a regular file's content. Offsets are the caller's
// to track; the handle holds the backing resources until Close. A memory mapping
// is served by the host above this interface: it reads the content through ReadAt
// into a descriptor of its own and maps that, so any backing — host, in-memory,
// network — is mappable without the File doing anything mmap-specific.
type File interface {
	io.ReaderAt
	io.WriterAt
	Truncate(size int64) error
	Close() error
}

// CreateSpec describes an object to create. Kind selects the object type; the
// remaining fields apply to the kinds that use them (Target for a symlink, Rdev
// for a device, Mode/Uid/Gid for all).
type CreateSpec struct {
	Kind     Kind
	Mode     uint32
	Uid, Gid uint32
	Target   string
	Rdev     uint64
}

// AttrUpdate is the set of attribute changes SetAttr applies; a nil field is
// left unchanged. Mode is the guest permission bits (07777). Atime/Mtime are
// unix nanoseconds. Owner and mode a backend cannot hold on the host are kept
// by the overlay's MetaStore instead.
type AttrUpdate struct {
	Mode     *uint32
	Uid, Gid *uint32
	Atime    *int64
	Mtime    *int64
}

// A Node is a filesystem object, identified independently of the names that
// reach it. Operations that change the object act through the node; operations
// that change a directory's contents act through the owning FileSystem with the
// parent node and a name.
type Node interface {
	// ID is the node's identity within its filesystem, stable across its names.
	ID() NodeID
	// Kind is the object type.
	Kind() Kind
	// Stat returns the node's current attributes.
	Stat() (Attr, error)
	// SetAttr applies the changes in u the backend can represent; a nil field is
	// left unchanged.
	SetAttr(u AttrUpdate) error
	// Readlink returns a symlink's target.
	Readlink() (string, error)
	// Open opens a regular file's content, honoring the access in flags
	// (os.O_RDONLY/O_WRONLY/O_RDWR and the modifiers the backend supports).
	Open(flags int) (File, error)
}

// A FileSystem owns a tree of objects and the single-component operations on
// them. The Namespace resolver supplies an already-resolved parent Node and one
// name; a FileSystem never resolves a multi-component path or a symlink itself.
type FileSystem interface {
	// Root is the filesystem's root directory node.
	Root() Node
	// Lookup returns the child named name in directory dir, or an error that
	// unwraps to fs.ErrNotExist when absent. It does not follow a final symlink.
	Lookup(dir Node, name string) (Node, error)
	// ReadDir lists dir's entries (without "." or "..").
	ReadDir(dir Node) ([]Dirent, error)
	// Create makes a new object named name in dir and returns its node.
	Create(dir Node, name string, spec CreateSpec) (Node, error)
	// Link adds a hardlink named name in dir to the existing node target.
	Link(dir Node, name string, target Node) (Node, error)
	// Remove unlinks name from dir; isDir selects a directory (rmdir) vs other.
	Remove(dir Node, name string, isDir bool) error
	// Rename moves from under fromDir to to under toDir.
	Rename(fromDir Node, from string, toDir Node, to string) error
}

// WriteFileSystem is implemented by a FileSystem whose regular-file content can
// be written in bulk, used by importers that have a layer's bytes in hand.
type WriteFileSystem interface {
	FileSystem
	WriteFile(dir Node, name string, spec CreateSpec, data []byte) (Node, error)
}

// Dirent is one entry of a merged directory listing. Ino is the entry's inode
// number (0 if the backend does not supply one), so a getdents reply can carry
// d_ino without a stat per entry.
type Dirent struct {
	Name string
	Kind Kind
	Ino  uint64
}
