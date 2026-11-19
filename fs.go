package laboon

import (
	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/bind"
	"github.com/samyfodil/laboon/filesystems/harden"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/filesystems/memfs"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
	"github.com/samyfodil/laboon/filesystems/readonly"
)

// This file is laboon's public filesystem surface: the FileSystem interface a
// mount is composed from, and the backends and wrappers that build one. WithFS
// mounts any of these into a guest. A FileSystem owns a tree of objects and the
// single-component operations on them; path resolution, symlink following and
// mount crossing happen above it, so a backend never sees a multi-component path.
// Content is read and written through File rather than a host path, so an
// in-memory or fully custom backend serves bytes like any other.

// FileSystem is a composable filesystem backend. Mount one with WithFS.
// Implement it for a custom backend (an object store, a database), or use a
// provided one: NewMemFS, NewDirFS, Overlay, and the ReadOnly and HardenFS
// wrappers.
type FileSystem = core.FileSystem

// These are the types a custom FileSystem implements against or returns.
type (
	// Node is a filesystem object, identified independently of the names reaching it.
	Node = core.Node
	// File is an open handle to a regular file's content.
	File = core.File
	// Attr is a node's attributes, as Node.Stat returns them.
	Attr = core.Attr
	// AttrUpdate is the set of changes SetAttr applies; a nil field is unchanged.
	AttrUpdate = core.AttrUpdate
	// CreateSpec describes an object to create.
	CreateSpec = core.CreateSpec
	// Dirent is one entry of a directory listing.
	Dirent = core.Dirent
	// Kind is a filesystem object's type.
	Kind = core.Kind
	// NodeID is a backend-local object identity, unique within one FileSystem.
	NodeID = core.NodeID
	// StatFS holds a filesystem's statfs counters.
	StatFS = core.StatFS
	// StatFSer is the optional capability of a FileSystem that reports statfs.
	StatFSer = core.StatFSer
	// WriteFileSystem is a FileSystem whose file content can be written in bulk.
	WriteFileSystem = core.WriteFileSystem
)

// The kinds a Kind takes.
const (
	KindReg      = core.Reg
	KindDir      = core.Dir
	KindSymlink  = core.Symlink
	KindFifo     = core.Fifo
	KindChardev  = core.Chardev
	KindBlockdev = core.Blockdev
	KindSocket   = core.Socket
)

// NewMemFS makes an empty in-memory FileSystem (the afero-mem equivalent): files,
// directories, symlinks and hardlinks held in memory, volatile across runs.
func NewMemFS() FileSystem { return memfs.NewMemFS() }

// NewDirFS presents the host directory root as a FileSystem. Unlike WithMount it
// is a plain tree with no subtree confinement or socket forwarding; use WithMount
// for a sandboxed host bind.
func NewDirFS(root string) FileSystem { return hostfs.NewDirFS(root) }

// Overlay unions layers into one copy-on-write FileSystem (aufs/overlayfs style):
// lowest layer first, the writable top layer last. A read sees the topmost layer
// that has the file; a write goes to the top.
func Overlay(layers ...FileSystem) FileSystem { return overlayfs.OverlayFS(layers...) }

// ReadOnly wraps fs so every change — create, link, remove, rename, and a
// write-mode open — fails with EROFS, while reads pass through.
func ReadOnly(fs FileSystem) FileSystem { return readonly.ReadOnly(fs) }

// Bind presents the subtree rooted at root (a node of fs) as its own FileSystem,
// so part of one filesystem can be mounted on its own.
func Bind(fs FileSystem, root Node) FileSystem { return bind.Bind(fs, root) }

// HardenFS wraps fs and removes capabilities with the given options, each denied
// with EPERM:
//
//	laboon.WithFS("/data", laboon.HardenFS(laboon.NewMemFS(),
//	    laboon.WithNoSymLink(), laboon.WithNoDevice(), laboon.WithNoSocket()))
func HardenFS(fs FileSystem, opts ...HardenOption) FileSystem { return harden.HardenFS(fs, opts...) }

// A HardenOption turns off one capability of a HardenFS.
type HardenOption = harden.HardenOption

// WithNoHardLink denies hardlink creation.
func WithNoHardLink() HardenOption { return harden.WithNoHardLink() }

// WithNoSymLink denies symlink creation.
func WithNoSymLink() HardenOption { return harden.WithNoSymLink() }

// WithNoDevice denies device-node creation.
func WithNoDevice() HardenOption { return harden.WithNoDevice() }

// WithNoSocket denies filesystem-socket creation.
func WithNoSocket() HardenOption { return harden.WithNoSocket() }

// WithNoFifo denies named-pipe creation.
func WithNoFifo() HardenOption { return harden.WithNoFifo() }

// WithConfinedLinks makes symlinks in the filesystem resolve relative to its own
// root, so a symlink inside cannot name a path outside it (an absolute target
// restarts at the mount point and "../" cannot climb out). A guest tmpfs is not
// confined, keeping exact Linux semantics; this is for an embedder-mounted
// backend meant to be self-contained.
func WithConfinedLinks() HardenOption { return harden.WithConfinedLinks() }
