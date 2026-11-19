package core

import (
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
)

// This file holds the small, host-free vocabulary the core vfs package and its
// host backends (the hostfs subpackage) share: the object kinds, the per-path
// metadata override a host file cannot carry, the attribute snapshot a Node
// reports, the OCI whiteout/sidecar names, and the pure helpers over them. The
// host-backed layer that reads and writes these on disk lives in hostfs, so the
// core package has no direct host-OS interaction.

// Kind is a path's file type.
type Kind uint8

const (
	Reg Kind = iota
	Dir
	Symlink
	Fifo
	Chardev
	Blockdev
	Socket
)

// Override is the guest metadata a host file cannot itself carry — an owner or
// mode an unprivileged host file cannot hold, or a special-node kind — kept in a
// per-path side table. It is the layer metadata a serializer (the OCI package)
// reads out and writes back.
type Override struct {
	Uid, Gid uint32
	Mode     uint32
	HasOwner bool
	HasMode  bool
	Kind     Kind // a special node (Fifo/Chardev/Blockdev/Socket) stored as a placeholder
	Special  bool
	Rdev     uint64
}

const (
	WhiteoutPrefix = ".wh."
	OpaqueMarker   = ".wh..wh..opq"
	// MetaFileName holds the override map on disk, so a layer directory carries
	// the guest owner/mode/special-node metadata the host files cannot. It is
	// never part of the image layer (WriteTar, Entries and ApplyTo skip it).
	MetaFileName = ".lc-vfsmeta"
)

// Internal reports whether a directory entry name is a vfs artifact — a whiteout
// or opaque marker, or the metadata sidecar — and so is part of neither the
// guest-visible filesystem nor the image. A directory listing over a layer
// directory filters these out.
func Internal(name string) bool {
	return name == MetaFileName || strings.HasPrefix(name, WhiteoutPrefix)
}

var errLoop = errors.New("vfs: too many symlink levels")

// ErrNotDir is returned when a path descends through a non-directory component;
// callers map it to the platform's ENOTDIR.
var ErrNotDir = errors.New("vfs: not a directory")

// ErrCrossDevice is returned by a FileSystem that is handed a node belonging to a
// different filesystem — a hard link across a mount point. Callers map it to the
// platform's EXDEV.
var ErrCrossDevice = errors.New("vfs: cross-device link")

// Errno is a Linux errno carried through an error return, so a host backend can
// name the exact Linux error the guest should see where no host error maps to it
// cleanly (a Windows reparse point as ELOOP, say). The sandbox recovers the
// number at the host-call boundary.
type Errno int64

func (e Errno) Error() string { return "linux errno " + strconv.Itoa(int(e)) }

// Attr is a snapshot of a path's metadata.
type Attr struct {
	Kind     Kind
	Mode     uint32
	Uid, Gid uint32
	Target   string
	Rdev     uint64
	Opaque   bool
	Whiteout bool

	// Full stat, so a guest stat/statx reply can be built from a Node. Times are
	// unix nanoseconds (0 if the backend does not provide them).
	Size                       int64
	Nlink                      uint64
	Blocks                     int64
	Blksize                    int64
	Atime, Mtime, Ctime, Btime int64
}

// Entry is one directory entry of a layer: a name with its kind, or a whiteout.
type Entry struct {
	Name     string
	Kind     Kind
	Whiteout bool
}

func clean(p string) string { return strings.Trim(path.Clean("/"+p), "/") }

// ModeKind maps a Kind to the Linux S_IFMT type bits of st_mode, so a guest
// stat/statx reply's mode can be assembled from a backend-agnostic Attr.
func ModeKind(k Kind) uint32 {
	switch k {
	case Dir:
		return 0x4000
	case Symlink:
		return 0xa000
	case Chardev:
		return 0x2000
	case Blockdev:
		return 0x6000
	case Fifo:
		return 0x1000
	case Socket:
		return 0xc000
	}
	return 0x8000 // regular
}

// HostMode is the host permission a layer file gets for guest bits mode, so an
// unprivileged owner keeps read/traverse access; the exact guest mode lives in
// the Override when it differs. A writer extracting a layer uses it to floor the
// files it creates to the layer's own convention. Directories stay traversable
// and files writable by the laboon user.
func HostMode(mode uint32, dir bool) os.FileMode {
	if dir {
		return os.FileMode(mode&0o777 | 0o700)
	}
	return os.FileMode(mode&0o777 | 0o600)
}
