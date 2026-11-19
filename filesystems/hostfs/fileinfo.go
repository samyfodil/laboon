//go:build darwin || linux || windows

package hostfs

import (
	"os"
	"syscall"
	"time"

	"github.com/samyfodil/laboon/core"
)

// ModeKind maps a core.Kind to the Linux S_IFMT type bits of st_mode.
func ModeKind(k core.Kind) uint32 {
	switch k {
	case core.Dir:
		return 0x4000
	case core.Symlink:
		return 0xa000
	case core.Chardev:
		return 0x2000
	case core.Blockdev:
		return 0x6000
	case core.Fifo:
		return 0x1000
	case core.Socket:
		return 0xc000
	}
	return 0x8000 // regular
}

// fileInfo is an os.FileInfo backed by a resolved vfs node's attributes, so code
// that consumes a host os.FileInfo (DAC, existence and mode checks, the stat
// reply builder) sees a node resolved through the Namespace as one. Its Sys is a
// *HostStat carrying the winning layer's identity and host mode, which StatOf
// recovers; a caller applies the guest owner and sub-floor mode overrides from
// the shared store keyed by that identity, exactly as for a real host FileInfo.
type fileInfo struct {
	name string
	st   HostStat
}

func (n *fileInfo) Name() string       { return n.name }
func (n *fileInfo) Size() int64        { return n.st.size }
func (n *fileInfo) ModTime() time.Time { return timespecTime(n.st.mtime) }
func (n *fileInfo) IsDir() bool        { return n.st.mode&0o170000 == 0o040000 }
func (n *fileInfo) Sys() any           { return &n.st }

func (n *fileInfo) Mode() os.FileMode {
	m := os.FileMode(n.st.mode & 0o777)
	switch n.st.mode & 0o170000 {
	case 0o040000:
		m |= os.ModeDir
	case 0o120000:
		m |= os.ModeSymlink
	case 0o010000:
		m |= os.ModeNamedPipe
	case 0o140000:
		m |= os.ModeSocket
	case 0o020000:
		m |= os.ModeDevice | os.ModeCharDevice
	case 0o060000:
		m |= os.ModeDevice
	}
	if n.st.mode&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if n.st.mode&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if n.st.mode&0o1000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

// NewFileInfo builds the os.FileInfo for a node resolved through the Namespace.
// The host mode (not the guest override) goes into the *HostStat, so it carries
// the same raw bits a host lstat of the winning layer would.
func NewFileInfo(name string, a core.Attr, id core.NodeID) os.FileInfo {
	st := HostStat{
		dev: id.Dev, ino: id.Ino, rdev: a.Rdev,
		mode:  ModeKind(a.Kind) | a.Mode&0o7777,
		nlink: uint32(a.Nlink),
		size:  a.Size, blocks: a.Blocks, blksize: 4096,
		atime: syscall.NsecToTimespec(a.Atime),
		mtime: syscall.NsecToTimespec(a.Mtime),
		ctime: syscall.NsecToTimespec(a.Ctime),
		btime: syscall.NsecToTimespec(a.Btime),
	}
	if a.Blksize > 0 {
		st.blksize = uint32(a.Blksize)
	}
	if st.nlink == 0 {
		st.nlink = 1
	}
	return &fileInfo{name: name, st: st}
}
