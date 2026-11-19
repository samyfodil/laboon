//go:build darwin || linux || windows

package hostfs

import (
	"os"
	"sync/atomic"
	"syscall"

	"github.com/samyfodil/laboon/core"
)

// HostStat is a host file's attributes in Linux terms: dev and rdev are Linux
// dev_t encodings and mode carries Linux S_IFMT type bits. Each host builds it
// from its own stat (StatOf), so the overlay never looks at a host stat type.
type HostStat struct {
	dev, ino, rdev             uint64
	mode, nlink, uid, gid      uint32
	size, blocks               int64
	blksize                    uint32
	atime, mtime, ctime, btime syscall.Timespec
}

// A host file's stable identity and size, for callers outside the package (the
// exec rewriter keys its site cache on these).
func (s HostStat) Dev() uint64             { return s.dev }
func (s HostStat) Ino() uint64             { return s.ino }
func (s HostStat) Size() int64             { return s.size }
func (s HostStat) Atime() syscall.Timespec { return s.atime }
func (s HostStat) Mtime() syscall.Timespec { return s.mtime }
func (s HostStat) Ctime() syscall.Timespec { return s.ctime }
func (s HostStat) Btime() syscall.Timespec { return s.btime }
func (s HostStat) Rdev() uint64            { return s.rdev }
func (s HostStat) Mode() uint32            { return s.mode }
func (s HostStat) Nlink() uint32           { return s.nlink }
func (s HostStat) Blocks() int64           { return s.blocks }
func (s HostStat) Blksize() uint32         { return s.blksize }

// hostSeq numbers the supervisor's private host objects (work-dir names).
var hostSeq atomic.Uint64

// HostFS is the host's file operations on overlay paths. Paths are host paths
// the overlay already resolved: none of their components is a guest symlink,
// and an implementation refuses to follow a host symlink below the layer roots.
// Errors are host errors; osErrno converts them.
type HostFS interface {
	hOpen(p string, flag int, perm os.FileMode) (*os.File, error)
	hLstat(p string) (os.FileInfo, error)
	hReadlink(p string) (string, error)
	hMkdir(p string, perm uint32) error
	hSymlink(target, p string) error
	hMkfifo(p string, perm uint32) error
	hMksock(p string, perm uint32) error
	hRename(from, to string, exchange bool) error
	hUnlink(p string, dir bool) error
	hChmod(p string, mode uint32) error
	hUtimes(p string, atime, mtime syscall.Timespec) error
	hLink(from, to string) error
	hClone(from, to string) error
	hCloneFile(f *os.File, to string) error
	hTruncate(p string, n int64) error
	hStatfs(dir string) (core.StatFS, error)
	hReadDir(p string) ([]os.FileInfo, error)
}
