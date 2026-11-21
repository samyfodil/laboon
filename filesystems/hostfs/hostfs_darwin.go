//go:build darwin

package hostfs

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/samyfodil/laboon/core"
	"golang.org/x/sys/unix"
)

// Host calls on overlay paths. The guest resolves its own symlinks, so a host
// path under the root or the upper layer never needs a symlink followed. The
// guest can still swap a directory for a symlink (rename, rmdir+symlink)
// between resolving a path and the host call that uses it, so every such call
// passes Darwin's NOFOLLOW_ANY: the kernel then refuses a symlink anywhere in
// the path instead of leaving the layer through it. Both layer roots are
// canonical (no symlinks), which NOFOLLOW_ANY needs. Without a root the guest
// path is the host path and is followed as given.
const (
	atNofollowAny    = 0x0800
	cloneNofollowAny = 0x0008
)

// HostONonblock is the host open flag for a non-blocking open.
const HostONonblock = unix.O_NONBLOCK

// FifoRendezvous: this backend has real FIFOs, so FIFO opens rendezvous.
const FifoRendezvous = true

// DarwinFS is the darwin HostFS.
type DarwinFS struct{ rootAbs, workAbs string }

func NewHostFS(rootAbs, upperAbs, workAbs string) HostFS {
	return newCachedFS(&DarwinFS{rootAbs, workAbs}, rootAbs, upperAbs)
}

// NewRawHostFS is an uncached host backend confined to root (see the linux note).
func NewRawHostFS(root string) HostFS { return &DarwinFS{rootAbs: root} }

// HostPath is the host path of resolved guest path gp under root.
func HostPath(root, gp string) string { return filepath.Join(root, filepath.FromSlash(gp)) }

func (fs *DarwinFS) oAny() int {
	if fs.rootAbs == "" {
		return 0
	}
	return unix.O_NOFOLLOW_ANY
}

func (fs *DarwinFS) atAny() int {
	if fs.rootAbs == "" {
		return 0
	}
	return atNofollowAny
}

func (fs *DarwinFS) hOpen(p string, flag int, perm os.FileMode) (*os.File, error) {
	// O_APPEND goes on the descriptor, not through os.OpenFile, whose append mode
	// refuses WriteAt for good, even after F_SETFL clears the flag.
	f, err := os.OpenFile(p, flag&^os.O_APPEND|fs.oAny(), perm)
	if err != nil || flag&os.O_APPEND == 0 {
		return f, err
	}
	rc, err := f.SyscallConn()
	if err == nil {
		cerr := rc.Control(func(fd uintptr) {
			var fl int
			if fl, err = unix.FcntlInt(fd, unix.F_GETFL, 0); err == nil {
				_, err = unix.FcntlInt(fd, unix.F_SETFL, fl|unix.O_APPEND)
			}
		})
		if err == nil {
			err = cerr
		}
	}
	if err != nil {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	return f, nil
}

// hLstat is os.Lstat that refuses a symlink in any component but the last.
func (fs *DarwinFS) hLstat(p string) (os.FileInfo, error) {
	fi := &HostInfo{name: filepath.Base(p)}
	if err := unix.Fstatat(unix.AT_FDCWD, p, (*unix.Stat_t)(unsafe.Pointer(&fi.st)), unix.AT_SYMLINK_NOFOLLOW|fs.atAny()); err != nil {
		return nil, &os.PathError{Op: "lstat", Path: p, Err: err}
	}
	return fi, nil
}

// hParent opens p's parent directory for an *at call on its last component.
func (fs *DarwinFS) hParent(p string) (*os.File, string, error) {
	d, err := os.OpenFile(filepath.Dir(p), unix.O_SEARCH|unix.O_DIRECTORY|fs.oAny(), 0)
	return d, filepath.Base(p), err
}

func (fs *DarwinFS) hReadlink(p string) (string, error) {
	d, base, err := fs.hParent(p)
	if err != nil {
		return "", err
	}
	defer d.Close()
	for n := 256; ; n *= 2 {
		b := make([]byte, n)
		m, err := unix.Readlinkat(int(d.Fd()), base, b)
		if err != nil {
			return "", &os.PathError{Op: "readlink", Path: p, Err: err}
		}
		if m < n {
			return string(b[:m]), nil
		}
	}
}

func (fs *DarwinFS) hMkdir(p string, perm uint32) error {
	d, base, err := fs.hParent(p)
	if err != nil {
		return err
	}
	defer d.Close()
	return unix.Mkdirat(int(d.Fd()), base, perm)
}

func (fs *DarwinFS) hSymlink(target, p string) error {
	d, base, err := fs.hParent(p)
	if err != nil {
		return err
	}
	defer d.Close()
	return unix.Symlinkat(target, int(d.Fd()), base)
}

// hMkfifo has no mkfifoat to call, so the FIFO is made in the private work dir
// and renamed into place.
func (fs *DarwinFS) hMkfifo(p string, perm uint32) error {
	if fs.workAbs == "" {
		return unix.Mkfifo(p, perm)
	}
	tmp := filepath.Join(fs.workAbs, "fifo-"+strconv.FormatUint(hostSeq.Add(1), 10))
	if err := unix.Mkfifo(tmp, perm); err != nil {
		return err
	}
	err := unix.RenameatxNp(unix.AT_FDCWD, tmp, unix.AT_FDCWD, p, unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY)
	if err != nil {
		unix.Unlink(tmp)
	}
	return err
}

// hMksock makes a socket file. Only root may mknod one on macOS, but binding
// a socket leaves the same unbound socket file.
func (fs *DarwinFS) hMksock(p string, perm uint32) error {
	s, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)
	err = fs.inDir(p, func(d int, name string) error {
		if err := unix.Bind(s, &unix.SockaddrUnix{Name: name}); err != nil {
			return err
		}
		return unix.Fchmodat(d, name, perm, unix.AT_SYMLINK_NOFOLLOW)
	})
	if err == unix.EADDRINUSE {
		return unix.EEXIST
	}
	return err
}

// hBindSock binds at a name of its own in p's directory and renames it into
// place, refusing an existing one, so the address the kernel reports for the
// socket is unique to it rather than p's bare name, which another directory's
// socket can share.
func (fs *DarwinFS) hBindSock(p string, bind func(addr string) error) error {
	return fs.inDir(p, func(d int, name string) error {
		tmp := ".lcsock-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(sockSeq.Add(1), 36)
		if err := bind(tmp); err != nil {
			return err
		}
		if err := unix.RenameatxNp(d, tmp, d, name, unix.RENAME_EXCL); err != nil {
			unix.Unlinkat(d, tmp, 0)
			if err == unix.EEXIST {
				return unix.EADDRINUSE
			}
			return err
		}
		return nil
	})
}

var sockSeq atomic.Uint64

func (fs *DarwinFS) hReachSock(p string, op func(addr string) error) error {
	return fs.inDir(p, func(_ int, name string) error { return op(name) })
}

// inDir runs call with the process in p's parent directory, opened confined,
// so a socket address is p's bare name: neither sun_path's 104 bytes nor a
// symlink on the way comes in. macOS has no per-thread chdir in the Go
// standard library, so the whole process's directory changes briefly on a
// locked, serialized thread and is restored; laboon uses absolute paths and
// descriptors, never the working directory, so nothing else sees it.
func (fs *DarwinFS) inDir(p string, call func(dir int, name string) error) error {
	d, err := unix.Open(filepath.Dir(p), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|fs.oAny(), 0)
	if err != nil {
		return err
	}
	defer unix.Close(d)
	bindMu.Lock()
	defer bindMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cwd, err := unix.Open(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(cwd)
	if err := unix.Fchdir(d); err != nil {
		return err
	}
	defer unix.Fchdir(cwd)
	return call(d, filepath.Base(p))
}

// bindMu serializes the brief process-wide fchdir of inDir.
var bindMu sync.Mutex

func (fs *DarwinFS) hRename(from, to string, exchange bool) error {
	var flags uint32
	if exchange {
		flags = unix.RENAME_SWAP
	}
	if fs.rootAbs != "" {
		flags |= unix.RENAME_NOFOLLOW_ANY
	}
	return unix.RenameatxNp(unix.AT_FDCWD, from, unix.AT_FDCWD, to, flags)
}

func (fs *DarwinFS) hUnlink(p string, dir bool) error {
	fl := fs.atAny()
	if dir {
		fl |= unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(unix.AT_FDCWD, p, fl)
}

func (fs *DarwinFS) hChmod(p string, mode uint32) error {
	return unix.Fchmodat(unix.AT_FDCWD, p, mode, unix.AT_SYMLINK_NOFOLLOW|fs.atAny())
}

func (fs *DarwinFS) hUtimes(p string, atime, mtime syscall.Timespec) error {
	ts := []unix.Timespec{unix.Timespec(atime), unix.Timespec(mtime)}
	return unix.UtimesNanoAt(unix.AT_FDCWD, p, ts, unix.AT_SYMLINK_NOFOLLOW|fs.atAny())
}

// FutimesOf sets the open file f's times. Darwin has no futimens in x/sys;
// futimes keeps microseconds.
func FutimesOf(f *os.File, atime, mtime syscall.Timespec) error {
	return unix.Futimes(hostFd(f), []unix.Timeval{
		unix.NsecToTimeval(syscall.TimespecToNsec(atime)), unix.NsecToTimeval(syscall.TimespecToNsec(mtime))})
}

func (fs *DarwinFS) hCloneFile(f *os.File, to string) error {
	return unix.Fclonefileat(hostFd(f), unix.AT_FDCWD, to, fs.cloneFlags()&^unix.CLONE_NOFOLLOW)
}

func (fs *DarwinFS) hLink(from, to string) error {
	return unix.Linkat(unix.AT_FDCWD, from, unix.AT_FDCWD, to, fs.atAny())
}

func (fs *DarwinFS) cloneFlags() int {
	if fs.rootAbs == "" {
		return unix.CLONE_NOFOLLOW
	}
	return unix.CLONE_NOFOLLOW | cloneNofollowAny
}

func (fs *DarwinFS) hClone(from, to string) error {
	return unix.Clonefileat(unix.AT_FDCWD, from, unix.AT_FDCWD, to, fs.cloneFlags())
}

func (fs *DarwinFS) hTruncate(p string, n int64) error {
	f, err := fs.hOpen(p, os.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(n)
}

func (fs *DarwinFS) hStatfs(dir string) (core.StatFS, error) {
	d, err := fs.hOpen(dir, unix.O_SEARCH|unix.O_DIRECTORY, 0)
	if err != nil {
		return core.StatFS{}, err
	}
	defer d.Close()
	return FstatfsOf(d)
}

// FstatfsOf is the statfs of the filesystem holding the open file f.
func FstatfsOf(f *os.File) (core.StatFS, error) {
	var s unix.Statfs_t
	if err := unix.Fstatfs(hostFd(f), &s); err != nil {
		return core.StatFS{}, err
	}
	return core.StatFS{
		Bsize: uint64(s.Bsize), Blocks: s.Blocks, Bfree: s.Bfree, Bavail: s.Bavail,
		Files: s.Files, Ffree: s.Ffree, Fsid: [2]uint32{uint32(s.Fsid.Val[0]), uint32(s.Fsid.Val[1])},
	}, nil
}

// hReadDir lists a host directory: names and lstat info, the info taken with
// hLstat (os.DirEntry.Info would re-walk the path and follow a symlink).
func (fs *DarwinFS) hReadDir(p string) ([]os.FileInfo, error) {
	f, err := fs.hOpen(p, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]os.FileInfo, 0, len(names))
	for _, n := range names {
		if fi, err := fs.hLstat(p + "/" + n); err == nil {
			out = append(out, fi)
		}
	}
	return out, nil
}

// HostInfo is the os.FileInfo of an hLstat, built like the os package's own.
// StatOf is fi's HostStat when fi describes a host file.
func StatOf(fi os.FileInfo) (HostStat, bool) {
	if h, ok := fi.Sys().(*HostStat); ok {
		return *h, true // a node-backed FileInfo (lstatGuest via the Namespace)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return HostStat{}, false
	}
	// Darwin's S_IFMT type bits are Linux's.
	return HostStat{
		dev: darwinRdev(uint64(uint32(st.Dev))), ino: st.Ino, rdev: darwinRdev(uint64(uint32(st.Rdev))),
		mode: uint32(st.Mode), nlink: uint32(st.Nlink), uid: st.Uid, gid: st.Gid,
		size: st.Size, blocks: st.Blocks, blksize: uint32(st.Blksize),
		atime: st.Atimespec, mtime: st.Mtimespec, ctime: st.Ctimespec, btime: st.Birthtimespec,
	}, true
}

type HostInfo struct {
	name string
	st   syscall.Stat_t
}

func (h *HostInfo) Name() string       { return h.name }
func (h *HostInfo) Size() int64        { return h.st.Size }
func (h *HostInfo) ModTime() time.Time { return timespecTime(h.st.Mtimespec) }
func (h *HostInfo) IsDir() bool        { return h.Mode().IsDir() }
func (h *HostInfo) Sys() any           { return &h.st }

func (h *HostInfo) Mode() os.FileMode {
	m := os.FileMode(h.st.Mode & 0o777)
	switch h.st.Mode & syscall.S_IFMT {
	case syscall.S_IFBLK, syscall.S_IFWHT:
		m |= os.ModeDevice
	case syscall.S_IFCHR:
		m |= os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFDIR:
		m |= os.ModeDir
	case syscall.S_IFIFO:
		m |= os.ModeNamedPipe
	case syscall.S_IFLNK:
		m |= os.ModeSymlink
	case syscall.S_IFSOCK:
		m |= os.ModeSocket
	}
	if h.st.Mode&syscall.S_ISGID != 0 {
		m |= os.ModeSetgid
	}
	if h.st.Mode&syscall.S_ISUID != 0 {
		m |= os.ModeSetuid
	}
	if h.st.Mode&syscall.S_ISVTX != 0 {
		m |= os.ModeSticky
	}
	return m
}

func darwinRdev(r uint64) uint64 {
	if r == 0 {
		return 0
	}
	return lxMakedev(r>>24&0xff, r&0xffffff)
}

func lxMakedev(major, minor uint64) uint64 {
	return minor&0xff | (major&0xfff)<<8 | (minor&^0xff)<<12 | (major&^0xfff)<<32
}
