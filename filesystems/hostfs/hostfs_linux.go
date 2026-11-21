package hostfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/samyfodil/laboon/core"
	"golang.org/x/sys/unix"
)

// Host calls on overlay paths. The guest resolves its own symlinks, so a host
// path under the root or the upper layer never needs one followed; the guest
// can still swap a directory for a symlink between resolving a path and the
// host call that uses it. So every call reaches its last component through
// the parent directory, opened with openat2's RESOLVE_NO_SYMLINKS, and acts
// on it without following: the kernel refuses a symlink anywhere on the way
// instead of leaving the layer through it. Without a root the guest path is
// the host path and is followed as given.

// HostONonblock is the host open flag for a non-blocking open.
const HostONonblock = unix.O_NONBLOCK

type LinuxFS struct{ rootAbs string }

func NewHostFS(rootAbs, upperAbs, workAbs string) HostFS {
	return newCachedFS(&LinuxFS{rootAbs}, rootAbs, upperAbs)
}

// NewRawHostFS is a host backend confined to root but without the overlay cache,
// for a writable bind whose directory changes under us (the cache assumes an
// immutable lower layer).
func NewRawHostFS(root string) HostFS { return &LinuxFS{root} }

// HostPath is the host path of resolved guest path gp under root.
func HostPath(root, gp string) string { return filepath.Join(root, filepath.FromSlash(gp)) }

func (fs *LinuxFS) resolve() uint64 {
	if fs.rootAbs == "" {
		return 0
	}
	return unix.RESOLVE_NO_SYMLINKS
}

func (fs *LinuxFS) open2(p string, flags int, perm uint32) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, p, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Mode: uint64(perm), Resolve: fs.resolve()})
}

func (fs *LinuxFS) hOpen(p string, flag int, perm os.FileMode) (*os.File, error) {
	fd, err := fs.open2(p, flag, uint32(perm.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	return os.NewFile(uintptr(fd), p), nil
}

// hParent opens p's parent directory for an *at call on its last component.
func (fs *LinuxFS) hParent(p string) (int, string, error) {
	fd, err := fs.open2(filepath.Dir(p), unix.O_PATH|unix.O_DIRECTORY, 0)
	return fd, filepath.Base(p), err
}

// atParent runs call on p's parent directory and last component.
func (fs *LinuxFS) atParent(p string, call func(dir int, base string) error) error {
	d, base, err := fs.hParent(p)
	if err != nil {
		return err
	}
	defer unix.Close(d)
	return call(d, base)
}

func (fs *LinuxFS) hLstat(p string) (os.FileInfo, error) {
	fi := &HostInfo{name: filepath.Base(p)}
	err := fs.atParent(p, func(d int, base string) error {
		return unix.Fstatat(d, base, (*unix.Stat_t)(unsafe.Pointer(&fi.st)), unix.AT_SYMLINK_NOFOLLOW)
	})
	if err != nil {
		return nil, &os.PathError{Op: "lstat", Path: p, Err: err}
	}
	return fi, nil
}

func (fs *LinuxFS) hReadlink(p string) (string, error) {
	var s string
	err := fs.atParent(p, func(d int, base string) error {
		for n := 256; ; n *= 2 {
			b := make([]byte, n)
			m, err := unix.Readlinkat(d, base, b)
			if err != nil {
				return err
			}
			if m < n {
				s = string(b[:m])
				return nil
			}
		}
	})
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: p, Err: err}
	}
	return s, nil
}

func (fs *LinuxFS) hMkdir(p string, perm uint32) error {
	return fs.atParent(p, func(d int, base string) error { return unix.Mkdirat(d, base, perm) })
}

func (fs *LinuxFS) hSymlink(target, p string) error {
	return fs.atParent(p, func(d int, base string) error { return unix.Symlinkat(target, d, base) })
}

func (fs *LinuxFS) hMkfifo(p string, perm uint32) error {
	return fs.atParent(p, func(d int, base string) error { return unix.Mkfifoat(d, base, perm) })
}

func (fs *LinuxFS) hMksock(p string, perm uint32) error {
	return fs.atParent(p, func(d int, base string) error { return unix.Mknodat(d, base, unix.S_IFSOCK|perm, 0) })
}

// sunPathMax is the size of Linux's sun_path, terminator included.
const sunPathMax = 108

// hBindSock binds through the parent directory's descriptor: the address is
// /proc/self/fd/N/name, short whatever the path's length, and reaches no
// further than the confined parent.
func (fs *LinuxFS) hBindSock(p string, bind func(addr string) error) error {
	return fs.atParent(p, func(d int, base string) error {
		addr := "/proc/self/fd/" + strconv.Itoa(d) + "/" + base
		if len(addr) >= sunPathMax {
			return unix.ENAMETOOLONG
		}
		return bind(addr)
	})
}

// hReachSock reaches the socket file itself through an O_PATH descriptor.
func (fs *LinuxFS) hReachSock(p string, op func(addr string) error) error {
	f, err := fs.open2(p, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(f)
	return op("/proc/self/fd/" + strconv.Itoa(f))
}

func (fs *LinuxFS) hRename(from, to string, exchange bool) error {
	var flags uint
	if exchange {
		flags = unix.RENAME_EXCHANGE
	}
	return fs.atParent(from, func(fd int, fbase string) error {
		return fs.atParent(to, func(td int, tbase string) error {
			return unix.Renameat2(fd, fbase, td, tbase, flags)
		})
	})
}

func (fs *LinuxFS) hUnlink(p string, dir bool) error {
	fl := 0
	if dir {
		fl = unix.AT_REMOVEDIR
	}
	return fs.atParent(p, func(d int, base string) error { return unix.Unlinkat(d, base, fl) })
}

// hChmod changes p's mode through a descriptor of p itself: Linux's fchmodat
// cannot leave a final symlink unfollowed, and a symlink's mode is not used.
func (fs *LinuxFS) hChmod(p string, mode uint32) error {
	fd, err := fs.open2(p, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil
	}
	return unix.Fchmodat(unix.AT_FDCWD, procFdPath(fd), mode, 0)
}

func procFdPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

func (fs *LinuxFS) hUtimes(p string, atime, mtime syscall.Timespec) error {
	ts := []unix.Timespec{unix.Timespec(atime), unix.Timespec(mtime)}
	return fs.atParent(p, func(d int, base string) error {
		return unix.UtimesNanoAt(d, base, ts, unix.AT_SYMLINK_NOFOLLOW)
	})
}

// FutimesOf sets the open file f's times.
func FutimesOf(f *os.File, atime, mtime syscall.Timespec) error {
	return unix.UtimesNanoAt(hostFd(f), "", []unix.Timespec{unix.Timespec(atime), unix.Timespec(mtime)}, unix.AT_EMPTY_PATH)
}

func (fs *LinuxFS) hLink(from, to string) error {
	return fs.atParent(from, func(fd int, fbase string) error {
		return fs.atParent(to, func(td int, tbase string) error {
			return unix.Linkat(fd, fbase, td, tbase, 0)
		})
	})
}

// hClone copies from to the new file to, sharing blocks where the filesystem
// can (FICLONE), with its mode.
func (fs *LinuxFS) hClone(from, to string) error {
	f, err := fs.hOpen(from, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return fs.hCloneFile(f, to)
}

func (fs *LinuxFS) hCloneFile(f *os.File, to string) error {
	var st unix.Stat_t
	if err := unix.Fstat(hostFd(f), &st); err != nil {
		return err
	}
	out, err := fs.hOpen(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, os.FileMode(st.Mode&0o7777))
	if err != nil {
		return err
	}
	if unix.IoctlFileClone(hostFd(out), hostFd(f)) != nil {
		if _, err = io.Copy(out, io.NewSectionReader(f, 0, st.Size)); err != nil {
			out.Close()
			fs.hUnlink(to, false)
			return err
		}
	}
	unix.Fchmod(hostFd(out), st.Mode&0o7777)
	return out.Close()
}

func (fs *LinuxFS) hTruncate(p string, n int64) error {
	f, err := fs.hOpen(p, os.O_WRONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(n)
}

func (fs *LinuxFS) hStatfs(dir string) (core.StatFS, error) {
	d, err := fs.hOpen(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
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
		Type: uint64(s.Type),
	}, nil
}

// hReadDir lists a host directory from one getdents64 stream: each entry's name,
// inode (d_ino) and type (d_type) come straight from the kernel, so there is no
// per-entry stat. An entry whose d_type is DT_UNKNOWN (rare -- some filesystems
// omit it) is stat'd on its own to learn its type.
func (fs *LinuxFS) hReadDir(p string) ([]os.FileInfo, error) {
	f, err := fs.hOpen(p, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fd := int(hostFd(f))
	var out []os.FileInfo
	buf := make([]byte, 16<<10)
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			break
		}
		for off := 0; off+19 <= n; {
			// struct linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) name.
			reclen := int(binary.LittleEndian.Uint16(buf[off+16:]))
			if reclen < 19 || off+reclen > n {
				break
			}
			ino := binary.LittleEndian.Uint64(buf[off:])
			dtype := buf[off+18]
			name := direntName(buf[off+19 : off+reclen])
			off += reclen
			if name == "" || name == "." || name == ".." {
				continue
			}
			fi := &HostInfo{name: name}
			fi.st.Ino = ino
			if m := modeFromDType(dtype); m != 0 {
				fi.st.Mode = m
			} else if unix.Fstatat(fd, name, (*unix.Stat_t)(unsafe.Pointer(&fi.st)), unix.AT_SYMLINK_NOFOLLOW) != nil {
				continue
			}
			out = append(out, fi)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].(*HostInfo).name < out[j].(*HostInfo).name })
	return out, nil
}

// direntName returns the NUL-terminated name from a linux_dirent64 name field.
func direntName(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// modeFromDType maps a getdents64 d_type to the S_IFMT type bits of st_mode, or
// 0 for DT_UNKNOWN (the caller then stats the entry).
func modeFromDType(dt byte) uint32 {
	switch dt {
	case unix.DT_REG:
		return syscall.S_IFREG
	case unix.DT_DIR:
		return syscall.S_IFDIR
	case unix.DT_LNK:
		return syscall.S_IFLNK
	case unix.DT_CHR:
		return syscall.S_IFCHR
	case unix.DT_BLK:
		return syscall.S_IFBLK
	case unix.DT_FIFO:
		return syscall.S_IFIFO
	case unix.DT_SOCK:
		return syscall.S_IFSOCK
	default:
		return 0
	}
}

// StatOf is fi's HostStat when fi describes a host file.
func StatOf(fi os.FileInfo) (HostStat, bool) {
	if h, ok := fi.Sys().(*HostStat); ok {
		return *h, true // a node-backed FileInfo (lstatGuest via the Namespace)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return HostStat{}, false
	}
	return HostStat{
		dev: st.Dev, ino: st.Ino, rdev: st.Rdev,
		mode: st.Mode, nlink: uint32(st.Nlink), uid: st.Uid, gid: st.Gid,
		size: st.Size, blocks: st.Blocks, blksize: uint32(st.Blksize),
		atime: st.Atim, mtime: st.Mtim, ctime: st.Ctim,
	}, true
}

// HostInfo is the os.FileInfo of an hLstat, built like the os package's own.
type HostInfo struct {
	name string
	st   syscall.Stat_t
}

func (h *HostInfo) Name() string       { return h.name }
func (h *HostInfo) Size() int64        { return h.st.Size }
func (h *HostInfo) ModTime() time.Time { return time.Unix(h.st.Mtim.Unix()) }
func (h *HostInfo) IsDir() bool        { return h.Mode().IsDir() }
func (h *HostInfo) Sys() any           { return &h.st }

func (h *HostInfo) Mode() os.FileMode {
	m := os.FileMode(h.st.Mode & 0o777)
	switch h.st.Mode & syscall.S_IFMT {
	case syscall.S_IFBLK:
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
