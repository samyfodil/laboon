//go:build darwin || linux

package sandbox

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// monoNow is CLOCK_MONOTONIC as the stub's clock_gettime reports it.
func monoNow() time.Duration {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return time.Duration(ts.Nano())
}

// dupFile duplicates f's host fd (close-on-exec) into a new *os.File. It fails
// rather than racing a concurrent close.
func dupFile(f *os.File) (*os.File, lxErrno) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, lxEBADF
	}
	nfd := -1
	var derr error
	if err := rc.Control(func(fd uintptr) { nfd, derr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
		return nil, lxEBADF
	}
	if derr != nil {
		return nil, osErrno(derr)
	}
	return os.NewFile(uintptr(nfd), f.Name()), 0
}

// dupFd is an owned duplicate of the host fd, named name.
func dupFd(fd int, name string) (*os.File, lxErrno) {
	nfd, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, osErrno(err)
	}
	return os.NewFile(uintptr(nfd), name), 0
}

// hostFd returns the host fd behind f without the side effect of os.File.Fd,
// which switches the file to blocking mode.
func hostFd(f *os.File) int {
	fd := -1
	if rc, err := f.SyscallConn(); err == nil {
		rc.Control(func(h uintptr) { fd = int(h) })
	}
	return fd
}

// readNonblock reads once without parking: EAGAIN goes back to the guest, as
// for a Linux O_NONBLOCK descriptor. A guest pipe's host fd is itself
// nonblocking, so the read returns EAGAIN on its own; but a FIFO reopened
// through /proc/self/fd, a terminal, or another descriptor laboon holds in
// blocking mode would park the read in the kernel until a writer appears. A
// zero-timeout readiness poll guards that case, so O_NONBLOCK means "never
// wait" whatever the host fd's mode -- the same emulation stdioRead uses.
func readNonblock(f *os.File, buf []byte) (int, error) { return readNonblockKind(f, buf, kindUnknown) }

// readNonblockKind is readNonblock of a file whose readKind is k, if known.
func readNonblockKind(f *os.File, buf []byte, k readKind) (int, error) {
	return readNonblockVia(f, func(fd int) (int, error) { return unix.Read(fd, buf) }, k)
}

// readNonblockVia is readNonblockKind making read once the fd is ready.
func readNonblockVia(f *os.File, read func(fd int) (int, error), k readKind) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var rerr error
	if err := rc.Read(func(fd uintptr) bool {
		// A blocking host fd parks the read until a writer appears, which an
		// O_NONBLOCK guest read must never do. Guard only the fd kinds that can
		// actually block on read -- a FIFO (a container's /proc/self/fd exec
		// fifo) or a socket -- with a zero-timeout readiness poll. A regular file
		// or character device (/dev/null, /dev/zero) never blocks, and polling
		// one is needless (and on darwin a poll of some can itself hang).
		if k == kindUnknown && pollableBlocking(int(fd)) {
			k = kindMayBlock
		}
		if k == kindMayBlock && blockingFd(int(fd)) {
			pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLPRI}}
			if m, pe := unix.Poll(pfd, 0); pe != nil {
				n, rerr = 0, pe
				return true
			} else if m == 0 || pfd[0].Revents&(unix.POLLIN|unix.POLLPRI|unix.POLLHUP|unix.POLLERR) == 0 {
				n, rerr = 0, unix.EAGAIN
				return true
			}
		}
		n, rerr = read(int(fd))
		n = max(n, 0)
		return true
	}); err != nil {
		return 0, err
	}
	return n, rerr
}

// blockingFd reports whether fd is in blocking mode.
func blockingFd(fd int) bool {
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	return err == nil && fl&unix.O_NONBLOCK == 0
}

// readKind is d's host file's, asked of the host once: its kind never changes.
func (d *dfile) readKind() readKind {
	if k := readKind(d.rkind.Load()); k != kindUnknown {
		return k
	}
	k := kindNoBlock
	if pollableBlocking(hostFd(d.f)) {
		k = kindMayBlock
	}
	d.rkind.Store(uint32(k))
	return k
}

// pollableBlocking reports whether fd is a kind that can actually block on a
// read -- a FIFO or a socket -- so a readiness poll is worth doing.
func pollableBlocking(fd int) bool {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return false
	}
	m := st.Mode & unix.S_IFMT
	return m == unix.S_IFIFO || m == unix.S_IFSOCK
}

func writeNonblock(f *os.File, buf []byte) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var werr error
	if err := rc.Write(func(fd uintptr) bool {
		n, werr = unix.Write(int(fd), buf)
		return true
	}); err != nil {
		return 0, err
	}
	return n, werr
}

// hostAccMode is f's host access mode as a Linux O_ACCMODE value, and whether
// it is in append mode.
func hostAccMode(f *os.File) (acc int64, appendMode bool, err error) {
	fl, err := unix.FcntlInt(uintptr(hostFd(f)), unix.F_GETFL, 0)
	if err != nil {
		return 0, false, err
	}
	// Darwin's O_ACCMODE values are Linux's.
	return int64(fl & unix.O_ACCMODE), fl&unix.O_APPEND != 0, nil
}

// setHostAppend turns f's host append mode on or off.
func setHostAppend(hfd int, on bool) {
	if hfd < 0 {
		return
	}
	fl, err := unix.FcntlInt(uintptr(hfd), unix.F_GETFL, 0)
	if err != nil {
		return
	}
	fl &^= unix.O_APPEND
	if on {
		fl |= unix.O_APPEND
	}
	unix.FcntlInt(uintptr(hfd), unix.F_SETFL, fl)
}

// seekDataHole is lseek SEEK_DATA (hole false) or SEEK_HOLE on f.
// hostHoles reports whether the host reports a file's holes.
const hostHoles = true

func seekDataHole(fd int, off int64, hole bool) (int64, lxErrno) {
	whence := unix.SEEK_DATA
	if hole {
		whence = unix.SEEK_HOLE
	}
	pos, err := unix.Seek(fd, off, whence)
	if err != nil {
		if errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ESPIPE) {
			return 0, hostErrno(err.(unix.Errno))
		}
		return 0, lxEINVAL
	}
	return pos, 0
}

func hostPipe(uint32) (r, w *os.File, err error) { return os.Pipe() }

// hostDevOpen opens the host device behind a synthetic /dev node.
func hostDevOpen(name string, flag int) (*os.File, error) { return os.OpenFile(name, flag, 0) }
