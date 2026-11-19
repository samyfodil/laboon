package sandbox

import (
	"fmt"
	"os"
	"strings"

	"github.com/samyfodil/laboon/filesystems/hostfs"
	"golang.org/x/sys/unix"
)

// kickSignal has a stub route its pending signals to its threads.
const kickSignal = unix.SIGURG

const (
	ioctlGetTermios  = unix.TCGETS
	ioctlSetTermiosW = unix.TCSETSW
)

func isHostTTY(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// hostTTYName returns the host device path of the terminal open at fd.
func hostTTYName(fd int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
}

// hostPtsNum is the number of host pty slave /dev/pts/N.
// hostPtsPath is the host path of pty slave n.
func hostPtsPath(n int) string { return fmt.Sprintf("/dev/pts/%d", n) }

func hostPtsNum(host string) (int, bool) {
	s, ok := strings.CutPrefix(host, "/dev/pts/")
	if !ok || s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// ttyRdev is the Linux st_rdev of a host device node: the host's own.
func ttyRdev(fi os.FileInfo) (uint64, bool) {
	if st, ok := hostfs.StatOf(fi); ok && st.Mode()&unix.S_IFMT == unix.S_IFCHR {
		return st.Rdev(), true
	}
	return 0, false
}

// hostPtyOpen opens a host pty master, unlocked, and names its slave.
func hostPtyOpen() (*os.File, string, lxErrno) {
	f, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, "", osErrno(err)
	}
	fd := hostFd(f)
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		f.Close()
		return nil, "", osErrno(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		f.Close()
		return nil, "", osErrno(err)
	}
	return f, fmt.Sprintf("/dev/pts/%d", n), 0
}
