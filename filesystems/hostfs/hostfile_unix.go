//go:build darwin || linux

package hostfs

import (
	"os"

	"golang.org/x/sys/unix"
)

// FstatOf is the HostStat of the open file f.
func FstatOf(f *os.File) (HostStat, error) {
	fi, err := f.Stat()
	if err != nil {
		return HostStat{}, err
	}
	st, _ := StatOf(fi)
	return st, nil
}

// fdOf is f's descriptor, without os.File.Fd's switch to blocking mode.
func fdOf(f *os.File) uintptr {
	fd := ^uintptr(0)
	if rc, err := f.SyscallConn(); err == nil {
		rc.Control(func(d uintptr) { fd = d })
	}
	return fd
}

// dupOf is an owned duplicate of f's descriptor.
func dupOf(f *os.File) (*os.File, error) {
	fd, err := unix.FcntlInt(fdOf(f), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), f.Name()), nil
}

// FileStat is the os.FileInfo of the open file f, which StatOf understands.
func FileStat(f *os.File) (os.FileInfo, error) { return f.Stat() }

// FchmodOf sets the open file f's permission bits.
func FchmodOf(f *os.File, mode uint32) error { return f.Chmod(os.FileMode(mode)) }

// AnonFile makes an unnamed host file in dir (named with prefix only while it is
// being made).
func AnonFile(dir, prefix string) (*os.File, error) {
	f, err := os.CreateTemp(dir, prefix)
	if err != nil {
		return nil, err
	}
	os.Remove(f.Name())
	return f, nil
}
