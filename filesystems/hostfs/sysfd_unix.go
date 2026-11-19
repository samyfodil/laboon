//go:build darwin || linux

package hostfs

import "os"

// hostFd is the host file descriptor backing f, or -1.
func hostFd(f *os.File) int {
	fd := -1
	if rc, err := f.SyscallConn(); err == nil {
		rc.Control(func(h uintptr) { fd = int(h) })
	}
	return fd
}
