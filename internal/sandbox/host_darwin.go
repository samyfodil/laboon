//go:build darwin

package sandbox

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// clockNow reads a guest clock in its own timebase, the one the stub's
// clock_gettime serves (local.zig): Darwin's MONOTONIC for the monotonic ones.
func clockNow(clock int64) time.Duration {
	var ts unix.Timespec
	id := int32(unix.CLOCK_MONOTONIC)
	if clock == 0 || clock == 5 || clock == 8 || clock == 11 {
		id = unix.CLOCK_REALTIME
	}
	unix.ClockGettime(id, &ts)
	return time.Duration(ts.Nano())
}

// hostIsTTY reports whether f is a host terminal.
func hostIsTTY(f *os.File) bool {
	_, err := unix.IoctlGetTermios(hostFd(f), unix.TIOCGETA)
	return err == nil
}

// setHostPipeSize leaves the host pipe as it is: Darwin sizes its pipes itself.
func setHostPipeSize(int, int) lxErrno { return 0 }
