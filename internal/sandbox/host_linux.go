package sandbox

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// clockNow reads a guest clock: the host's clock of the same id.
func clockNow(clock int64) time.Duration {
	var ts unix.Timespec
	if unix.ClockGettime(int32(clock), &ts) != nil {
		unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	}
	return time.Duration(ts.Nano())
}

// hostIsTTY reports whether f is a host terminal.
func hostIsTTY(f *os.File) bool {
	_, err := unix.IoctlGetTermios(hostFd(f), unix.TCGETS)
	return err == nil
}

// setHostPipeSize sizes the host pipe behind hfd to n bytes, as F_SETPIPE_SZ
// asked of the guest's pipe.
func setHostPipeSize(hfd int, n int) lxErrno {
	if _, err := unix.FcntlInt(uintptr(hfd), unix.F_SETPIPE_SZ, n); err != nil {
		if e, ok := hostErrnoOf(err); ok {
			return e
		}
		return lxEINVAL
	}
	return 0
}
