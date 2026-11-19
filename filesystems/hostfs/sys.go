//go:build darwin || linux || windows

package hostfs

import (
	"os"
	"syscall"
	"time"
)

// HostDevIno returns a host file's device and inode numbers (0,0 if unknown).
func HostDevIno(fi os.FileInfo) (dev, ino uint64) {
	if st, ok := StatOf(fi); ok {
		return st.dev, st.ino
	}
	return 0, 0
}

// TsNano is a timespec as unix nanoseconds.
func TsNano(t syscall.Timespec) int64 { return int64(t.Sec)*1e9 + int64(t.Nsec) }

func timespecTime(ts syscall.Timespec) time.Time { return time.Unix(ts.Sec, ts.Nsec) }
