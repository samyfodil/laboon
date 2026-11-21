package hostfs

import (
	"os"

	"golang.org/x/sys/unix"
)

// Modeless reports whether the host keeps no permission bits for an object:
// Darwin refuses fchmod on a socket or a pipe (EINVAL).
func Modeless(f *os.File) bool {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil {
		return false
	}
	t := st.Mode & unix.S_IFMT
	return t == unix.S_IFSOCK || t == unix.S_IFIFO
}
