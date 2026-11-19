//go:build darwin

package hostfs

import "golang.org/x/sys/unix"

const xattrSizeMax = 65536

// fsetxattr is unix.Fsetxattr with its flags honored: x/sys drops them, so
// XATTR_CREATE and XATTR_REPLACE are checked here first.
func fsetxattr(fd int, name string, val []byte, flags int) error {
	if flags&(unix.XATTR_CREATE|unix.XATTR_REPLACE) != 0 {
		_, err := unix.Fgetxattr(fd, name, nil)
		switch {
		case err == nil && flags&unix.XATTR_CREATE != 0:
			return unix.EEXIST
		case err == unix.ENOATTR && flags&unix.XATTR_REPLACE != 0:
			return unix.ENOATTR
		}
	}
	return unix.Fsetxattr(fd, name, val, 0)
}
