//go:build darwin

package hostfs

import (
	"os"

	"golang.org/x/sys/unix"
)

// xattrOp runs an xattr call on the host object at backend-relative p. A
// confined (writable, guest-mutable) layer is reached through an fd opened
// without following a symlink, so a dir→symlink swap cannot redirect the call;
// a read-only layer uses the path directly.
func (f *HostDirFS) xattrOp(p string, byFd func(int) error, byPath func(string) error) error {
	hp := f.hp(p)
	if !f.confine {
		return byPath(hp)
	}
	fd, err := f.h.hOpen(hp, os.O_RDONLY|unix.O_SYMLINK|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer fd.Close()
	return byFd(int(fd.Fd()))
}

func (n *HostNode) Getxattr(name string) ([]byte, error) {
	val := make([]byte, xattrSizeMax)
	var nn int
	err := n.fs.xattrOp(n.p, func(fd int) (e error) {
		nn, e = unix.Fgetxattr(fd, name, val)
		return
	}, func(p string) (e error) {
		nn, e = unix.Lgetxattr(p, name, val)
		return
	})
	if err != nil {
		return nil, err
	}
	out := make([]byte, nn)
	copy(out, val)
	return out, nil
}

func (n *HostNode) Listxattr() ([]byte, error) {
	raw := make([]byte, 1<<16)
	var nn int
	err := n.fs.xattrOp(n.p, func(fd int) (e error) {
		nn, e = unix.Flistxattr(fd, raw)
		return
	}, func(p string) (e error) {
		nn, e = unix.Llistxattr(p, raw)
		return
	})
	if err != nil {
		return nil, err
	}
	out := make([]byte, nn)
	copy(out, raw)
	return out, nil
}

func (n *HostNode) Setxattr(name string, value []byte, flags int) error {
	return n.fs.xattrOp(n.p, func(fd int) error {
		return fsetxattr(fd, name, value, flags)
	}, func(p string) error {
		return unix.Lsetxattr(p, name, value, flags)
	})
}

func (n *HostNode) Removexattr(name string) error {
	return n.fs.xattrOp(n.p, func(fd int) error {
		return unix.Fremovexattr(fd, name)
	}, func(p string) error {
		return unix.Lremovexattr(p, name)
	})
}
