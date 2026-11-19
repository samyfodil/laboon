//go:build darwin

package sandbox

import (
	"errors"
	"os"
	"strings"

	"github.com/samyfodil/laboon/core"
	"golang.org/x/sys/unix"
)

// Extended attributes: real host xattrs, set on the upper layer (copying the
// file up first) and read through the overlay. Only Linux-namespaced names are
// exposed, so the host's own com.apple.* attributes stay invisible. There are
// no POSIX ACLs: system.* reads as absent and cannot be set.

const (
	lxXattrCreate  = 1
	lxXattrReplace = 2
	xattrNameMax   = 255
	xattrSizeMax   = 65536
)

func init() {
	for nr := uint64(5); nr <= 16; nr++ {
		op, kind := (nr-5)/3, (nr-5)%3 // set/get/list/remove x path/lpath/fd
		syscalls[nr] = func(g *dguest, a [6]uint64) int64 { return g.xattr(op, kind, a) }
	}
}

func lxXattrNamespace(name string) bool {
	for _, p := range []string{"user.", "trusted.", "security.", "system."} {
		if strings.HasPrefix(name, p) && len(name) > len(p) {
			return true
		}
	}
	return false
}

func darwinXattrErr(err error) lxErrno {
	if errors.Is(err, unix.ENOATTR) {
		return lxENODATA
	}
	return osErrno(err)
}

// xattr serves the twelve xattr syscalls: op 0 set, 1 get, 2 list, 3 remove;
// kind 0 follows symlinks, 1 does not (l*), 2 takes a fd (f*).
func (g *dguest) xattr(op, kind uint64, a [6]uint64) int64 {
	var gp string
	var d *dfile
	if kind == 2 {
		dd, ok := g.ft.get(int(a[0]))
		if !ok || dd.fx.opath {
			return sErr(lxEBADF)
		}
		if dd.f == nil {
			if op == 0 || op == 3 {
				return sErr(lxEOPNOTSUPP)
			}
			if op == 2 {
				return 0
			}
			return sErr(lxENODATA)
		}
		gp, d = dd.name(), dd
	} else {
		p, e := g.lookup(lxAtFdcwd, a[0], kind == 0)
		if e != 0 {
			return sErr(e)
		}
		gp = p
	}
	var name string
	if op != 2 {
		n, err := g.readCStr(a[1])
		if err != nil {
			return sErr(lxEFAULT)
		}
		if n == "" || len(n) > xattrNameMax {
			return sErr(lxERANGE)
		}
		if !lxXattrNamespace(n) {
			return sErr(lxEOPNOTSUPP)
		}
		name = n
	}
	switch op {
	case 0:
		return g.setxattr(gp, d, name, a[2], int64(a[3]), int64(a[4]))
	case 1:
		return g.getxattr(gp, d, name, a[2], int64(a[3]))
	case 2:
		return g.listxattr(gp, d, a[1], int64(a[2]))
	default:
		return g.removexattr(gp, d, name)
	}
}

func (g *dguest) getxattr(gp string, d *dfile, name string, buf uint64, size int64) int64 {
	if strings.HasPrefix(name, "system.") {
		return sErr(lxENODATA)
	}
	var val []byte
	var err error
	if d != nil {
		fi, serr := d.f.Stat()
		if serr != nil {
			return sErr(osErrno(serr))
		}
		if fi.Mode()&os.ModeSymlink != 0 && strings.HasPrefix(name, "user.") {
			return sErr(lxENODATA)
		}
		raw := make([]byte, xattrSizeMax)
		var n int
		n, err = unix.Fgetxattr(hostFd(d.f), name, raw)
		val = raw[:n]
	} else {
		loc, e := g.vns().Resolve(gp, false)
		if e != nil {
			return sErr(osErrno(e))
		}
		if loc.Node.Kind() == core.Symlink && strings.HasPrefix(name, "user.") {
			return sErr(lxENODATA)
		}
		xn, ok := loc.Node.(core.XattrNode)
		if !ok {
			return sErr(lxEOPNOTSUPP) // a synthetic node carries no xattrs
		}
		val, err = xn.Getxattr(name)
	}
	if err != nil {
		return sErr(darwinXattrErr(err))
	}
	if size == 0 {
		return int64(len(val))
	}
	if int64(len(val)) > size {
		return sErr(lxERANGE)
	}
	if err := g.writeMem(buf, val); err != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(val))
}

func (g *dguest) listxattr(gp string, d *dfile, buf uint64, size int64) int64 {
	var raw []byte
	var err error
	if d != nil {
		b := make([]byte, 1<<16)
		var n int
		n, err = unix.Flistxattr(hostFd(d.f), b)
		raw = b[:n]
	} else {
		loc, e := g.vns().Resolve(gp, false)
		if e != nil {
			return sErr(osErrno(e))
		}
		xn, ok := loc.Node.(core.XattrNode)
		if !ok {
			return 0 // a synthetic node lists no xattrs
		}
		raw, err = xn.Listxattr()
	}
	if err != nil {
		return sErr(darwinXattrErr(err))
	}
	var out []byte
	for _, nm := range strings.Split(string(raw), "\x00") {
		if lxXattrNamespace(nm) {
			out = append(append(out, nm...), 0)
		}
	}
	if size == 0 {
		return int64(len(out))
	}
	if int64(len(out)) > size {
		return sErr(lxERANGE)
	}
	if err := g.writeMem(buf, out); err != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(out))
}

func (g *dguest) setxattr(gp string, d *dfile, name string, valAddr uint64, size, flags int64) int64 {
	if flags&^(lxXattrCreate|lxXattrReplace) != 0 {
		return sErr(lxEINVAL)
	}
	if size < 0 || size > xattrSizeMax {
		return sErr(lxE2BIG)
	}
	if strings.HasPrefix(name, "system.") {
		return sErr(lxEOPNOTSUPP)
	}
	val, err := g.readMem(valAddr, int(size))
	if err != nil {
		return sErr(lxEFAULT)
	}
	df := 0
	if flags&lxXattrCreate != 0 {
		df |= unix.XATTR_CREATE
	}
	if flags&lxXattrReplace != 0 {
		df |= unix.XATTR_REPLACE
	}
	user := strings.HasPrefix(name, "user.")
	if g.fdInPlace(d) {
		fi, serr := fileStat(d.f)
		if serr != nil {
			return sErr(osErrno(serr))
		}
		if user && !fi.Mode().IsRegular() && !fi.IsDir() {
			return sErr(lxEPERM)
		}
		err = fsetxattr(hostFd(d.f), name, val, df)
	} else {
		loc, e := g.vns().Resolve(gp, false)
		if e != nil {
			return sErr(osErrno(e))
		}
		if k := loc.Node.Kind(); user && k != core.Reg && k != core.Dir {
			return sErr(lxEPERM)
		}
		xn, ok := loc.Node.(core.XattrNode)
		if !ok {
			return sErr(lxEOPNOTSUPP)
		}
		err = xn.Setxattr(name, val, df)
	}
	if err != nil {
		return sErr(darwinXattrErr(err))
	}
	g.notify(gp, inAttrib, 0)
	return 0
}

func (g *dguest) removexattr(gp string, d *dfile, name string) int64 {
	if strings.HasPrefix(name, "system.") {
		return sErr(lxENODATA)
	}
	var err error
	if g.fdInPlace(d) {
		err = unix.Fremovexattr(hostFd(d.f), name)
	} else {
		loc, e := g.vns().Resolve(gp, false)
		if e != nil {
			return sErr(osErrno(e))
		}
		xn, ok := loc.Node.(core.XattrNode)
		if !ok {
			return sErr(lxEOPNOTSUPP)
		}
		err = xn.Removexattr(name)
	}
	if err != nil {
		return sErr(darwinXattrErr(err))
	}
	g.notify(gp, inAttrib, 0)
	return 0
}

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
