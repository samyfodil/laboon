//go:build darwin || linux || windows

package sandbox

import (
	"os"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// hostFdOf is the host descriptor behind a File opened from a host-backed node,
// borrowed (the File keeps owning it), or ok false for a File with none (an
// in-memory or synthetic backend). It comes through the File's HostFd hook —
// the one escape hatch a host-backed File exposes, for what only the host
// object can do (map, poll, lend to the stub) — never by asserting the concrete
// type past the File interface.
func hostFdOf(f core.File) (int, bool) {
	if h, ok := f.(interface{ HostFd() uintptr }); ok {
		return int(h.HostFd()), true
	}
	return -1, false
}

// hostDupOf is an owned duplicate of the descriptor behind f, named name: the
// stream plane of a filesystem object whose bytes the supervisor moves itself,
// as it does a pipe's (a directory, FIFO, device or O_PATH pin), or a real host
// file for a caller that must hand one on (the loader). The caller closes it;
// f stays open until its own Close.
func hostDupOf(f core.File, name string) (*os.File, bool) {
	fd, ok := hostFdOf(f)
	if !ok {
		return nil, false
	}
	nf, e := dupFd(fd, name)
	return nf, e == 0
}

// hostFd is d's host descriptor: its own for a supervisor-owned object, its
// backing's (borrowed) for a host-backed regular file.
func (d *dfile) hostFd() (int, bool) {
	if d.f != nil {
		return hostFd(d.f), true
	}
	if d.vf != nil {
		return hostFdOf(d.vf)
	}
	return -1, false
}

// held reports whether the supervisor holds d's object (a descriptor or a
// regular file's backing), which stub-served stdio is not.
func (d *dfile) held() bool { return d.f != nil || d.vf != nil }

// fsFile is d's filesystem handle: a host-backed object's, or a non-host
// regular file's backing; nil for a supervisor-owned object.
func (d *dfile) fsFile() core.File {
	if d.hf != nil {
		return d.hf
	}
	return d.vf
}

// hostStat returns the open file's portable type bits and size. A guest
// filesystem object (hf set) is read through its vfs handle, so the sandbox
// never interprets host metadata itself; a supervisor-owned object (memfd, pipe,
// device, socket) is read from its own descriptor, which it owns. The mode's
// type and permission bits and the size are portable across platforms; callers
// that need the full Linux stat (identity, rdev) go through hf.Stat.
func (d *dfile) hostStat() (os.FileMode, int64, error) {
	if h := d.fsFile(); h != nil {
		info, err := h.Stat()
		if err != nil {
			return 0, 0, err
		}
		return info.Mode(), info.Size(), nil
	}
	if d.f == nil {
		return 0, 0, os.ErrInvalid
	}
	fi, err := d.f.Stat()
	if err != nil {
		return 0, 0, err
	}
	return fi.Mode(), fi.Size(), nil
}

// hostDevIno returns the open file's device and inode numbers (a Linux dev_t and
// ino). A filesystem object's identity comes through its vfs handle; a
// supervisor-owned object (memfd, device) reports its own descriptor's. Zero on
// error, so callers must not treat an all-zero result as a real identity.
func (d *dfile) hostDevIno() (dev, ino uint64) {
	if h := d.fsFile(); h != nil {
		info, err := h.Stat()
		if err != nil {
			return 0, 0
		}
		id := info.ID()
		return id.Dev, id.Ino
	}
	if d.f != nil {
		if fi, err := hostfs.FileStat(d.f); err == nil {
			return HostDevIno(fi)
		}
	}
	return 0, 0
}
