//go:build darwin || linux || windows

package sandbox

import (
	"os"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// hostOf is the host *os.File behind a File opened from a host-backed node, or
// nil if the File has no host descriptor (an in-memory or synthetic backend). The
// descriptor is taken through the File's own HostFile hook — the one deliberate
// escape hatch a host-backed File exposes for the supervisor's fast path (mmap,
// poll, fcntl) — never by asserting the concrete type past the File interface.
func hostOf(f core.File) (*os.File, bool) {
	if h, ok := f.(interface{ HostFile() *os.File }); ok {
		return h.HostFile(), true
	}
	return nil, false
}

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
