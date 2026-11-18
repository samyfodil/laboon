package sandbox

import (
	"io"
	"syscall"
)

// This file is laboon's file layer: the operations the kernel's fd/file code
// performs on an open regular file whose backing is a vfs.File. laboon manages
// the fd and the file offset; the filesystem (vfs.FileSystem, public) links the
// file to its backing and answers ReadAt/WriteAt/Truncate/Stat. The backing never
// sees the guest — the guest-facing work (mmap into guest memory, the Linux stat
// layout) is done here, around the backing's clean interface. A host-backed file
// returns an *os.File from Open, and that is the only "can this be mapped or
// zero-copied directly" capability; anything else takes the generic path.
//
// These are plain methods, not an interface a filesystem implements, so a
// filesystem carries no sandbox types and no global state is needed.

// noEOF maps io.EOF to a nil error with the short count, matching read(2), which
// reports end of file as a zero-length read rather than an error.
func noEOF(n int, err error) (int, error) {
	if err == io.EOF {
		return n, nil
	}
	return n, err
}

// shared returns the live per-vnode MAP_SHARED backing, or nil. While one
// exists it is the file's authoritative copy, so read/write/size/truncate route
// through it and stay coherent with the guest's shared mappings (sharedback.go).
func (d *dfile) shared() *shBacking {
	if d.fs == nil || d.vn == nil {
		return nil
	}
	return d.fs.backing(d.vn.ID())
}

// content reads the file's current bytes: the live shared backing if there is
// one (so a private or executable mapping, or a sendfile, sees stores made
// through a shared mapping), else the backend directly.
func (d *dfile) content() io.ReaderAt {
	if sb := d.shared(); sb != nil {
		return sb
	}
	return d.vf
}

// size0 is the file's current logical size (for SEEK_END, O_APPEND and fstat):
// from the live backing if there is one, else the node.
func (d *dfile) size0() (int64, error) {
	if sb := d.shared(); sb != nil {
		return sb.size0(), nil
	}
	a, err := d.vn.Stat()
	if err != nil {
		return 0, err
	}
	return a.Size, nil
}

// vfReadAt reads at an explicit offset (pread); the file offset is untouched.
func (d *dfile) vfReadAt(p []byte, off int64) (int, error) {
	if sb := d.shared(); sb != nil {
		return noEOF(sb.ReadAt(p, off))
	}
	return noEOF(d.vf.ReadAt(p, off))
}

// vfWriteAt writes at an explicit offset (pwrite); the file offset is untouched.
func (d *dfile) vfWriteAt(p []byte, off int64) (int, error) {
	if sb := d.shared(); sb != nil {
		return sb.writeAt(p, off)
	}
	return d.vf.WriteAt(p, off)
}

// vfRead reads at the file offset and advances it (read(2)).
func (d *dfile) vfRead(p []byte) (int, error) {
	d.fmu.Lock()
	defer d.fmu.Unlock()
	var n int
	var err error
	if sb := d.shared(); sb != nil {
		n, err = noEOF(sb.ReadAt(p, d.fpos))
	} else {
		n, err = noEOF(d.vf.ReadAt(p, d.fpos))
	}
	d.fpos += int64(n)
	return n, err
}

// vfWrite writes at the file offset and advances it; O_APPEND writes at the end
// (write(2)).
func (d *dfile) vfWrite(p []byte) (int, error) {
	d.fmu.Lock()
	defer d.fmu.Unlock()
	off := d.fpos
	if d.fx.oflags&lxOAppend != 0 {
		if s, e := d.size0(); e == nil {
			off = s
		}
	}
	var n int
	var err error
	if sb := d.shared(); sb != nil {
		n, err = sb.writeAt(p, off)
	} else {
		n, err = d.vf.WriteAt(p, off)
	}
	d.fpos = off + int64(n)
	return n, err
}

func (d *dfile) vfSeek(off int64, whence int) (int64, error) {
	d.fmu.Lock()
	defer d.fmu.Unlock()
	var base int64
	switch whence {
	case 0: // SEEK_SET
	case 1: // SEEK_CUR
		base = d.fpos
	case 2: // SEEK_END
		s, err := d.size0()
		if err != nil {
			return 0, err
		}
		base = s
	default:
		return 0, syscall.EINVAL
	}
	if base+off < 0 {
		return 0, syscall.EINVAL
	}
	d.fpos = base + off
	return d.fpos, nil
}

func (d *dfile) vfTruncate(size int64) error {
	if sb := d.shared(); sb != nil {
		return sb.truncate(size)
	}
	return d.vf.Truncate(size)
}

// vfSync flushes the backing if it can; an in-memory backing is already durable.
func (d *dfile) vfSync() error {
	if s, ok := d.vf.(interface{ Sync() error }); ok {
		return s.Sync()
	}
	return nil
}

// vfFstat fills the Linux stat for the open file from the node, then applies a
// per-fd mode override the backend could not record. Statting the node (not a
// path) stays correct for a file unlinked while open.
func (g *dguest) vfFstat(d *dfile) (lxStat, lxErrno) {
	a, err := d.vn.Stat()
	if err != nil {
		return lxStat{}, osErrno(err)
	}
	st := nodeStat(a, d.vn.ID())
	if sb := d.shared(); sb != nil { // the live size, which may lead the backend
		st.size = sb.size0()
		st.blocks = (st.size + 511) / 512
	}
	if p := d.fx.perm.Load(); p&permSet != 0 {
		st.mode = st.mode&^0o7777 | p&0o7777
	}
	return st, 0
}

// vfFallocate allocates or zeroes a range on a vfs.File backing. A plain
// allocation past the end extends via Truncate; KEEP_SIZE and the hole/zero
// modes are hints on a backing that has no sparse representation here.
func (g *dguest) vfFallocate(d *dfile, mode, off, length int64) int64 {
	if mode == 0 {
		if a, e := d.vn.Stat(); e == nil && off+length > a.Size {
			if te := d.vf.Truncate(off + length); te != nil {
				return sErr(osErrno(te))
			}
		}
	}
	return 0
}
