package sandbox

import (
	"io"
	"syscall"

	"github.com/samyfodil/laboon/core"
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

// nonHost reports whether d is a regular file with no host descriptor behind its
// backing (in-memory, user-defined), which a mapping must materialize.
func (d *dfile) nonHost() bool {
	if d.vf == nil {
		return false
	}
	_, ok := hostFdOf(d.vf)
	return !ok
}

// shared returns the live per-vnode MAP_SHARED backing, or nil. While one
// exists it is the file's authoritative copy, so read/write/size/truncate route
// through it and stay coherent with the guest's shared mappings (sharedback.go).
// A host file has none: the guest maps the file itself.
func (d *dfile) shared() *shBacking {
	if d.fs == nil || d.vn == nil || !d.nonHost() {
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
// from the live backing if there is one, else the open file itself, which stays
// right after the file is unlinked or replaced.
func (d *dfile) size0() (int64, error) {
	if sb := d.shared(); sb != nil {
		return sb.size0(), nil
	}
	info, err := d.vf.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// appendAt writes p at the end of the file and returns the new end: atomically
// where the backing can (a host file, memfs), else at its current size with
// every such append in the run serialized.
func (d *dfile) appendAt(p []byte) (int, int64, error) {
	if sb := d.shared(); sb != nil {
		off := sb.size0()
		n, err := sb.writeAt(p, off)
		return n, off + int64(n), err
	}
	if a, ok := d.vf.(core.Appender); ok {
		return a.Append(p)
	}
	if d.fs != nil {
		d.fs.appendMu.Lock()
		defer d.fs.appendMu.Unlock()
	}
	off, err := d.size0()
	if err != nil {
		return 0, 0, err
	}
	n, err := d.vf.WriteAt(p, off)
	return n, off + int64(n), err
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
	if d.fx.oflags&lxOAppend != 0 {
		n, end, err := d.appendAt(p)
		if n > 0 {
			d.fpos = end
		}
		return n, err
	}
	n, err := d.vfWriteAt(p, d.fpos)
	d.fpos += int64(n)
	return n, err
}

// tell is the file offset: laboon's for a regular file, else the host's.
func (d *dfile) tell() (int64, error) {
	if d.vf != nil {
		d.fmu.Lock()
		defer d.fmu.Unlock()
		return d.fpos, nil
	}
	return d.f.Seek(0, io.SeekCurrent)
}

// seek moves the file offset: laboon's for a regular file, else the host's.
func (d *dfile) seek(off int64, whence int) (int64, error) {
	if d.vf != nil {
		return d.vfSeek(off, whence)
	}
	return d.f.Seek(off, whence)
}

// seqRead reads at the file offset and advances it; end of file is a short
// count.
func (d *dfile) seqRead(p []byte) (int, error) {
	if d.vf != nil {
		return d.vfRead(p)
	}
	return noEOF(d.f.Read(p))
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
	case 3, 4: // SEEK_DATA, SEEK_HOLE
		p, err := d.seekDataHole(off, whence == 4)
		if err != nil {
			return 0, err
		}
		d.fpos = p
		return p, nil
	default:
		return 0, syscall.EINVAL
	}
	if base+off < 0 {
		return 0, syscall.EINVAL
	}
	d.fpos = base + off
	return d.fpos, nil
}

// seekDataHole finds the next data or hole at or after off: the host's sparse
// map for a host file, else the whole file is data and its end the only hole.
func (d *dfile) seekDataHole(off int64, hole bool) (int64, error) {
	if fd, ok := d.hostFd(); ok && hostHoles && d.shared() == nil {
		p, e := seekDataHole(fd, off, hole)
		if e != 0 {
			return 0, lxErr(e)
		}
		return p, nil
	}
	_, size, err := d.hostStat()
	if err != nil {
		return 0, err
	}
	if off < 0 || off >= size {
		return 0, lxErr(lxENXIO)
	}
	if hole {
		return size, nil
	}
	return off, nil
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
	var st lxStat
	if d.nonHost() {
		a, err := d.vn.Stat()
		if err != nil {
			return lxStat{}, osErrno(err)
		}
		st = nodeStat(a, d.vn.ID())
	} else { // a host file: fstat of the open handle, its identity the host inode's
		info, err := d.vf.Stat()
		if err != nil {
			return lxStat{}, osErrno(err)
		}
		st = nodeStat(info.Attr(), info.ID())
	}
	if sb := d.shared(); sb != nil { // the live size, which may lead the backend
		st.size = sb.size0()
		st.blocks = (st.size + 511) / 512
	}
	if p := d.perm().Load(); p&permSet != 0 {
		st.mode = st.mode&^0o7777 | p&0o7777
	}
	return st, 0
}

// vfFallocate allocates or zeroes a range on a vfs.File backing. A plain
// allocation past the end extends via Truncate; KEEP_SIZE and the hole/zero
// modes are hints on a backing that has no sparse representation here.
func (g *dguest) vfFallocate(d *dfile, mode, off, length int64) int64 {
	if mode == 0 {
		if size, e := d.size0(); e == nil && off+length > size {
			if te := d.vf.Truncate(off + length); te != nil {
				return sErr(osErrno(te))
			}
		}
	}
	return 0
}

// accessOK reports whether d's access mode allows a read (write false) or a
// write.
func (d *dfile) accessOK(write bool) bool {
	if !d.fx.hasFlags {
		return true
	}
	switch d.fx.oflags & lxOAccmod {
	case lxORdonly:
		return !write
	case lxOWronly:
		return write
	}
	return true
}

// regRead reads a regular file into the guest's iovecs v at off, or at the file
// offset when off is -1. The offset is held for the whole call, as the kernel
// holds f_pos_lock, and moves only past what reached the guest: a read stops
// where the guest's buffer stops being writable.
func (g *dguest) regRead(d *dfile, v [][2]uint64, off int64) int64 {
	if !d.accessOK(false) {
		return sErr(lxEBADF)
	}
	n := iovTotal(v)
	seq := off < 0
	if seq {
		d.fmu.Lock()
		defer d.fmu.Unlock()
		off = d.fpos
	}
	if p := g.writableVecPrefix(v, n); p < n {
		if p == 0 {
			// With no room at all, end of file still reads as nothing.
			if size, err := d.size0(); err == nil && off >= size {
				return 0
			}
			return sErr(lxEFAULT)
		}
		n = p
	}
	buf := g.ioBuf(min(n, ioChunk))
	var total int
	for total < n {
		b := buf[:min(n-total, len(buf))]
		m, err := d.vfReadAt(b, off+int64(total))
		if m > 0 {
			if g.scatter(v, total, b[:m]) != 0 {
				break
			}
			total += m
		}
		if err != nil && total == 0 {
			return sErr(ioErrno(err))
		}
		if err != nil || m < len(b) {
			break
		}
	}
	if seq {
		d.fpos = off + int64(total)
	}
	if total > 0 {
		g.notifyFd(d, inAccess)
	}
	return int64(total)
}

// regWrite writes the guest's iovecs v to a regular file at off, or at the file
// offset when off is -1, holding the offset for the whole call. An O_APPEND
// description appends each chunk atomically, a positional write included, as
// Linux's pwrite does; only a sequential one moves the offset. Where the guest's
// bytes stop being readable the write stops, as Linux's would.
func (g *dguest) regWrite(d *dfile, v [][2]uint64, off int64) int64 {
	if !d.accessOK(true) {
		return sErr(lxEBADF)
	}
	n := iovTotal(v)
	app := d.fx.oflags&lxOAppend != 0
	seq := off < 0
	if seq || app {
		d.fmu.Lock()
		defer d.fmu.Unlock()
	}
	if seq {
		off = d.fpos
	}
	// A vector gathers into a buffer of its own (see writeHost).
	buf := g.ioBuf(min(n, ioChunk))
	if len(v) > 1 {
		buf = g.gbuf(len(buf))
	}
	pos := off
	var total int
	for total < n {
		b := buf[:min(n-total, len(buf))]
		got := g.gatherPrefix(v, total, b)
		if got == 0 {
			if total == 0 {
				return sErr(lxEFAULT)
			}
			break
		}
		var m int
		var err error
		if app {
			var end int64
			if m, end, err = d.appendAt(b[:got]); m > 0 {
				pos = end
			}
		} else {
			m, err = d.vfWriteAt(b[:got], pos)
			pos += int64(m)
		}
		total += m
		if err != nil && total == 0 {
			return sErr(ioErrno(err))
		}
		if err != nil || m < len(b) {
			break
		}
	}
	if seq {
		d.fpos = pos
	}
	if total > 0 {
		g.modified(d)
	}
	return int64(total)
}
