//go:build darwin || linux || windows

package sandbox

import (
	"errors"
	"io"
	"os"
)

// Positional and in-kernel-copy I/O: pread/pwrite and their vector forms,
// sendfile, copy_file_range, splice, vmsplice, fallocate and the sync family.
// Data moves through the supervisor in bounded chunks, like read/write.

const (
	lxFallocate     = 47
	lxPread64       = 67
	lxPwrite64      = 68
	lxPreadv        = 69
	lxPwritev       = 70
	lxSendfile      = 71
	lxVmsplice      = 75
	lxSplice        = 76
	lxSync          = 81
	lxFsync         = 82
	lxFdatasync     = 83
	lxSyncFileRange = 84
	lxFadvise64     = 223
	lxSyncfs        = 267
	lxCopyFileRange = 285
	lxPreadv2       = 286
	lxPwritev2      = 287

	lxSpliceNonblock  = 2
	lxFallocKeepSize  = 1
	lxFallocPunchHole = 2
	lxFallocZeroRange = 0x10
)

func init() {
	syscalls[lxPread64] = func(g *dguest, a [6]uint64) int64 { return g.pread(int64(a[0]), a[1], int64(a[2]), int64(a[3])) }
	syscalls[lxPwrite64] = func(g *dguest, a [6]uint64) int64 { return g.pwrite(int64(a[0]), a[1], int64(a[2]), int64(a[3])) }
	syscalls[lxPreadv] = func(g *dguest, a [6]uint64) int64 { return g.preadv(int64(a[0]), a[1], int64(a[2]), int64(a[3]), 0) }
	syscalls[lxPwritev] = func(g *dguest, a [6]uint64) int64 { return g.pwritev(int64(a[0]), a[1], int64(a[2]), int64(a[3]), 0) }
	syscalls[lxPreadv2] = func(g *dguest, a [6]uint64) int64 {
		return g.preadv(int64(a[0]), a[1], int64(a[2]), int64(a[3]), a[5])
	}
	syscalls[lxPwritev2] = func(g *dguest, a [6]uint64) int64 {
		return g.pwritev(int64(a[0]), a[1], int64(a[2]), int64(a[3]), a[5])
	}
	syscalls[lxSendfile] = func(g *dguest, a [6]uint64) int64 { return g.sendfile(int64(a[0]), int64(a[1]), a[2], int64(a[3])) }
	syscalls[lxCopyFileRange] = func(g *dguest, a [6]uint64) int64 {
		return g.copyFileRange(int64(a[0]), a[1], int64(a[2]), a[3], int64(a[4]), a[5])
	}
	syscalls[lxSplice] = func(g *dguest, a [6]uint64) int64 {
		return g.splice(int64(a[0]), a[1], int64(a[2]), a[3], int64(a[4]), a[5])
	}
	syscalls[lxVmsplice] = func(g *dguest, a [6]uint64) int64 { return g.vmsplice(int64(a[0]), a[1], int64(a[2])) }
	syscalls[lxFallocate] = func(g *dguest, a [6]uint64) int64 {
		return g.fallocate(int64(a[0]), int64(a[1]), int64(a[2]), int64(a[3]))
	}
	syscalls[lxFsync] = func(g *dguest, a [6]uint64) int64 { return g.fsync(int64(a[0])) }
	syscalls[lxFdatasync] = syscalls[lxFsync]
	syscalls[lxSync] = func(g *dguest, a [6]uint64) int64 { return 0 }
	syscalls[lxFadvise64] = func(g *dguest, a [6]uint64) int64 { return g.fadvise(int64(a[0]), int64(a[2]), a[3]) }
	syscalls[lxSyncfs] = func(g *dguest, a [6]uint64) int64 {
		if _, ok := g.ft.get(int(a[0])); !ok {
			return sErr(lxEBADF)
		}
		return 0
	}
	syscalls[lxSyncFileRange] = func(g *dguest, a [6]uint64) int64 {
		if a[3]&^7 != 0 || int64(a[1]) < 0 || int64(a[2]) < 0 {
			return sErr(lxEINVAL)
		}
		if _, ok := g.ft.get(int(a[0])); !ok {
			return sErr(lxEBADF)
		}
		return 0
	}
}

// ioFile returns fd's open file for data I/O: EBADF for unknown fds, O_PATH
// descriptions and stub-served stdio, EISDIR for a directory.
func (g *dguest) ioFile(fd int64) (*dfile, lxErrno) {
	d, ok := g.ft.get(int(fd))
	if !ok || d.f == nil || d.fx.opath {
		return nil, lxEBADF
	}
	if d.isDir {
		return nil, lxEISDIR
	}
	return d, 0
}

func ioErrno(err error) lxErrno {
	if err == errSigIntr {
		return errRestart
	}
	if errors.Is(err, os.ErrClosed) {
		return lxEBADF
	}
	return osErrno(err)
}

// readAt reads at off without moving the file offset; EOF is a short count.
func (d *dfile) readAt(buf []byte, off int64) (int, error) {
	if d.pipe != nil && d.pipe.io != nil {
		return 0, lxErr(lxESPIPE)
	}
	n, err := d.f.ReadAt(buf, off)
	if err == io.EOF {
		err = nil
	}
	return n, err
}

// writeAt writes at off without moving the file offset. An O_APPEND
// description appends regardless, as Linux's pwrite does.
func (d *dfile) writeAt(buf []byte, off int64) (int, error) {
	if d.pipe != nil && d.pipe.io != nil {
		return 0, lxErr(lxESPIPE)
	}
	if d.full {
		return 0, lxErr(lxENOSPC)
	}
	if d.fx.oflags&lxOAppend != 0 {
		return d.f.Write(buf)
	}
	return d.f.WriteAt(buf, off)
}

// readSome reads once at the current offset (a pipe read returns what is there).
func (g *dguest) readSome(d *dfile, buf []byte, nonblock bool) (int, error) {
	if d.pipe != nil && d.pipe.io != nil {
		return d.pipe.io.read(g, d, buf, nonblock || d.nonblock.Load(), false)
	}
	if nonblock || d.nonblock.Load() {
		return readNonblock(d.f, buf)
	}
	n, err := d.f.Read(buf)
	if err == io.EOF {
		err = nil
	}
	return n, err
}

func (g *dguest) writeAll(d *dfile, buf []byte, nonblock bool) (int, error) {
	if d.pipe != nil && d.pipe.io != nil {
		return d.pipe.io.write(g, d, buf, nonblock || d.nonblock.Load())
	}
	if d.full {
		return 0, lxErr(lxENOSPC)
	}
	if nonblock || d.nonblock.Load() {
		return writeNonblock(d.f, buf)
	}
	return d.f.Write(buf)
}

func (d *dfile) sealCheckWrite(off int64, n int) lxErrno {
	if !d.fx.memfd || d.fx.seals.Load() == 0 {
		return 0
	}
	fi, err := fileStat(d.f)
	if err != nil {
		return osErrno(err)
	}
	end := off + int64(n)
	if d.fx.oflags&lxOAppend != 0 {
		end = fi.Size() + int64(n)
	}
	return d.checkSeals(fi.Size(), max(end, fi.Size()), true)
}

func (g *dguest) pread(fd int64, bufAddr uint64, n, off int64) int64 {
	d, e := g.ioFile(fd)
	if e == 0 && d.served() {
		return sErr(lxESPIPE)
	}
	if e != 0 {
		if r, ok := g.memPread(fd, bufAddr, n, off); ok {
			return r
		}
		return sErr(e)
	}
	if n < 0 || off < 0 {
		return sErr(lxEINVAL)
	}
	if n > ioChunk && d.fillsReads() {
		return g.readFull(d, bufAddr, n, off)
	}
	buf := g.ioBuf(int(min(n, ioChunk)))
	m, err := d.readAt(buf, off)
	if err != nil && m == 0 {
		return sErr(ioErrno(err))
	}
	// A positional read takes nothing from the file: the guest gets what fits
	// before its buffer stops being writable, as Linux's copy stops there.
	if p := int(g.writablePrefix(bufAddr, uint64(m))); p < m {
		if p == 0 {
			return sErr(lxEFAULT)
		}
		m = p
	}
	if err := g.putOut(bufAddr, buf[:m]); err != nil {
		return sErr(lxEFAULT)
	}
	if m > 0 {
		g.notifyFd(d, inAccess)
	}
	return int64(m)
}

func (g *dguest) pwrite(fd int64, bufAddr uint64, n, off int64) int64 {
	if r, ok := g.memPwrite(fd, bufAddr, n, off); ok {
		return r
	}
	d, e := g.ioFile(fd)
	if e == 0 && d.served() {
		return sErr(lxESPIPE)
	}
	if e != 0 {
		return sErr(e)
	}
	if n < 0 || off < 0 {
		return sErr(lxEINVAL)
	}
	if e := d.sealCheckWrite(off, int(n)); e != 0 {
		return sErr(e)
	}
	// A chunk at a time, so a large write does not stage all of it here.
	var total int64
	for total < n || n == 0 {
		buf := g.ioBuf(int(min(n-total, ioChunk)))
		if err := g.argGet(bufAddr+uint64(total), buf); err != nil {
			if total == 0 {
				return sErr(lxEFAULT)
			}
			break
		}
		m, err := d.writeAt(buf, off+total)
		if err != nil && m <= 0 {
			if total == 0 {
				return sErr(ioErrno(err))
			}
			break
		}
		total += int64(m)
		if m < len(buf) || n == 0 {
			break
		}
	}
	g.modified(d)
	return total
}

// rwfKnown are the RWF_* flags preadv2/pwritev2 accept (all advisory here).
const rwfKnown = 0x1f

func (g *dguest) preadv(fd int64, iov uint64, cnt, off int64, rwf uint64) int64 {
	if rwf&^rwfKnown != 0 {
		return sErr(lxEOPNOTSUPP)
	}
	if off == -1 {
		return g.readv(fd, iov, cnt)
	}
	v, e := g.iovecs(iov, cnt)
	if e != 0 {
		return sErr(e)
	}
	var total int64
	for _, x := range v {
		if x[1] == 0 {
			continue
		}
		r := g.pread(fd, x[0], int64(x[1]), off+total)
		if r < 0 {
			if total > 0 {
				return total
			}
			return r
		}
		total += r
		if r < int64(x[1]) {
			break
		}
	}
	return total
}

func (g *dguest) pwritev(fd int64, iov uint64, cnt, off int64, rwf uint64) int64 {
	if rwf&^rwfKnown != 0 {
		return sErr(lxEOPNOTSUPP)
	}
	if off == -1 {
		return g.writev(fd, iov, cnt)
	}
	v, e := g.iovecs(iov, cnt)
	if e != 0 {
		return sErr(e)
	}
	var total int64
	for _, x := range v {
		if x[1] == 0 {
			continue
		}
		r := g.pwrite(fd, x[0], int64(x[1]), off+total)
		if r < 0 {
			if total > 0 {
				return total
			}
			return r
		}
		total += r
		if r < int64(x[1]) {
			break
		}
	}
	return total
}

func (d *dfile) isRegular() bool {
	if d.f == nil || d.isDir || d.fx.opath {
		return false
	}
	fi, err := fileStat(d.f)
	return err == nil && fi.Mode().IsRegular()
}

func (d *dfile) isPipe() bool {
	if d.f == nil || d.ev != nil || d.ep != nil || d.fx.in != nil {
		return false
	}
	if d.name() == "pipe:" {
		return true
	}
	fi, err := fileStat(d.f)
	return err == nil && fi.Mode()&os.ModeNamedPipe != 0
}

func (g *dguest) readOff(addr uint64) (int64, lxErrno) {
	b, err := g.readMem(addr, 8)
	if err != nil {
		return 0, lxEFAULT
	}
	off := int64(le64(b))
	if off < 0 {
		return 0, lxEINVAL
	}
	return off, 0
}

func (g *dguest) writeOff(addr uint64, off int64) lxErrno {
	var b [8]byte
	put64(b[:], uint64(off))
	if err := g.writeMem(addr, b[:]); err != nil {
		return lxEFAULT
	}
	return 0
}

// sendfile copies from a regular file to any fd.
func (g *dguest) sendfile(outFd, inFd int64, offAddr uint64, count int64) int64 {
	in, ok := g.ft.get(int(inFd))
	out, ok2 := g.ft.get(int(outFd))
	if !ok || !ok2 || in.f == nil && in.stub < 0 || in.fx.opath || out.fx.opath {
		return sErr(lxEBADF)
	}
	if !out.writable() || in.fx.hasFlags && in.fx.oflags&lxOAccmod == lxOWronly {
		return sErr(lxEBADF)
	}
	if in.f == nil || out.f == nil || !in.isRegular() || out.fx.oflags&lxOAppend != 0 || out.served() {
		return sErr(lxEINVAL)
	}
	if count < 0 {
		return sErr(lxEINVAL)
	}
	var off int64 = -1
	if offAddr != 0 {
		var e lxErrno
		if off, e = g.readOff(offAddr); e != 0 {
			return sErr(e)
		}
	}
	var total int64
	buf := make([]byte, min(count, ioChunk))
	for total < count {
		chunk := buf[:min(int64(len(buf)), count-total)]
		var n int
		var err error
		if off >= 0 {
			n, err = in.readAt(chunk, off+total)
		} else {
			n, err = in.f.Read(chunk)
			if err == io.EOF {
				err = nil
			}
		}
		if err != nil && n == 0 {
			if total > 0 {
				break
			}
			return sErr(ioErrno(err))
		}
		if n == 0 {
			break
		}
		w, werr := g.writeAll(out, chunk[:n], false)
		if w < n && off < 0 {
			in.f.Seek(int64(w-n), io.SeekCurrent) // give back what was not written
		}
		total += int64(max(w, 0))
		if werr != nil || w < n {
			if total == 0 {
				return sErr(ioErrno(werr))
			}
			break
		}
	}
	if total > 0 {
		g.notifyFd(in, inAccess)
		g.modified(out)
	}
	if off >= 0 {
		if e := g.writeOff(offAddr, off+total); e != 0 {
			return sErr(e)
		}
	}
	return total
}

func (g *dguest) copyFileRange(inFd int64, offInAddr uint64, outFd int64, offOutAddr uint64, n int64, flags uint64) int64 {
	if flags != 0 {
		return sErr(lxEINVAL)
	}
	in, ok := g.ft.get(int(inFd))
	out, ok2 := g.ft.get(int(outFd))
	if !ok || !ok2 || in.fx.opath || out.fx.opath {
		return sErr(lxEBADF)
	}
	if in.isDir || out.isDir {
		return sErr(lxEISDIR)
	}
	if !out.writable() || out.fx.oflags&lxOAppend != 0 || in.fx.hasFlags && in.fx.oflags&lxOAccmod == lxOWronly {
		return sErr(lxEBADF)
	}
	if !in.isRegular() || !out.isRegular() {
		return sErr(lxEINVAL)
	}
	if n < 0 {
		return sErr(lxEINVAL)
	}
	pos := func(d *dfile, addr uint64) (int64, lxErrno) {
		if addr != 0 {
			return g.readOff(addr)
		}
		p, err := d.f.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, osErrno(err)
		}
		return p, 0
	}
	ioff, e := pos(in, offInAddr)
	if e != 0 {
		return sErr(e)
	}
	ooff, e := pos(out, offOutAddr)
	if e != 0 {
		return sErr(e)
	}
	ifi, err1 := fileStat(in.f)
	ofi, err2 := fileStat(out.f)
	if err1 == nil && err2 == nil && inodeKey(ifi) == inodeKey(ofi) && ioff < ooff+n && ooff < ioff+n {
		return sErr(lxEINVAL)
	}
	if e := out.sealCheckWrite(ooff, int(n)); e != 0 {
		return sErr(e)
	}
	var total int64
	buf := make([]byte, min(n, ioChunk))
	for total < n {
		chunk := buf[:min(int64(len(buf)), n-total)]
		r, err := in.readAt(chunk, ioff+total)
		if err != nil && r == 0 {
			if total > 0 {
				break
			}
			return sErr(ioErrno(err))
		}
		if r == 0 {
			break
		}
		w, err := out.f.WriteAt(chunk[:r], ooff+total)
		total += int64(w)
		if err != nil {
			if total == 0 {
				return sErr(ioErrno(err))
			}
			break
		}
	}
	upd := func(d *dfile, addr uint64, base int64) lxErrno {
		if addr != 0 {
			return g.writeOff(addr, base+total)
		}
		_, err := d.f.Seek(base+total, io.SeekStart)
		if err != nil {
			return osErrno(err)
		}
		return 0
	}
	if e := upd(in, offInAddr, ioff); e != 0 {
		return sErr(e)
	}
	if e := upd(out, offOutAddr, ooff); e != 0 {
		return sErr(e)
	}
	if total > 0 {
		g.notifyFd(in, inAccess)
		g.modified(out)
	}
	return total
}

// splice moves up to n bytes between a pipe and another fd by copying through
// the supervisor.
func (g *dguest) splice(inFd int64, offInAddr uint64, outFd int64, offOutAddr uint64, n int64, flags uint64) int64 {
	in, ok := g.ft.get(int(inFd))
	out, ok2 := g.ft.get(int(outFd))
	if !ok || !ok2 || in.fx.opath || out.fx.opath {
		return sErr(lxEBADF)
	}
	if !out.writable() || in.fx.hasFlags && in.fx.oflags&lxOAccmod == lxOWronly {
		return sErr(lxEBADF)
	}
	if in.f == nil || out.f == nil || in.served() || out.served() {
		return sErr(lxEINVAL)
	}
	inPipe, outPipe := in.isPipe(), out.isPipe()
	if !inPipe && !outPipe {
		return sErr(lxEINVAL)
	}
	if inPipe && offInAddr != 0 || outPipe && offOutAddr != 0 {
		return sErr(lxESPIPE)
	}
	if n <= 0 {
		return 0
	}
	nb := flags&lxSpliceNonblock != 0
	var ioff, ooff int64 = -1, -1
	var e lxErrno
	if offInAddr != 0 {
		if ioff, e = g.readOff(offInAddr); e != 0 {
			return sErr(e)
		}
	}
	if offOutAddr != 0 {
		if ooff, e = g.readOff(offOutAddr); e != 0 {
			return sErr(e)
		}
	}
	buf := make([]byte, min(n, ioChunk))
	var r int
	var err error
	switch {
	case ioff >= 0:
		r, err = in.readAt(buf, ioff)
	case inPipe:
		r, err = g.readSome(in, buf, nb)
	default:
		r, err = in.f.Read(buf)
		if err == io.EOF {
			err = nil
		}
	}
	if err != nil && r == 0 {
		return sErr(ioErrno(err))
	}
	if r == 0 {
		return 0
	}
	var w int
	if ooff >= 0 {
		w, err = out.writeAt(buf[:r], ooff)
	} else {
		w, err = g.writeAll(out, buf[:r], nb && outPipe)
	}
	if w < r && !inPipe && ioff < 0 {
		in.f.Seek(int64(max(w, 0)-r), io.SeekCurrent)
	}
	if err != nil && w <= 0 {
		return sErr(ioErrno(err))
	}
	if ioff >= 0 {
		g.writeOff(offInAddr, ioff+int64(w))
	}
	if ooff >= 0 {
		g.writeOff(offOutAddr, ooff+int64(w))
	}
	if !outPipe {
		g.modified(out)
	}
	return int64(w)
}

// vmsplice on a pipe's write end is writev into it; on its read end, readv.
func (g *dguest) vmsplice(fd int64, iov uint64, cnt int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok || d.f == nil {
		return sErr(lxEBADF)
	}
	if !d.isPipe() {
		return sErr(lxEBADF)
	}
	if d.writable() && d.fx.oflags&lxOAccmod == lxOWronly {
		return g.writev(fd, iov, cnt)
	}
	return g.readv(fd, iov, cnt)
}

func (g *dguest) fallocate(fd, mode, off, n int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok || d.fx.opath || !d.writable() {
		return sErr(lxEBADF)
	}
	if off < 0 || n <= 0 {
		return sErr(lxEINVAL)
	}
	if d.isDir {
		return sErr(lxEISDIR)
	}
	if d.isPipe() {
		return sErr(lxESPIPE)
	}
	if d.f == nil {
		if d.mem != nil && d.mem.vf != nil { // an in-memory file (tmpfs, WithFS)
			if mode == 0 { // plain allocate: extend to off+n if needed
				if a, e := d.mem.vn.Stat(); e == nil && off+n > a.Size {
					if te := d.mem.vf.Truncate(off + n); te != nil {
						return sErr(osErrno(te))
					}
				}
			}
			return 0 // KEEP_SIZE and the hole/zero modes are hints on a memory file
		}
		return sErr(lxEBADF)
	}
	if !d.isRegular() {
		return sErr(lxENODEV)
	}
	fi, err := fileStat(d.f)
	if err != nil {
		return sErr(osErrno(err))
	}
	switch mode {
	case 0:
	case lxFallocKeepSize:
		return 0
	case lxFallocPunchHole | lxFallocKeepSize, lxFallocZeroRange, lxFallocZeroRange | lxFallocKeepSize:
		if e := d.checkSeals(0, 0, true); e != 0 {
			return sErr(e)
		}
		end := off + n
		if mode&lxFallocKeepSize != 0 {
			end = min(end, fi.Size())
		}
		if e := d.zeroRange(off, min(end, fi.Size())); e != 0 {
			return sErr(e)
		}
		if end > fi.Size() {
			if err := d.f.Truncate(end); err != nil {
				return sErr(osErrno(err))
			}
		}
		g.modified(d)
		return 0
	case lxFallocPunchHole:
		return sErr(lxEOPNOTSUPP) // a hole punch must keep the size
	default:
		return sErr(lxEOPNOTSUPP)
	}
	if off+n <= fi.Size() {
		return 0
	}
	if e := d.checkSeals(fi.Size(), off+n, false); e != 0 {
		return sErr(e)
	}
	if err := d.f.Truncate(off + n); err != nil {
		return sErr(osErrno(err))
	}
	g.modified(d)
	return 0
}

// zeroRange overwrites [off, end) with zeros (a punched hole reads as zeros).
func (d *dfile) zeroRange(off, end int64) lxErrno {
	if end <= off {
		return 0
	}
	z := make([]byte, min(end-off, ioChunk))
	for off < end {
		n, err := d.f.WriteAt(z[:min(int64(len(z)), end-off)], off)
		if err != nil {
			return osErrno(err)
		}
		off += int64(n)
	}
	return 0
}

func (g *dguest) fsync(fd int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok || d.fx.opath {
		return sErr(lxEBADF)
	}
	if d.rf != nil { // a regular file, whatever backs it
		if err := d.rf.sync(); err != nil {
			return sErr(osErrno(err))
		}
		return 0
	}
	if d.mem != nil && d.mem.vf != nil {
		return 0 // an in-memory file not yet on regFile: nothing to flush
	}
	if d.f == nil || d.ev != nil || d.ep != nil || d.fx.in != nil || d.isPipe() {
		return sErr(lxEINVAL)
	}
	if err := d.f.Sync(); err != nil && !d.isDir {
		return sErr(osErrno(err))
	}
	return 0
}

// fadvise checks a posix_fadvise as Linux does; the advice itself is only a
// hint, which the host's page cache does without.
func (g *dguest) fadvise(fd, n int64, advice uint64) int64 {
	const noreuse = 5 // POSIX_FADV_NOREUSE, the highest
	d, ok := g.ft.get(int(fd))
	switch {
	case !ok:
		return sErr(lxEBADF)
	case d.sk != nil || d.isPipe():
		return sErr(lxESPIPE)
	case n < 0 || advice > noreuse:
		return sErr(lxEINVAL)
	}
	return 0
}
