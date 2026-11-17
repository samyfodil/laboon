package sandbox

import (
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/samyfodil/laboon/internal/vfs"
)

// regFile is the content of an open regular file, whatever filesystem backs it:
// a host-backed backend (hostDirFS, the overlay), the in-memory memFS, or a
// synthetic /proc file. The regular-file syscall handlers operate on this
// interface, so a new filesystem is served by implementing it rather than by a
// new case in each handler; an operation a backend cannot do returns an error
// the handler maps to an errno. A regular file never blocks, so read and write
// advance the open description's offset, which the backing keeps (the host fd's,
// or the memFS position) — unlike a stream fd (socket, pipe, fifo), which is not
// a filesystem and keeps the existing host-fd path.
type regFile interface {
	read(p []byte) (int, error)
	write(p []byte) (int, error)
	readAt(p []byte, off int64) (int, error)
	writeAt(p []byte, off int64) (int, error)
	seek(off int64, whence int) (int64, error)
	truncate(size int64) error
	sync() error
	// attr reports the file's current attributes from its node, so fstat is
	// correct even for a file unlinked while open.
	attr() (vfs.Attr, vfs.NodeID, error)
	// fstat fills the Linux stat for an open fd on this file: the backend supplies
	// it (a host fstat, or the node's attributes), and a per-fd mode override the
	// backend could not hold is applied on top.
	fstat(g *dguest, d *dfile) (lxStat, lxErrno)
	// fallocate allocates or zeroes a range (fallocate(2)); a host file extends or
	// zeroes its storage, an in-memory one grows. The arguments are the syscall's.
	fallocate(g *dguest, d *dfile, mode, off, length int64) int64
	closeFile() error
}

// noEOF maps io.EOF to a nil error with the short count, matching read(2), which
// reports end of file as a zero-length read rather than an error.
func noEOF(n int, err error) (int, error) {
	if err == io.EOF {
		return n, nil
	}
	return n, err
}

// hostRF backs a regular file with a host file: a host-backed vfs backend opened
// it, so every operation is the host's and a host fd is available for the
// zero-copy paths.
type hostRF struct {
	f  *os.File
	vn vfs.Node
}

func (h *hostRF) read(p []byte) (int, error)               { return noEOF(h.f.Read(p)) }
func (h *hostRF) write(p []byte) (int, error)              { return h.f.Write(p) }
func (h *hostRF) readAt(p []byte, off int64) (int, error)  { return noEOF(h.f.ReadAt(p, off)) }
func (h *hostRF) writeAt(p []byte, off int64) (int, error) { return h.f.WriteAt(p, off) }
func (h *hostRF) seek(o int64, w int) (int64, error)       { return h.f.Seek(o, w) }
func (h *hostRF) truncate(size int64) error                { return h.f.Truncate(size) }
func (h *hostRF) sync() error                              { return h.f.Sync() }
func (h *hostRF) attr() (vfs.Attr, vfs.NodeID, error) {
	a, err := h.vn.Stat()
	return a, h.vn.ID(), err
}

func (h *hostRF) fstat(g *dguest, d *dfile) (lxStat, lxErrno) {
	fi, err := g.fileInfo(d)
	if err != nil {
		return lxStat{}, osErrno(err)
	}
	st := g.linuxStat(fi)
	if p := d.fx.perm.Load(); p&permSet != 0 {
		st.mode = st.mode&^0o7777 | p&0o7777
	}
	return st, 0
}
func (h *hostRF) fallocate(g *dguest, d *dfile, mode, off, length int64) int64 {
	return g.fallocateHostFd(d, mode, off, length)
}
func (h *hostRF) closeFile() error { return h.f.Close() }

// memRF backs a regular file with an in-memory backend (memFS, WithFS): content
// is read and written through the vfs.File handle over the node. There is no host
// fd, so the zero-copy paths fall back to a copy; sync is a no-op (the content is
// already in memory).
type memRF struct {
	vf     vfs.File
	vn     vfs.Node
	mu     sync.Mutex
	pos    int64
	append bool
}

func (m *memRF) read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err := noEOF(m.vf.ReadAt(p, m.pos))
	m.pos += int64(n)
	return n, err
}

func (m *memRF) write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	off := m.pos
	if m.append {
		if a, e := m.vn.Stat(); e == nil {
			off = a.Size
		}
	}
	n, err := m.vf.WriteAt(p, off)
	m.pos = off + int64(n)
	return n, err
}

func (m *memRF) readAt(p []byte, off int64) (int, error)  { return noEOF(m.vf.ReadAt(p, off)) }
func (m *memRF) writeAt(p []byte, off int64) (int, error) { return m.vf.WriteAt(p, off) }

func (m *memRF) seek(off int64, whence int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var base int64
	switch whence {
	case 0: // SEEK_SET
	case 1: // SEEK_CUR
		base = m.pos
	case 2: // SEEK_END
		a, err := m.vn.Stat()
		if err != nil {
			return 0, err
		}
		base = a.Size
	default:
		return 0, syscall.EINVAL
	}
	if base+off < 0 {
		return 0, syscall.EINVAL
	}
	m.pos = base + off
	return m.pos, nil
}

func (m *memRF) truncate(size int64) error { return m.vf.Truncate(size) }
func (m *memRF) sync() error               { return nil }
func (m *memRF) attr() (vfs.Attr, vfs.NodeID, error) {
	a, err := m.vn.Stat()
	return a, m.vn.ID(), err
}

func (m *memRF) fstat(g *dguest, d *dfile) (lxStat, lxErrno) {
	// Stat the node, not the path: correct for a file unlinked while still open.
	a, err := m.vn.Stat()
	if err != nil {
		return lxStat{}, osErrno(err)
	}
	st := nodeStat(a, m.vn.ID())
	if p := d.fx.perm.Load(); p&permSet != 0 {
		st.mode = st.mode&^0o7777 | p&0o7777
	}
	return st, 0
}
func (m *memRF) fallocate(g *dguest, d *dfile, mode, off, length int64) int64 {
	if mode == 0 { // plain allocate: extend to off+length if needed
		if a, _, e := m.attr(); e == nil && off+length > a.Size {
			if te := m.truncate(off + length); te != nil {
				return sErr(osErrno(te))
			}
		}
	}
	return 0 // KEEP_SIZE and the hole/zero modes are hints on a memory file
}
func (m *memRF) closeFile() error { return m.vf.Close() }
