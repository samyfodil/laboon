package sandbox

import (
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/samyfodil/laboon/core"
)

// shBacking is the one host object that backs a non-host file while any part of
// it is mapped MAP_SHARED: a memfd on Linux, an unlinked temp file on the other
// backends. It is keyed by vnode on the shared dfs, so independent opens and
// fork children map the same object and see each other's writes. While it exists
// it is the authoritative copy of the file's data — reads, writes, size and
// truncate for that vnode go through it — and its content is written back to the
// core.File on msync and at teardown. The object is a plain *os.File, so the
// coherence and write-back logic here is backend- and platform-independent; only
// creating it (memfd vs temp file) and mapping it into the stub are per-platform.
type shBacking struct {
	id   core.NodeID
	mu   sync.Mutex
	f    *os.File     // the mapping-capable host object; the stub maps this
	vf   core.File    // the backend the content is written back to
	size int64        // the object's allocated length (>= eof)
	eof  int64        // the file's logical size: reads stop here, write-back covers [0,eof)
	maps atomic.Int64 // live mapped pages across all address spaces; evicted at zero
	path string       // the backing file to delete on release (Windows, which cannot unlink an open file); empty when already unlinked
	key  uint64       // the shared-futex key every mapping of this backing uses (Windows)
}

// fd is the raw descriptor the platform maps into the stub.
func (sb *shBacking) fd() int { return int(sb.f.Fd()) }

// ReadAt reads the file's bytes from the backing, stopping at the logical end of
// file (a short read there reports io.EOF, as a regular file does), so a read or
// a fresh private mapping sees writes made through a shared mapping.
func (sb *shBacking) ReadAt(p []byte, off int64) (int, error) {
	sb.mu.Lock()
	eof := sb.eof
	sb.mu.Unlock()
	if off >= eof {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	short := false
	if int64(len(p)) > eof-off {
		p = p[:eof-off]
		short = true
	}
	n, err := sb.f.ReadAt(p, off)
	if err == nil && short {
		err = io.EOF
	}
	return n, err
}

// writeAt writes into the backing (so every mapping of the vnode sees it) and
// extends the logical size if the write runs past the end; the bytes reach the
// core.File at the next write-back. off is an absolute file offset.
func (sb *shBacking) writeAt(p []byte, off int64) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if err := sb.growLocked(off + int64(len(p))); err != nil {
		return 0, err
	}
	n, err := sb.f.WriteAt(p, off)
	if off+int64(n) > sb.eof {
		sb.eof = off + int64(n)
	}
	return n, err
}

// truncate resizes the logical file: the backend is truncated now, the backing
// object is grown or shrunk to match, and the logical end moves; a later
// write-back then covers exactly [0, size).
func (sb *shBacking) truncate(size int64) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if err := sb.vf.Truncate(size); err != nil {
		return err
	}
	if err := sb.f.Truncate(size); err != nil {
		return err
	}
	sb.size, sb.eof = size, size
	return nil
}

// size0 is the current logical size (for SEEK_END, O_APPEND and fstat).
func (sb *shBacking) size0() int64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.eof
}

// growLocked makes the backing object at least n bytes. sb.mu held.
func (sb *shBacking) growLocked(n int64) error {
	if n <= sb.size {
		return nil
	}
	if err := sb.f.Truncate(n); err != nil {
		return err
	}
	sb.size = n
	return nil
}

// writeBack copies the logical content out to the core.File, so the guest's
// shared-mapping and write() stores reach the backend. Only [0, eof) is written:
// a mapping may run past the end of the file, but those bytes are not part of it.
// A write error is returned so eviction can keep a backing whose data did not
// reach the backend.
func (sb *shBacking) writeBack() error {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	buf := make([]byte, 1<<20)
	for off := int64(0); off < sb.eof; {
		n, rerr := sb.f.ReadAt(buf[:min(int64(len(buf)), sb.eof-off)], off)
		if n > 0 {
			if _, werr := sb.vf.WriteAt(buf[:n], off); werr != nil {
				return werr
			}
			off += int64(n)
		}
		if rerr != nil || n == 0 {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
	return nil
}

// fillFrom copies size bytes of r into w at the same offsets, for filling a
// fresh backing from its file. Bytes past the content stay zero.
func fillFrom(w *os.File, r io.ReaderAt, size int64) error {
	buf := make([]byte, min(size, 1<<20))
	for pos := int64(0); pos < size; {
		b := buf[:min(size-pos, int64(len(buf)))]
		n, err := r.ReadAt(b, pos)
		if n > 0 {
			if _, werr := w.WriteAt(b[:n], pos); werr != nil {
				return werr
			}
			pos += int64(n)
		}
		if err != nil || n == 0 {
			break
		}
	}
	return nil
}

// closeFile releases the backing's host object, removing the backing file too
// where it could not be unlinked while open (Windows).
func (sb *shBacking) closeFile() {
	sb.f.Close()
	if sb.path != "" {
		os.Remove(sb.path)
	}
}

// reserve raises sb's mapped-page count for a mapping about to be made. It runs
// under fs.shMu so it cannot race an eviction's zero check: once reserved, the
// backing stays live until the mapping is released. fs.shMu held.
func (sb *shBacking) reserve(pages int64) { sb.maps.Add(pages) }

// release lowers the mapped-page count when a mapping goes away and evicts the
// backing once nothing maps it.
func (fs *dfs) release(sb *shBacking, pages int64) {
	if sb.maps.Add(-pages) <= 0 {
		fs.evict(sb)
	}
}

// evict writes a no-longer-mapped backing back to its file and releases it. A
// failed write-back keeps the backing (and its data) in place so a later msync
// or teardown retries, rather than losing the stores. The zero check is repeated
// under fs.shMu, where reservations are made, so a mapping being made right now
// keeps the backing.
func (fs *dfs) evict(sb *shBacking) {
	fs.shMu.Lock()
	if sb.maps.Load() > 0 || fs.shared[sb.id] != sb {
		fs.shMu.Unlock()
		return
	}
	delete(fs.shared, sb.id)
	fs.sharedN.Add(-1)
	fs.shMu.Unlock()
	if err := sb.writeBack(); err != nil {
		fs.shMu.Lock()
		if fs.shared == nil {
			fs.shared = map[core.NodeID]*shBacking{}
		}
		fs.shared[sb.id] = sb
		fs.sharedN.Add(1)
		fs.shMu.Unlock()
		return
	}
	sb.closeFile()
}

// backing returns the live shared backing of vnode id, or nil. The atomic count
// makes the common case (nothing shared-mapped) a single load with no lock.
func (fs *dfs) backing(id core.NodeID) *shBacking {
	if fs.sharedN.Load() == 0 {
		return nil
	}
	fs.shMu.Lock()
	sb := fs.shared[id]
	fs.shMu.Unlock()
	return sb
}

// putBacking records sb as vnode id's backing. fs.shMu held.
func (fs *dfs) putBacking(id core.NodeID, sb *shBacking) {
	sb.id = id
	if fs.shared == nil {
		fs.shared = map[core.NodeID]*shBacking{}
	}
	fs.shared[id] = sb
	fs.sharedN.Add(1)
}

// syncSharedMem writes every backing out to its file (an msync), keeping the
// backing live.
func (fs *dfs) syncSharedMem() {
	if fs.sharedN.Load() == 0 {
		return
	}
	fs.shMu.Lock()
	sbs := make([]*shBacking, 0, len(fs.shared))
	for _, sb := range fs.shared {
		sbs = append(sbs, sb)
	}
	fs.shMu.Unlock()
	for _, sb := range sbs {
		sb.writeBack()
	}
}

// flushSharedMem writes every backing out to its file and releases them, at
// teardown.
func (fs *dfs) flushSharedMem() {
	fs.shMu.Lock()
	sbs := fs.shared
	fs.shared = nil
	fs.sharedN.Store(0)
	fs.shMu.Unlock()
	for _, sb := range sbs {
		sb.writeBack()
		sb.closeFile()
	}
}
