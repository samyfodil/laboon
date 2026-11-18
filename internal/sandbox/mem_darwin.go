//go:build darwin

package sandbox

import (
	"encoding/binary"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// The guest's memory syscalls are served in the stub (stub/macos/mem.zig). The
// supervisor's part is the host fds: a file mapping needs the real host file
// behind a guest fd, which the stub cannot open itself. Each guest process
// pairs with the supervisor over a datagram socketpair (fdlink); the
// supervisor sends a host fd down it with SCM_RIGHTS and has the stub collect
// it (repFdSync). The stub caches what it received keyed by the open-file id
// below, and the supervisor tells it to drop an entry once that open-file
// description is closed.

// Supervisor services the stub posts like syscalls (outside the Linux range).
const (
	lcMmapFd  = 0x4c430001 // (guest fd, shared writable, shared executable) -> stub fd, or kindZero<<32 for /dev/zero
	lcRewrite = 0x4c430002 // (base, len, file off, guest fd): rewrite a copied-in text segment; args[4] = 1: only count its sites

	lcShmat       = 0x4c430003 // (shmid) -> stub fd | pages<<32
	lcShmAttached = 0x4c430004 // (shmid) -> attachment cookie
	lcShmGone     = 0x4c430005 // (cookie): no part of the attachment is mapped
	lcCodeFile    = 0x4c430006 // (open-file id): the stub maps that file shared and executable

	kindZero = 1
)

// repFdSync has the stub drop the closed ids packed in the slot scratch
// (args[0] of them), receive args[1] queued datagrams, and reply msgHostRet
// with the stub fd it holds for id args[2].
const repFdSync = 20

// repForkChild makes a pooled stub a fork child (stub/macos/sfork.zig): the
// slot scratch holds the child slot's offset, the parent stub's pid and the
// child's gpid; it acks msgHostRet and works on the child slot.
const repForkChild = 21

// fdlink datagram ops: {op, id} riding one fd.
const (
	fdOpInstall = 1
)

func init() {
	syscalls[lcMmapFd] = func(g *dguest, a [6]uint64) int64 { return g.mmapFd(int64(int32(a[0])), a[1] != 0, a[2] != 0) }
	syscalls[lcCodeFile] = func(g *dguest, a [6]uint64) int64 {
		g.mp.mu.Lock()
		fn, ok := g.mp.names[a[0]]
		g.mp.mu.Unlock()
		if ok && g.dfs.run != nil && g.ps.ospid > 0 {
			g.dfs.run.broker.code.mark(g.ps.ospid, [2]uint64{fn.dev, fn.ino})
		}
		return 0
	}
	syscalls[lcRewrite] = func(g *dguest, a [6]uint64) int64 {
		d, e := g.file(int64(int32(a[3])))
		if e != 0 {
			return 0
		}
		if a[4] != 0 {
			return int64(len(libSites(g.cfg.Cache, a[1], a[2], d)))
		}
		g.rewriteLibSites(a[0], a[1], a[2], d)
		return 0
	}
}

// mmapFd resolves a guest fd for mmap and returns the stub's copy of it.
// wshared is a writable shared mapping, which an append-only file refuses.
func (g *dguest) mmapFd(fd int64, wshared, code bool) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	if d.gp == "/dev/zero" {
		return kindZero << 32
	}
	if d.vf != nil {
		// A non-host file (in-memory, user-defined, network): the guest never
		// touches the real backing — the supervisor materializes the content into
		// an unlinked temp file through the file's ReadAt and the stub maps that.
		// A private executable mapping is still rewritten in place afterwards
		// (lcRewrite -> libSites reads the materialized file). Only a shared
		// writable or shared executable mapping is unsupported, so refuse those.
		if code || wshared {
			return sErr(lxENODEV)
		}
		if e := g.materializeMapf(d); e != 0 {
			return sErr(e)
		}
		sfd, e := g.mp.stubFd(g, d)
		if e != 0 {
			return sErr(e)
		}
		return int64(sfd)
	}
	if d.f == nil || d.ev != nil || d.ep != nil {
		return sErr(lxENODEV)
	}
	fi, err := d.f.Stat()
	if err != nil {
		return sErr(osErrno(err))
	}
	if !fi.Mode().IsRegular() {
		return sErr(lxENODEV)
	}
	if wshared {
		if fl, err := unix.FcntlInt(uintptr(hostFd(d.f)), unix.F_GETFL, 0); err == nil && fl&unix.O_APPEND != 0 {
			return sErr(lxEACCES)
		}
	}
	if code {
		g.codeFile(fi) // its writes reach the stub's shadows of its pages
	}
	sfd, e := g.mp.stubFd(g, d)
	if e != 0 {
		return sErr(e)
	}
	return int64(sfd)
}

// materializeMapf makes (or refreshes) d.mapf, an unlinked temp file holding a
// non-host file's whole content read through its ReadAt, for the stub to map.
// mmapFd carries no offset or length, so the whole file is materialized, a
// snapshot as the mapping is; it is kept on the description and remade only if the
// file has since grown past it (else a map past its end would fault).
func (g *dguest) materializeMapf(d *dfile) lxErrno {
	a, err := d.vn.Stat()
	if err != nil {
		return osErrno(err)
	}
	if d.mapf != nil {
		if fi, e := d.mapf.Stat(); e == nil && fi.Size() >= a.Size {
			return 0
		}
		d.mapf.Close()
		d.mapf = nil
	}
	tf, err := os.CreateTemp("", "lc-mmap")
	if err != nil {
		return osErrno(err)
	}
	os.Remove(tf.Name()) // unlink; the fd keeps it alive
	if a.Size > 0 {
		if err := tf.Truncate(a.Size); err != nil {
			tf.Close()
			return osErrno(err)
		}
		if e := g.fillFile(tf, d.vf, a.Size); e != 0 {
			tf.Close()
			return e
		}
	}
	d.mapf = tf
	return 0
}

// fillFile copies size bytes of r into w through ReadAt; any part past the
// content stays zero, as a file mapping's tail does.
func (g *dguest) fillFile(w *os.File, r io.ReaderAt, size int64) lxErrno {
	buf := g.ioBuf(int(min(size, ioChunk)))
	for pos := int64(0); pos < size; {
		b := buf[:min(size-pos, int64(len(buf)))]
		n, err := r.ReadAt(b, pos)
		if n > 0 {
			if _, werr := w.WriteAt(b[:n], pos); werr != nil {
				return osErrno(werr)
			}
			pos += int64(n)
		}
		if err != nil || n == 0 {
			break
		}
	}
	return 0
}

// memProc is one guest process's side of fdlink, shared by its threads.
type memProc struct {
	mu     sync.Mutex
	sock   int                 // the supervisor's end
	sent   map[uint64]int32    // open-file id -> the stub's fd for it
	names  map[uint64]fileName // open-file id -> what /proc/<pid>/maps shows for it
	closed []uint64            // ids to drop at the next sync
	refs   int

	shm    map[uint64]*shmAttach  // SysV segments attached, by address
	semadj map[int]map[uint16]int // SEM_UNDO adjustments, by set and semaphore

	anon anonCode // what is known of its code made executable at run time (anoncode.go)
}

// newMemProc makes a pairing; the stub's end is returned for the caller to
// hand down (as fd 3 at spawn, or over the parent's pairing at fork).
func newMemProc() (*memProc, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, nil, err
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	m := &memProc{sock: fds[0], sent: map[uint64]int32{}, names: map[uint64]fileName{}, refs: 1, shm: map[uint64]*shmAttach{}, semadj: map[int]map[uint16]int{}}
	return m, os.NewFile(uintptr(fds[1]), "fdlink"), nil
}

func (m *memProc) share() *memProc {
	m.mu.Lock()
	m.refs++
	m.mu.Unlock()
	return m
}

// release drops a thread's reference; the last one, the process exiting,
// closes the pairing and lets go of its SysV IPC state.
// renew moves the process to nm, the pairing of the fresh stub an exec started
// (exec_darwin.go execRespawn): SEM_UNDO adjustments survive exec, the old
// stub's fds and SysV attachments do not.
func (m *memProc) renew(g *dguest, nm *memProc) *memProc {
	m.mu.Lock()
	nm.semadj, m.semadj = m.semadj, map[int]map[uint16]int{}
	m.mu.Unlock()
	m.release(g)
	return nm
}

func (m *memProc) release(g *dguest) {
	m.mu.Lock()
	m.refs--
	last := m.refs == 0
	ids := m.sent
	ipc := len(m.shm) > 0 || len(m.semadj) > 0
	if last {
		m.sent = nil
		unix.Close(m.sock)
	}
	m.mu.Unlock()
	if !last {
		return
	}
	stubFiles.forget(m, ids)
	if ipc {
		m.detachAll(g)
		m.undoSems(g)
	}
}

func (m *memProc) send(op, id uint64, f *os.File) error {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:], op)
	binary.LittleEndian.PutUint64(b[8:], id)
	return unix.Sendmsg(m.sock, b[:], unix.UnixRights(hostFd(f)), nil, 0)
}

// sync runs repFdSync on g's slot: pending drops, nrecv datagrams, and the
// stub's fd for id. The caller holds m.mu.
func (m *memProc) sync(g *dguest, nrecv int, id uint64) int64 {
	sc := g.scratch()
	for {
		n := min(len(m.closed), len(sc)/8)
		for i, c := range m.closed[:n] {
			put64(sc[i*8:], c)
		}
		m.closed = m.closed[n:]
		last := len(m.closed) == 0
		g.ch.page.args = [6]uint64{uint64(n)}
		if last {
			g.ch.page.args[1] = uint64(nrecv)
			g.ch.page.args[2] = id
		}
		g.ch.reply(repFdSync)
		if err := g.ch.wait(); err != nil || g.ch.page.kind != msgHostRet {
			return sErr(lxEIO)
		}
		if last {
			return int64(g.ch.page.ret)
		}
	}
}

// stubFd returns the stub's fd for d, sending it first if the stub lacks one.
func (m *memProc) stubFd(g *dguest, d *dfile) (int, lxErrno) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := stubFiles.id(d, m)
	if sfd, ok := m.sent[id]; ok && len(m.closed) == 0 {
		return int(sfd), 0
	}
	nrecv := 0
	if _, ok := m.sent[id]; !ok {
		f := d.f
		if f == nil {
			f = d.mapf // a non-host file's materialized mmap backing (mmapFd)
		}
		if err := m.send(fdOpInstall, id, f); err != nil {
			return 0, osErrno(err)
		}
		nrecv = 1
		fn := fileName{path: d.name()}
		if fi, err := f.Stat(); err == nil {
			fn.dev, fn.ino = hostDevIno(fi)
		}
		m.names[id] = fn
	}
	r := m.sync(g, nrecv, id)
	if r < 0 {
		delete(m.sent, id)
		return 0, hostErrno(unix.Errno(-r))
	}
	m.sent[id] = int32(r)
	return int(r), 0
}

// adopt gives c, a pooled stub's pairing taken for a fork child of m's
// process, m's cache: the parent stub hands the child its files on the same
// fds (sfork.zig), so the supervisor's record of them is m's. The parent first
// drops the closed ones, so the two agree on what it holds.
func (m *memProc) adopt(c *memProc, g *dguest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.sync(g, 0, 0); r < 0 {
		return unix.Errno(-r)
	}
	c.mu.Lock()
	for id, fd := range m.sent {
		c.sent[id] = fd
	}
	for id, fn := range m.names {
		c.names[id] = fn
	}
	c.mu.Unlock()
	stubFiles.adopt(c, c.sent)
	return nil
}

// stubFiles numbers open-file descriptions for the stubs' caches and tracks
// which processes hold a copy, so closing the description drops those.
var stubFiles = &fileRegistry{ids: map[*dfile]uint64{}, holders: map[uint64]map[*memProc]bool{}}

type fileRegistry struct {
	mu      sync.Mutex
	next    uint64
	ids     map[*dfile]uint64
	holders map[uint64]map[*memProc]bool
}

// id returns d's id, recording m as a holder.
func (r *fileRegistry) id(d *dfile, m *memProc) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.ids[d]
	if !ok {
		r.next++
		id = r.next
		r.ids[d] = id
		r.holders[id] = map[*memProc]bool{}
	}
	r.holders[id][m] = true
	return id
}

func (r *fileRegistry) adopt(m *memProc, ids map[uint64]int32) {
	r.mu.Lock()
	for id := range ids {
		if h := r.holders[id]; h != nil {
			h[m] = true
		}
	}
	r.mu.Unlock()
}

func (r *fileRegistry) forget(m *memProc, ids map[uint64]int32) {
	r.mu.Lock()
	for id := range ids {
		delete(r.holders[id], m)
	}
	r.mu.Unlock()
}

// closed is called when d's last reference goes: every stub holding a copy
// drops it at its next sync. Until then the copy keeps the host file open,
// which a regular file (the only kind mapped) does not show.
func (r *fileRegistry) closed(d *dfile) {
	r.mu.Lock()
	id, ok := r.ids[d]
	var hs map[*memProc]bool
	if ok {
		hs = r.holders[id]
		delete(r.ids, d)
		delete(r.holders, id)
	}
	r.mu.Unlock()
	for m := range hs {
		m.mu.Lock()
		if _, held := m.sent[id]; held {
			delete(m.sent, id)
			m.closed = append(m.closed, id)
		}
		m.mu.Unlock()
	}
}

// hostMaps lists the guest's mappings: the stub tracks all of them.
func (g *dguest) hostMaps() ([]mapEnt, bool) { return g.mapsOfStub() }

// otherMaps lists another process's mappings: its stub's service thread
// answers for it, whatever its guest threads are doing.
func (g *dguest) otherMaps(p *dguest) ([]mapEnt, bool) {
	fs := g.dfs
	if fs.run == nil || fs.run.broker == nil {
		return nil, false
	}
	fs.mu.Lock()
	dp := fs.procs[p.tgid]
	fs.mu.Unlock()
	if dp == nil || dp.ospid <= 0 {
		return nil, false
	}
	pid := dp.ospid
	return fs.run.broker.mapsOf(pid, func() bool { return fs.stubDone(pid) })
}

// lcMapName is the HVF stub asking for the id a mapping of the file behind a
// guest fd is listed by in /proc/<pid>/maps, naming the file. HVF maps a file
// by reading it in, so its stub gets no id from stubFd.
const lcMapName = 0x4c430031

func init() {
	regSys(lcMapName, func(g *dguest, a [6]uint64) int64 {
		d, ok := g.ft.get(int(a[0]))
		if !ok || d.f == nil {
			return sErr(lxEBADF)
		}
		m := g.mp
		m.mu.Lock()
		defer m.mu.Unlock()
		id := stubFiles.id(d, m)
		if _, ok := m.names[id]; !ok {
			fn := fileName{path: d.name()}
			if fi, err := d.f.Stat(); err == nil {
				fn.dev, fn.ino = hostDevIno(fi)
			}
			m.names[id] = fn
		}
		return int64(id)
	})
}

// guestPageSize is the guest's page size, AT_PAGESZ: the host's 16 KiB, or
// the 4 KiB pages of a guest under the hypervisor.
func (g *dguest) guestPageSize() int {
	if g.ps.hvf {
		return 0x1000
	}
	return os.Getpagesize()
}

// flushSharedMem is a no-op: this backend does not serve a non-host file's
// writable MAP_SHARED through a shared backing yet (see mmap_linux.go).
func (fs *dfs) flushSharedMem() {}
