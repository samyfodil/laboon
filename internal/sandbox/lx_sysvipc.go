//go:build darwin || linux || windows

package sandbox

import (
	"encoding/binary"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// System V IPC for the macOS backend: shared memory, semaphores and message
// queues, one namespace per Run (like a Linux IPC namespace), shared by every
// guest process in it. A shared memory segment is an unlinked host file that
// each attaching process maps MAP_SHARED from a host fd passed to its stub, so
// forked guests see each other's stores. Semaphores and queues live here and
// block the calling guest thread's serve goroutine.

const (
	lxMsgget     = 186
	lxMsgctl     = 187
	lxMsgrcv     = 188
	lxMsgsnd     = 189
	lxSemget     = 190
	lxSemctl     = 191
	lxSemtimedop = 192
	lxSemop      = 193
	lxShmget     = 194
	lxShmctl     = 195
)

const (
	ipcCreat  = 0o1000
	ipcExcl   = 0o2000
	ipcNowait = 0o4000
	ipc64     = 0x100

	ipcRmid = 0
	ipcSet  = 1
	ipcStat = 2
	ipcInfo = 3

	shmLock    = 11
	shmUnlock  = 12
	shmStat    = 13
	shmInfo    = 14
	shmStatAny = 15
	shmDest    = 0o1000
	shmLocked  = 0o2000
	shmMni     = 4096

	semGetpid  = 11
	semGetval  = 12
	semGetall  = 13
	semGetncnt = 14
	semGetzcnt = 15
	semSetval  = 16
	semSetall  = 17
	semStat    = 18
	semInfo    = 19
	semStatAny = 20
	semUndo    = 0x1000
	semMni     = 32000
	semMsl     = 32000
	semMns     = 1 << 20
	semOpm     = 500
	semVmx     = 32767

	msgStat    = 11
	msgInfo    = 12
	msgStatAny = 13
	msgNoerror = 0o10000
	msgExcept  = 0o20000
	msgCopy    = 0o40000
	msgMax     = 8192
	msgMnb     = 16384
	msgMni     = 32000
	msgSsz     = 16
	msgHdr     = 48 // a message's charge on top of its text, Linux's struct msg_msg
)

// Where Linux's default is effectively unlimited the namespace holds these
// instead, so the supervisor's own resources stay bounded: shmDefault bytes of
// segment backing (SHMMAX and SHMALL; Linux's defaults before 3.16 allowed
// 8 GiB of segments), semMns semaphores in all (32 MiB of supervisor heap,
// where Linux's SEMMNI*SEMMSL would be 32 GiB) and msgPool bytes of queued
// messages, each charged msgHdr more than its text. A send the pool cannot
// hold fails with ENOMEM, as Linux's does when its allocation is refused.
const (
	shmDefault = 8 << 30
	msgPool    = 64 << 20
)

// ipcLimits are a namespace's segment bounds in the guest's pages, as
// IPC_INFO and /proc/sys/kernel report them. A memory cap (Config.MaxBytes)
// also caps the segments' total.
type ipcLimits struct {
	page   uint64
	shmMax uint64 // bytes in one segment
	shmAll uint64 // pages in all segments
}

func (g *dguest) ipcLimits() ipcLimits {
	page := uint64(g.guestPageSize())
	all := uint64(shmDefault)
	if g.cfg.MaxBytes > 0 {
		all = min(all, g.cfg.MaxBytes)
	}
	return ipcLimits{page: page, shmMax: all / page * page, shmAll: all / page}
}

func (l ipcLimits) pages(size uint64) uint64 { return (size + l.page - 1) / l.page }

func init() {
	syscalls[lxShmget] = func(g *dguest, a [6]uint64) int64 { return g.ipc().shmget(g, int32(a[0]), a[1], int64(a[2])) }
	syscalls[lcShmat] = func(g *dguest, a [6]uint64) int64 { return g.ipc().shmat(g, int(int32(a[0]))) }
	syscalls[lcShmAttached] = func(g *dguest, a [6]uint64) int64 { return g.ipc().attached(g, int(int32(a[0]))) }
	syscalls[lcShmGone] = func(g *dguest, a [6]uint64) int64 { return g.ipc().gone(g, a[0]) }
	syscalls[lxShmctl] = func(g *dguest, a [6]uint64) int64 { return g.ipc().shmctl(g, int(int32(a[0])), int64(a[1]), a[2]) }
	syscalls[lxSemget] = func(g *dguest, a [6]uint64) int64 {
		return g.ipc().semget(g, int32(a[0]), int64(int32(a[1])), int64(a[2]))
	}
	syscalls[lxSemop] = func(g *dguest, a [6]uint64) int64 { return g.ipc().semop(g, int(int32(a[0])), a[1], a[2], 0) }
	syscalls[lxSemtimedop] = func(g *dguest, a [6]uint64) int64 { return g.ipc().semop(g, int(int32(a[0])), a[1], a[2], a[3]) }
	syscalls[lxSemctl] = func(g *dguest, a [6]uint64) int64 {
		return g.ipc().semctl(g, int(int32(a[0])), int(int32(a[1])), int64(a[2]), a[3])
	}
	syscalls[lxMsgget] = func(g *dguest, a [6]uint64) int64 { return g.ipc().msgget(g, int32(a[0]), int64(a[1])) }
	syscalls[lxMsgsnd] = func(g *dguest, a [6]uint64) int64 {
		return g.ipc().msgsnd(g, int(int32(a[0])), a[1], int64(a[2]), int64(a[3]))
	}
	syscalls[lxMsgrcv] = func(g *dguest, a [6]uint64) int64 {
		return g.ipc().msgrcv(g, int(int32(a[0])), a[1], int64(a[2]), int64(a[3]), int64(a[4]))
	}
	syscalls[lxMsgctl] = func(g *dguest, a [6]uint64) int64 { return g.ipc().msgctl(g, int(int32(a[0])), int64(a[1]), a[2]) }
}

// ---- namespace ----------------------------------------------------------------

type ipcKind int

const (
	kShm ipcKind = iota
	kSem
	kMsg
)

type ipcNS struct {
	mu   sync.Mutex
	cond *sync.Cond // a semaphore or queue changed
	shm  map[int]*shmSeg
	sem  map[int]*semSet
	msg  map[int]*msgQueue
	keys [3]map[int32]int
	next [3]int
	lim  ipcLimits
	// shmTot counts the pages of every segment, semUsed every semaphore and
	// msgBytes every queued message's charge.
	shmTot   uint64
	semUsed  int
	msgBytes uint64
	// undo holds every process with SEM_UNDO adjustments, which SETVAL and
	// SETALL clear.
	undo map[*memProc]bool
}

var ipcSpaces = struct {
	sync.Mutex
	m map[*dfs]*ipcNS
}{m: map[*dfs]*ipcNS{}}

func (g *dguest) ipc() *ipcNS {
	ipcSpaces.Lock()
	defer ipcSpaces.Unlock()
	ns := ipcSpaces.m[g.dfs]
	if ns == nil {
		ns = &ipcNS{shm: map[int]*shmSeg{}, sem: map[int]*semSet{}, msg: map[int]*msgQueue{}, undo: map[*memProc]bool{}, lim: g.ipcLimits()}
		for i := range ns.keys {
			ns.keys[i] = map[int32]int{}
		}
		ns.cond = sync.NewCond(&ns.mu)
		ipcSpaces.m[g.dfs] = ns
	}
	return ns
}

// dropIPC releases a finished Run's segments.
func dropIPC(fs *dfs) {
	ipcSpaces.Lock()
	ns := ipcSpaces.m[fs]
	delete(ipcSpaces.m, fs)
	ipcSpaces.Unlock()
	if ns == nil {
		return
	}
	ns.mu.Lock()
	for id, s := range ns.shm {
		delete(ns.shm, id)
		s.d.unref()
	}
	ns.mu.Unlock()
}

// lookupKey finds key's object of kind k for a get call: its id, -1 to create
// one, or an error.
func (ns *ipcNS) lookupKey(k ipcKind, key int32, flg int64) (int, lxErrno) {
	if key == 0 { // IPC_PRIVATE
		return -1, 0
	}
	id, ok := ns.keys[k][key]
	if !ok {
		if flg&ipcCreat == 0 {
			return 0, lxENOENT
		}
		return -1, 0
	}
	if flg&ipcCreat != 0 && flg&ipcExcl != 0 {
		return 0, lxEEXIST
	}
	return id, 0
}

func (ns *ipcNS) newID(k ipcKind, key int32) int {
	id := ns.next[k]
	ns.next[k]++
	if key != 0 {
		ns.keys[k][key] = id
	}
	return id
}

// wait blocks on cond (ns.mu held) until it is signalled or deadline (zero:
// none) passes, which the caller checks. It reports false on teardown or a
// signal (semop, msgsnd and msgrcv then fail with EINTR, never restarted).
func (ns *ipcNS) wait(g *dguest, deadline time.Time) bool {
	if !deadline.IsZero() {
		t := time.AfterFunc(max(time.Until(deadline), 0), ns.cond.Broadcast)
		defer t.Stop()
	}
	return g.condWaitIntr(ns.cond)
}

// ipcPerm is struct ipc64_perm: key, uid, gid, cuid, cgid, mode, seq, then
// padding to 48 bytes.
type ipcPerm struct {
	key  int32
	mode uint32
	seq  uint16
}

func (p ipcPerm) put(b []byte) {
	put32(b[0:], uint32(p.key))
	put32(b[20:], p.mode)
	binary.LittleEndian.PutUint16(b[24:], p.seq)
}

// setPerm applies IPC_SET's uid/gid/mode from a guest *_ds at addr.
func (g *dguest) setPerm(p *ipcPerm, addr uint64) lxErrno {
	b, err := g.readMem(addr, 48)
	if err != nil {
		return lxEFAULT
	}
	p.mode = p.mode&^0o777 | le32(b[20:])&0o777
	return 0
}

func now() int64 { return time.Now().Unix() }

// ---- shared memory --------------------------------------------------------------

type shmSeg struct {
	perm    ipcPerm
	size    uint64
	d       *dfile
	atime   int64
	dtime   int64
	ctime   int64
	cpid    int
	lpid    int
	nattch  int
	removed bool
}

// shmAttach is one process's attachment, for shmdt and fork/exit accounting.
type shmAttach struct {
	id  int
	seg *shmSeg
}

func (ns *ipcNS) shmget(g *dguest, key int32, size uint64, flg int64) int64 {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	id, e := ns.lookupKey(kShm, key, flg)
	if e != 0 {
		return sErr(e)
	}
	if id >= 0 {
		if size > ns.shm[id].size {
			return sErr(lxEINVAL)
		}
		return int64(id)
	}
	if size < 1 || size > ns.lim.shmMax {
		return sErr(lxEINVAL)
	}
	pages := ns.lim.pages(size)
	if ns.shmTot+pages > ns.lim.shmAll || len(ns.shm) >= shmMni {
		return sErr(lxENOSPC)
	}
	f, err := os.CreateTemp(g.dfs.tmpDir, "lc-shm-")
	if err != nil {
		return sErr(lxENOSPC)
	}
	os.Remove(f.Name())
	if err := f.Truncate(int64(pageUp(size))); err != nil {
		f.Close()
		return sErr(lxENOSPC)
	}
	d := &dfile{f: f, gp: "SYSV", stub: -1}
	d.refs.Add(1)
	id = ns.newID(kShm, key)
	ns.shmTot += pages
	ns.shm[id] = &shmSeg{perm: ipcPerm{key: key, mode: uint32(flg & 0o777)}, size: size, d: d, ctime: now(), cpid: g.tgid}
	return int64(id)
}

func pageUp(n uint64) uint64 { return (n + darwinPage - 1) &^ (darwinPage - 1) }

// shmat and shmdt are served in the stub (stub/macos/mem.zig), which maps a
// segment's file like any shared file mapping. It asks here for the file
// (lcShmat), reports the mapping made (lcShmAttached), and reports an
// attachment once none of it is mapped any more (lcShmGone), whether by
// shmdt, munmap or a mapping over it.

// shmat returns the stub's fd for segment id's file and its size in pages.
func (ns *ipcNS) shmat(g *dguest, id int) int64 {
	ns.mu.Lock()
	s := ns.shm[id]
	if s == nil {
		ns.mu.Unlock()
		return sErr(lxEINVAL)
	}
	s.d.refs.Add(1) // held while sending, against a concurrent IPC_RMID
	ns.mu.Unlock()
	defer s.d.unref()
	// The stub maps the segment itself, so hand it a backing it understands:
	// a stub fd (a /proc-fd pairing) on Linux and macOS, a duplicated section
	// handle on Windows. pages counts the stub's own page size.
	tok, pages, e := g.shmBack(s.d, s.size)
	if e != 0 {
		return sErr(e)
	}
	return tok | int64(pages)<<32
}

// shmCookies names attachments, unique across processes so a forked child's
// copies keep their parent's names.
var shmCookies atomic.Uint64

func (ns *ipcNS) attached(g *dguest, id int) int64 {
	ns.mu.Lock()
	s := ns.shm[id]
	if s == nil {
		ns.mu.Unlock()
		return sErr(lxEINVAL)
	}
	s.nattch++
	s.atime = now()
	s.lpid = g.tgid
	ns.mu.Unlock()
	c := shmCookies.Add(1)
	g.mp.mu.Lock()
	g.mp.shm[c] = &shmAttach{id: id, seg: s}
	g.mp.mu.Unlock()
	return int64(c)
}

func (ns *ipcNS) gone(g *dguest, c uint64) int64 {
	g.mp.mu.Lock()
	at := g.mp.shm[c]
	delete(g.mp.shm, c)
	g.mp.mu.Unlock()
	if at != nil {
		ns.detach(g.tgid, at)
	}
	return 0
}

// detach drops one attachment of a segment, destroying it if it was removed
// and this was the last.
func (ns *ipcNS) detach(pid int, at *shmAttach) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	s := at.seg
	s.nattch--
	s.dtime = now()
	s.lpid = pid
	if s.removed && s.nattch == 0 {
		ns.destroyShm(at.id, s)
	}
}

func (ns *ipcNS) destroyShm(id int, s *shmSeg) {
	if ns.shm[id] == s {
		delete(ns.shm, id)
		ns.shmTot -= ns.lim.pages(s.size)
		s.d.unref()
	}
}

func (ns *ipcNS) shmctl(g *dguest, id int, cmd int64, buf uint64) int64 {
	cmd &^= ipc64
	ns.mu.Lock()
	defer ns.mu.Unlock()
	switch cmd {
	case ipcInfo:
		var b [72]byte // struct shminfo64
		put64(b[0:], ns.lim.shmMax)
		put64(b[8:], 1)
		put64(b[16:], shmMni)
		put64(b[24:], shmMni)
		put64(b[32:], ns.lim.shmAll)
		return ns.out(g, buf, b[:], ns.maxIndex(kShm))
	case shmInfo:
		var b [48]byte // struct shm_info
		put32(b[0:], uint32(len(ns.shm)))
		put64(b[8:], ns.shmTot)
		put64(b[16:], ns.shmTot)
		return ns.out(g, buf, b[:], ns.maxIndex(kShm))
	}
	s := ns.shm[id]
	if s == nil {
		return sErr(lxEINVAL)
	}
	switch cmd {
	case ipcStat, shmStat, shmStatAny:
		var b [112]byte // struct shmid64_ds
		s.perm.put(b[:])
		put64(b[48:], s.size)
		put64(b[56:], uint64(s.atime))
		put64(b[64:], uint64(s.dtime))
		put64(b[72:], uint64(s.ctime))
		put32(b[80:], uint32(s.cpid))
		put32(b[84:], uint32(s.lpid))
		put64(b[88:], uint64(s.nattch))
		ret := int64(0)
		if cmd != ipcStat {
			ret = int64(id)
		}
		return ns.out(g, buf, b[:], ret)
	case ipcSet:
		if e := g.setPerm(&s.perm, buf); e != 0 {
			return sErr(e)
		}
		s.ctime = now()
		return 0
	case ipcRmid:
		if !s.removed {
			s.removed = true
			s.perm.mode |= shmDest
			if ns.keys[kShm][s.perm.key] == id {
				delete(ns.keys[kShm], s.perm.key)
			}
			s.perm.key = 0
			if s.nattch == 0 {
				ns.destroyShm(id, s)
			}
		}
		return 0
	case shmLock:
		s.perm.mode |= shmLocked
		return 0
	case shmUnlock:
		s.perm.mode &^= shmLocked
		return 0
	}
	return sErr(lxEINVAL)
}

// out writes a *_ds/info result to the guest and returns ret.
func (ns *ipcNS) out(g *dguest, addr uint64, b []byte, ret int64) int64 {
	if err := g.writeMem(addr, b); err != nil {
		return sErr(lxEFAULT)
	}
	return ret
}

func (ns *ipcNS) maxIndex(k ipcKind) int64 {
	m := int64(0)
	var ids []int
	switch k {
	case kShm:
		for id := range ns.shm {
			ids = append(ids, id)
		}
	case kSem:
		for id := range ns.sem {
			ids = append(ids, id)
		}
	case kMsg:
		for id := range ns.msg {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		m = max(m, int64(id))
	}
	return m
}

// forkShm gives a forked child its parent's attachments (the mappings are
// inherited with the address space).
func (m *memProc) forkShm(c *memProc, g *dguest) {
	m.mu.Lock()
	ats := make(map[uint64]*shmAttach, len(m.shm))
	for a, at := range m.shm {
		ats[a] = &shmAttach{id: at.id, seg: at.seg}
	}
	m.mu.Unlock()
	if len(ats) == 0 {
		return
	}
	ns := g.ipc()
	ns.mu.Lock()
	for _, at := range ats {
		at.seg.nattch++
	}
	ns.mu.Unlock()
	c.mu.Lock()
	c.shm = ats
	c.mu.Unlock()
}

// detachAll drops every attachment: at exit (the mappings die with the
// process) and at exec (the stub unmaps them as it resets).
func (m *memProc) detachAll(g *dguest) {
	m.mu.Lock()
	ats := m.shm
	m.shm = map[uint64]*shmAttach{}
	m.mu.Unlock()
	if len(ats) == 0 {
		return
	}
	ns := g.ipc()
	for _, at := range ats {
		ns.detach(g.tgid, at)
	}
}

// ---- semaphores ---------------------------------------------------------------------

type semSet struct {
	perm    ipcPerm
	vals    []semVal
	otime   int64
	ctime   int64
	removed bool
}

type semVal struct {
	val  int
	pid  int
	ncnt int
	zcnt int
}

func (ns *ipcNS) semget(g *dguest, key int32, nsems, flg int64) int64 {
	if nsems < 0 || nsems > semMsl {
		return sErr(lxEINVAL)
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	id, e := ns.lookupKey(kSem, key, flg)
	if e != 0 {
		return sErr(e)
	}
	if id >= 0 {
		if nsems > int64(len(ns.sem[id].vals)) {
			return sErr(lxEINVAL)
		}
		return int64(id)
	}
	if nsems == 0 {
		return sErr(lxEINVAL)
	}
	if ns.semUsed+int(nsems) > semMns || len(ns.sem) >= semMni {
		return sErr(lxENOSPC)
	}
	ns.semUsed += int(nsems)
	id = ns.newID(kSem, key)
	ns.sem[id] = &semSet{perm: ipcPerm{key: key, mode: uint32(flg & 0o777)}, vals: make([]semVal, nsems), ctime: now()}
	return int64(id)
}

type sembuf struct {
	num uint16
	op  int16
	flg int16
}

func (ns *ipcNS) semop(g *dguest, id int, sopsAddr, nsops, tsAddr uint64) int64 {
	if nsops == 0 {
		return sErr(lxEINVAL)
	}
	if nsops > semOpm {
		return sErr(lxE2BIG)
	}
	raw, err := g.readMem(sopsAddr, int(nsops)*6)
	if err != nil {
		return sErr(lxEFAULT)
	}
	ops := make([]sembuf, nsops)
	for i := range ops {
		b := raw[i*6:]
		ops[i] = sembuf{binary.LittleEndian.Uint16(b), int16(binary.LittleEndian.Uint16(b[2:])), int16(binary.LittleEndian.Uint16(b[4:]))}
	}
	var deadline time.Time
	if tsAddr != 0 {
		ts, err := g.readMem(tsAddr, 16)
		if err != nil {
			return sErr(lxEFAULT)
		}
		sec, nsec := int64(le64(ts)), int64(le64(ts[8:]))
		if sec < 0 || nsec < 0 || nsec >= 1e9 {
			return sErr(lxEINVAL)
		}
		deadline = time.Now().Add(time.Duration(sec)*time.Second + time.Duration(nsec))
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	s := ns.sem[id]
	if s == nil {
		return sErr(lxEINVAL)
	}
	for _, o := range ops {
		if int(o.num) >= len(s.vals) {
			return sErr(lxEFBIG)
		}
	}
	for {
		if s.removed {
			return sErr(lxEIDRM)
		}
		blockOn, zero, e := s.try(ops)
		if e != 0 {
			return sErr(e)
		}
		if blockOn < 0 {
			for _, o := range ops {
				s.vals[o.num].pid = g.tgid
				if o.flg&semUndo != 0 && o.op != 0 {
					g.mp.semAdjust(id, o.num, -int(o.op))
					ns.undo[g.mp] = true
				}
			}
			s.otime = now()
			ns.cond.Broadcast()
			return 0
		}
		if ops[blockOn].flg&ipcNowait != 0 || (!deadline.IsZero() && !time.Now().Before(deadline)) {
			return sErr(lxEAGAIN)
		}
		v := &s.vals[ops[blockOn].num]
		if zero {
			v.zcnt++
		} else {
			v.ncnt++
		}
		alive := ns.wait(g, deadline)
		if zero {
			v.zcnt--
		} else {
			v.ncnt--
		}
		if !alive {
			return sErr(lxEINTR)
		}
	}
}

// try applies ops atomically if all can proceed, else returns the index of
// the first that must wait (and whether it waits for zero).
func (s *semSet) try(ops []sembuf) (int, bool, lxErrno) {
	vals := make([]int, len(s.vals))
	for i, v := range s.vals {
		vals[i] = v.val
	}
	for i, o := range ops {
		switch {
		case o.op > 0:
			if vals[o.num]+int(o.op) > semVmx {
				return 0, false, lxERANGE
			}
			vals[o.num] += int(o.op)
		case o.op == 0:
			if vals[o.num] != 0 {
				return i, true, 0
			}
		default:
			if vals[o.num]+int(o.op) < 0 {
				return i, false, 0
			}
			vals[o.num] += int(o.op)
		}
	}
	for i := range s.vals {
		s.vals[i].val = vals[i]
	}
	return -1, false, 0
}

func (ns *ipcNS) semctl(g *dguest, id, num int, cmd int64, arg uint64) int64 {
	cmd &^= ipc64
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if cmd == ipcInfo || cmd == semInfo {
		var b [40]byte // struct seminfo: ten ints
		info := []uint32{semMns, semMni, semMns, semMns, semMsl, semOpm, semOpm, 20, semVmx, semVmx}
		if cmd == semInfo {
			info[7], info[9] = uint32(len(ns.sem)), uint32(ns.semUsed)
		}
		for i, v := range info {
			put32(b[i*4:], v)
		}
		return ns.out(g, arg, b[:], ns.maxIndex(kSem))
	}
	s := ns.sem[id]
	if s == nil {
		return sErr(lxEINVAL)
	}
	val := func() (*semVal, lxErrno) {
		if num < 0 || num >= len(s.vals) {
			return nil, lxEINVAL
		}
		return &s.vals[num], 0
	}
	switch cmd {
	case ipcStat, semStat, semStatAny:
		abi := g.abi()
		b := make([]byte, abi.semdsLen) // struct semid64_ds, its layout per architecture
		s.perm.put(b)
		put64(b[48:], uint64(s.otime))
		put64(b[abi.semdsCtime:], uint64(s.ctime))
		put64(b[abi.semdsNsems:], uint64(len(s.vals)))
		ret := int64(0)
		if cmd != ipcStat {
			ret = int64(id)
		}
		return ns.out(g, arg, b[:], ret)
	case ipcSet:
		if e := g.setPerm(&s.perm, arg); e != 0 {
			return sErr(e)
		}
		s.ctime = now()
		return 0
	case ipcRmid:
		s.removed = true
		delete(ns.sem, id)
		ns.semUsed -= len(s.vals)
		ns.clearUndo(id, -1)
		if ns.keys[kSem][s.perm.key] == id {
			delete(ns.keys[kSem], s.perm.key)
		}
		ns.cond.Broadcast()
		return 0
	case semGetval, semGetpid, semGetncnt, semGetzcnt:
		v, e := val()
		if e != 0 {
			return sErr(e)
		}
		switch cmd {
		case semGetval:
			return int64(v.val)
		case semGetpid:
			return int64(v.pid)
		case semGetncnt:
			return int64(v.ncnt)
		}
		return int64(v.zcnt)
	case semSetval:
		v, e := val()
		if e != 0 {
			return sErr(e)
		}
		x := int(int32(arg))
		if x < 0 || x > semVmx {
			return sErr(lxERANGE)
		}
		v.val = x
		v.pid = g.tgid
		ns.clearUndo(id, num)
		s.ctime = now()
		ns.cond.Broadcast()
		return 0
	case semGetall:
		b := make([]byte, 2*len(s.vals))
		for i, v := range s.vals {
			binary.LittleEndian.PutUint16(b[i*2:], uint16(v.val))
		}
		return ns.out(g, arg, b, 0)
	case semSetall:
		b, err := g.readMem(arg, 2*len(s.vals))
		if err != nil {
			return sErr(lxEFAULT)
		}
		for i := range s.vals {
			if binary.LittleEndian.Uint16(b[i*2:]) > semVmx {
				return sErr(lxERANGE)
			}
		}
		for i := range s.vals {
			s.vals[i].val = int(binary.LittleEndian.Uint16(b[i*2:]))
			s.vals[i].pid = g.tgid
		}
		ns.clearUndo(id, -1)
		s.ctime = now()
		ns.cond.Broadcast()
		return 0
	}
	return sErr(lxEINVAL)
}

// clearUndo forgets SEM_UNDO adjustments for one semaphore (num) or the whole
// set (-1), as SETVAL, SETALL and IPC_RMID do on Linux. A process left with
// none leaves ns.undo, since only a process with adjustments undoes them at
// exit. ns.mu is held.
func (ns *ipcNS) clearUndo(id, num int) {
	for m := range ns.undo {
		m.mu.Lock()
		if adj := m.semadj[id]; adj != nil {
			if num >= 0 {
				delete(adj, uint16(num))
			}
			if num < 0 || len(adj) == 0 {
				delete(m.semadj, id)
			}
		}
		if len(m.semadj) == 0 {
			delete(ns.undo, m)
		}
		m.mu.Unlock()
	}
}

func (m *memProc) semAdjust(id int, num uint16, by int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.semadj[id] == nil {
		m.semadj[id] = map[uint16]int{}
	}
	m.semadj[id][num] += by
}

// undoSems applies a process's SEM_UNDO adjustments as it exits.
func (m *memProc) undoSems(g *dguest) {
	m.mu.Lock()
	adj := m.semadj
	m.semadj = map[int]map[uint16]int{}
	m.mu.Unlock()
	ns := g.ipc()
	ns.mu.Lock()
	defer ns.mu.Unlock()
	delete(ns.undo, m)
	for id, nums := range adj {
		s := ns.sem[id]
		if s == nil {
			continue
		}
		for num, by := range nums {
			v := &s.vals[num]
			v.val = min(max(v.val+by, 0), semVmx)
			v.pid = g.tgid
		}
	}
	ns.cond.Broadcast()
}

// ---- message queues ---------------------------------------------------------------------

type msgQueue struct {
	perm    ipcPerm
	msgs    []ipcMsg
	cbytes  uint64
	qbytes  uint64
	stime   int64
	rtime   int64
	ctime   int64
	lspid   int
	lrpid   int
	removed bool
}

type ipcMsg struct {
	typ  int64
	text []byte
}

func (ns *ipcNS) msgget(g *dguest, key int32, flg int64) int64 {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	id, e := ns.lookupKey(kMsg, key, flg)
	if e != 0 {
		return sErr(e)
	}
	if id >= 0 {
		return int64(id)
	}
	if len(ns.msg) >= msgMni {
		return sErr(lxENOSPC)
	}
	id = ns.newID(kMsg, key)
	ns.msg[id] = &msgQueue{perm: ipcPerm{key: key, mode: uint32(flg & 0o777)}, qbytes: msgMnb, ctime: now()}
	return int64(id)
}

func (ns *ipcNS) msgsnd(g *dguest, id int, addr uint64, size, flg int64) int64 {
	if size < 0 || size > msgMax {
		return sErr(lxEINVAL)
	}
	b, err := g.readMem(addr, 8+int(size))
	if err != nil {
		return sErr(lxEFAULT)
	}
	m := ipcMsg{typ: int64(le64(b)), text: b[8:]}
	if m.typ < 1 {
		return sErr(lxEINVAL)
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	q := ns.msg[id]
	if q == nil {
		return sErr(lxEINVAL)
	}
	for {
		if q.removed {
			return sErr(lxEIDRM)
		}
		if q.cbytes+uint64(size) <= q.qbytes && uint64(len(q.msgs)) < q.qbytes {
			if ns.msgBytes+uint64(size)+msgHdr > msgPool {
				return sErr(lxENOMEM)
			}
			q.msgs = append(q.msgs, m)
			q.cbytes += uint64(size)
			ns.msgBytes += uint64(size) + msgHdr
			q.stime = now()
			q.lspid = g.tgid
			ns.cond.Broadcast()
			return 0
		}
		if flg&ipcNowait != 0 {
			return sErr(lxEAGAIN)
		}
		if !ns.wait(g, time.Time{}) {
			return sErr(lxEINTR)
		}
	}
}

func (ns *ipcNS) msgrcv(g *dguest, id int, addr uint64, size, typ, flg int64) int64 {
	if size < 0 {
		return sErr(lxEINVAL)
	}
	if flg&msgCopy != 0 {
		return sErr(lxENOSYS)
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	q := ns.msg[id]
	if q == nil {
		return sErr(lxEINVAL)
	}
	for {
		if q.removed {
			return sErr(lxEIDRM)
		}
		if i := q.pick(typ, flg&msgExcept != 0); i >= 0 {
			m := q.msgs[i]
			text := m.text
			if int64(len(text)) > size {
				if flg&msgNoerror == 0 {
					return sErr(lxE2BIG)
				}
				text = text[:size]
			}
			out := make([]byte, 8+len(text))
			put64(out, uint64(m.typ))
			copy(out[8:], text)
			if err := g.writeMem(addr, out); err != nil {
				return sErr(lxEFAULT)
			}
			q.msgs = append(q.msgs[:i], q.msgs[i+1:]...)
			q.cbytes -= uint64(len(m.text))
			ns.msgBytes -= uint64(len(m.text)) + msgHdr
			q.rtime = now()
			q.lrpid = g.tgid
			ns.cond.Broadcast()
			return int64(len(text))
		}
		if flg&ipcNowait != 0 {
			return sErr(lxENOMSG)
		}
		if !ns.wait(g, time.Time{}) {
			return sErr(lxEINTR)
		}
	}
}

// pick returns the index of the message msgrcv takes for typ, or -1.
func (q *msgQueue) pick(typ int64, except bool) int {
	best := -1
	for i, m := range q.msgs {
		switch {
		case typ == 0:
			return i
		case typ > 0 && !except && m.typ == typ, typ > 0 && except && m.typ != typ:
			return i
		case typ < 0 && m.typ <= -typ && (best < 0 || m.typ < q.msgs[best].typ):
			best = i
		}
	}
	return best
}

func (ns *ipcNS) msgctl(g *dguest, id int, cmd int64, buf uint64) int64 {
	cmd &^= ipc64
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if cmd == ipcInfo || cmd == msgInfo {
		var b [32]byte // struct msginfo
		info := []uint32{msgPool / 1024, msgMnb, msgMax, msgMnb, msgMni, msgSsz, msgMnb, 0}
		if cmd == msgInfo {
			var n, bytes int
			for _, q := range ns.msg {
				n += len(q.msgs)
				bytes += int(q.cbytes)
			}
			info[0], info[1], info[6] = uint32(len(ns.msg)), uint32(n), uint32(bytes)
		}
		for i, v := range info[:7] {
			put32(b[i*4:], v)
		}
		binary.LittleEndian.PutUint16(b[28:], 0xffff)
		return ns.out(g, buf, b[:], ns.maxIndex(kMsg))
	}
	q := ns.msg[id]
	if q == nil {
		return sErr(lxEINVAL)
	}
	switch cmd {
	case ipcStat, msgStat, msgStatAny:
		var b [120]byte // struct msqid64_ds
		q.perm.put(b[:])
		put64(b[48:], uint64(q.stime))
		put64(b[56:], uint64(q.rtime))
		put64(b[64:], uint64(q.ctime))
		put64(b[72:], q.cbytes)
		put64(b[80:], uint64(len(q.msgs)))
		put64(b[88:], q.qbytes)
		put32(b[96:], uint32(q.lspid))
		put32(b[100:], uint32(q.lrpid))
		ret := int64(0)
		if cmd != ipcStat {
			ret = int64(id)
		}
		return ns.out(g, buf, b[:], ret)
	case ipcSet:
		b, err := g.readMem(buf, 96)
		if err != nil {
			return sErr(lxEFAULT)
		}
		q.perm.mode = q.perm.mode&^0o777 | le32(b[20:])&0o777
		q.qbytes = le64(b[88:])
		q.ctime = now()
		ns.cond.Broadcast()
		return 0
	case ipcRmid:
		q.removed = true
		delete(ns.msg, id)
		ns.msgBytes -= q.cbytes + uint64(len(q.msgs))*msgHdr
		if ns.keys[kMsg][q.perm.key] == id {
			delete(ns.keys[kMsg], q.perm.key)
		}
		ns.cond.Broadcast()
		return 0
	}
	return sErr(lxEINVAL)
}
