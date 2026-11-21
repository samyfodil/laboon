//go:build darwin || linux || windows

package sandbox

import (
	"io"
	"math"
	"sync"
	"sync/atomic"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// Advisory file locks, kept by the supervisor: every guest process's host
// files belong to the one supervisor process, so host POSIX locks could never
// conflict between guests. flock locks belong to an open-file description;
// fcntl F_SETLK locks to a process; F_OFD_* locks to a description. The two
// families do not interact, as on Linux.

const (
	lxFlock = 32

	lxLockSh = 1
	lxLockEx = 2
	lxLockNb = 4
	lxLockUn = 8

	lxFRdlck = 0
	lxFWrlck = 1
	lxFUnlck = 2

	lxFGetlk     = 5
	lxFSetlk     = 6
	lxFSetlkw    = 7
	lxFOfdGetlk  = 36
	lxFOfdSetlk  = 37
	lxFOfdSetlkw = 38
)

type lockOwner struct {
	fs   *dfs
	tgid int
	ofd  *dfile // OFD lock owner; nil for a process (POSIX) lock
}

type rangeLock struct {
	owner      lockOwner
	write      bool
	start, end int64 // inclusive; end == math.MaxInt64 means to EOF and beyond
}

type inodeLocks struct {
	ranges []rangeLock
	flocks map[*dfile]bool // description -> exclusive
}

var locks struct {
	mu    sync.Mutex
	m     map[lkey]*inodeLocks
	gen   chan struct{} // closed and replaced on every release
	posix atomic.Int32  // POSIX range locks held, so close skips the lookup when 0
}

func init() {
	syscalls[lxFlock] = func(g *dguest, a [6]uint64) int64 { return g.flock(int64(a[0]), int64(a[1])) }
}

// lkey names a guest file for locking: the run (two runs over one root are
// separate machines) and the host inode, mapped back to the lower inode a
// copy-up came from, so a description opened before the copy-up and one opened
// after lock the same file.
type lkey struct {
	fs *dfs
	ikey
}

func (g *dguest) lockKey(d *dfile) (lkey, lxErrno) {
	if d.f == nil && d.vf == nil || d.fx.opath {
		return lkey{}, lxEBADF
	}
	if h := d.fsFile(); h != nil { // a filesystem object: its vfs identity, kept across copy-up
		info, err := h.Stat()
		if err != nil {
			return lkey{}, osErrno(err)
		}
		id := info.ID()
		return lkey{g.dfs, g.ov.originOf(ikey{id.Dev, id.Ino})}, 0
	}
	// A supervisor-owned object (memfd, device) has no vfs handle; its own
	// descriptor's identity keys the lock.
	fi, err := hostfs.FileStat(d.f)
	if err != nil {
		return lkey{}, osErrno(err)
	}
	return lkey{g.dfs, g.ov.originOf(inodeKey(fi))}, 0
}

// locksChanged wakes every waiter; the caller holds locks.mu.
func locksChanged() {
	if locks.gen != nil {
		close(locks.gen)
	}
	locks.gen = make(chan struct{})
}

func inodeLocksFor(k lkey) *inodeLocks {
	if locks.m == nil {
		locks.m = map[lkey]*inodeLocks{}
	}
	il := locks.m[k]
	if il == nil {
		il = &inodeLocks{flocks: map[*dfile]bool{}}
		locks.m[k] = il
	}
	return il
}

func (il *inodeLocks) gc(k lkey) {
	if len(il.ranges) == 0 && len(il.flocks) == 0 {
		delete(locks.m, k)
	}
}

// waitLocks parks until the lock table changes (every release says so, a
// holder's close and exit included), the guest goes away or a signal arrives.
// It drops and retakes locks.mu. It returns 0 to retry, else what the call
// returns.
func (g *dguest) waitLocks() int64 {
	if locks.gen == nil {
		locks.gen = make(chan struct{})
	}
	gen := locks.gen
	locks.mu.Unlock()
	defer locks.mu.Lock()
	var kick chan struct{}
	if t := g.sigs().thread(g.pid); t != nil {
		kick = t.kick()
	}
	if g.sigIntr() {
		return restartSys
	}
	select {
	case <-gen:
	case <-kick:
		if g.sigIntr() {
			return restartSys
		}
	case <-g.ch.done:
		return sErr(lxEINTR)
	case <-g.ch.stop:
		return sErr(lxEINTR)
	}
	return 0
}

func (g *dguest) flock(fd, op int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok || d.fx.opath {
		return sErr(lxEBADF)
	}
	if d.f == nil && d.vf == nil {
		return 0 // stub-served stdio
	}
	nb := op&lxLockNb != 0
	op &^= lxLockNb
	if op != lxLockSh && op != lxLockEx && op != lxLockUn {
		return sErr(lxEINVAL)
	}
	k, e := g.lockKey(d)
	if e != 0 {
		return sErr(e)
	}
	locks.mu.Lock()
	defer locks.mu.Unlock()
	il := inodeLocksFor(k)
	if op == lxLockUn {
		if _, held := il.flocks[d]; held {
			delete(il.flocks, d)
			locksChanged()
		}
		il.gc(k)
		return 0
	}
	excl := op == lxLockEx
	if cur, held := il.flocks[d]; held && cur != excl {
		// A conversion is not atomic on Linux either: drop, then acquire.
		delete(il.flocks, d)
		locksChanged()
	}
	for {
		conflict := false
		for o, x := range il.flocks {
			if o != d && (x || excl) {
				conflict = true
				break
			}
		}
		if !conflict {
			break
		}
		if nb {
			il.gc(k)
			return sErr(lxEAGAIN)
		}
		if r := g.waitLocks(); r != 0 {
			return r
		}
		il = inodeLocksFor(k)
	}
	il.flocks[d] = excl
	d.fx.locked.Store(true)
	return 0
}

// fcntlLock serves F_GETLK/F_SETLK/F_SETLKW and their F_OFD_* forms. The arm64
// struct flock is {s16 type, s16 whence, pad, s64 start, s64 len, s32 pid, pad}.
func (g *dguest) fcntlLock(d *dfile, cmd int64, addr uint64) int64 {
	if d.fx.opath || d.f == nil && d.vf == nil {
		return sErr(lxEBADF)
	}
	b, err := g.readMem(addr, 32)
	if err != nil {
		return sErr(lxEFAULT)
	}
	typ := int16(uint16(b[0]) | uint16(b[1])<<8)
	whence := int16(uint16(b[2]) | uint16(b[3])<<8)
	start, ln := int64(le64(b[8:])), int64(le64(b[16:]))
	pid := int32(le32(b[24:]))
	ofd := cmd >= lxFOfdGetlk
	if ofd && pid != 0 {
		return sErr(lxEINVAL)
	}
	if typ != lxFRdlck && typ != lxFWrlck && typ != lxFUnlck {
		return sErr(lxEINVAL)
	}
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		p, err := d.tell()
		if err != nil {
			return sErr(osErrno(err))
		}
		base = p
	case io.SeekEnd:
		_, size, err := d.hostStat()
		if err != nil {
			return sErr(osErrno(err))
		}
		base = size
	default:
		return sErr(lxEINVAL)
	}
	s := base + start
	var end int64
	switch {
	case ln > 0:
		end = s + ln - 1
	case ln == 0:
		end = math.MaxInt64
	default:
		s, end = s+ln, s-1
	}
	if s < 0 {
		return sErr(lxEINVAL)
	}
	owner := lockOwner{fs: g.dfs, tgid: g.tgid}
	if ofd {
		owner = lockOwner{ofd: d}
	}
	k, e := g.lockKey(d)
	if e != 0 {
		return sErr(e)
	}
	want := rangeLock{owner: owner, write: typ == lxFWrlck, start: s, end: end}

	locks.mu.Lock()
	defer locks.mu.Unlock()
	il := inodeLocksFor(k)
	defer func() { il.gc(k) }()
	conflict := func() *rangeLock {
		for i := range il.ranges {
			r := &il.ranges[i]
			if r.owner != owner && r.start <= want.end && want.start <= r.end && (r.write || want.write) {
				return r
			}
		}
		return nil
	}
	if cmd == lxFGetlk || cmd == lxFOfdGetlk {
		if typ == lxFUnlck {
			return sErr(lxEINVAL)
		}
		var out [32]byte
		copy(out[:], b)
		if c := conflict(); c != nil {
			ct := int16(lxFRdlck)
			if c.write {
				ct = lxFWrlck
			}
			out[0], out[1] = byte(ct), byte(ct>>8)
			out[2], out[3] = 0, 0
			put64(out[8:], uint64(c.start))
			if c.end == math.MaxInt64 {
				put64(out[16:], 0)
			} else {
				put64(out[16:], uint64(c.end-c.start+1))
			}
			p := int32(-1)
			if c.owner.ofd == nil {
				p = int32(c.owner.tgid)
			}
			put32(out[24:], uint32(p))
		} else {
			out[0], out[1] = lxFUnlck, 0
		}
		if err := g.writeMem(addr, out[:]); err != nil {
			return sErr(lxEFAULT)
		}
		return 0
	}
	if typ == lxFRdlck && d.fx.hasFlags && d.fx.oflags&lxOAccmod == lxOWronly ||
		typ == lxFWrlck && !d.writable() {
		return sErr(lxEBADF)
	}
	if typ != lxFUnlck {
		for conflict() != nil {
			if cmd == lxFSetlk || cmd == lxFOfdSetlk {
				return sErr(lxEAGAIN)
			}
			if r := g.waitLocks(); r != 0 {
				return r
			}
			il = inodeLocksFor(k)
		}
	}
	// Carve the range out of this owner's locks, then add the new one.
	var kept []rangeLock
	changed := false
	for _, r := range il.ranges {
		if r.owner != owner || r.end < want.start || r.start > want.end {
			kept = append(kept, r)
			continue
		}
		changed = true
		if r.start < want.start {
			l := r
			l.end = want.start - 1
			kept = append(kept, l)
		}
		if r.end > want.end {
			rr := r
			rr.start = want.end + 1
			kept = append(kept, rr)
		}
	}
	if typ != lxFUnlck {
		kept = append(kept, want)
	}
	if !ofd {
		locks.posix.Add(int32(countOwner(kept, owner) - countOwner(il.ranges, owner)))
	} else {
		d.fx.locked.Store(true)
	}
	il.ranges = kept
	if changed {
		locksChanged()
	}
	return 0
}

func countOwner(rs []rangeLock, o lockOwner) int {
	n := 0
	for _, r := range rs {
		if r.owner == o {
			n++
		}
	}
	return n
}

// dropPosixLocks releases the process's POSIX locks on d's inode (any close of
// a fd for the file does, on Linux), or on every inode when d is nil (exit).
func (g *dguest) dropPosixLocks(d *dfile) {
	if locks.posix.Load() == 0 {
		return
	}
	owner := lockOwner{fs: g.dfs, tgid: g.tgid}
	var only *lkey
	if d != nil {
		k, e := g.lockKey(d)
		if e != 0 {
			return
		}
		only = &k
	}
	locks.mu.Lock()
	defer locks.mu.Unlock()
	for k, il := range locks.m {
		if only != nil && k != *only {
			continue
		}
		n := countOwner(il.ranges, owner)
		if n == 0 {
			continue
		}
		var kept []rangeLock
		for _, r := range il.ranges {
			if r.owner != owner {
				kept = append(kept, r)
			}
		}
		il.ranges = kept
		locks.posix.Add(int32(-n))
		il.gc(k)
		locksChanged()
	}
}

// dropFileLocks releases the flock and OFD locks of a description whose last
// reference is gone.
func dropFileLocks(d *dfile) {
	locks.mu.Lock()
	defer locks.mu.Unlock()
	for k, il := range locks.m {
		delete(il.flocks, d)
		var kept []rangeLock
		for _, r := range il.ranges {
			if r.owner.ofd != d {
				kept = append(kept, r)
			}
		}
		il.ranges = kept
		il.gc(k)
	}
	locksChanged()
}

// releaseFx frees the filesystem state of a description with its last
// reference: its locks and, for an inotify fd, the instance.
func (d *dfile) releaseFx() {
	if d.fx.locked.Load() {
		dropFileLocks(d)
	}
	if d.fx.in != nil {
		d.fx.in.close()
	}
	dnotifyDrop(d)
	if d.fx.ov != nil {
		d.fx.ov.untrackFile(d)
	}
}
