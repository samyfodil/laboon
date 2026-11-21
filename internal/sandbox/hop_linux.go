package sandbox

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Each stub process has a host-op ("hop") thread that runs the process-wide
// host syscalls the supervisor needs in the guest's address space -- memory
// mappings, descriptors and forks -- which the guest's own threads may not
// make (stub/zig/seccomp.zig). Its requests arrive on a page the stub maps
// read-only, after the channel region; its replies go on a page the stub maps
// read-write (stub/zig/stub.zig, hopReqAddr and hopRepAddr), which the guest
// can write too, so a reply is only ever a result the guest could have had
// anyway. A host call whose meaning is the calling thread's -- a futex wait,
// its TLS, its exit -- stays on that thread's channel.
// leaderHoldsSlot is false: a slot is freed once its stub process is gone
// (freeStubSlot), which a gone leader's is only with its process.
const leaderHoldsSlot = false

const (
	hopReqOff = chanLen
	hopRepOff = hopReqOff + maxSlots*slotSize
	hopEnd    = hopRepOff + maxSlots*slotSize

	// stubSpOff is where the stub records the guest sp at each syscall: in the
	// slot page, sig.zig's REC_OFF plus Thread.sp's offset.
	stubSpOff = 128 + 8

	// hopFork, as a request's nr, has the hop thread fork its stub process
	// (stub.zig HOP_FORK): args are the child's slot, its hop's request page
	// (hopReqAddr), the forking thread's context and the guest stack.
	hopFork = ^uintptr(0)

	// hopWinOff is where the request pages are in the stub's window
	// (stub.zig hopReqAddr).
	hopWinOff = 0x1600000000
)

// hopReqAddr is where a stub maps hop entry idx's request page.
func hopReqAddr(idx int) uint64 {
	return stubLo + hopWinOff + uint64(idx)*slotSize
}

type hopReq struct {
	seq, supSleep uint32
	nr            uint64
	args          [6]uint64
}

type hopRep struct {
	seq, hopSleep uint32
	ret           uint64
}

// hop is the supervisor's end of one stub process's host-op thread.
type hop struct {
	mu   sync.Mutex
	idx  int
	req  *hopReq
	rep  *hopRep
	dead atomic.Bool
}

// hopTable is the run's hop entries: which are taken, and whose they are.
type hopTable struct {
	used  []bool
	byPid map[int]*hop // by stub host pid
}

// hopRuns reports whether host call nr acts on the whole stub process, so its
// hop thread runs it.
func hopRuns(nr uintptr) bool {
	switch nr {
	case unix.SYS_MMAP, unix.SYS_MPROTECT, unix.SYS_MUNMAP, unix.SYS_MREMAP, unix.SYS_MADVISE,
		unix.SYS_MSYNC, unix.SYS_MINCORE, unix.SYS_CLOSE, unix.SYS_RECVMSG, unix.SYS_MEMBARRIER:
		return true
	}
	return false
}

// onOwnStack reports whether [addr, addr+n) holds the guest stack the
// calling thread is running on: its sp at this syscall, which the stub
// records (0 while it serves an execve, when no guest stack is underfoot).
func (g *dguest) onOwnStack(addr, n uint64) bool {
	sp := atomic.LoadUint64((*uint64)(unsafe.Pointer(&g.mem[g.slot*slotSize+stubSpOff])))
	return sp != 0 && sp-addr < n
}

// call has the hop thread run nr(args) for the thread on channel c and returns
// its result. A call to a stub that is gone returns EIO, as does one from a
// thread whose slot was ended, as on its own channel: an exec ends the other
// threads' slots before it replaces the address space, so none of their calls
// may run after.
func (h *hop) call(c *channel, nr uintptr, args ...uint64) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if atomic.LoadUint32(&c.page.state) == stDead {
		return sErr(lxEIO)
	}
	req, rep := h.req, h.rep
	req.nr = uint64(nr)
	req.args = [6]uint64{}
	copy(req.args[:], args)
	s := atomic.AddUint32(&req.seq, 1)
	if atomic.LoadUint32(&rep.hopSleep) != 0 {
		unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&req.seq)), futexWake, 1, 0, 0, 0)
	}
	if !h.spin(s) {
		for {
			atomic.StoreUint32(&req.supSleep, 1)
			cur := atomic.LoadUint32(&rep.seq)
			if h.dead.Load() {
				atomic.StoreUint32(&req.supSleep, 0)
				return sErr(lxEIO)
			}
			if cur == s {
				break
			}
			unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&rep.seq)), futexWait, uintptr(cur), 0, 0, 0)
		}
		atomic.StoreUint32(&req.supSleep, 0)
	}
	return int64(rep.ret)
}

// spin polls for reply s for about the cost of a park, as channel.wait does.
func (h *hop) spin(s uint32) bool {
	var end uint64
	if adaptive {
		ensureCalibrated()
		end = cputicks() + parkCost()
	}
	for i := 0; ; i++ {
		if atomic.LoadUint32(&h.rep.seq) == s {
			return !h.dead.Load()
		}
		spinHint()
		if adaptive {
			if i&31 == 31 && cputicks() >= end {
				return false
			}
		} else if i >= fixedSpin {
			return false
		}
	}
}

// kill ends the hop of a stub process that is gone: a waiting call returns.
// Bumping the reply word wakes a call about to sleep on it; dead, stored
// first, tells it the reply is not one.
func (h *hop) kill() {
	h.dead.Store(true)
	atomic.AddUint32(&h.rep.seq, 1)
	unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&h.rep.seq)), futexWake, 1<<31-1, 0, 0, 0)
}

// exitGroup has the hop thread end its stub process, waiting for no reply:
// none comes, and the process's end is seen as any stub's (watchStub).
func (h *hop) exitGroup() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.req.nr = unix.SYS_EXIT_GROUP
	h.req.args = [6]uint64{}
	atomic.AddUint32(&h.req.seq, 1)
	if atomic.LoadUint32(&h.rep.hopSleep) != 0 {
		unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&h.req.seq)), futexWake, 1, 0, 0, 0)
	}
}

// endStub ends the stub process of ps, whose threads have all exited one by
// one: Linux ends a process with its last thread, but the stub's hop thread
// would keep it. A process still running in that stub (a CLONE_VM child) keeps
// it instead.
func (fs *dfs) endStub(ps *pstate) {
	fs.mu.Lock()
	ospid := ps.ospid
	for _, p := range fs.pt {
		if p != ps && p.ospid == ospid && !p.zombie {
			fs.mu.Unlock()
			return
		}
	}
	h := fs.hops.byPid[ospid]
	fs.mu.Unlock()
	if h != nil {
		h.exitGroup()
	}
}

// allocHop takes a free hop entry for a new stub process, cleared; nil when
// none is free.
func (fs *dfs) allocHop() *hop {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	t := &fs.hops
	if t.used == nil {
		t.used = make([]bool, maxSlots)
		t.byPid = map[int]*hop{}
	}
	for i, used := range t.used {
		if used {
			continue
		}
		t.used[i] = true
		h := &hop{idx: i,
			req: (*hopReq)(unsafe.Pointer(&fs.mem[hopReqOff+i*slotSize])),
			rep: (*hopRep)(unsafe.Pointer(&fs.mem[hopRepOff+i*slotSize]))}
		*h.req = hopReq{}
		*h.rep = hopRep{}
		return h
	}
	return nil
}

// adoptHop records that stub process ospid runs hop h.
func (fs *dfs) adoptHop(ospid int, h *hop) {
	fs.mu.Lock()
	fs.hops.byPid[ospid] = h
	fs.mu.Unlock()
}

// freeHop returns an entry no stub process ever ran a thread on.
func (fs *dfs) freeHop(h *hop) {
	fs.mu.Lock()
	fs.hops.used[h.idx] = false
	fs.mu.Unlock()
}

// hopGone ends stub process ospid's hop, so waits on it return. Once the
// process is reaped its entry is free again: only then can no thread of it
// still answer a request meant for the entry's next owner.
func (fs *dfs) hopGone(ospid int, reaped bool) {
	fs.mu.Lock()
	h := fs.hops.byPid[ospid]
	if reaped && h != nil {
		delete(fs.hops.byPid, ospid)
		fs.hops.used[h.idx] = false
	}
	fs.mu.Unlock()
	if h != nil {
		h.kill()
	}
}

// killHops ends every hop at the run's end.
func (fs *dfs) killHops() {
	fs.mu.Lock()
	hs := make([]*hop, 0, len(fs.hops.byPid))
	for _, h := range fs.hops.byPid {
		hs = append(hs, h)
	}
	fs.mu.Unlock()
	for _, h := range hs {
		h.kill()
	}
}
