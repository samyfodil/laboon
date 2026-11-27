//go:build darwin || linux || windows

package sandbox

import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Linux signals for the macOS backend, the supervisor's half: the process and
// thread registry, routing (which process or thread a signal goes to, and
// waking it), default actions that need the OS (kill, stop, continue),
// SIGCHLD, timers, signalfd/pidfd and host signal forwarding, and the pending
// sets and actions themselves (sigQueue, sigProc.acts), which the guest cannot
// reach. Delivery -- building the rt_sigframe, redirecting a thread -- is the
// stub's (stub/macos/sig.zig), since only it holds the guest CPU state: it
// takes a signal with its action by a call (lxSigTake).
//
// Both sides share the signal area: one record per channel slot after the
// slots in the channel file. A thread's record holds its mask and
// sigaltstack, which the stub keeps, and a copy of its pending bits; the
// record at a thread-group leader's slot holds a copy of the process's. Only
// the supervisor writes the copies: the stub reads them to know when to take a
// signal, and nothing the guest writes there can hold the supervisor up.
//
// Posting a signal sets its pending bit, then wakes the target: a thread
// blocked in a supervisor-served call is interrupted here (it returns
// -ERESTARTSYS and the stub restarts it or delivers EINTR per SA_RESTART); a
// thread running guest code or waiting in the stub is reached by a Darwin
// SIGUSR1 to its stub process, whose handler kicks the threads that can take
// the signal.

const (
	lxSignalfd4               = 74
	lxGetitimer               = 102
	lxSetitimer               = 103
	lxTimerCreate             = 107
	lxTimerGettime            = 108
	lxTimerGetoverrun         = 109
	lxTimerSettime            = 110
	lxTimerDelete             = 111
	lxKill                    = 129
	lxTkill                   = 130
	lxTgkill                  = 131
	lxRtSigqueueinfo          = 138
	lxRtTgsigqueueinfo        = 240
	lxPidfdSendSignal         = 424
	lxSigDie                  = 0x4c430010 // stub: a fatal default action, args[0] = signal (after mem_darwin.go's 0x4c4300xx)
	lxSigStop                 = 0x4c430011 // stub: a stop default action
	lxSigTake                 = 0x4c430012 // stub: take a pending signal in args[0] (args[1] = 1: for a wait, no action); info and action to the scratch
	lxSigSettle               = 0x4c430013 // stub: act on the pending signals in args[0] that need no handler; 1 if one the stub must take is pending
	lxSigFault                = 0x4c430014 // stub: the action for synchronous signal args[0] (args[1] = 1: blocked; args[2] si_addr, args[3] si_code, args[4] the pc, for the trace); to the scratch
	lxSigRaise                = 0x4c430015 // stub: make args[0] pending for this thread, si_code args[1]
	lxExecStop                = 0x4c430018 // stub (darwin respawn): run the ptrace exec-event stop, args = new entry, sp
	lxStepStop                = 0x4c430019 // stub (HVF): one instruction single-stepped, run the SIGTRAP step stop
	restartSys                = -512       // ERESTARTSYS: interrupted; the stub resolves it
	sigIgn                    = 1
	saNoCldStop               = 1
	saNoCldWait               = 2
	saResethand               = 0x80000000
	saKnown                   = 0x1 | 0x2 | 0x4 | 0x800 | 0x04000000 | 0x08000000 | 0x10000000 | 0x40000000 | saResethand // the flags Linux keeps
	siUser                    = 0
	siKernel                  = 0x80
	siQueue                   = -1
	siTimer                   = -2
	siTkill                   = -6
	sigHUP, sigINT            = 1, 2
	sigQUIT                   = 3
	sigKILL                   = 9
	sigALRM                   = 14
	sigTERM                   = 15
	sigCHLD                   = 17
	sigCONT                   = 18
	sigSTOP                   = 19
	sigTSTP                   = 20
	sigTTIN                   = 21
	sigTTOU                   = 22
	sigURG                    = 23
	sigVTALRM, sigPROF        = 26, 27
	sigWINCH                  = 28
	killStopMask       uint64 = 1<<(sigKILL-1) | 1<<(sigSTOP-1)
	stopMask           uint64 = 1<<(sigSTOP-1) | 1<<(sigTSTP-1) | 1<<(sigTTIN-1) | 1<<(sigTTOU-1)
	syncMask           uint64 = 1<<(4-1) | 1<<(5-1) | 1<<(7-1) | 1<<(8-1) | 1<<(11-1) | 1<<(31-1) // ILL TRAP BUS FPE SEGV SYS
)

// Signal area layout; stub/macos/sig.zig asserts the same offsets.
const (
	sigStride  = 0x4000
	sigAreaLen = sigStride * maxSlots
	sigProcOff = 0x1000
	// sigRunOff, in slot 0's stride past its records, holds what every stub
	// reads of the run as a whole: how many processes it has (a process
	// alone shares memory with none: stub/macos/wx.zig).
	sigRunOff = 0x2000
	// sigRunMemCap is Config.MaxBytes, which the macOS stubs enforce
	// together: each publishes what its process has mapped at spMem, and
	// keeps sigRunMemUsed, the sum of those, by adding what it changed.
	sigRunMemCap  = sigRunOff + 8
	sigRunMemUsed = sigRunOff + 16

	stProc    = 4
	stMask    = 8
	stPending = 16
	stWaitset = 24
	stSsSp    = 32
	stSsSize  = 40
	stSsFlags = 48
	stTid     = 52
	stTgid    = 56
	stSaved   = 60
	stSavedMk = 64
	// stBusy and stInHandler mirror the stub's per-thread flags (windows only,
	// stub/windows/sig.zig): whether a thread is in stub code or in a signal
	// handler, so the supervisor can decide whether to redirect it.
	stBusy      = 72
	stInHandler = 76
	// stRseq and stRseqSig are the thread's registered rseq area and its
	// signature, which the stub reads to abort a critical section a signal
	// interrupts (darwin, windows: lx_rseq.go).
	stRseq    = 0x800
	stRseqSig = 0x808

	spPending = 8
	spMem     = 16

	rtq      = 32 // queued real-time signal instances per pending set
	sigRTMIN = 32
)

var errSigIntr = errors.New("interrupted by a signal")

var sigDbg = os.Getenv("LC_SIGDEBUG") == "1"

// sigInfo is the head of a Linux siginfo_t: a and b are its bytes 16..32.
type sigInfo struct {
	errno, code int32
	a, b        uint64
}

type sigAct struct{ handler, flags, restorer, mask uint64 }

// sigQueue is a pending set, a thread's or a process's. It lives here, out
// of the guest's reach; the area holds a copy of its bits (mirror), which only
// the supervisor writes and the stubs read to know when to ask for a signal.
type sigQueue struct {
	bits   uint64
	info   [64]sigInfo
	rt     []rtSig // real-time instances beyond the one in info, oldest first
	mirror int     // offset of the pending word in the area
	// trap asks the thread to take a ptrace trap (ptraceTrap): the mirror
	// shows it as a pending SIGSTOP, which no mask holds back, so the stub
	// comes to take a signal, while the queue itself stays as it was.
	trap bool
	// park asks the thread to wait in its process's job-control stop
	// (parkStopped), shown the same way: a stop its threads hold rather than
	// the host, since a tracer let one of them go on alone.
	park bool
}

// word is the pending word the stub sees.
func (q *sigQueue) word() uint64 {
	if q.trap || q.park {
		return q.bits | sigBit(sigSTOP)
	}
	return q.bits
}

type rtSig struct {
	sig int
	si  sigInfo
}

type sigRun struct {
	fs        *dfs
	area      []byte
	mainOspid int

	// bg counts the rekick loops and firing timers, which touch the area;
	// close waits for them before the area is unmapped.
	bg   sync.WaitGroup
	quit chan struct{}

	// sq guards every pending set and action table. It is taken last: no
	// other lock is taken while it is held.
	sq sync.Mutex

	// parkMu guards the parked threads' waits (parkStopped); it is taken
	// before sq.
	parkMu   sync.Mutex
	parkCond *sync.Cond

	mu      sync.Mutex
	closed  bool
	threads map[int]*sigThread // by tid
	procs   map[int]*sigProc   // by tgid
	files   map[*sigFile]struct{}
	changed chan struct{} // closed and replaced when a pending set may have grown
}

type sigThread struct {
	tid, tgid, slot int
	q               sigQueue                  // guarded by sigRun.sq
	readOn          atomic.Pointer[os.File]   // the file a blocking read is parked on
	writeOn         atomic.Pointer[os.File]   // the file a blocking write is parked on
	condOn          atomic.Pointer[sync.Cond] // the condition a blocking call waits on
	kickCh          chan struct{}             // a token per wake, for channel-based waits

	mu      sync.Mutex
	wr, ww  int  // Unix wake pipe; Windows wr is a wake event; -1 until used
	waits   int  // Unix: the waits holding the pipe (wakeFd)
	retired bool // Unix: closeWake ran; the last wait closes the pipe
}

type sigProc struct {
	tgid, slot, ppid int
	threads          []*sigThread
	killedBy         int
	stopped          bool
	stopSig          int        // the signal that stopped it, while stopped
	parked           bool       // its threads hold the stop (park), not the host; guarded by sigRun.sq
	job              sync.Mutex // orders stop and cont, their host signals included
	q                sigQueue   // guarded by sigRun.sq
	acts             [64]sigAct // guarded by sigRun.sq
	dead             bool
	timers           map[int]*ptimer
	nextTimer        int
	itimers          [3]*ptimer
}

func (fs *dfs) sigs() *sigRun { return fs.sr.Load() }

func newSigRun(fs *dfs, mem []byte, ospid int) *sigRun {
	sr := &sigRun{
		fs: fs, area: mem[slotsLen : slotsLen+sigAreaLen], mainOspid: ospid,
		threads: map[int]*sigThread{}, procs: map[int]*sigProc{}, files: map[*sigFile]struct{}{},
		quit: make(chan struct{}),
	}
	sr.parkCond = sync.NewCond(&sr.parkMu)
	t := newSigThread(1, 1, 0)
	sr.procs[1] = newSigProc(1, 0, 0, t)
	sr.threads[1] = t
	sr.countProcs()
	sr.initThread(0, 0, 1, 1, 0, [3]uint64{})
	fs.sr.Store(sr)
	return sr
}

// setMemCap publishes the run's memory cap in the channel memory mem.
func setMemCap(mem []byte, n uint64) {
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&mem[slotsLen+sigRunMemCap])), n)
}

// countProcs publishes how many processes the run has (sigRunOff). sr.mu
// is held, or the run is not yet shared.
func (sr *sigRun) countProcs() {
	atomic.StoreUint32(sr.p32(sigRunOff), uint32(len(sr.procs)))
}

// close stops every timer and rekick loop at the end of the run.
func (sr *sigRun) close() {
	sr.mu.Lock()
	sr.closed = true
	close(sr.quit)
	for _, p := range sr.procs {
		sr.reapLocked(p)
	}
	for _, t := range sr.threads {
		t.closeWake()
	}
	sr.mu.Unlock()
	sr.bg.Wait()
	sr.fs.sr.Store(nil)
}

// ---- the shared area --------------------------------------------------------------

func tOff(slot int) int { return slot * sigStride }
func pOff(slot int) int { return slot*sigStride + sigProcOff }

func (sr *sigRun) p32(off int) *uint32 { return (*uint32)(unsafe.Pointer(&sr.area[off])) }
func (sr *sigRun) p64(off int) *uint64 { return (*uint64)(unsafe.Pointer(&sr.area[off])) }
func (sr *sigRun) ld(off int) uint64   { return atomic.LoadUint64(sr.p64(off)) }
func (sr *sigRun) st(off int, v uint64) {
	atomic.StoreUint64(sr.p64(off), v)
}

// dropMem takes the process leading slot out of the memory the run has
// mapped. The swap pairs with the stubs' (setProcMem), so the run's sum stays
// the sum of the records whichever comes first.
func (sr *sigRun) dropMem(slot int) {
	old := atomic.SwapUint64(sr.p64(pOff(slot)+spMem), 0)
	atomic.AddUint64(sr.p64(sigRunMemUsed), -old)
}

func newSigThread(tid, tgid, slot int) *sigThread {
	return &sigThread{tid: tid, tgid: tgid, slot: slot, q: sigQueue{mirror: tOff(slot) + stPending}, wr: -1, ww: -1}
}

func newSigProc(tgid, slot, ppid int, leader *sigThread) *sigProc {
	return &sigProc{tgid: tgid, slot: slot, ppid: ppid, q: sigQueue{mirror: pOff(slot) + spPending}, threads: []*sigThread{leader}, timers: map[int]*ptimer{}}
}

func sigBit(sig int) uint64 { return 1 << (sig - 1) }

// initThread resets a slot's thread record for a new thread of the process
// whose leader is at procSlot. ss is the inherited sigaltstack (sp, size, flags).
func (sr *sigRun) initThread(slot, procSlot, tid, tgid int, mask uint64, ss [3]uint64) {
	o := tOff(slot)
	atomic.StoreUint32(sr.p32(o+stProc), uint32(procSlot))
	sr.st(o+stMask, mask&^killStopMask)
	sr.st(o+stPending, 0)
	atomic.StoreUint32(sr.p32(o+stSaved), 0)
	sr.st(o+stWaitset, 0)
	sr.st(o+stSsSp, ss[0])
	sr.st(o+stSsSize, ss[1])
	atomic.StoreUint32(sr.p32(o+stSsFlags), uint32(ss[2]))
	atomic.StoreUint32(sr.p32(o+stTid), uint32(tid))
	atomic.StoreUint32(sr.p32(o+stTgid), uint32(tgid))
	sr.st(o+stRseq, 0)
	atomic.StoreUint32(sr.p32(o+stRseqSig), 0)
}

func (sr *sigRun) act(p *sigProc, sig int) sigAct {
	sr.sq.Lock()
	defer sr.sq.Unlock()
	return p.acts[sig-1]
}

// Outcomes of queue and send.
const (
	sigDropped = iota // discarded, or a standard signal already pending
	sigQueued
	sigFull // a real-time instance found its queue full
)

// queue marks sig pending in q with its info. A standard signal already
// pending is not queued again; a real-time one queues behind it.
func (sr *sigRun) queue(q *sigQueue, sig int, si sigInfo) int {
	sr.sq.Lock()
	defer sr.sq.Unlock()
	b := sigBit(sig)
	if q.bits&b == 0 {
		q.info[sig-1] = si
		q.bits |= b
		sr.st(q.mirror, q.word())
		return sigQueued
	}
	if sig < sigRTMIN {
		return sigDropped
	}
	if len(q.rt) >= rtq {
		return sigFull
	}
	q.rt = append(q.rt, rtSig{sig, si})
	return sigQueued
}

func (sr *sigRun) isPending(p *sigProc, th *sigThread, sig int) bool {
	q := &p.q
	if th != nil {
		q = &th.q
	}
	sr.sq.Lock()
	defer sr.sq.Unlock()
	return q.bits&sigBit(sig) != 0
}

// pickLocked dequeues the lowest pending signal in allow from q, the
// synchronous ones first, as Linux does. The caller holds sr.sq.
func (sr *sigRun) pickLocked(q *sigQueue, allow uint64) (int, sigInfo) {
	m := q.bits & allow
	if m == 0 {
		return 0, sigInfo{}
	}
	if m&syncMask != 0 {
		m &= syncMask
	}
	sig := bits.TrailingZeros64(m) + 1
	si := q.info[sig-1]
	if sig >= sigRTMIN {
		for k, e := range q.rt {
			if e.sig == sig {
				q.info[sig-1] = e.si
				q.rt = slices.Delete(q.rt, k, k+1)
				return sig, si
			}
		}
	}
	q.bits &^= sigBit(sig)
	sr.st(q.mirror, q.word())
	return sig, si
}

// takeLocked dequeues a pending signal in allow for thread t of process p:
// its own first, then its process's. The caller holds sr.sq.
func (sr *sigRun) takeLocked(t *sigThread, p *sigProc, allow uint64) (int, sigInfo) {
	if s, si := sr.pickLocked(&t.q, allow); s != 0 {
		return s, si
	}
	return sr.pickLocked(&p.q, allow)
}

// dequeue takes a pending signal in allow for g: its own first, then its
// process's.
func (g *dguest) dequeue(allow uint64) (int, sigInfo) {
	sr := g.sigs()
	t, p := sr.thread(g.pid), sr.proc(g.tgid)
	if t == nil || p == nil {
		return 0, sigInfo{}
	}
	sr.sq.Lock()
	defer sr.sq.Unlock()
	return sr.takeLocked(t, p, allow)
}

// procSlot is the slot of g's process record, from the supervisor's own
// registry (the area's copy is guest-writable).
func (g *dguest) procSlot() int {
	if slot, ok := g.sigs().procSlot(g.tgid); ok {
		return slot
	}
	return g.slot
}

// clearPending discards the signals in mask pending for p or any of its
// threads, every queued instance of them.
func (sr *sigRun) clearPending(p *sigProc, mask uint64) {
	qs := []*sigQueue{&p.q}
	for _, t := range sr.threadsOf(p) {
		qs = append(qs, &t.q)
	}
	sr.sq.Lock()
	defer sr.sq.Unlock()
	for _, q := range qs {
		q.bits &^= mask
		q.rt = slices.DeleteFunc(q.rt, func(e rtSig) bool { return sigBit(e.sig)&mask != 0 })
		sr.st(q.mirror, q.word())
	}
}

func (sr *sigRun) accepts(t *sigThread, sig int) bool {
	o := tOff(t.slot)
	return (sr.ld(o+stMask)&^sr.ld(o+stWaitset))&sigBit(sig) == 0
}

// deliverable is the set of signals thread t would take now.
func (sr *sigRun) deliverable(t *sigThread, p *sigProc) uint64 {
	o := tOff(t.slot)
	pend := sr.ld(o+stPending) | sr.ld(pOff(p.slot)+spPending)
	return pend & (^sr.ld(o+stMask) | sr.ld(o+stWaitset)) &^ killStopMask
}

// status is /proc/<pid>/status's signal sets for thread tid of process tgid:
// thread pending, shared pending, blocked, ignored and caught.
func (sr *sigRun) status(tid, tgid int) [5]uint64 {
	var out [5]uint64
	if sr == nil {
		return out
	}
	sr.mu.Lock()
	p := sr.procs[tgid]
	var slot int
	if p != nil {
		slot = p.slot
	}
	sr.mu.Unlock()
	if p == nil {
		return out
	}
	out[1] = sr.ld(pOff(slot) + spPending)
	if t := sr.thread(tid); t != nil {
		o := tOff(t.slot)
		out[0] = sr.ld(o + stPending)
		out[2] = sr.ld(o+stMask) &^ killStopMask
	}
	sr.sq.Lock()
	acts := p.acts
	sr.sq.Unlock()
	for sig := 1; sig <= 64; sig++ {
		switch h := acts[sig-1].handler; {
		case h == sigIgn:
			out[3] |= sigBit(sig)
		case h > sigIgn:
			out[4] |= sigBit(sig)
		}
	}
	return out
}

// ---- registry ---------------------------------------------------------------------

func (sr *sigRun) threadsOf(p *sigProc) []*sigThread {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return append([]*sigThread(nil), p.threads...)
}

func (sr *sigRun) proc(tgid int) *sigProc {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.procs[tgid]
}

// procSlot is the slot of process tgid's record, read under the lock an exec's
// takeover moves it under (sigTakeOver).
func (sr *sigRun) procSlot(tgid int) (int, bool) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if p := sr.procs[tgid]; p != nil {
		return p.slot, true
	}
	return 0, false
}

func (sr *sigRun) thread(tid int) *sigThread {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.threads[tid]
}

func (sr *sigRun) ospid(p *sigProc) int {
	if p.tgid == 1 {
		return sr.mainOspid
	}
	sr.fs.mu.Lock()
	defer sr.fs.mu.Unlock()
	if dp := sr.fs.procs[p.tgid]; dp != nil {
		return dp.ospid
	}
	return 0
}

// sigFork gives a forked child its signal state: the parent's handlers, the
// forking thread's mask and sigaltstack, nothing pending.
func (g *dguest) sigFork(child *dguest) {
	sr := g.sigs()
	pp := sr.proc(g.tgid)
	if pp == nil {
		return
	}
	sr.st(pOff(child.slot)+spPending, 0)
	sr.dropMem(child.slot)
	o := tOff(g.slot)
	ss := [3]uint64{sr.ld(o + stSsSp), sr.ld(o + stSsSize), uint64(atomic.LoadUint32(sr.p32(o + stSsFlags)))}
	sr.initThread(child.slot, child.slot, child.pid, child.pid, sr.ld(o+stMask), ss)
	t := newSigThread(child.pid, child.pid, child.slot)
	cp := newSigProc(child.pid, child.slot, g.tgid, t)
	sr.sq.Lock()
	cp.acts = pp.acts
	sr.sq.Unlock()
	sr.mu.Lock()
	sr.procs[child.pid] = cp
	sr.threads[child.pid] = t
	sr.countProcs()
	sr.mu.Unlock()
	sr.sigFileFork(child)
}

// clearAltstack disables a child's sigaltstack. A CLONE_VM child does not
// inherit the creator's alternate stack: it lives in the now-shared address
// space and belongs to the creator thread, so Linux leaves the child with
// none. Only a fork (or a clone without CLONE_VM) inherits it.
func (g *dguest) clearAltstack(child *dguest) {
	sr := g.sigs()
	o := tOff(child.slot)
	sr.st(o+stSsSp, 0)
	sr.st(o+stSsSize, 0)
	atomic.StoreUint32(sr.p32(o+stSsFlags), 0)
}

// sigClone registers a new thread: the creator's mask, no altstack, nothing
// pending, the creator's process.
func (g *dguest) sigClone(child *dguest) {
	sr := g.sigs()
	p := sr.proc(g.tgid)
	if p == nil {
		return
	}
	sr.initThread(child.slot, p.slot, child.pid, g.tgid, sr.ld(tOff(g.slot)+stMask), [3]uint64{})
	t := newSigThread(child.pid, g.tgid, child.slot)
	sr.mu.Lock()
	p.threads = append(p.threads, t)
	sr.threads[t.tid] = t
	sr.mu.Unlock()
}

// sigExec resets caught signals to the default and clears every action's flags,
// mask and restorer (ignored stay ignored; the mask and pending signals
// survive), drops the altstack and the POSIX timers.
func (g *dguest) sigExec() {
	sr := g.sigs()
	p := sr.proc(g.tgid)
	if p == nil {
		return
	}
	sr.sq.Lock()
	for i := range p.acts {
		h := p.acts[i].handler
		if h != sigIgn {
			h = 0
		}
		p.acts[i] = sigAct{handler: h}
	}
	sr.sq.Unlock()
	o := tOff(g.slot)
	sr.st(o+stSsSp, 0)
	sr.st(o+stSsSize, 0)
	atomic.StoreUint32(sr.p32(o+stSsFlags), 0)
	sr.mu.Lock()
	for id, pt := range p.timers {
		pt.disarm()
		delete(p.timers, id)
	}
	sr.mu.Unlock()
}

// sigTakeOver follows takeOverGroup in the signal registry: thread tid execs,
// the process's other threads are gone, and it goes on as the leader, its tid
// the process's. Its pending set goes with it.
func (fs *dfs) sigTakeOver(tid, tgid int) {
	sr := fs.sigs()
	sr.mu.Lock()
	defer sr.mu.Unlock()
	me, p := sr.threads[tid], sr.procs[tgid]
	if me == nil || p == nil {
		return
	}
	for _, t := range p.threads {
		delete(sr.threads, t.tid)
		t.closeWake()
	}
	nt := newSigThread(tgid, tgid, me.slot)
	sr.sq.Lock()
	nt.q.bits, nt.q.info, nt.q.rt = me.q.bits, me.q.info, me.q.rt
	if p.slot != me.slot {
		// The process's record moves into the survivor's slot: the old
		// leader's slot is freed once its serve loop ends.
		from, to := pOff(p.slot), pOff(me.slot)
		sr.st(to+spMem, sr.ld(from+spMem))
		sr.st(from+spPending, 0)
		sr.st(from+spMem, 0)
		p.slot, p.q.mirror = me.slot, to+spPending
		sr.st(p.q.mirror, p.q.word())
	}
	sr.sq.Unlock()
	o := tOff(me.slot)
	atomic.StoreUint32(sr.p32(o+stProc), uint32(me.slot))
	atomic.StoreUint32(sr.p32(o+stTid), uint32(tgid))
	atomic.StoreUint32(sr.p32(o+stTgid), uint32(tgid))
	p.threads = []*sigThread{nt}
	sr.threads[tgid] = nt
}

// sigThreadExit drops an exited thread.
func (fs *dfs) sigThreadExit(tid int) {
	sr := fs.sigs()
	sr.mu.Lock()
	defer sr.mu.Unlock()
	t := sr.threads[tid]
	if t == nil {
		return
	}
	delete(sr.threads, tid)
	if p := sr.procs[t.tgid]; p != nil {
		for i, x := range p.threads {
			if x == t {
				p.threads = append(p.threads[:i], p.threads[i+1:]...)
				break
			}
		}
	}
	t.closeWake()
}

func (sr *sigRun) reapLocked(p *sigProc) {
	p.dead = true
	for _, pt := range p.timers {
		pt.disarm()
	}
	for _, pt := range p.itimers {
		if pt != nil {
			pt.disarm()
		}
	}
}

func (sr *sigRun) killedBy(tgid int) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if p := sr.procs[tgid]; p != nil {
		return p.killedBy
	}
	return 0
}

// sigDie handles the stub's report that sig's default action ends the process.
func (g *dguest) sigDie(sig int) int {
	g.ptraceEvent(ptraceEventExit, uint64(sig))
	sr := g.sigs()
	sr.mu.Lock()
	if p := sr.procs[g.tgid]; p != nil && p.killedBy == 0 {
		p.killedBy = sig
	}
	sr.mu.Unlock()
	return -sig
}

func (g *dguest) sigStopSelf(sig int) {
	if g.traceGroupStop(sig) {
		return
	}
	sr := g.sigs()
	g.dfs.mu.Lock()
	pgid := g.ps.pgid
	g.dfs.mu.Unlock()
	if sig != sigSTOP && g.dfs.pgrpOrphaned(pgid) {
		return // a terminal stop no one could continue is discarded, as on Linux
	}
	if p := sr.proc(g.tgid); p != nil {
		sr.stop(p, sig)
	}
}

// settle acts on the pending signals in allow whose action needs no handler
// and no end of the process (ignore, stop), as the kernel does inside an
// interrupted sleep, which then goes on. True if one the stub must take is
// pending (a handler, or a default that ends the process): that ends the wait.
func (g *dguest) settle(allow uint64) bool {
	sr := g.sigs()
	t, p := sr.thread(g.pid), sr.proc(g.tgid)
	if t == nil || p == nil {
		return true
	}
	allow &^= sigBit(sigKILL)
	if !g.dfs.isTraced(g.pid) {
		allow &^= sigBit(sigSTOP)
	}
	for {
		sr.sq.Lock()
		if t.q.trap || t.q.park {
			sr.sq.Unlock()
			return true
		}
		pend := (t.q.bits | p.q.bits) & allow
		for m := pend; m != 0; m &= m - 1 {
			if sig := bits.TrailingZeros64(m) + 1; g.traced.Load() || stubTakes(p.acts[sig-1], sig) {
				sr.sq.Unlock()
				return true
			}
		}
		sig, _ := sr.takeLocked(t, p, pend)
		var a sigAct
		if sig != 0 {
			a = p.acts[sig-1]
		}
		sr.sq.Unlock()
		if sig == 0 {
			return false
		}
		if a.handler == 0 && sigBit(sig)&stopMask != 0 {
			g.sigStopSelf(sig)
		}
	}
}

// stubTakes reports whether sig with action a is the stub's to take: a
// handler, or a default that ends the process.
func stubTakes(a sigAct, sig int) bool {
	return a.handler > sigIgn || a.handler == 0 && sigBit(sig)&stopMask == 0 && !ignoredByDefault(sig)
}

// ---- routing ----------------------------------------------------------------------

func (sr *sigRun) leader(p *sigProc) *sigThread {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if len(p.threads) == 0 {
		return nil
	}
	return p.threads[0]
}

func ignoredByDefault(sig int) bool {
	return sig == sigCHLD || sig == sigURG || sig == sigWINCH || sig == sigCONT
}

// ignored reports whether sig would be discarded on generation: ignored and
// not blocked by the thread it is aimed at.
func (sr *sigRun) ignored(p *sigProc, t *sigThread, sig int) bool {
	if sr.ld(tOff(t.slot)+stMask)&sigBit(sig) != 0 {
		return false
	}
	a := sr.act(p, sig)
	return a.handler == sigIgn || (a.handler == 0 && ignoredByDefault(sig))
}

// target picks the thread to wake for a process-directed sig: the first
// thread (leader first) that takes it, as Linux does. nil if every thread
// blocks it.
func (sr *sigRun) target(p *sigProc, sig int) *sigThread {
	for _, t := range sr.threadsOf(p) {
		if sr.accepts(t, sig) {
			return t
		}
	}
	return nil
}

// send generates sig for process p, or for its thread th when th != nil. from
// is the sending guest thread (nil for the supervisor). It reports whether the
// signal was queued, dropped, or found the real-time queue full.
func (sr *sigRun) send(p *sigProc, th *sigThread, sig int, si sigInfo, from *dguest) int {
	switch sig {
	case sigKILL:
		sr.kill(p, sigKILL)
		return sigQueued
	case sigSTOP:
		// A traced thread takes it as a signal (its signal-delivery stop
		// comes first), whichever thread of its process is traced.
		if !sr.fs.isTraced(p.tgid) && (th == nil || !sr.fs.isTraced(th.tid)) {
			sr.stop(p, sigSTOP)
			return sigQueued
		}
	case sigCONT:
		sr.cont(p)
	}
	if sig == sigTSTP || sig == sigTTIN || sig == sigTTOU {
		sr.clearPending(p, sigBit(sigCONT))
	}
	aim := th
	if aim == nil {
		aim = sr.leader(p)
	}
	if aim == nil || !sr.fs.isTraced(aim.tid) && sr.ignored(p, aim, sig) {
		return sigDropped
	}
	t := th
	if t == nil {
		t = sr.target(p, sig)
	} else if !sr.accepts(t, sig) {
		t = nil
	}
	var res int
	switch {
	case th != nil:
		res = sr.queue(&th.q, sig, si)
	case t != nil && from != nil && from.tgid == p.tgid && from.pid != t.tid:
		// A sibling's kill: the sender would take a process-wide signal on
		// its way out, where Linux has the target take it.
		res = sr.queue(&t.q, sig, si)
	default:
		res = sr.queue(&p.q, sig, si)
	}
	sr.refreshFiles()
	if res != sigQueued {
		return res
	}
	// Whom to wake is decided now that the signal is pending: a thread
	// unblocking it stores its mask and then looks for pending signals, so
	// one of the two sees the other (both sides' accesses are sequentially
	// consistent).
	t = th
	if t == nil {
		t = sr.target(p, sig)
	} else if !sr.accepts(t, sig) {
		t = nil
	}
	if sigDbg {
		println("[send] sig", sig, "targetnil", t == nil, "fromnil", from == nil)
	}
	if t == nil || (from != nil && from.pid == t.tid) {
		return sigQueued // blocked (taken once unblocked), or the sender takes it on its way out
	}
	sr.wake(t)
	sr.kick(p)
	return sigQueued
}

// wake interrupts t if it is blocked in a supervisor-served call.
func (sr *sigRun) wake(t *sigThread) {
	if f := t.readOn.Load(); f != nil {
		f.SetReadDeadline(time.Unix(1, 0))
	}
	if f := t.writeOn.Load(); f != nil {
		f.SetWriteDeadline(time.Unix(1, 0))
	}
	if c := t.condOn.Load(); c != nil {
		c.L.Lock()
		c.Broadcast()
		c.L.Unlock()
	}
	select {
	case t.kick() <- struct{}{}:
	default:
	}
	sr.wakeThread(t)
	sr.fs.mu.Lock()
	sr.fs.cond.Broadcast()
	sr.fs.mu.Unlock()
}

// kick has the stub process route its pending signals to its threads. A kick
// that lands while a thread is busy in the stub is kept and taken on the way
// out (the stub never loses one), so it is sent once.
func (sr *sigRun) kick(p *sigProc) {
	if pid := sr.ospid(p); pid > 0 {
		osKick(pid)
	}
}

func (sr *sigRun) kill(p *sigProc, sig int) {
	sr.mu.Lock()
	if p.killedBy == 0 {
		p.killedBy = sig
	}
	sr.mu.Unlock()
	if sr.fs.sharedStub(p.tgid) || sr.fs.processTraced(p.tgid) {
		// A CLONE_VM child runs in its parent's stub, which must live on:
		// its thread takes SIGKILL like a pending signal and ends itself.
		// Traced processes also take it here, so TRACEEXIT precedes death.
		sr.queue(&p.q, sig, sigInfo{code: siKernel})
		sr.hostCont(p) // a stopped one must run to end itself
		for _, t := range sr.threadsOf(p) {
			sr.wake(t)
		}
		sr.kick(p)
		return
	}
	if pid := sr.ospid(p); pid > 0 {
		osKill(pid)
	}
}

// stop stops p on the host before a waiter can see it stopped: a SIGCONT sent
// in between would otherwise come first and leave p stopped for good.
func (sr *sigRun) stop(p *sigProc, sig int) {
	p.job.Lock()
	defer p.job.Unlock()
	sr.mu.Lock()
	was := p.stopped
	p.stopped = true
	if !was {
		p.stopSig = sig
	}
	sr.mu.Unlock()
	if was {
		return
	}
	sr.clearPending(p, sigBit(sigCONT))
	sr.hostStop(p)
	sr.fs.setStopped(p.tgid, sig)
	sr.notifyParent(p, cldStopped, sig)
}

// cont resumes a stopped process and discards its pending stop signals.
func (sr *sigRun) cont(p *sigProc) {
	p.job.Lock()
	defer p.job.Unlock()
	sr.mu.Lock()
	was := p.stopped
	p.stopped = false
	sr.mu.Unlock()
	if was {
		sr.fs.setContinued(p.tgid)
		sr.hostCont(p)
	}
	sr.clearPending(p, stopMask)
	if was {
		sr.notifyParent(p, cldContinued, sigCONT)
	}
	for _, tid := range sr.fs.ptraceContinued(p.tgid) {
		if t := sr.thread(tid); t != nil {
			sr.setTrap(t)
		}
	}
}

// jobStop reports whether process tgid is stopped by job control, and the
// signal that stopped it.
func (sr *sigRun) jobStop(tgid int) (int, bool) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if p := sr.procs[tgid]; p != nil && p.stopped {
		return p.stopSig, true
	}
	return 0, false
}

// setTrap asks thread t to take a ptrace trap where it next looks for
// signals, and wakes it there.
func (sr *sigRun) setTrap(t *sigThread) {
	sr.sq.Lock()
	t.q.trap = true
	sr.st(t.q.mirror, t.q.word())
	sr.sq.Unlock()
	sr.wake(t)
	if p := sr.proc(t.tgid); p != nil {
		sr.kick(p)
	}
}

// parkStopped holds thread t while it is asked to park, as Linux's
// do_signal_stop: until a SIGCONT, a tracer's release, or a SIGKILL. False if
// it was not asked.
func (sr *sigRun) parkStopped(g *dguest, t *sigThread) bool {
	parked := func() bool {
		sr.sq.Lock()
		defer sr.sq.Unlock()
		return t.q.park
	}
	sr.parkMu.Lock()
	defer sr.parkMu.Unlock()
	if !parked() {
		return false
	}
	sr.parkCond.Broadcast() // a stop waits for its threads to park (parkStop)
	for parked() {
		if !g.condWaitIntrMask(sr.parkCond, sigBit(sigKILL)) {
			break
		}
	}
	return true
}

// setPark asks threads ts of p to park or lets them go, records whether p's
// stop is held by its threads (parked) rather than the host, and wakes the
// parked ones to look.
func (sr *sigRun) setPark(p *sigProc, ts []*sigThread, park, parked bool) {
	sr.parkMu.Lock()
	sr.sq.Lock()
	for _, t := range ts {
		t.q.park = park
		sr.st(t.q.mirror, t.q.word())
	}
	p.parked = parked
	sr.sq.Unlock()
	sr.parkCond.Broadcast()
	sr.parkMu.Unlock()
}

// isParked reports whether p's stop is held by its threads.
func (sr *sigRun) isParked(p *sigProc) bool {
	sr.sq.Lock()
	defer sr.sq.Unlock()
	return p.parked
}

// takeTrap clears thread t's trap request, reporting whether there was one.
func (sr *sigRun) takeTrap(t *sigThread) bool {
	sr.sq.Lock()
	defer sr.sq.Unlock()
	if !t.q.trap {
		return false
	}
	t.q.trap = false
	sr.st(t.q.mirror, t.q.word())
	return true
}

func (sr *sigRun) notifyParent(p *sigProc, code int32, status int) {
	sr.fs.mu.Lock()
	sr.fs.cond.Broadcast() // a wait4 for WUNTRACED/WCONTINUED
	sr.fs.mu.Unlock()
	parent := sr.proc(p.ppid)
	if parent == nil || sr.act(parent, sigCHLD).flags&saNoCldStop != 0 {
		return
	}
	sr.send(parent, nil, sigCHLD, sigInfo{code: code, a: uint64(uint32(p.tgid)), b: uint64(uint32(status))}, nil)
}

// ---- interruptible waits ------------------------------------------------------

// sigIntr reports whether a signal is waiting for this guest thread, which
// ends a blocking supervisor-served call (EINTR, or a restart).
func (g *dguest) sigIntr() bool {
	sr := g.sigs()
	o := tOff(g.slot)
	return (sr.ld(o+stPending)|sr.ld(pOff(g.procSlot())+spPending))&^sr.ld(o+stMask) != 0
}

func (t *sigThread) kick() chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.kickCh == nil {
		t.kickCh = make(chan struct{}, 1)
	}
	return t.kickCh
}

// sleepIntr waits up to d, or until a signal is sent to this thread.
func (g *dguest) sleepIntr(d time.Duration) {
	t := g.sigs().thread(g.pid)
	if t == nil {
		time.Sleep(d)
		return
	}
	select {
	case <-t.kick():
	case <-time.After(d):
	}
}

// condWaitIntr is c.Wait (c.L held) that a signal for this thread also ends;
// false if one is pending.
func (g *dguest) condWaitIntr(c *sync.Cond) bool {
	return g.condWaitIntrMask(c, ^uint64(0))
}

func (g *dguest) condWaitIntrMask(c *sync.Cond, allow uint64) bool {
	intr := func() bool {
		sr := g.sigs()
		o := tOff(g.slot)
		return (sr.ld(o+stPending)|sr.ld(pOff(g.procSlot())+spPending))&^sr.ld(o+stMask)&allow != 0
	}
	t := g.sigs().thread(g.pid)
	if t == nil {
		c.Wait()
		return true
	}
	t.condOn.Store(c)
	defer t.condOn.Store(nil)
	if intr() || g.ch.dead() {
		return false
	}
	c.Wait()
	return !intr() && !g.ch.dead()
}

// writeIntr is a blocking write that a signal can interrupt, as readIntr is
// for reads: it returns what it wrote before the signal, or errSigIntr if
// nothing.
func (g *dguest) writeIntr(f *os.File, buf []byte) (int, error) {
	t := g.sigs().thread(g.pid)
	if t == nil {
		return f.Write(buf)
	}
	done := 0
	for {
		t.writeOn.Store(f)
		if g.sigIntr() {
			t.writeOn.Store(nil)
			if done > 0 {
				return done, nil
			}
			return 0, errSigIntr
		}
		n, err := g.hostInterruptibleWrite(f, buf[done:])
		t.writeOn.Store(nil)
		done += n
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return done, err
		}
		if g.ch.dead() {
			return done, errSigIntr
		}
		f.SetWriteDeadline(time.Time{})
	}
}

// parkIO registers f as the file this thread's socket call is about to block
// on, so a signal cuts the wait short; the returned func unregisters it.
func (g *dguest) parkIO(f *os.File, write bool) func() {
	t := g.sigs().thread(g.pid)
	if t == nil {
		return func() {}
	}
	on := &t.readOn
	if write {
		on = &t.writeOn
	}
	on.Store(f)
	return func() { on.Store(nil) }
}

// sigSwapMask runs the rest of the current syscall under a temporary signal
// mask, as pselect, ppoll and epoll_pwait do. The stub restores the real mask
// on the way out, after delivering, under the temporary one, the signals that
// interrupted the call. maskAddr is the guest's sigset_t, size its size.
func (g *dguest) sigSwapMask(maskAddr, size uint64) lxErrno {
	if size != 8 {
		return lxEINVAL
	}
	b, err := g.argRead(maskAddr, 8)
	if err != nil {
		return lxEFAULT
	}
	sr := g.sigs()
	o := tOff(g.slot)
	sr.st(o+stSavedMk, sr.ld(o+stMask))
	atomic.StoreUint32(sr.p32(o+stSaved), 1)
	sr.st(o+stMask, le64(b)&^killStopMask)
	return 0
}

// epollPwait is epoll_pwait: epoll_wait under the given signal mask.
func (g *dguest) epollPwait(a [6]uint64) int64 {
	if a[4] != 0 {
		if e := g.sigSwapMask(a[4], a[5]); e != 0 {
			return sErr(e)
		}
	}
	return g.epollWait(int64(a[0]), a[1], int64(int32(a[2])), int64(int32(a[3])))
}

// readIntr is a blocking read that a signal can interrupt. It parks in the
// netpoller like any read; wake cuts it short by putting the file's read
// deadline in the past. Other readers of the same file see that deadline too
// and simply read again.
func (g *dguest) readIntr(f *os.File, buf []byte, k readKind) (int, error) {
	t := g.sigs().thread(g.pid)
	if t == nil {
		return f.Read(buf)
	}
	for {
		t.readOn.Store(f)
		if g.sigIntr() {
			t.readOn.Store(nil)
			return 0, errSigIntr
		}
		n, err := g.hostInterruptibleRead(f, buf, k)
		t.readOn.Store(nil)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return n, err
		}
		if g.ch.dead() {
			return 0, errSigIntr // the process is gone (a SIGKILL queues no signal)
		}
		f.SetReadDeadline(time.Time{})
	}
}

// ---- sigaction and the stubs' calls -----------------------------------------------

func init() {
	syscalls[lxRtSigaction] = func(g *dguest, a [6]uint64) int64 { return g.rtSigaction(int(a[0]), a[1], a[2], a[3]) }
}

func (g *dguest) rtSigaction(sig int, actAddr, oldAddr, size uint64) int64 {
	if size != 8 {
		return sErr(lxEINVAL)
	}
	if sig < 1 || sig > 64 || actAddr != 0 && (sig == sigKILL || sig == sigSTOP) {
		return sErr(lxEINVAL)
	}
	sr := g.sigs()
	p := sr.proc(g.tgid)
	if p == nil {
		return sErr(lxEINVAL)
	}
	var nw *sigAct
	if actAddr != 0 {
		b, err := g.argRead(actAddr, 32)
		if err != nil {
			return sErr(lxEFAULT)
		}
		nw = &sigAct{le64(b), le64(b[8:]) & saKnown, le64(b[16:]), le64(b[24:]) &^ killStopMask}
	}
	sr.sq.Lock()
	old := p.acts[sig-1]
	if nw != nil {
		p.acts[sig-1] = *nw
	}
	sr.sq.Unlock()
	if nw != nil && (nw.handler == sigIgn || nw.handler == 0 && ignoredByDefault(sig)) {
		// An action that ignores the signal discards it pending, as on Linux.
		sr.clearPending(p, sigBit(sig))
	}
	if oldAddr != 0 {
		var b [32]byte
		put64(b[:], old.handler)
		put64(b[8:], old.flags)
		put64(b[16:], old.restorer)
		put64(b[24:], old.mask)
		if err := g.writeMem(oldAddr, b[:]); err != nil {
			return sErr(lxEFAULT)
		}
	}
	return 0
}

// sigCall serves the stubs' calls on the pending sets and actions, which only
// the supervisor touches: lxSigTake, lxSigSettle, lxSigFault, lxSigRaise. A
// signal taken, and an action, go to the slot's scratch: the 32-byte head of
// a siginfo_t, then the action (handler, flags, restorer, mask).
func (g *dguest) sigCall(nr uint64, a [6]uint64) int64 {
	sr := g.sigs()
	t, p := sr.thread(g.pid), sr.proc(g.tgid)
	if t == nil || p == nil {
		return 0
	}
	switch nr {
	case lxSigTake:
		var sig int
		var si sigInfo
		for {
			// A ptrace trap comes before each signal, as Linux's get_signal
			// runs a pending jobctl trap before it dequeues one.
			if a[1] == 0 && sr.takeTrap(t) {
				g.ptraceTrap()
				continue
			}
			if a[1] == 0 && sr.parkStopped(g, t) {
				continue
			}
			sr.sq.Lock()
			sig, si = sr.takeLocked(t, p, a[0])
			sr.sq.Unlock()
			if sig == 0 || a[1] != 0 {
				break
			}
			sig, si = g.traceSignal(sig, si)
			if sig != 0 {
				break
			}
		}
		var act sigAct
		sr.sq.Lock()
		if sig != 0 && a[1] == 0 {
			act = p.acts[sig-1]
			if act.handler > sigIgn && act.flags&saResethand != 0 {
				p.acts[sig-1].handler = 0
			}
		}
		sr.sq.Unlock()
		if act.handler > sigIgn {
			g.restart = nil // the interrupted call fails with EINTR, and its handler's return forgets it, as Linux's sigreturn does
		}
		sr.refreshFiles()
		if sig != 0 {
			g.putSigReply(sig, si, act)
		}
		return int64(sig)
	case lxSigSettle:
		if g.settle(a[0]) {
			return 1
		}
		return 0
	case lxSigFault:
		sig := int(a[0])
		if sig < 1 || sig > 64 {
			return 0
		}
		if g.cfg.Trace != nil {
			fmt.Fprintf(g.cfg.Trace, "[pid %d] fault sig=%d addr=%#x code=%d pc=%#x\n", g.pid, sig, a[2], int32(a[3]), a[4])
		}
		sig, _ = g.traceSignal(sig, sigInfo{code: int32(a[3]), a: a[2]})
		if sig == 0 {
			return 0
		}
		// A synchronous signal blocked or ignored is reset to the default,
		// which ends the process, as Linux's force_sig does.
		sr.sq.Lock()
		act := p.acts[sig-1]
		if a[1] != 0 || act.handler == sigIgn {
			act.handler = 0
			p.acts[sig-1].handler = 0
		} else if act.handler > sigIgn && act.flags&saResethand != 0 {
			p.acts[sig-1].handler = 0
		}
		sr.sq.Unlock()
		g.putSigReply(0, sigInfo{}, act)
		return int64(sig)
	case lxSigRaise:
		sig := int(a[0])
		if sig < 1 || sig > 64 {
			return 0
		}
		sr.queue(&t.q, sig, sigInfo{code: int32(a[1]), a: uint64(uint32(g.tgid))})
		sr.refreshFiles()
		return 0
	}
	return 0
}

func (g *dguest) putSigReply(sig int, si sigInfo, act sigAct) {
	b := g.scratch()[:64]
	put32(b, uint32(sig))
	put32(b[4:], uint32(si.errno))
	put32(b[8:], uint32(si.code))
	put32(b[12:], 0)
	put64(b[16:], si.a)
	put64(b[24:], si.b)
	put64(b[32:], act.handler)
	put64(b[40:], act.flags)
	put64(b[48:], act.restorer)
	put64(b[56:], act.mask)
}

// ---- kill and friends -------------------------------------------------------------

func init() {
	syscalls[lxKill] = sysKill
	syscalls[lxTkill] = func(g *dguest, a [6]uint64) int64 {
		tid := int(int32(a[0]))
		if tid <= 0 {
			return sErr(lxEINVAL)
		}
		gt, ok := g.nsToGlobal(tid)
		if !ok {
			return sErr(lxESRCH)
		}
		return g.sendThread(0, gt, int(int32(a[1])), sigInfo{code: siTkill, a: uint64(uint32(g.nsPid(g.tgid)))})
	}
	syscalls[lxTgkill] = func(g *dguest, a [6]uint64) int64 {
		tgid, tid := int(int32(a[0])), int(int32(a[1]))
		if tgid <= 0 || tid <= 0 {
			return sErr(lxEINVAL)
		}
		gg, ok := g.nsToGlobal(tgid)
		gt, ok2 := g.nsToGlobal(tid)
		if !ok || !ok2 {
			return sErr(lxESRCH)
		}
		return g.sendThread(gg, gt, int(int32(a[2])), sigInfo{code: siTkill, a: uint64(uint32(g.nsPid(g.tgid)))})
	}
	syscalls[lxRtSigqueueinfo] = func(g *dguest, a [6]uint64) int64 {
		tgid := int(int32(a[0]))
		gg, ok := g.nsToGlobal(tgid)
		if !ok {
			return sErr(lxESRCH)
		}
		si, e := g.queueInfo(gg, a[2])
		if e != 0 {
			return sErr(e)
		}
		return g.sendProc(gg, int(int32(a[1])), si)
	}
	syscalls[lxRtTgsigqueueinfo] = func(g *dguest, a [6]uint64) int64 {
		tgid, tid := int(int32(a[0])), int(int32(a[1]))
		if tgid <= 0 || tid <= 0 {
			return sErr(lxEINVAL)
		}
		gg, ok := g.nsToGlobal(tgid)
		gt, ok2 := g.nsToGlobal(tid)
		if !ok || !ok2 {
			return sErr(lxESRCH)
		}
		tgid, tid = gg, gt
		si, e := g.queueInfo(tgid, a[3])
		if e != 0 {
			return sErr(e)
		}
		return g.sendThread(tgid, tid, int(int32(a[2])), si)
	}
	syscalls[lxPidfdSendSignal] = sysPidfdSendSignal
}

func validSig(sig int) bool { return sig >= 0 && sig <= 64 }

// killTargets resolves kill's pid argument: a process, the caller's process
// group (0), every process but init and the caller (-1), or process group -pid.
func (sr *sigRun) killTargets(g *dguest, pid int) []*sigProc {
	var pids []int
	switch {
	case pid == 0:
		g.dfs.mu.Lock()
		pg := g.ps.pgid
		g.dfs.mu.Unlock()
		pids = g.dfs.pidsInPgrp(pg)
	case pid < -1:
		pids = g.dfs.pidsInPgrp(-pid)
	}
	sr.mu.Lock()
	defer sr.mu.Unlock()
	var out []*sigProc
	switch {
	case pid > 0:
		if p := sr.procs[pid]; p != nil {
			return []*sigProc{p}
		}
		if t := sr.threads[pid]; t != nil && sr.procs[t.tgid] != nil {
			return []*sigProc{sr.procs[t.tgid]}
		}
	case pid == -1:
		for _, p := range sr.procs {
			if p.tgid != 1 && p.tgid != g.tgid {
				out = append(out, p)
			}
		}
	default:
		for _, id := range pids {
			if p := sr.procs[id]; p != nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// killOK reports whether g may send sig to process tgid, per kill(2): privileged
// (CAP_KILL), or the sender's real or effective uid equals the target's real or
// saved uid, or SIGCONT within the same session. The caller holds dfs.mu.
func (g *dguest) killOK(tgid, sig int) bool {
	t := g.dfs.pt[tgid]
	if t == nil {
		return true // gone/zombie: let send resolve it, no creds to judge
	}
	c, tc := &g.ps.cred, &t.cred
	if c.capable(capKill) {
		return true
	}
	if is(c.euid, tc.ruid, tc.suid) || is(c.ruid, tc.ruid, tc.suid) {
		return true
	}
	return sig == sigCONT && t.sid != 0 && g.ps.sid == t.sid
}

// nsSees reports whether process tgid is visible in g's pid namespace. The
// caller holds dfs.mu.
func (g *dguest) nsSees(tgid int) bool {
	if g.ps.ns == nil || g.ps.ns.id == 0 {
		return true // the host namespace sees every process
	}
	return g.ps.ns.localOf(tgid) != 0
}

func sysKill(g *dguest, a [6]uint64) int64 {
	pid, sig := int(int32(a[0])), int(int32(a[1]))
	if !validSig(sig) {
		return sErr(lxEINVAL)
	}
	// A pid or pgid the caller names is in its pid namespace.
	if pid > 0 || pid < -1 {
		ns := pid
		if ns < 0 {
			ns = -ns
		}
		t, ok := g.nsToGlobal(ns)
		if !ok {
			return sErr(lxESRCH)
		}
		if pid < 0 {
			t = -t
		}
		pid = t
	}
	sr := g.sigs()
	ps := sr.killTargets(g, pid)
	if len(ps) == 0 {
		if pid > 0 && g.dfs.isZombie(pid) {
			return 0
		}
		return sErr(lxESRCH)
	}
	// kill(-1) must not reach processes outside the caller's pid namespace, and
	// every target is subject to the signal-sending credential check.
	g.dfs.mu.Lock()
	allow := ps[:0:0]
	denied := false
	for _, p := range ps {
		if pid == -1 && !g.nsSees(p.tgid) {
			continue
		}
		if !g.killOK(p.tgid, sig) {
			denied = true
			continue
		}
		allow = append(allow, p)
	}
	g.dfs.mu.Unlock()
	if len(allow) == 0 {
		if denied {
			return sErr(lxEPERM)
		}
		return sErr(lxESRCH)
	}
	if sig == 0 {
		return 0
	}
	for _, p := range allow {
		sr.send(p, nil, sig, sigInfo{code: siUser, a: uint64(uint32(g.tgid))}, g)
	}
	return 0
}

func (g *dguest) sendProc(tgid, sig int, si sigInfo) int64 {
	if !validSig(sig) {
		return sErr(lxEINVAL)
	}
	sr := g.sigs()
	p := sr.proc(tgid)
	if p == nil {
		if tgid > 0 && g.dfs.isZombie(tgid) {
			return 0
		}
		return sErr(lxESRCH)
	}
	if sig != 0 {
		return sendErr(sr.send(p, nil, sig, si, g), si)
	}
	return 0
}

// sendErr is EAGAIN for a sigqueue-style real-time signal whose queue is
// full; kill's (SI_USER) is dropped silently, as on Linux.
func sendErr(res int, si sigInfo) int64 {
	if res == sigFull && si.code != siUser {
		return sErr(lxEAGAIN)
	}
	return 0
}

// sendThread sends to thread tid, which must belong to tgid when tgid > 0.
func (g *dguest) sendThread(tgid, tid, sig int, si sigInfo) int64 {
	if !validSig(sig) {
		return sErr(lxEINVAL)
	}
	sr := g.sigs()
	t := sr.thread(tid)
	if t == nil || (tgid > 0 && t.tgid != tgid) {
		return sErr(lxESRCH)
	}
	p := sr.proc(t.tgid)
	if p == nil {
		return sErr(lxESRCH)
	}
	g.dfs.mu.Lock()
	ok := g.killOK(t.tgid, sig)
	g.dfs.mu.Unlock()
	if !ok {
		return sErr(lxEPERM)
	}
	if sig != 0 {
		return sendErr(sr.send(p, t, sig, si, g), si)
	}
	return 0
}

// queueInfo reads a sigqueue siginfo. Only the sender's own process may be
// sent a kernel-looking si_code (>= 0, or SI_TKILL), as on Linux.
func (g *dguest) queueInfo(tgid int, addr uint64) (sigInfo, lxErrno) {
	b, err := g.readMem(addr, 32)
	if err != nil {
		return sigInfo{}, lxEFAULT
	}
	si := sigInfo{errno: int32(le32(b[4:])), code: int32(le32(b[8:])), a: le64(b[16:]), b: le64(b[24:])}
	if (si.code >= 0 || si.code == siTkill) && tgid != g.tgid {
		return sigInfo{}, lxEPERM
	}
	return si, 0
}

// ---- host signals -----------------------------------------------------------------
