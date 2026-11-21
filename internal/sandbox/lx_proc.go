//go:build darwin || linux || windows

package sandbox

import (
	"errors"
	"os"
	"path"
	"sort"
	"sync/atomic"
	"time"
)

// The process model of the macOS backend: every guest process (thread group)
// has a pstate in dfs.pt, keyed by its tgid, from fork until its parent reaps
// it. It carries what Linux keeps per process -- parentage, process group and
// session, credentials, resource limits, scheduling knobs -- and, once the
// process has exited, its zombie status for wait4/waitid. Everything in it is
// guarded by dfs.mu, and dfs.cond is broadcast whenever a waiter might care
// (an exit, a stop or continue, a reparenting, teardown).

const (
	lxWaitid      = 95
	lxSetpgid     = 154
	lxGetpgid     = 155
	lxGetsid      = 156
	lxSetsid      = 157
	lxExecveat    = 281
	lxPidfdOpen   = 434
	lxClone3      = 435
	lxPidfdGetfd  = 438
	lxSigchld     = 17
	lxSigkill     = 9
	lxSigcont     = 18
	lxCloneThread = 0x10000
	lxCloneVfork  = 0x4000
)

// Linux wait option bits.
const (
	wNohang    = 0x1
	wUntraced  = 0x2 // WSTOPPED for waitid
	wExited    = 0x4
	wContinued = 0x8
	wNowait    = 0x01000000
	wNothread  = 0x20000000
	wAll       = 0x40000000
	wClone     = 0x80000000
)

type pstate struct {
	tgid, ppid int
	pgid, sid  int
	ospid      int  // the stub process's host pid, 0 until known
	checkedIn  bool // the first stub checked in; never cleared, unlike ospid across an exec
	start      time.Time
	exitSignal int // signal the parent gets on exit; not SIGCHLD makes a "clone" child
	execed     bool
	forked     bool // its stub came from a fork, not an exec of the stub binary
	shared     bool // a clone(CLONE_VM) child: a thread of its parent's stub, until it execs
	hvf        bool // darwin: this process runs in the HVF (VM) stub, not the native one

	threads int            // live threads, the leader included
	comm    map[int]string // per-thread name (PR_SET_NAME, /proc/<tid>/comm)
	ft      *ftable        // the leader's fd table (pidfd_getfd)

	leaderGone bool          // the leader exited first; the last thread ends the process
	leaderCode int           // its exit code, the process's status on Linux
	heldSlot   int           // the gone leader's slot, which holds the process's signal record: finishGroup frees it
	ended      chan struct{} // closed when a leader-gone process's last thread ends

	exiting  bool // exit_group (or the leader's exit) was called
	exitCode int
	killSig  int // host-side kill cause, reported as WIFSIGNALED
	zombie   bool
	status   int    // Linux wait status, valid once zombie
	mask     []byte // the leader's CPU affinity as last set or inherited, for a zombie (Linux)

	stopSig     int  // a stop not yet reported to a WUNTRACED waiter
	contPending bool // a continue not yet reported to a WCONTINUED waiter

	ru, cru rusage // own usage at exit; reaped descendants' usage
	ruPrev  rusage // usage of the stubs this process exec'd away from

	vforkDone chan struct{} // closed when a vfork child execs or exits
	pidfdR    *os.File      // exit notifier shared by this process's pidfds (each holds a dup)
	pidfdW    *os.File      // its write end, written and closed at exit

	cred  creds
	rlim  [rlimCount]rlimit
	sched schedState

	personality uint32
	dumpable    int
	noNewPrivs  bool
	subreaper   bool
	pdeathsig   int
	seccomp     atomic.Int32 // SECCOMP_MODE_*: the mode the guest set; read lock-free on each syscall
	seccompProg [][]byte     // installed seccomp-bpf filters, oldest first, each run on every syscall (under mu)
	ns          *pidns       // pid namespace this process belongs to
	childPidNs  *pidns       // set by unshare(CLONE_NEWPID): the namespace new children enter
	netns       atomic.Int32 // network namespace id; 0 is the host network, nonzero an isolated empty one
	uts         *utsState    // UTS namespace (node/domain names); shared until CLONE_NEWUTS
	mntns       int          // mount namespace id; 0 is the root, nonzero a CLONE_NEWNS one whose mounts drop when it empties
}

// newInitProc registers pid 1, the run's first process, and records its stub's
// host pid.
func (fs *dfs) newInitProc(ospid int, prog string, user *UserID) *pstate {
	ps := &pstate{
		tgid: 1, pgid: 1, sid: 1, ospid: ospid, start: time.Now(),
		exitSignal: lxSigchld, threads: 1, comm: map[int]string{1: commOf(prog)},
		cred: initCreds(user), rlim: defaultRlimits(), sched: defaultSched(), dumpable: 1,
		ns: fs.initNs, uts: &fs.uts,
	}
	fs.mu.Lock()
	fs.pt[1] = ps
	fs.mu.Unlock()
	return ps
}

// forkState builds a child's pstate from its parent's: Linux fork copies the
// credentials, limits, scheduling, personality and the dumpable / no_new_privs
// flags, and resets the rest.
func (p *pstate) forkState(tgid, ppid, exitSignal int) *pstate {
	ps := &pstate{
		tgid: tgid, ppid: ppid, pgid: p.pgid, sid: p.sid, forked: true, start: time.Now(),
		exitSignal: exitSignal, threads: 1, comm: map[int]string{},
		cred: p.cred.clone(), rlim: p.rlim, sched: p.sched.forked(), hvf: p.hvf,
		personality: p.personality, dumpable: p.dumpable, noNewPrivs: p.noNewPrivs,
		seccompProg: p.seccompProg, ns: p.ns, uts: p.uts, mntns: p.mntns,
	}
	ps.seccomp.Store(p.seccomp.Load())
	ps.netns.Store(p.netns.Load())
	return ps
}

func commOf(prog string) string {
	c := path.Base(prog)
	if len(c) > 15 {
		c = c[:15]
	}
	return c
}

// commOf returns a thread's name, as /proc/<tid>/comm shows it.
func (fs *dfs) commOf(tid int) (string, bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	p := fs.procs[tid]
	if p == nil || p.ps == nil {
		return "", false
	}
	return p.ps.comm[tid], true
}

// procView is a snapshot of one process for /proc: its ids, state, threads
// and their names, credentials, nice value, limits and start time.
type procView struct {
	Pid, PPid, Pgid, Sid int
	Zombie               bool
	Tids                 []int // ascending; the leader first
	Comm                 map[int]string
	Uid, Euid, Suid      uint32
	Gid, Egid, Sgid      uint32
	Groups               []uint32
	CapEff, CapPrm       uint64
	CapInh, CapBnd       uint64
	Nice                 int
	Rlim                 [rlimCount]rlimit
	Start                time.Time
	HostPid              int
	Userns               bool // entered a new user namespace
}

// procView returns pid's snapshot (pid may also be one of its thread ids).
func (fs *dfs) procView(pid int) (procView, bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	ps := fs.pt[pid]
	if ps == nil {
		if d := fs.procs[pid]; d != nil {
			ps = d.ps
		}
	}
	if ps == nil {
		return procView{}, false
	}
	v := procView{
		Pid: ps.tgid, PPid: ps.ppid, Pgid: ps.pgid, Sid: ps.sid, Zombie: ps.zombie,
		Comm: map[int]string{}, Uid: ps.cred.ruid, Euid: ps.cred.euid, Suid: ps.cred.suid,
		Gid: ps.cred.rgid, Egid: ps.cred.egid, Sgid: ps.cred.sgid,
		Groups: append([]uint32(nil), ps.cred.groups...),
		CapEff: ps.cred.capEff, CapPrm: ps.cred.capPrm, CapInh: ps.cred.capInh, CapBnd: ps.cred.capBnd,
		Nice: ps.sched.nice, Rlim: ps.rlim, Start: ps.start, HostPid: ps.ospid,
		Userns: ps.cred.userns,
	}
	for tid, d := range fs.procs {
		if d.ps == ps {
			v.Tids = append(v.Tids, tid)
		}
	}
	sort.Ints(v.Tids)
	for tid, c := range ps.comm {
		v.Comm[tid] = c
	}
	return v, true
}

// procList lists every process's pid, zombies included, ascending.
func (fs *dfs) procList() []int {
	fs.mu.Lock()
	out := make([]int, 0, len(fs.pt))
	for pid := range fs.pt {
		out = append(out, pid)
	}
	fs.mu.Unlock()
	sort.Ints(out)
	return out
}

// pidsInPgrp lists the live processes of process group pgid (kill(-pgid),
// job control).
func (fs *dfs) pidsInPgrp(pgid int) []int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	var out []int
	for pid, p := range fs.pt {
		if !p.zombie && p.pgid == pgid {
			out = append(out, pid)
		}
	}
	return out
}

// pidsInSession lists the live processes of session sid.
func (fs *dfs) pidsInSession(sid int) []int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	var out []int
	for pid, p := range fs.pt {
		if !p.zombie && p.sid == sid {
			out = append(out, pid)
		}
	}
	return out
}

// wakeWaiters re-runs every blocked wait4/waitid check.
func (fs *dfs) wakeWaiters() {
	fs.mu.Lock()
	fs.cond.Broadcast()
	fs.mu.Unlock()
}

// setStopped / setContinued record a job-control stop or continue of process
// pid for a WUNTRACED / WCONTINUED waiter (the signal code calls them).
func (fs *dfs) setStopped(pid, sig int) {
	fs.mu.Lock()
	if p := fs.pt[pid]; p != nil && !p.zombie {
		p.stopSig, p.contPending = sig, false
		fs.cond.Broadcast()
	}
	fs.mu.Unlock()
}

func (fs *dfs) setContinued(pid int) {
	fs.mu.Lock()
	if p := fs.pt[pid]; p != nil && !p.zombie {
		p.stopSig, p.contPending = 0, true
		fs.cond.Broadcast()
	}
	fs.mu.Unlock()
}

// setKillSig records that pid is being killed by signal sig, so its wait
// status reports WIFSIGNALED with that signal once its stub is gone.
func (fs *dfs) setKillSig(pid, sig int) {
	fs.mu.Lock()
	if p := fs.pt[pid]; p != nil && !p.zombie {
		p.killSig = sig
	}
	fs.mu.Unlock()
}

// Hooks for the signal subsystem. The defaults keep a run without signal
// delivery coherent; the signal code replaces them.
var (
	// procSignal sends sig to process pid (PR_SET_PDEATHSIG). By default a
	// signal whose default action terminates kills the stub on the host.
	procSignal = func(fs *dfs, pid, sig int) {
		switch sig {
		case 1, 2, 3, 6, 9, 15: // HUP INT QUIT ABRT KILL TERM
		default:
			return
		}
		fs.mu.Lock()
		p := fs.pt[pid]
		ospid := 0
		if p != nil && !p.zombie {
			p.killSig = sig
			ospid = p.ospid
		}
		fs.mu.Unlock()
		if ospid > 0 {
			osKill(ospid)
		}
	}

	// childExited notifies parent ppid that child pid exited with Linux wait
	// status, through the child's exit signal sig (normally SIGCHLD; 0 sends
	// nothing).
	childExited = func(fs *dfs, ppid, pid, sig, status int) {}

	// sigchldIgnored reports whether process ppid has SIGCHLD set to SIG_IGN or
	// SA_NOCLDWAIT, in which case its children are reaped as they exit and
	// leave no status for wait.
	sigchldIgnored = func(fs *dfs, ppid int) bool { return false }

	// waitInterrupted ends a blocked wait4/waitid when a signal is pending for
	// the waiting thread, with the value to return (EINTR or a restart).
	waitInterrupted = func(g *dguest) (int64, bool) { return 0, false }

	// execHook runs at every successful execve, past the point of no return
	// (the signal code resets handled signals to their defaults).
	execHook = func(g *dguest) {}
)

// beginExit runs at exit_group (or the leader's exit) before the stub's host
// exit: it fixes the exit code, as the first exit_group in a group does on
// Linux, and samples the process's CPU usage while its stub still exists.
func (g *dguest) beginExit(code int) {
	fs := g.dfs
	var ru rusage
	if !g.sharedStub() {
		ru = g.exitRusage()
	}
	fs.mu.Lock()
	if !g.ps.exiting {
		g.ps.exiting, g.ps.exitCode = true, code
		g.ps.ru = ru.plus(g.ps.ruPrev)
	}
	fs.mu.Unlock()
}

// groupExited reports whether the process has begun exit_group.
func (g *dguest) groupExited() bool {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	return g.ps.exiting
}

// processExit turns an exited process into a zombie for its parent to reap:
// it fixes the wait status, unwinds the group's other threads, reparents its
// children (to the nearest subreaper ancestor, else pid 1), signals its
// pidfds, releases a vfork parent, and wakes every waiter. A process whose
// stub vanished without an exit call (killed on the host) reports the signal.
func (fs *dfs) processExit(ps *pstate, code int, clean bool) {
	type wake struct {
		tid  int
		ch   *hostChan
		stop chan struct{}
	}
	var wakes []wake
	var deathsig []int
	var tracekill, released []int
	fs.mu.Lock()
	ppid := ps.ppid
	fs.mu.Unlock()
	autoReap := sigchldIgnored(fs, ppid)
	fs.mu.Lock()
	switch {
	case ps.exiting:
		ps.status = (ps.exitCode & 0xff) << 8
	case clean && code < 0: // the signal code reports a fatal signal as -sig
		ps.status = -code & 0x7f
	case clean:
		ps.status = (code & 0xff) << 8
	case ps.killSig != 0:
		ps.status = ps.killSig & 0x7f
	default:
		ps.status = lxSigkill
	}
	ps.zombie = true
	dropNs := ps.mntns // the mount namespace to tear down if this was its last live process
	if dropNs != 0 {
		for _, p := range fs.pt {
			if p != ps && !p.zombie && p.mntns == dropNs {
				dropNs = 0
				break
			}
		}
	}
	held := false
	if fs.tracing != nil {
		autoReap = autoReap && !fs.tracing.owns(ps)
		held = fs.tracing.holdsExit(ps)
		tracekill, released = fs.tracing.processExit(ps)
	}
	ps.stopSig, ps.contPending = 0, false
	var pi *procInfo
	for tid, p := range fs.procs {
		if p.ps == ps {
			if tid == ps.tgid {
				if p.g != nil {
					pi = p.g.pi
				}
				delete(fs.procs, tid)
				continue
			}
			wakes = append(wakes, wake{tid, p.ch, p.stop})
		}
	}
	heir := fs.reaperFor(ps)
	for pid, c := range fs.pt {
		if c.ppid != ps.tgid || pid == ps.tgid {
			continue
		}
		c.ppid = heir
		if c.pdeathsig != 0 && !c.zombie {
			deathsig = append(deathsig, pid, c.pdeathsig)
		}
	}
	if ps.pidfdW != nil {
		ps.pidfdW.Write([]byte{1})
		ps.pidfdW.Close()
		ps.pidfdR.Close()
		ps.pidfdR, ps.pidfdW = nil, nil
	}
	if ps.vforkDone != nil {
		close(ps.vforkDone)
		ps.vforkDone = nil
	}
	parent, sig, status := ps.ppid, ps.exitSignal, ps.status
	if held {
		sig = 0 // the parent is told when the tracer lets the zombie go (ptraceReleased)
	}
	tracing := fs.tracing
	leader := ps.sid == ps.tgid
	if autoReap && parent == ppid {
		delete(fs.pt, ps.tgid)
		ps.ns.deregister(ps.tgid)
		if pp := fs.pt[parent]; pp != nil {
			pp.cru = pp.cru.plus(ps.ru.plus(ps.cru))
		}
	}
	fs.cond.Broadcast()
	fs.mu.Unlock()

	if dropNs != 0 {
		fs.dropMntnsMounts(dropNs)
	}
	if pi != nil {
		pi.dropExe()
	}
	for _, w := range wakes {
		fs.endServe(w.tid, w.stop, w.ch)
	}
	for _, pid := range tracekill {
		procSignal(fs, pid, sigKILL)
	}
	for _, pid := range released {
		fs.ptraceReleased(pid)
	}
	for i := 0; i < len(deathsig); i += 2 {
		procSignal(fs, deathsig[i], deathsig[i+1])
	}
	if leader {
		fs.endSession(ps.tgid)
	}
	if parent != 0 {
		childExited(fs, parent, ps.tgid, sig, status)
	}
	if tracing != nil {
		tracing.notifyExit(ps)
	}
}

// ptraceReleased tells a traced zombie's real parent of its exit once its
// tracer has let it go: the parent is signaled, and a parent ignoring SIGCHLD
// has it reaped then. The caller does not hold mu.
func (fs *dfs) ptraceReleased(pid int) {
	fs.mu.Lock()
	ps := fs.pt[pid]
	if ps == nil || !ps.zombie {
		fs.mu.Unlock()
		return
	}
	ppid, sig, status := ps.ppid, ps.exitSignal, ps.status
	fs.mu.Unlock()
	if sigchldIgnored(fs, ppid) {
		fs.mu.Lock()
		if fs.pt[pid] == ps && ps.ppid == ppid {
			delete(fs.pt, pid)
			ps.ns.deregister(pid)
			if pp := fs.pt[ppid]; pp != nil {
				pp.cru = pp.cru.plus(ps.ru.plus(ps.cru))
			}
			fs.cond.Broadcast()
		}
		fs.mu.Unlock()
	}
	childExited(fs, ppid, pid, sig, status)
}

// reaperFor picks the new parent of an exiting process's children: its nearest
// live ancestor that set PR_SET_CHILD_SUBREAPER, else pid 1. The caller holds mu.
func (fs *dfs) reaperFor(ps *pstate) int {
	for p := fs.pt[ps.ppid]; p != nil && p.tgid != 1; p = fs.pt[p.ppid] {
		if p.subreaper && !p.zombie {
			return p.tgid
		}
	}
	return 1
}

// groupExitCode returns the exit_group code of process pid, if it called one.
func (fs *dfs) groupExitCode(pid int) (int, bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if p := fs.pt[pid]; p != nil && p.exiting {
		return p.exitCode & 0xff, true
	}
	return 0, false
}

// threadDone retires a thread's registry entry when its serve loop ends. It
// reports whether that was the last thread of a process whose leader exited
// first, which ends the process.
func (fs *dfs) threadDone(ps *pstate, tid int) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.procs, tid)
	delete(ps.comm, tid)
	if tid != ps.tgid && (fs.tracing == nil || !fs.tracing.traced(tid)) { // the leader's id is dropped when the process is reaped
		ps.ns.deregister(tid)
	}
	ps.threads--
	return ps.leaderGone && ps.threads == 0
}

// nrThreadGone is the stub's notice that it ended a thread on an exit (not
// exit_group) while other threads run; nothing replies to it.
const nrThreadGone = 0x1_0000_0002

// errLeaderGone ends a leader's serve loop when the leader thread exited
// before the rest of its process.
var errLeaderGone = errors.New("leader thread exited")

// leaderExited records that g, the process leader, exited with code while
// other threads run, as Linux keeps the process (and its pid) until the last
// thread is gone; the process then reports the leader's code. It waits for
// that end and returns the code to report (pid 1's serve returns it as the
// run's status).
func (fs *dfs) leaderExited(g *dguest, code int) int {
	fs.mu.Lock()
	ps := g.ps
	ps.leaderGone, ps.leaderCode = true, code
	// Its pid lives on with the process, but its channel's slot is freed
	// now and may be another's before the process ends.
	if p := fs.procs[ps.tgid]; p != nil && p.ch == g.ch {
		p.ch = nil
	}
	if ps.ended == nil {
		ps.ended = make(chan struct{})
	}
	ended := ps.ended
	ps.threads--
	last := ps.threads == 0
	if !last && leaderHoldsSlot {
		ps.heldSlot, g.slotHeld = g.slot, true
	}
	fs.mu.Unlock()
	if last {
		fs.finishGroup(ps, nil)
	}
	if ps.tgid == 1 {
		select {
		case <-ended:
		case <-g.ch.done:
		}
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if ps.exiting {
		return ps.exitCode & 0xff
	}
	return ps.leaderCode & 0xff
}

// finishGroup ends a process whose leader exited first, once its last thread
// is gone (err: how that thread's serve loop ended).
func (fs *dfs) finishGroup(ps *pstate, err error) {
	if err == nil {
		fs.mu.Lock()
		ospid := ps.ospid
		fs.mu.Unlock()
		fs.awaitStubGone(ospid)
	}
	if ps.tgid != 1 {
		fs.processExit(ps, ps.leaderCode, err == nil)
		fs.endStub(ps)
	}
	fs.mu.Lock()
	if ps.ended != nil {
		close(ps.ended)
		ps.ended = nil
	}
	held := ps.heldSlot
	ps.heldSlot = 0
	fs.mu.Unlock()
	if held > 0 {
		fs.freeSlot(held)
	}
}

// forgetProc removes a process that never ran (its fork failed in the stub).
func (fs *dfs) forgetProc(ps *pstate) {
	fs.mu.Lock()
	if fs.tracing != nil {
		fs.tracing.forget(ps)
	}
	delete(fs.procs, ps.tgid)
	delete(fs.pt, ps.tgid)
	ps.ns.deregister(ps.tgid)
	if ps.vforkDone != nil {
		close(ps.vforkDone)
		ps.vforkDone = nil
	}
	fs.mu.Unlock()
}

// execDone records a successful execve: setpgid on the process now fails with
// EACCES, the thread takes the program's name, and a vfork parent resumes.
func (g *dguest) execDone(prog string) {
	fs := g.dfs
	fs.mu.Lock()
	ps := g.ps
	ps.execed = true
	ps.comm = map[int]string{g.pid: commOf(prog)}
	ps.dumpable = 1
	ps.cred.onExec()
	if ps.vforkDone != nil {
		close(ps.vforkDone)
		ps.vforkDone = nil
	}
	fs.mu.Unlock()
}

// waitSel is which children a wait call selects: one pid, a process group, or
// any child, plus the __WCLONE/__WALL split.
type waitSel struct {
	pid, pgid int // pid > 0: that child; else pgid > 0: that group; else any
	opts      uint64
}

func (w waitSel) match(c *pstate) bool {
	if w.pid > 0 && c.tgid != w.pid || w.pid <= 0 && w.pgid > 0 && c.pgid != w.pgid {
		return false
	}
	if w.opts&wAll != 0 {
		return true
	}
	return (c.exitSignal != lxSigchld) == (w.opts&wClone != 0)
}

// waitEvent is what a wait call found: an exited child (reaped unless
// WNOWAIT), a stop, or a continue.
type waitEvent struct {
	intr   int64 // set when a signal interrupted the wait: the call's result
	pid    int
	uid    uint32
	status int // Linux wait status
	code   int // waitid si_code: CLD_EXITED, CLD_KILLED, CLD_DUMPED, CLD_STOPPED, CLD_CONTINUED
	sistat int // waitid si_status
	ru     rusage
}

const (
	cldExited    = 1
	cldKilled    = 2
	cldDumped    = 3
	cldTrapped   = 4
	cldStopped   = 5
	cldContinued = 6
)

// waitChild blocks until a child selected by (pid, opts) has an event to
// report, the shared core of wait4 and waitid. It returns ok=false with an
// errno, or ok=true with ev.pid == 0 for WNOHANG with nothing ready.
func (g *dguest) waitChild(w waitSel, exited, stopped, continued bool) (waitEvent, lxErrno) {
	opts := w.opts
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	me := g.ps
	for {
		found := false
		if fs.tracing != nil {
			ev, exists, ready := fs.tracing.wait(g, w, exited)
			if ready {
				return ev, 0
			}
			found = exists
		}
		for cpid, c := range fs.pt {
			if c.ppid != me.tgid || cpid == me.tgid || !w.match(c) {
				continue
			}
			found = true
			if fs.tracing != nil && fs.tracing.owns(c) {
				continue
			}
			// The reported pid is the child's in the waiter's namespace,
			// computed before a reap drops its mapping.
			rpid := me.ns.seen(c)
			switch {
			case c.zombie && exited:
				ev := waitEvent{pid: rpid, uid: c.cred.ruid, status: c.status}
				ev.ru = c.ru.plus(c.cru)
				switch {
				case c.status&0x7f == 0:
					ev.code, ev.sistat = cldExited, (c.status>>8)&0xff
				case c.status&0x80 != 0:
					ev.code, ev.sistat = cldDumped, c.status&0x7f
				default:
					ev.code, ev.sistat = cldKilled, c.status&0x7f
				}
				if opts&wNowait == 0 {
					me.cru = me.cru.plus(ev.ru)
					delete(fs.pt, cpid)
					c.ns.deregister(cpid)
				}
				return ev, 0
			case !c.zombie && stopped && c.stopSig != 0:
				ev := waitEvent{pid: rpid, uid: c.cred.ruid, status: c.stopSig<<8 | 0x7f, code: cldStopped, sistat: c.stopSig}
				if opts&wNowait == 0 {
					c.stopSig = 0
				}
				return ev, 0
			case !c.zombie && continued && c.contPending:
				ev := waitEvent{pid: rpid, uid: c.cred.ruid, status: 0xffff, code: cldContinued, sistat: lxSigcont}
				if opts&wNowait == 0 {
					c.contPending = false
				}
				return ev, 0
			}
		}
		if !found {
			return waitEvent{}, lxECHILD
		}
		if opts&wNohang != 0 {
			return waitEvent{}, 0
		}
		if g.ch.dead() {
			return waitEvent{}, lxEINTR
		}
		if r, ok := waitInterrupted(g); ok {
			return waitEvent{intr: r}, lxEINTR
		}
		fs.cond.Wait()
	}
}

// dead reports whether this channel's stub is gone (the run is ending or the
// process was killed), so a supervisor-side block must give up. A Windows
// channel's stop closes only once its slot is ended; until then its stub's
// process handle tells (ended).
func (c *hostChan) dead() bool {
	select {
	case <-c.done:
		return true
	case <-c.stop:
		return true
	default:
		return c.ended()
	}
}

// waitTargetPid maps a positive wait target (a pid, or a pgid when negated)
// from the caller's pid namespace to the global value the process table uses.
// ok is false when the namespace has no such id, which wait turns into ECHILD.
func (g *dguest) waitTargetPid(nsPid int) (int, bool) { return g.nsToGlobal(nsPid) }

func (g *dguest) wait4(pid int, statusAddr, opts, ruAddr uint64) int64 {
	if opts&^uint64(wNohang|wUntraced|wContinued|wNothread|wAll|wClone) != 0 {
		return sErr(lxEINVAL)
	}
	w := waitSel{opts: opts}
	switch {
	case pid == -1<<31:
		return sErr(lxESRCH)
	case pid > 0:
		gp, ok := g.waitTargetPid(pid)
		if !ok {
			return sErr(lxECHILD)
		}
		w.pid = gp
	case pid == 0:
		g.dfs.mu.Lock()
		w.pgid = g.ps.pgid
		g.dfs.mu.Unlock()
	case pid < -1:
		gp, ok := g.waitTargetPid(-pid)
		if !ok {
			return sErr(lxECHILD)
		}
		w.pgid = gp
	}
	ev, e := g.waitChild(w, true, opts&wUntraced != 0, opts&wContinued != 0)
	if ev.intr != 0 {
		return ev.intr
	}
	if e != 0 {
		return sErr(e)
	}
	if ev.pid == 0 {
		return 0
	}
	if statusAddr != 0 {
		var b [4]byte
		put32(b[:], uint32(ev.status))
		if g.writeMem(statusAddr, b[:]) != nil {
			return sErr(lxEFAULT)
		}
	}
	if ruAddr != 0 && g.writeMem(ruAddr, ev.ru.linux()) != nil {
		return sErr(lxEFAULT)
	}
	return int64(ev.pid)
}

// waitid(idtype, id, infop, options, rusage). The siginfo it fills is the
// Linux 128-byte layout with the SIGCHLD fields at offset 16; with WNOHANG and
// nothing ready it is zeroed (si_pid 0), as Linux does.
func (g *dguest) waitid(idtype, id, infoAddr, opts, ruAddr uint64) int64 {
	const (
		pAll   = 0
		pPid   = 1
		pPgid  = 2
		pPidfd = 3
	)
	if opts&^uint64(wNohang|wUntraced|wExited|wContinued|wNowait|wNothread|wAll|wClone) != 0 ||
		opts&(wExited|wUntraced|wContinued) == 0 {
		return sErr(lxEINVAL)
	}
	w := waitSel{opts: opts}
	switch idtype {
	case pAll:
	case pPid:
		if int32(id) <= 0 {
			return sErr(lxEINVAL)
		}
		gp, ok := g.waitTargetPid(int(int32(id)))
		if !ok {
			return sErr(lxECHILD)
		}
		w.pid = gp
	case pPgid:
		if int32(id) < 0 {
			return sErr(lxEINVAL)
		}
		w.pgid = int(int32(id))
		if w.pgid == 0 {
			g.dfs.mu.Lock()
			w.pgid = g.ps.pgid
			g.dfs.mu.Unlock()
		} else if gp, ok := g.waitTargetPid(w.pgid); ok {
			w.pgid = gp
		} else {
			return sErr(lxECHILD)
		}
	case pPidfd:
		p, e := g.pidfdPid(int64(int32(id)))
		if e != 0 {
			return sErr(e)
		}
		w.pid = p
	default:
		return sErr(lxEINVAL)
	}
	ev, e := g.waitChild(w, opts&wExited != 0, opts&wUntraced != 0, opts&wContinued != 0)
	if ev.intr != 0 {
		return ev.intr
	}
	if e != 0 {
		return sErr(e)
	}
	return g.writeWaitid(ev, infoAddr, ruAddr)
}

func (g *dguest) writeWaitid(ev waitEvent, infoAddr, ruAddr uint64) int64 {
	if infoAddr != 0 {
		var si [128]byte
		if ev.pid != 0 {
			put32(si[0:], lxSigchld)
			put32(si[8:], uint32(ev.code))
			put32(si[16:], uint32(ev.pid))
			put32(si[20:], ev.uid)
			put32(si[24:], uint32(ev.sistat))
			put64(si[32:], uint64(ev.ru.utime/10_000_000))
			put64(si[40:], uint64(ev.ru.stime/10_000_000))
		}
		if g.writeMem(infoAddr, si[:]) != nil {
			return sErr(lxEFAULT)
		}
	}
	if ruAddr != 0 && g.writeMem(ruAddr, ev.ru.linux()) != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

// ---- process groups and sessions ----------------------------------------------

func (g *dguest) setpgid(pid, pgid int) int64 {
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	me := g.ps
	if pid == 0 {
		pid = me.tgid
	}
	if pgid == 0 {
		pgid = pid
	}
	if pid < 0 || pgid < 0 {
		return sErr(lxEINVAL)
	}
	p := fs.pt[pid] // a zombie still counts until reaped, as on Linux
	if p == nil || (p != me && p.ppid != me.tgid) {
		return sErr(lxESRCH)
	}
	if p != me {
		if p.sid != me.sid {
			return sErr(lxEPERM)
		}
		if p.execed {
			return sErr(lxEACCES)
		}
	}
	if p.sid == p.tgid {
		return sErr(lxEPERM) // a session leader cannot move
	}
	if pgid != pid {
		found := false
		for _, q := range fs.pt {
			if q.pgid == pgid && q.sid == me.sid {
				found = true
				break
			}
		}
		if !found {
			return sErr(lxEPERM)
		}
	}
	p.pgid = pgid
	return 0
}

// procOf returns process pid (0 = the caller), live or zombie, or ESRCH. The
// caller holds mu.
func (g *dguest) procOf(pid int) (*pstate, lxErrno) {
	if pid == 0 {
		return g.ps, 0
	}
	if pid < 0 {
		return nil, lxESRCH
	}
	if p := g.dfs.pt[pid]; p != nil {
		return p, 0
	}
	// A thread id names its process for these calls.
	if d := g.dfs.procs[pid]; d != nil && d.ps != nil {
		return d.ps, 0
	}
	return nil, lxESRCH
}

func (g *dguest) getpgid(pid int) int64 {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	p, e := g.procOf(pid)
	if e != 0 {
		return sErr(e)
	}
	return int64(p.pgid)
}

func (g *dguest) getsid(pid int) int64 {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	p, e := g.procOf(pid)
	if e != 0 {
		return sErr(e)
	}
	return int64(p.sid)
}

func (g *dguest) setsid() int64 {
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	me := g.ps
	for _, q := range fs.pt {
		if q.pgid == me.tgid {
			return sErr(lxEPERM) // the caller leads a group, or its pid names one
		}
	}
	me.sid, me.pgid = me.tgid, me.tgid
	return int64(me.tgid)
}

func (g *dguest) getppid() int64 {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	if parent := g.dfs.pt[g.ps.ppid]; parent != nil {
		// 0 when the parent is in an ancestor namespace and so not visible.
		return int64(g.ps.ns.seen(parent))
	}
	return int64(g.ps.ns.localOf(g.ps.ppid))
}

// ---- pidfd ----------------------------------------------------------------------

// A pidfd holds a dup of its process's exit notifier, a pipe that gets a byte
// when the process exits, so poll/epoll see it readable exactly then.
func (g *dguest) pidfdOpen(pid int, flags uint64) int64 {
	if flags&^uint64(lxONonblock) != 0 || pid <= 0 {
		return sErr(lxEINVAL)
	}
	gp, ok := g.nsToGlobal(pid)
	if !ok {
		return sErr(lxESRCH)
	}
	pid = gp
	fs := g.dfs
	fs.mu.Lock()
	p := fs.pt[pid]
	if p == nil {
		_, isThread := fs.procs[pid]
		fs.mu.Unlock()
		if isThread {
			return sErr(lxEINVAL)
		}
		return sErr(lxESRCH)
	}
	fd := g.newPidfd(p, flags&lxONonblock != 0)
	fs.mu.Unlock()
	return fd
}

// newPidfd creates a pidfd for p (close-on-exec, as Linux makes them). The
// caller holds mu.
func (g *dguest) newPidfd(p *pstate, nonblock bool) int64 {
	var f *os.File
	if p.zombie {
		r, w, err := os.Pipe()
		if err != nil {
			return sErr(osErrno(err))
		}
		w.Write([]byte{1})
		w.Close()
		f = r
	} else {
		if p.pidfdR == nil {
			r, w, err := os.Pipe()
			if err != nil {
				return sErr(osErrno(err))
			}
			p.pidfdR, p.pidfdW = r, w
		}
		nf, e := dupFile(p.pidfdR)
		if e != 0 {
			return sErr(e)
		}
		f = nf
	}
	d := &dfile{f: f, gp: "anon_inode:[pidfd]", stub: -1, pid: p.tgid}
	d.nonblock.Store(nonblock)
	fd := g.ft.add(d, 0)
	if fd < 0 {
		return int64(fd)
	}
	g.ft.setCloexec(fd, true)
	return int64(fd)
}

// pidfdPid returns the process a pidfd refers to.
func (g *dguest) pidfdPid(fd int64) (int, lxErrno) {
	d, ok := g.ft.get(int(fd))
	if !ok || d.pid == 0 {
		return 0, lxEBADF
	}
	return d.pid, 0
}

func (g *dguest) pidfdGetfd(pidfd int64, target int64, flags uint64) int64 {
	if flags != 0 {
		return sErr(lxEINVAL)
	}
	pid, e := g.pidfdPid(pidfd)
	if e != 0 {
		return sErr(e)
	}
	fs := g.dfs
	fs.mu.Lock()
	p := fs.pt[pid]
	if p == nil || p.zombie || p.ft == nil {
		fs.mu.Unlock()
		return sErr(lxESRCH)
	}
	if !ptraceMayAccess(g.ps, p) {
		fs.mu.Unlock()
		return sErr(lxEPERM)
	}
	ft := p.ft
	fs.mu.Unlock()
	d, ok := ft.get(int(target))
	if !ok {
		return sErr(lxEBADF)
	}
	fd := g.ft.add(d, 0)
	g.ft.setCloexec(fd, true)
	return int64(fd)
}

func init() {
	syscalls[lxWait4] = func(g *dguest, a [6]uint64) int64 {
		return g.wait4(int(int32(a[0])), a[1], uint64(uint32(a[2])), a[3])
	}
	syscalls[lxWaitid] = func(g *dguest, a [6]uint64) int64 {
		return g.waitid(uint64(uint32(a[0])), a[1], a[2], uint64(uint32(a[3])), a[4])
	}
	syscalls[lxGetppid] = func(g *dguest, a [6]uint64) int64 { return g.getppid() }
	syscalls[lxSetpgid] = func(g *dguest, a [6]uint64) int64 { return g.setpgid(int(int32(a[0])), int(int32(a[1]))) }
	syscalls[lxGetpgid] = func(g *dguest, a [6]uint64) int64 { return g.getpgid(int(int32(a[0]))) }
	syscalls[lxGetsid] = func(g *dguest, a [6]uint64) int64 { return g.getsid(int(int32(a[0]))) }
	syscalls[lxSetsid] = func(g *dguest, a [6]uint64) int64 { return g.setsid() }
	syscalls[lxPidfdOpen] = func(g *dguest, a [6]uint64) int64 { return g.pidfdOpen(int(int32(a[0])), uint64(uint32(a[1]))) }
	syscalls[lxPidfdGetfd] = func(g *dguest, a [6]uint64) int64 {
		return g.pidfdGetfd(int64(int32(a[0])), int64(int32(a[1])), uint64(uint32(a[2])))
	}
}

// pgrpOrphaned reports whether process group pgid is orphaned (POSIX): none of
// its members has a parent in another group of the same session. Pid 1's
// parent is whoever ran the sandbox, as a shell runs a job, so its group is
// never orphaned.
func (fs *dfs) pgrpOrphaned(pgid int) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, p := range fs.pt {
		if p.pgid != pgid || p.zombie {
			continue
		}
		if p.tgid == 1 {
			return false
		}
		if pp := fs.pt[p.ppid]; pp != nil && !pp.zombie && pp.pgid != pgid && pp.sid == p.sid {
			return false
		}
	}
	return true
}
