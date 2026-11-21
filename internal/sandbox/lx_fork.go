//go:build darwin || linux || windows

package sandbox

import "errors"

// Process creation shared by the hosts: clone and clone3 decoded into one
// request and checked, then a thread (cloneThread), a process sharing this
// one's memory (cloneVMProc) or a fork (forkProc), each the host's own; the
// vfork hold and the end of a child process.

// cloneReq is a clone or clone3 call decoded into one shape.
type cloneReq struct {
	flags      uint64
	exitSignal int
	stack      uint64 // the child's sp; 0 keeps the parent's
	ptid, tls  uint64
	ctid       uint64
	pidfdAddr  uint64 // where CLONE_PIDFD stores the new pidfd
}

// nrVforkWait is the stub's pseudo-syscall that parks a vfork parent.
const nrVforkWait = 0x1_0000_0001

// nrForked is the parent stub's report, right after its fork or clone, of
// the child (macOS: a fork's host pid; 0: no child).
const nrForked = 0x1_0000_0003

// cloned answers a traced caller's report of the thread or CLONE_VM process
// it made (the stub reports only when traced): the clone event and the
// syscall-exit stop, then the result.
func (g *dguest) cloned(tid, ret int, event int) {
	if err := g.ch.wait(); err != nil || g.ch.page.nr != nrForked {
		return
	}
	if g.ch.page.args[0] == 0 { // the stub could not start the thread
		g.ch.page.ret = 0
		g.ch.reply(repResult)
		return
	}
	if event != 0 {
		g.ptraceEvent(event, uint64(tid))
	}
	g.ch.page.ret = uint64(ret)
	g.ptraceSyscallExit(int64(ret))
	g.ch.reply(repResult)
}

const (
	lxClonePidfd       = 0x1000
	lxCloneSighand     = 0x800
	lxCloneParent      = 0x8000
	lxCloneSettls      = 0x80000
	lxCloneParentSetid = 0x100000
	lxCloneNewMask     = 0x7e020000 // CLONE_NEW{NS,CGROUP,UTS,IPC,USER,PID,NET}
	lxCloneNewNs       = 0x00020000
	lxCloneNewUser     = 0x10000000
	lxCloneNewPid      = 0x20000000
	lxCloneNewNet      = 0x40000000
	lxCloneNewUts      = 0x04000000
)

// cloneArgs decodes clone(flags, stack, ptid, tls, ctid).
func cloneArgs(a [6]uint64) (cloneReq, lxErrno) {
	r := cloneReq{flags: a[0] &^ 0xff, exitSignal: int(a[0] & 0xff), stack: a[1], ptid: a[2], tls: a[3], ctid: a[4]}
	if r.flags&lxClonePidfd != 0 {
		if r.flags&lxCloneParentSetid != 0 {
			return r, lxEINVAL // both would use ptid
		}
		r.pidfdAddr = a[2]
	}
	return r, 0
}

// clone3Args decodes struct clone_args {flags, pidfd, child_tid, parent_tid,
// exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup}.
func (g *dguest) clone3Args(addr, size uint64) (cloneReq, lxErrno) {
	const ver0, full = 64, 88
	if size < ver0 {
		return cloneReq{}, lxEINVAL
	}
	if size > 4096 { // PAGE_SIZE
		return cloneReq{}, lxE2BIG
	}
	b, err := g.readMem(addr, int(size))
	if err != nil {
		return cloneReq{}, lxEFAULT
	}
	for _, x := range b[min(size, full):] {
		if x != 0 {
			return cloneReq{}, lxE2BIG
		}
	}
	b = append(b, make([]byte, full)...)
	flags, sig, stack, ssize := le64(b), le64(b[32:]), le64(b[40:]), le64(b[48:])
	if flags&0xff != 0 || sig > 64 || le64(b[72:]) != 0 || flags>>32 != 0 ||
		(stack == 0) != (ssize == 0) {
		return cloneReq{}, lxEINVAL
	}
	r := cloneReq{flags: flags, exitSignal: int(sig), ptid: le64(b[24:]), tls: le64(b[56:]), ctid: le64(b[16:])}
	if stack != 0 {
		r.stack = stack + ssize
	}
	if flags&lxClonePidfd != 0 {
		r.pidfdAddr = le64(b[8:])
	}
	return r, 0
}

// clone creates a thread or a process. CLONE_THREAD makes a thread of this
// process; CLONE_VM without it a process sharing this one's memory (vfork,
// posix_spawn), which runs as a thread of this stub; anything else forks.
// CLONE_VFORK holds the parent until the child execs or exits. It replies to
// the guest itself; the result is for tracing.
func (g *dguest) clone(r cloneReq, cfg Config) int {
	fail := func(e lxErrno) int {
		g.ch.page.ret = errno(e)
		ptraceReturn(g, int64(g.ch.page.ret))
		g.ch.reply(repResult)
		return -1
	}
	f := r.flags
	switch {
	case r.exitSignal > 64:
		return fail(lxEINVAL)
	case f&lxCloneThread != 0 && f&lxCloneSighand == 0, f&lxCloneSighand != 0 && f&lxCloneVM == 0:
		return fail(lxEINVAL)
	case f&lxClonePidfd != 0 && f&lxCloneThread != 0:
		return fail(lxEINVAL)
	}
	switch {
	case f&lxCloneThread != 0:
		return g.cloneThread(r, cfg)
	case f&lxCloneVM != 0:
		return g.cloneVMProc(r, cfg)
	}
	return g.forkProc(r, cfg)
}

// vforkHold answers the parent stub's vfork pseudo-syscall once the child has
// exec'd or exited, with the vfork's result (ret, the child's pid). A tracer
// sees the vfork event (when event is it and the stub had no earlier stop to
// report it at), the vfork-done event and the syscall exit, as on Linux.
func (g *dguest) vforkHold(done chan struct{}, ret uint64, event int) {
	if err := g.ch.wait(); err != nil || g.ch.page.nr != nrVforkWait {
		return
	}
	if event != 0 {
		g.ptraceEvent(event, ret)
	}
	select {
	case <-done:
	case <-g.ch.done:
	case <-g.ch.stop:
	}
	g.ptraceEvent(ptraceEventVforkDone, ret)
	g.ch.page.ret = ret
	g.ptraceSyscallExit(int64(ret))
	g.ch.reply(repResult)
}

// errNeverRan ends the serve loop of a CLONE_VM child whose thread the stub
// failed to create.
var errNeverRan = errors.New("clone child never ran")

// sharedStub reports whether g's process is a CLONE_VM child still running as
// a thread of its parent's stub.
func (g *dguest) sharedStub() bool {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	return g.ps.shared
}

// sharedStub reports whether process pid is a CLONE_VM child running in its
// parent's stub.
func (fs *dfs) sharedStub(pid int) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	p := fs.pt[pid]
	return p != nil && p.shared
}

// endSharedThread ends the stub thread a CLONE_VM child process runs on and
// waits for its notice that it is gone, after which nothing in the stub
// touches the slot.
func (g *dguest) endSharedThread() error {
	g.ch.reply(repThreadEnd)
	for {
		if err := g.ch.wait(); err != nil {
			return err
		}
		if g.ch.page.nr == nrThreadGone {
			return nil
		}
	}
}

const cloneFiles = 0x00000400 // share the open-file table (same fds)
const cloneFs = 0x00000200    // share the fs state (root and cwd)

// childDone ends a child process whose leader's serve loop returned.
func (fs *dfs) childDone(child *dguest, code int, err error) {
	if err == errLeaderGone {
		child.release()
		fs.leaderExited(child, code)
		return
	}
	if fs.superseded(child) {
		// A thread of this process exec'd and took over as its leader.
		child.release()
		fs.mu.Lock()
		child.ps.threads--
		fs.mu.Unlock()
		return
	}
	if err != nil {
		if k := fs.sigs().killedBy(child.tgid); k != 0 {
			fs.setKillSig(child.tgid, k)
		}
	}
	fs.endProcess(child, code, err)
}

// endProcess finishes a process whose leader's serve loop has returned: once
// its stub is gone it drops its fds (closing pipe ends its parent may be
// reading) and becomes a zombie for wait4.
func (fs *dfs) endProcess(g *dguest, code int, err error) {
	if err == nil {
		fs.mu.Lock()
		ospid := g.ps.ospid
		if g.ps.shared {
			ospid = 0 // its thread is gone; the stub is its parent's
		}
		fs.mu.Unlock()
		fs.awaitStubGone(ospid)
	}
	g.release()
	fs.processExit(g.ps, code, err == nil)
}

// superseded reports whether g, a process leader, was replaced by a thread
// that exec'd: the registry's entry for its pid now serves another channel.
func (fs *dfs) superseded(g *dguest) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	p := fs.procs[g.pid]
	return p != nil && p.ch != g.ch
}

// cloneNamespaces places the new process ps, global pid gpid, in the
// namespaces clone's flags ask for and gives it a pid in each pid namespace
// it is seen from. The caller holds fs.mu.
func (g *dguest) cloneNamespaces(ps *pstate, gpid int, flags uint64) {
	fs := g.dfs
	if flags&lxCloneNewUser != 0 {
		// The child is root in its new user namespace, with every capability
		// (a sandbox clones itself this way).
		ps.cred.userns = true
		ps.cred.capEff, ps.cred.capPrm, ps.cred.capBnd, ps.cred.capInh = capAll, capAll, capAll, capAll
	}
	if flags&lxCloneNewPid != 0 {
		ps.ns = g.ps.ns.child(fs.nextNsID) // where the child is pid 1
		fs.nextNsID++
	} else if g.ps.childPidNs != nil {
		ps.ns = g.ps.childPidNs // a prior unshare(CLONE_NEWPID) placed the caller's children here
	}
	if flags&lxCloneNewNet != 0 {
		ps.netns.Store(int32(fs.nextNsID)) // empty: no host network there
		fs.nextNsID++
	}
	if flags&lxCloneNewUts != 0 {
		ps.uts = g.utsNS().clone()
	}
	if flags&lxCloneNewNs != 0 {
		ps.mntns = fs.nextNsID // its mounts are dropped when it empties
		fs.nextNsID++
	}
	ps.ns.register(gpid)
}
