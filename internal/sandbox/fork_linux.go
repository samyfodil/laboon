package sandbox

import (
	"maps"
	"slices"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// fork, threads and vfork with the Linux stub. A fork is the stub forking
// itself onto the child's slot (REP_FORK): the child announces its host pid
// there (msgForked) and returns 0, the parent returns the pid the supervisor
// left in the reply. A thread is a stub thread the stub spawns (REP_CLONE)
// on a small bootstrap stack of its own.

// cloneFlag bits the stub protocol needs.
const (
	lxCloneChildSettid  = 0x01000000
	lxCloneChildCleartd = 0x00200000
)

// stubLocalLen is the size of the stub's own per-thread state in a slot page
// (struct Thread in stub/zig/sig.zig).
const stubLocalLen = 112

// resetStubLocal clears the stub's own state in slot idx for a new thread:
// what the slot's last thread left (a held unmap, say) is not the new one's.
func resetStubLocal(mem []byte, idx int) {
	o := idx*slotSize + stubRecOff
	clear(mem[o : o+stubLocalLen])
	o = slotsLen + tOff(idx) + traceRegsOff
	clear(mem[o : o+16+34*8])
}

// holdCloneChild marks a clone child's slot busy before it launches, so no
// signal is delivered to it until it has finished bootstrapping (lc_thread_start
// publishes its host tid, then restores registers) and run its first syscall,
// which clears busy. lc_thread_start does not set busy and resetStubLocal
// cleared it; without this a kick can reach the child mid register-restoration
// and build a signal frame on an unready stack. A fork or vfork child is held
// by the stub itself (stub.zig), so only the thread and CLONE_VM paths need it.
func holdCloneChild(mem []byte, idx int) {
	put32(mem[idx*slotSize+stubBusy:], 1)
}

// forkCopy is a fork child's memory state: a copy of m's, for a stub not yet
// known by pid.
func (m *memProc) forkCopy(fs *dfs) *memProc {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := newMemProc(0)
	c.sites.share(&m.sites)
	c.fast, c.strays = m.fast, m.strays
	c.reserved = slices.Clone(m.reserved)
	c.fileCode = slices.Clone(m.fileCode)
	c.vm, c.noWrite = m.vm.clone(), m.noWrite.clone()
	c.special = slices.Clone(m.special)
	c.lay = m.lay
	c.used = m.used
	c.brk, c.brkLo = m.brk, m.brkLo
	c.stackChunks = maps.Clone(m.stackChunks) // a fork inherits the stub's mappings
	c.forkShMaps(m, fs)                       // the child inherits the shared mappings; keep their backings live
	return c
}

func (g *dguest) forkProc(r cloneReq, cfg Config) int {
	fs := g.dfs
	pg := g.ch.page
	fail := func(e lxErrno) int {
		pg.ret = errno(e)
		g.ptraceSyscallExit(int64(pg.ret))
		g.ch.reply(repResult)
		return -1
	}
	if r.flags&lxCloneParent != 0 && g.ps.tgid == 1 {
		return fail(lxEINVAL)
	}
	idx := fs.allocSlot()
	if idx < 0 {
		return fail(lxEAGAIN)
	}
	h := fs.allocHop()
	if h == nil {
		fs.freeSlot(idx)
		return fail(lxEAGAIN)
	}
	// The child's thread runs on its slot's stacks as the fork returns: map
	// them here, before forkCopy, so the child inherits them and knows it.
	g.mp.mu.Lock()
	mapped := g.mapSlotStacks(idx)
	g.mp.mu.Unlock()
	if !mapped {
		fs.freeHop(h)
		fs.freeSlot(idx)
		return fail(lxENOMEM)
	}
	gpid := fs.allocPid()
	// stop ends the child's waits once its stub is gone (watchStub).
	stop := make(chan struct{})
	resetStubLocal(fs.mem, idx)
	cch := newChannel(fs.mem, idx, slotsAddr, fs.done, stop)
	child := g.fork(cch, idx, gpid)
	child.rseqReg, child.forkMask = g.rseqReg, g.affinity()
	if r.flags&cloneFs != 0 && g.pfs != nil {
		child.pfs = g.pfs // CLONE_FS: share root and cwd, so a chroot here reaches the parent
	}
	child.mp = g.mp.forkCopy(fs)
	child.mp.hopPend = h
	g.mp.forkShm(child.mp, g)    // the child inherits the SysV attachments
	g.memUsed.Add(child.mp.used) // the child's copy of the address space draws from the pool

	fs.mu.Lock()
	ppid, sig := g.ps.tgid, r.exitSignal
	if r.flags&lxCloneParent != 0 {
		ppid, sig = g.ps.ppid, g.ps.exitSignal
	}
	ps := g.ps.forkState(gpid, ppid, sig)
	g.cloneNamespaces(ps, gpid, r.flags)
	parentPid := g.ps.ns.seen(ps) // the child's pid as the parent's namespace sees it
	ps.ft = child.ft
	ps.comm[gpid] = g.ps.comm[g.pid]
	var vforkDone chan struct{}
	if r.flags&lxCloneVfork != 0 {
		vforkDone = make(chan struct{})
		ps.vforkDone = vforkDone
	}
	child.ps, child.ppid = ps, ppid
	fs.pt[gpid] = ps
	fs.procs[gpid] = &dproc{ppid: ppid, ch: cch, stop: stop, ps: ps, g: child}
	event := g.ptraceFork(child, r)
	pidfd := int64(-1)
	if r.flags&lxClonePidfd != 0 {
		pidfd = g.newPidfd(ps, false)
	}
	fs.mu.Unlock()
	g.sigFork(child)
	var b [4]byte
	if pidfd >= 0 {
		put32(b[:], uint32(pidfd))
		g.writeMem(r.pidfdAddr, b[:])
	}
	if r.flags&lxCloneParentSetid != 0 {
		put32(b[:], uint32(parentPid))
		g.writeMem(r.ptid, b[:])
	}
	fs.wg.Add(1)
	go serveChild(child)
	// The forking thread saves its context, and its stub's hop thread forks:
	// the child's guest thread resumes from that context (stub.zig forkPrep).
	// CLONE_VFORK also applies when CLONE_VM fell back to a real fork.
	g.ch.reply(repFork)
	if err := g.ch.wait(); err != nil || pg.kind != msgHostRet {
		cch.end()
		g.ch.end()
		return -1
	}
	ret := g.mp.hopP.Load().call(g.ch, hopFork, slotsAddr+uint64(idx*slotSize), hopReqAddr(h.idx), pg.ret, r.stack)
	if ret < 0 {
		cch.end()     // serveChild releases the child that never ran
		fs.freeHop(h) // no process was made to run it
		return fail(lxErrno(-ret))
	}
	// The child's first thread is a copy of the stub's hop thread, where
	// Linux's is a copy of the forking thread: it takes on that one's mask,
	// here for the parent to see once fork returns, and in serveChild before
	// the child runs, which may come first.
	child.forkTid = int(ret)
	setAffinity(child.forkTid, child.forkMask)
	fs.mu.Lock()
	child.ps.mask = child.forkMask
	fs.mu.Unlock()
	if event != 0 {
		g.ptraceEvent(event, uint64(gpid))
	}
	if vforkDone != nil && !g.waitVfork(vforkDone) {
		return -1
	}
	if vforkDone != nil {
		g.ptraceEvent(ptraceEventVforkDone, uint64(gpid))
	}
	pg.ret = uint64(parentPid)
	g.ptraceSyscallExit(int64(pg.ret))
	g.ch.reply(repResult)
	return gpid
}

// serveChild records a fork child's host pid from its first message, then
// runs its syscall loop.
func serveChild(child *dguest) {
	fs := child.dfs
	defer fs.wg.Done()
	ch := child.ch
	if err := ch.wait(); err != nil || ch.page.kind != msgForked {
		child.release()
		fs.forgetProc(child.ps)
		fs.freeSlot(child.slot) // after the registry lets go of it (endServe)
		fs.sigThreadExit(child.pid)
		return
	}
	ospid := int(ch.page.args[0])
	defer fs.freeStubSlot(child.slot, ospid)
	child.mp.pid.Store(int64(ospid))
	fs.adoptHop(ospid, child.mp.hopPend)
	child.mp.hopP.Store(child.mp.hopPend) // the child started it before announcing
	fs.mu.Lock()
	child.ps.ospid, child.ps.checkedIn = ospid, true
	if p := fs.procs[child.pid]; p != nil {
		p.ospid = ospid
	}
	fs.mu.Unlock()
	fs.watchStub(ospid) // after the registry names ospid: its end may come at once
	// A kill that came before the stub checked in found no host process.
	if fs.sigs().killedBy(child.pid) != 0 {
		osKill(ospid)
	}
	child.ptraceChildStart()
	setAffinity(ospid, child.forkMask)
	child.inheritRseq()
	ch.reply(repResult)
	code, err := serveGuest(child)
	endProcess(child, code, err)
}

// endProcess ends a child process whose leader's serve loop returned.
func endProcess(child *dguest, code int, err error) {
	fs := child.dfs
	if err == errLeaderGone {
		// The leader thread exited with others still running; the last one
		// ends the process.
		child.release()
		fs.leaderExited(child, code)
		return
	}
	if fs.superseded(child) {
		child.release()
		fs.mu.Lock()
		child.ps.threads--
		fs.mu.Unlock()
		return
	}
	fs.childDone(child, code, err)
}

func (g *dguest) cloneThread(r cloneReq, cfg Config) int {
	fail := func(e lxErrno) int {
		g.ch.page.ret = errno(e)
		g.ptraceSyscallExit(int64(g.ch.page.ret))
		g.ch.reply(repResult)
		return -1
	}
	fs := g.dfs
	idx := fs.allocSlot()
	if idx < 0 {
		return fail(lxEAGAIN)
	}
	g.mp.mu.Lock()
	mapped := g.mapSlotStacks(idx)
	g.mp.mu.Unlock()
	if !mapped {
		fs.freeSlot(idx)
		return fail(lxENOMEM)
	}
	resetStubLocal(fs.mem, idx)
	holdCloneChild(fs.mem, idx)
	cch := newChannel(fs.mem, idx, slotsAddr, fs.done, g.ch.stop)
	tid := fs.allocPid()
	var ft *ftable
	if r.flags&cloneFiles != 0 {
		ft = g.ft.share()
	} else {
		ft = g.ft.clone()
	}
	child := g.child(cch, idx, tid, ft)
	child.mp = g.mp.share()
	child.isThread = true
	child.tgid = g.tgid
	child.ppid = g.ppid
	child.ps = g.ps
	fs.mu.Lock()
	g.ps.threads++
	g.ps.ns.register(tid)
	nsTid := g.ps.ns.localOf(tid) // the new thread's tid in its namespace
	g.ps.comm[tid] = g.ps.comm[g.pid]
	fs.procs[tid] = &dproc{ospid: g.ps.ospid, ppid: g.pid, ch: cch, stop: fs.procStop(g.ps), ps: g.ps, g: child, thread: true}
	event := g.ptraceFork(child, r)
	fs.mu.Unlock()
	g.sigClone(child)
	var b [4]byte
	put32(b[:], uint32(nsTid))
	if r.flags&lxCloneParentSetid != 0 {
		g.writeMem(r.ptid, b[:])
	}
	if r.flags&lxCloneChildSettid != 0 {
		g.writeMem(r.ctid, b[:])
	}
	if r.flags&lxCloneChildCleartd != 0 {
		g.mp.mu.Lock()
		g.mp.clearTid[tid] = r.ctid
		g.mp.mu.Unlock()
	}
	tls := r.tls
	if r.flags&lxCloneSettls == 0 {
		tls = 0
	}
	atomic.StoreUint32(&cch.page.alive, 1)
	fs.wg.Add(1)
	go serveThread(child)
	// The stub spawns the host thread and reports its tid, which is not used.
	g.ch.clone(r.stack, tls, (slotsAddr + uint64(idx*slotSize)), bootStackTop(idx))
	if event != 0 {
		g.ptraceEvent(event, uint64(tid))
	}
	g.ch.page.ret = uint64(nsTid)
	g.ptraceSyscallExit(int64(g.ch.page.ret))
	g.ch.reply(repResult)
	return tid
}

// procStop is the stop channel of process ps (nil for pid 1, whose waits end
// with the run), kept in each of its entries so whatever finds one of them
// gone or exiting ends the waits of all its threads. The caller holds mu.
func (fs *dfs) procStop(ps *pstate) chan struct{} {
	// After exec, retired siblings can still be unwinding with the old
	// image's (closed) stop channel. New threads belong to the survivor.
	if p := fs.procs[ps.tgid]; p != nil && p.ps == ps {
		return p.stop
	}
	for _, p := range fs.procs {
		if p.ps == ps && p.stop != nil {
			return p.stop
		}
	}
	return nil
}

// serveThread runs a thread's syscall loop and retires it when done.
func serveThread(child *dguest) {
	fs := child.dfs
	defer fs.wg.Done()
	code, err := serveGuest(child)
	// A thread that exited alone is gone already (awaitGone); one that
	// ended its process, or went with it, is gone with the process.
	if child.groupExited() || !child.isThread {
		fs.mu.Lock()
		ospid := child.ps.ospid
		fs.mu.Unlock()
		defer fs.freeStubSlot(child.slot, ospid)
	} else {
		defer fs.freeSlot(child.slot)
	}
	fs.sigThreadExit(child.pid)
	if !child.isThread {
		// It exec'd and became the process's leader.
		endProcess(child, code, err)
		return
	}
	child.ptraceThreadExit(code)
	child.release()
	if fs.threadDone(child.ps, child.pid) {
		fs.finishGroup(child.ps, err)
	}
}

// cloneVMProc creates a child process that shares this one's memory (vfork,
// posix_spawn): a thread of this stub with a process's identity, its own
// pid, fd table (unless CLONE_FILES), signal state and exit status. Its exit
// ends only that thread; an exec first moves it into a stub process of its
// own (vforkExec). With CLONE_VFORK the parent's clone returns only then.
func (g *dguest) cloneVMProc(r cloneReq, cfg Config) int {
	if r.stack == 0 {
		// No stack of its own: the child runs on the caller's, from its sp, as
		// vfork's does. The stub keeps nothing below a thread's sp while it
		// serves its syscall (lc_syscall_entry), so a parent held in vfork
		// loses nothing to the child's use of that stack.
		r.stack = le64(g.mem[g.slot*slotSize+stubSp:])
	}
	fs := g.dfs
	fail := func(e lxErrno) int {
		g.ch.page.ret = errno(e)
		g.ptraceSyscallExit(int64(g.ch.page.ret))
		g.ch.reply(repResult)
		return -1
	}
	if r.flags&lxCloneParent != 0 && g.ps.tgid == 1 {
		return fail(lxEINVAL)
	}
	idx := fs.allocSlot()
	if idx < 0 {
		return fail(lxEAGAIN)
	}
	g.mp.mu.Lock()
	mapped := g.mapSlotStacks(idx)
	g.mp.mu.Unlock()
	if !mapped {
		fs.freeSlot(idx)
		return fail(lxENOMEM)
	}
	gpid := fs.allocPid()
	stop := make(chan struct{})
	resetStubLocal(fs.mem, idx)
	holdCloneChild(fs.mem, idx)
	cch := newChannel(fs.mem, idx, slotsAddr, fs.done, stop)
	var ft *ftable
	if r.flags&cloneFiles != 0 {
		ft = g.ft.share()
	} else {
		ft = g.ft.clone()
	}
	child := g.child(cch, idx, gpid, ft)
	child.pi = g.pi.forked()
	if g.pfs != nil && r.flags&cloneFs == 0 {
		// Without CLONE_FS the child gets its own root and cwd; with it (as the
		// sandbox's chroot helper uses) child() already shares g's, so a chroot
		// there reaches this process too.
		child.pfs = g.pfs.clone()
	}
	child.mp = g.mp.share()

	fs.mu.Lock()
	ppid, sig := g.ps.tgid, r.exitSignal
	if r.flags&lxCloneParent != 0 {
		ppid, sig = g.ps.ppid, g.ps.exitSignal
	}
	ps := g.ps.forkState(gpid, ppid, sig)
	g.cloneNamespaces(ps, gpid, r.flags)
	parentPid := g.ps.ns.seen(ps)
	ps.shared, ps.ospid, ps.checkedIn = true, g.ps.ospid, true
	ps.ft = ft
	ps.comm[gpid] = g.ps.comm[g.pid]
	var vforkDone chan struct{}
	if r.flags&lxCloneVfork != 0 {
		vforkDone = make(chan struct{})
		ps.vforkDone = vforkDone
	}
	child.ps, child.ppid = ps, ppid
	fs.pt[gpid] = ps
	fs.procs[gpid] = &dproc{ospid: g.ps.ospid, ppid: ppid, ch: cch, stop: stop, ps: ps, g: child}
	event := g.ptraceFork(child, r)
	pidfd := int64(-1)
	if r.flags&lxClonePidfd != 0 {
		pidfd = g.newPidfd(ps, false)
	}
	fs.mu.Unlock()
	g.sigFork(child)
	if r.flags&lxCloneVfork == 0 {
		// A CLONE_VM process (not a vfork, which runs briefly on the parent's
		// stack then execs) shares the address space, so it must not inherit the
		// creator's alternate signal stack.
		g.clearAltstack(child)
	}
	var b [4]byte
	if pidfd >= 0 {
		put32(b[:], uint32(pidfd))
		g.writeMem(r.pidfdAddr, b[:])
	}
	if r.flags&lxCloneParentSetid != 0 {
		put32(b[:], uint32(parentPid))
		g.writeMem(r.ptid, b[:])
	}
	tls := r.tls
	if r.flags&lxCloneSettls == 0 {
		tls = 0
	}
	atomic.StoreUint32(&cch.page.alive, 1)
	fs.wg.Add(1)
	go serveVMProc(child)
	g.ch.clone(r.stack, tls, (slotsAddr + uint64(idx*slotSize)), bootStackTop(idx))
	if event != 0 {
		g.ptraceEvent(event, uint64(gpid))
	}
	if vforkDone != nil && !g.waitVfork(vforkDone) {
		return -1
	}
	if vforkDone != nil {
		g.ptraceEvent(ptraceEventVforkDone, uint64(gpid))
	}
	g.ch.page.ret = uint64(parentPid)
	g.ptraceSyscallExit(int64(g.ch.page.ret))
	g.ch.reply(repResult)
	return gpid
}

// waitVfork releases a live parent only when its child has exec'd or exited.
// Cancellation is teardown, never a successful clone return: keep the stub
// from resuming guest code even if endServe has not marked its slot dead yet.
func (g *dguest) waitVfork(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-g.ch.done:
	case <-g.ch.stop:
	}
	g.ch.end()
	return false
}

// serveVMProc runs a CLONE_VM child process's syscall loop.
func serveVMProc(child *dguest) {
	fs := child.dfs
	defer fs.wg.Done()
	code, err := serveGuest(child)
	fs.mu.Lock()
	shared, ospid := child.ps.shared, child.ps.ospid
	fs.mu.Unlock()
	if shared {
		defer fs.freeSlot(child.slot) // its thread is gone (awaitGone)
	} else {
		defer fs.freeStubSlot(child.slot, ospid) // it exec'd into a stub of its own
	}
	fs.sigThreadExit(child.pid)
	fs.childDone(child, code, err)
}

// vforkExec moves a CLONE_VM child about to exec out of its parent's stub:
// its thread there ends, leaving the slot to the new process, which the
// stub's hop thread forks and which announces its host pid on that slot. Its
// next reply is the exec's. The child then has a copy of the parent's memory,
// which the exec replaces.
func (g *dguest) vforkExec() error {
	ch := g.ch
	fs := g.dfs
	h := fs.allocHop()
	if h == nil {
		return errExited
	}
	g.endRseq()
	ch.page.nr = unix.SYS_EXIT
	ch.page.args = [6]uint64{}
	ch.reply(repHost)
	ch.awaitGone()
	// The stack chunks the child is known to have are those mapped before the
	// fork: another thread of the parent may map one while the child announces.
	g.mp.mu.Lock()
	chunks := maps.Clone(g.mp.stackChunks)
	g.mp.mu.Unlock()
	if r := g.mp.hopP.Load().call(ch, hopFork, slotsAddr+uint64(g.slot*slotSize), hopReqAddr(h.idx), 0, 0); r < 0 {
		fs.freeHop(h)
		return errExited
	}
	// A failure below leaves h taken: the child may still run its hop thread.
	if err := ch.wait(); err != nil {
		return err
	}
	if ch.page.kind != msgForked {
		return errExited
	}
	ospid := int(ch.page.args[0])
	old := g.mp
	m := old.forkCopy(fs)
	m.stackChunks = chunks
	m.pid.Store(int64(ospid))
	m.hopPend = h
	fs.adoptHop(ospid, h)
	m.hopP.Store(h) // the child started it before announcing
	g.memUsed.Add(m.used)
	fs.mu.Lock()
	g.mp = m
	g.ps.shared = false
	g.ps.ospid = ospid
	if p := fs.procs[g.pid]; p != nil {
		p.ospid = ospid
	}
	fs.mu.Unlock()
	old.release(g)
	fs.watchStub(ospid)
	return nil
}

// exitShared ends the stub thread a CLONE_VM child process runs on: the
// stub is its parent's, which lives on.
func (g *dguest) exitShared(code int) {
	g.beginExit(code)
	g.endShared(code)
}

// endShared ends that thread without fixing an exit code, for a death by
// signal.
func (g *dguest) endShared(code int) {
	g.endRseq()
	g.ch.page.nr = unix.SYS_EXIT
	g.ch.page.args = [6]uint64{uint64(code)}
	g.ch.reply(repHost)
	g.ch.awaitGone()
	g.unmapOwnStack()
}

// awaitStubGone is where the other hosts wait for an exiting stub process
// to let go of the guest's files before it becomes a zombie. A Linux stub
// holds none, so its end is visible at once; its slot waits (freeStubSlot).
func (fs *dfs) awaitStubGone(ospid int) {}

// freeStubSlot frees slot idx once the stub process ospid that served it is
// gone from the host, so the slot is free of its last reads, and reaps it. It waits on a
// goroutine of its own: a blocking wait here would hold up the parent the
// exit just woke, which runs next on this thread.
func (fs *dfs) freeStubSlot(idx, ospid int) {
	fs.wg.Add(1)
	go fs.awaitFreeSlot(idx, ospid)
}

func (fs *dfs) awaitFreeSlot(idx, ospid int) {
	defer fs.wg.Done()
	if ospid > 0 {
		fs.mu.Lock()
		gone := fs.exited[ospid]
		fs.mu.Unlock()
		if gone != nil {
			<-gone
		}
		if pid, err := unix.Wait4(ospid, nil, 0, nil); pid == ospid || err == unix.ECHILD {
			fs.mu.Lock()
			if fs.exited[ospid] == gone {
				delete(fs.exited, ospid)
			}
			fs.mu.Unlock()
			fs.hopGone(ospid, true)
		}
	}
	fs.freeSlot(idx)
}

// watchStub has stub process ospid's end run stubGone, whatever the cause:
// an exit, a crash or a kill. awaitFreeSlot reaps the stub only after that,
// so its pid cannot name another stub while the registry still holds it.
func (fs *dfs) watchStub(ospid int) {
	gone := make(chan struct{})
	fs.mu.Lock()
	fs.exited[ospid] = gone
	fs.mu.Unlock()
	pfd, err := unix.PidfdOpen(ospid, 0)
	if err != nil {
		osKill(ospid) // unwatchable: end it, so stubGone below is true
	}
	fs.wg.Add(1)
	go func() {
		defer fs.wg.Done()
		if err == nil {
			fds := []unix.PollFd{{Fd: int32(pfd), Events: unix.POLLIN}}
			for {
				if n, err := unix.Poll(fds, -1); n > 0 || err != unix.EINTR {
					break
				}
			}
			unix.Close(pfd)
		}
		fs.hopGone(ospid, false)
		fs.stubGone(ospid)
		close(gone)
	}()
}
