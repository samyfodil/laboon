//go:build darwin

package sandbox

import (
	"crypto/sha256"
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Multi-process support for the macOS backend: fork, execve and wait4.
//
// On Linux the stub forks and the supervisor loads an execve target into the
// stub's address space over the shared memfd. macOS gives the supervisor no
// write view of the stub, so the split is different: the stub still forks (a
// real COW fork, proven to survive the Seatbelt profile), but on execve the
// supervisor only prepares the target — resolves it in the root, computes the
// svc sites, packs the host paths into the process's channel scratch — and the
// stub loads and enters the new program itself (lcExec). The fork/exec reply
// kinds (repFork, repExec) and the MSG_FORKED handshake are the shared ABI.

// cloneVMProc creates a child process that shares this one's memory. Darwin
// cannot share an address space between processes, so the child is a thread
// of this stub with a process's identity: its own pid, fd table (unless
// CLONE_FILES), signal handlers and pending set, and an exit status its
// parent reaps with wait4. Its exit ends only that thread, and an exec moves
// it into a fresh stub of its own (execRespawn).
func (g *dguest) cloneVMProc(r cloneReq, cfg Config) int {
	fs := g.dfs
	fail := func(e lxErrno) int {
		g.ch.page.ret = errno(e)
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
	gpid := fs.allocPid()
	cch := newChannel(fs.mem, idx, 0, fs.done, nil)
	cch.page.state, cch.page.kind, cch.page.stubSleep, cch.page.supSleep, cch.page.rip = 0, 0, 0, 0, 0
	stop := make(chan struct{})
	cch.stop = stop
	var ft *ftable
	if r.flags&cloneFiles != 0 {
		ft = g.ft.share()
	} else {
		ft = g.ft.clone()
	}
	child := g.child(cch, idx, gpid, ft)
	child.pi = g.pi.forked()
	if g.pfs != nil {
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
	ps.shared, ps.ospid, ps.checkedIn = true, g.ps.ospid, true
	ps.ft = ft
	ps.comm[gpid] = g.ps.comm[g.pid]
	var vforkDone chan struct{}
	if r.flags&lxCloneVfork != 0 {
		vforkDone = make(chan struct{})
		ps.vforkDone = vforkDone
	}
	child.ps, child.ppid = ps, ppid
	parentPid := g.ps.ns.seen(ps)
	fs.pt[gpid] = ps
	fs.procs[gpid] = &dproc{ospid: g.ps.ospid, ppid: ppid, ch: cch, stop: stop, ps: ps, g: child}
	event := g.ptraceFork(child, r)
	pidfd := int64(-1)
	if r.flags&lxClonePidfd != 0 {
		pidfd = g.newPidfd(ps, false)
	}
	fs.mu.Unlock()
	g.sigFork(child)
	if pidfd >= 0 {
		var b [4]byte
		put32(b[:], uint32(pidfd))
		g.writeMem(r.pidfdAddr, b[:])
	}

	fs.wg.Add(1)
	go serveVMProc(fs, child, gpid, cfg)

	if cfg.Trace != nil {
		fmt.Fprintf(cfg.Trace, "[clone] vm process pid=%d slotOff=%#x flags=%#x\n", gpid, idx*slotSize, r.flags)
	}
	traced := g.stubTraced()
	g.ch.page.ret = uint64(parentPid)
	g.ch.page.args = [6]uint64{uint64(idx * slotSize), r.flags, r.stack, r.ptid, r.tls, r.ctid}
	g.ch.reply(repClone)
	switch {
	case vforkDone != nil:
		g.vforkHold(vforkDone, uint64(parentPid), event)
	case traced:
		g.cloned(gpid, parentPid, event)
	}
	return gpid
}

// serveVMProc runs a CLONE_VM child process's syscall loop. Like a thread it
// starts straight in the guest (no fork handshake).
func serveVMProc(fs *dfs, child *dguest, gpid int, cfg Config) {
	defer fs.wg.Done()
	defer fs.releaseSlot(child)
	code, err := serveLoop(child, cfg)
	if cfg.Trace != nil {
		fmt.Fprintf(cfg.Trace, "[vm child %d] serveLoop returned code=%d err=%v\n", gpid, code, err)
	}
	if err == errNeverRan {
		child.release()
		fs.forgetProc(child.ps)
		return
	}
	fs.childDone(child, code, err)
}

// forkProc creates a child process. It allocates a channel slot and guest
// pid, builds the child's supervisor state (a copy of this process's fd table
// over the shared filesystem, its pstate), starts the child's serve goroutine,
// and tells the stub to fork onto the child's slot. The stub returns the child
// pid to the parent and 0 to the child; the supervisor replies here, so the
// loop's next wait receives the parent's following syscall.
func (g *dguest) forkProc(r cloneReq, cfg Config) int {
	fs := g.dfs
	if f := r.flags; f&lxCloneParent != 0 && g.ps.tgid == 1 {
		g.ch.page.ret = errno(lxEINVAL)
		g.ch.reply(repResult)
		return -1
	}
	idx := fs.allocSlot()
	if idx < 0 {
		g.ch.page.ret = errno(lxEAGAIN)
		g.ch.reply(repResult)
		return -1
	}
	gpid := fs.allocPid()
	cch := newChannel(fs.mem, idx, 0, fs.done, nil)
	// A reused slot still holds the previous occupant's control state; clear it
	// so this child's first handshake starts clean (stale state/sleep flags
	// would desync the first exchange).
	cch.page.state = 0
	cch.page.kind = 0
	cch.page.stubSleep = 0
	cch.page.supSleep = 0
	cch.page.rip = 0
	// A native child is a fresh stub, a pooled one adopted for it, which gets
	// the parent's memory from the parent stub (sfork.zig) and its file cache
	// on its own pairing. The HVF stub keeps no such cache (file I/O goes
	// through the supervisor) and snapshot-copies its memory itself
	// (forkSpawn), so it shares the (unused) memProc.
	var mp *memProc
	var pooled *pooledStub
	if g.ps.hvf {
		mp = g.mp.share()
	} else if pooled, mp = g.forkTarget(idx, gpid); pooled == nil {
		fs.freeSlot(idx)
		g.ch.page.ret = errno(lxEAGAIN)
		g.ch.reply(repResult)
		return -1
	}
	stop := make(chan struct{})
	cch.stop = stop
	child := g.fork(cch, idx, gpid)
	child.mp = mp
	if !g.ps.hvf {
		g.mp.forkShm(mp, g)
	}

	fs.mu.Lock()
	ppid, sig := g.ps.tgid, r.exitSignal
	if r.flags&lxCloneParent != 0 {
		ppid, sig = g.ps.ppid, g.ps.exitSignal
	}
	ps := g.ps.forkState(gpid, ppid, sig)
	g.cloneNamespaces(ps, gpid, r.flags)
	ps.ft = child.ft
	ps.comm[gpid] = g.ps.comm[g.pid]
	var vforkDone chan struct{}
	if r.flags&lxCloneVfork != 0 {
		vforkDone = make(chan struct{})
		ps.vforkDone = vforkDone
	}
	child.ps, child.ppid = ps, ppid
	parentPid := g.ps.ns.seen(ps) // the child's pid as the parent's namespace sees it
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
	go serveChild(fs, child, gpid, cfg)

	if pooled != nil {
		// Last before the reply: the parent stub takes the child's mailbox
		// from its own as soon as it sees repFork (none if the child died).
		fs.run.broker.sendChild(g.ps.ospid, pooled.cmd.Process.Pid, fs.stubDone)
	}
	// args[0] is the child slot's byte offset from the stub's channel base;
	// the stub adds it to its own mapping base to find the slot after forking.
	g.ch.page.ret = uint64(parentPid)
	g.ch.page.args = [6]uint64{uint64(idx * slotSize), r.flags, r.stack, 0, r.tls, r.ctid}
	g.ch.reply(repFork)
	g.forked(gpid, parentPid, cch, stop, event, vforkDone != nil)
	if vforkDone != nil {
		// The parent stub holds the guest in a pseudo-syscall until the child
		// execs or exits; answer it then.
		g.vforkHold(vforkDone, uint64(parentPid), 0)
	}
	return gpid
}

// cloneThread does the supervisor's share of creating a guest thread (clone
// with CLONE_VM): a fresh channel slot, a thread id, a serve goroutine, and the
// open-file table — shared with CLONE_FILES (which musl pthreads always set) so
// the threads see one another's fds, copied otherwise. The thread itself (the OS
// thread, stack, TLS, the CLONE_*_SETTID / CLEARTID tid words, and later its
// exit and futex wakes) is the stub's; the reply carries the tid, the slot
// offset and the decoded clone arguments.
func (g *dguest) cloneThread(r cloneReq, cfg Config) int {
	fs := g.dfs
	idx := fs.allocSlot()
	if idx < 0 {
		g.ch.page.ret = errno(lxEAGAIN)
		g.ch.reply(repResult)
		return -1
	}
	tid := fs.allocPid()
	cch := newChannel(fs.mem, idx, 0, fs.done, nil)
	cch.page.state, cch.page.kind, cch.page.stubSleep, cch.page.supSleep = 0, 0, 0, 0
	stop := make(chan struct{})
	cch.stop = stop
	var ft *ftable
	if r.flags&cloneFiles != 0 {
		ft = g.ft.share()
	} else {
		ft = g.ft.clone()
	}
	child := g.child(cch, idx, tid, ft)
	child.mp = g.mp.share()
	child.isThread = true
	child.tgid = g.tgid // one thread group: the child's getpid == the process
	child.ppid = g.ppid
	child.ps = g.ps
	fs.mu.Lock()
	g.ps.threads++
	g.ps.ns.register(tid)
	nsTid := g.ps.ns.localOf(tid)
	g.ps.comm[tid] = g.ps.comm[g.pid]
	fs.procs[tid] = &dproc{ospid: g.ps.ospid, ppid: g.pid, ch: cch, stop: stop, ps: g.ps, g: child, thread: true}
	event := g.ptraceFork(child, r)
	fs.mu.Unlock()
	g.sigClone(child)

	fs.wg.Add(1)
	go serveThread(fs, child, tid, cfg)

	if cfg.Trace != nil {
		fmt.Fprintf(cfg.Trace, "[clone] tid=%d slotOff=%#x resume(svc)=%#x flags=%#x\n",
			tid, idx*slotSize, g.ch.page.guestRip, r.flags)
	}
	traced := g.stubTraced()
	g.ch.page.ret = uint64(nsTid)
	g.ch.page.args = [6]uint64{uint64(idx * slotSize), r.flags, r.stack, r.ptid, r.tls, r.ctid}
	g.ch.reply(repClone)
	if traced {
		g.cloned(tid, tid, event)
	}
	return tid
}

// serveThread runs a guest thread's syscall loop. A clone child does not do the
// fork handshake (it resumes straight into the guest), so its first message is
// a syscall; serveLoop's leading wait receives it.
func serveThread(fs *dfs, child *dguest, tid int, cfg Config) {
	defer fs.wg.Done()
	defer fs.releaseSlot(child)
	code, err := serveLoop(child, cfg)
	if cfg.Trace != nil {
		fmt.Fprintf(cfg.Trace, "[thread %d] serveLoop returned code=%d err=%v\n", tid, code, err)
	}
	fs.sigThreadExit(tid)
	if !child.isThread {
		// It exec'd and became the process's leader (takeOverGroup).
		fs.endProcess(child, code, err)
		return
	}
	if err == nil && child.groupExited() {
		fs.awaitStubGone(child.ps.ospid) // this thread ran exit_group
	}
	child.ptraceThreadExit(code)
	child.release()
	if fs.threadDone(child.ps, tid) {
		fs.finishGroup(child.ps, err)
	}
}

// forkTarget takes a pooled stub (or starts one) to be the native fork
// child on slot idx: it gets the parent's file cache record and moves to the
// slot, where it waits for the parent stub's memory. nil if none could be had.
func (g *dguest) forkTarget(idx, gpid int) (*pooledStub, *memProc) {
	fs := g.dfs
	p := fs.takePooled()
	if p == nil {
		if p = fs.startPooled(); p == nil {
			return nil, nil
		}
	}
	if g.mp.adopt(p.mp, g) != nil {
		p.mu.Lock()
		p.released = true // ours to end
		p.mu.Unlock()
		p.cmd.Process.Kill()
		unix.Close(p.mp.sock)
		fs.freeSlot(p.slot)
		return nil, nil
	}
	if !p.assignFork(fs, idx, g.ps.ospid, gpid) {
		p.cmd.Process.Kill()
		return nil, nil
	}
	return p, p.mp
}

// nrChildStop is a traced new thread's report before its first instruction,
// where it takes the stop an auto-attached tracee starts with.
const nrChildStop = 0x1_0000_0004

// forked takes the parent stub's report of the fork, so that a child that
// dies before it checks in is still seen to end, and answers it with the
// fork's result (ret, the child's pid), after a tracer's fork event and
// syscall-exit stops; a vfork's exit stop comes when its hold ends. If the
// parent stub dies first, the child's pid it stored in the child slot's rip
// tells whether the fork happened: if not, the child's serve goroutine
// (holding a copy of the parent's fds) is released rather than left waiting.
func (g *dguest) forked(gpid, ret int, cch *channel, stop chan struct{}, event int, vfork bool) {
	fs := g.dfs
	var pid int
	reported := g.ch.wait() == nil
	if reported {
		if g.ch.page.nr != nrForked {
			return // not the report: left posted for the serve loop
		}
		pid = int(g.ch.page.args[0])
		if pid <= 0 {
			g.ch.page.ret = 0
			g.ch.reply(repResult)
			return // no child: the stub retired its slot
		}
	} else if pid = int(atomic.LoadUint64(&cch.page.rip)); pid <= 0 {
		fs.endServe(gpid, stop, cch) // the parent died before it forked
		return
	}
	fs.mu.Lock()
	if p := fs.procs[gpid]; p != nil && p.ospid == 0 {
		p.ospid = pid
	}
	fs.mu.Unlock()
	fs.watchStub(pid)
	if !reported {
		return
	}
	if event != 0 {
		g.ptraceEvent(event, uint64(gpid))
	}
	g.ch.page.ret = uint64(ret)
	if !vfork {
		g.ptraceSyscallExit(int64(ret))
	}
	g.ch.reply(repResult)
}

// stubTraced reports whether g's stub reports a clone: it does while its
// slot's stdio word carries the traced bit.
func (g *dguest) stubTraced() bool {
	return atomic.LoadUint64(&g.ch.page.stdio)&stdioTraced != 0
}

// serveChild completes the fork handshake (recording the child stub's real OS
// pid), releases the child stub to resume the guest, then runs the child's
// syscall loop. When the process is gone it drops its fds (closing pipe ends
// its parent may be reading) and becomes a zombie for wait4.
func serveChild(fs *dfs, child *dguest, gpid int, cfg Config) {
	defer fs.wg.Done()
	defer fs.releaseSlot(child)
	ch := child.ch
	if err := ch.wait(); err != nil || ch.page.kind != msgForked {
		child.release()
		fs.forgetProc(child.ps)
		return
	}
	ospid := int(ch.page.args[0])
	fs.mu.Lock()
	child.ps.ospid = ospid
	child.ps.checkedIn = true
	if p := fs.procs[gpid]; p != nil {
		p.ospid = ospid
	}
	fs.mu.Unlock()
	fs.watchStub(ospid) // unless the parent's report (forked) did already
	if cfg.Trace != nil {
		fmt.Fprintf(cfg.Trace, "[child %d] forked, ospid=%d slot=%d\n", gpid, ospid, child.slot)
	}
	child.ptraceChildStart()
	fs.mu.Lock()
	pp := fs.procs[child.ppid]
	fs.mu.Unlock()
	if pp != nil {
		fs.forkCode(pp.ospid, ospid)
	}
	ch.reply(repResult) // release the child stub to resume the guest
	code, err := serveLoop(child, cfg)
	if cfg.Trace != nil {
		fmt.Fprintf(cfg.Trace, "[child %d] serveLoop returned code=%d err=%v\n", gpid, code, err)
	}
	fs.childDone(child, code, err)
}

// writeExecSites computes the svc sites for a host ELF and writes them to a
// temp file the stub reads during lcExec. The file is deleted at end of run
// (the stub reads it after the repExec reply), not inline.
// One file serves every exec of the same program in a run.
func (g *dguest) writeExecSites(host string) (string, error) {
	sites, err := computeSites(g.cfg.Cache, host)
	if err != nil {
		return "", err
	}
	b := make([]byte, 4*len(sites))
	for i, s := range sites {
		put32(b[4*i:], s)
	}
	key := sha256.Sum256(b)
	fs := g.dfs
	fs.mu.Lock()
	path, ok := fs.run.sites[key]
	fs.mu.Unlock()
	if ok {
		return path, nil
	}
	path, _, err = writeSites(g.dfs.tmpDir, sites)
	if err != nil {
		return "", err
	}
	fs.addTmp(path)
	fs.mu.Lock()
	if fs.run.sites == nil {
		fs.run.sites = map[[32]byte]string{}
	}
	fs.run.sites[key] = path
	fs.mu.Unlock()
	return path, nil
}

// packStrings writes NUL-terminated strings into buf, returning false if they
// do not fit.
func packStrings(buf []byte, strs []string) bool {
	off := 0
	for _, s := range strs {
		if off+len(s)+1 > len(buf) {
			return false
		}
		copy(buf[off:], s)
		buf[off+len(s)] = 0
		off += len(s) + 1
	}
	return true
}
