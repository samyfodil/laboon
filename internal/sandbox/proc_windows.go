//go:build windows

package sandbox

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"path"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// Processes on Windows: threads, fork, CLONE_VM children (vfork,
// posix_spawn), execve and exit. See windows/DESIGN.md §8.
//
//   - A thread is an NtCreateThreadEx thread of its process's stub.
//   - fork clones the stub with RtlCloneUserProcess. The child inherits the
//     channel view, the shared sections and the slot's channel events, which
//     the supervisor duplicated into the parent as inheritable handles; it
//     takes its own slot and reports with MSG_FORKED.
//   - A CLONE_VM child (vfork, posix_spawn) runs as a thread of its parent's
//     stub with a process's identity until it execs or exits.
//   - execve starts a fresh stub on the process's slot and loads the program
//     from outside, as the first stub of a run is; the old stub (or a CLONE_VM
//     child's thread) is ended first.

// lcForked is a parent stub's report after RtlCloneUserProcess: args[0] is
// the child's OS pid (0 if the clone failed), args[1] the NTSTATUS.
const lcForked = 0x4c430025

// processAllAccess is PROCESS_ALL_ACCESS as winnt.h has it: x/sys's lacks
// SYNCHRONIZE and the standard rights, so its handle cannot be waited on.
const processAllAccess = 0x1fffff

// lcFault is the stub's report of a guest fault with no handler (signo,
// address, pc): the process ends as killed by that signal.
const lcFault = 0x4c430022

// serveGuest runs one guest thread's syscall loop (a process leader, a
// thread, a CLONE_VM child). Signals, futexes, memory and sleeps are handled
// in the stub; the loop serves the rest and the control messages: faults,
// clone and fork, execve, thread and process exit, default actions.
func serveGuest(dg *dguest) (int, error) {
	ch := dg.ch
	finishIO, err := ch.startIO()
	if err != nil {
		return 0, err
	}
	defer finishIO()
	dg.attachStdio()
	defer dg.detachStdio()
	for {
		if err := ch.wait(); err != nil {
			return 0, err // raw errExited: the caller maps it to killedBy / the group exit code
		}
		w := dg.mp.w
		pg := ch.page
		if pg.kind == msgThreadId {
			winRegisterThread(dg.sigs(), dg.pid, uint32(pg.args[0]), w.st)
			dg.ptraceChildStart() // before its first instruction
			ch.reply(repResult)
			continue
		}
		if pg.kind == msgTraceLocal {
			// A syscall the stub already served in-guest. Run the entry and
			// exit stops so a tracer observes it; ptraceSyscallExit leaves the
			// (possibly edited) result in pg.ret, which the stub reads back.
			dg.ptraceEnter(pg.nr, pg.args)
			dg.ptraceSyscallExit(int64(pg.ret))
			ch.reply(repResult)
			continue
		}
		if pg.kind != msgSyscall {
			return 0, errProtocol
		}
		nr, a := pg.nr, pg.args
		dg.noteOut(pg.ret)
		// ptrace syscall-entry stop: a traced thread blocks here until the
		// tracer resumes it, which may edit its registers.
		if !dg.ptraceEnter(nr, a) {
			pg.ret = errno(lxEINTR)
			ch.reply(repResult)
			continue
		}
		if pg.nr != nr || pg.args != a {
			dg.outW = ^uint64(0) // a tracer's edit: the stub measured other arguments
		}
		nr, a = pg.nr, pg.args
		gnr, _, generic := toGeneric(nr, a)
		switch {
		case nr == lcFault:
			sig := int(a[0])
			w.tracef("[lc] [%d] signal %d: fault at %#x, pc %#x\n", dg.pid, sig, a[1], a[2])
			dg.sigDie(sig)
			if !dg.isThread && dg.sharedStub() {
				return -sig, dg.endSharedThread()
			}
			windows.TerminateProcess(w.sp.proc, uint32(128+sig))
			windows.WaitForSingleObject(w.sp.proc, windows.INFINITE)
			return 0, errExited
		case nr == nrThreadGone:
			code := int(int32(a[0]))
			w.tracef("[lc] [%d] thread exit code=%d\n", dg.pid, code)
			if !dg.isThread && !dg.sharedStub() {
				return code, errLeaderGone
			}
			return code, nil
		case nr == nrForked: // a traced clone's report no one waited for (the trace began meanwhile)
			pg.ret = a[0]
			ch.reply(repResult)
		case nr == lxSigDie:
			sig := int(a[0])
			w.tracef("[lc] [%d] signal %d: default-action exit\n", dg.pid, sig)
			if !dg.isThread && dg.sharedStub() {
				return dg.sigDie(sig), dg.endSharedThread()
			}
			dg.sigDie(sig)
			pg.ret = 0
			ch.reply(repResult) // the stub terminates the process
		case nr == lxSigStop:
			dg.sigStopSelf(int(a[0]))
			pg.ret = 0
			ch.reply(repResult)
		case nr >= lxSigTake && nr <= lxSigRaise:
			pg.ret = uint64(dg.sigCall(nr, a))
			ch.reply(repResult)
		case generic && (gnr == lxClone || gnr == lxClone3):
			_, ga, _ := toGeneric(nr, a)
			var r cloneReq
			var e lxErrno
			if gnr == lxClone {
				r, e = cloneArgs(ga)
			} else {
				r, e = dg.clone3Args(ga[0], ga[1])
			}
			if e != 0 {
				pg.ret = errno(e)
				ch.reply(repResult)
				break
			}
			id := dg.clone(r, dg.cfg)
			w.tracef("[lc] [%d] clone(%#x) = %d\n", dg.pid, r.flags, id)
		case generic && (gnr == lxExecve || gnr == lxExecveat):
			_, ga, _ := toGeneric(nr, a)
			var ok bool
			var err error
			if gnr == lxExecve {
				ok, err = execve(dg, lxAtFdcwd, ga[0], ga[1], ga[2], 0)
			} else {
				ok, err = execve(dg, int64(int32(ga[0])), ga[1], ga[2], ga[3], int64(int32(ga[4])))
			}
			if err != nil {
				return 0, err
			}
			if !ok {
				ch.reply(repResult) // errno in page.ret; the guest goes on
			}
		case nr == wExit || nr == wExitGroup:
			code := int(a[0] & 0xff)
			w.tracef("[lc] [%d] exit(%d)\n", dg.pid, code)
			dg.ptraceEvent(ptraceEventExit, uint64(code<<8))
			dg.beginExit(code)
			if !dg.isThread && dg.sharedStub() {
				return code, dg.endSharedThread()
			}
			windows.TerminateProcess(w.sp.proc, uint32(code))
			windows.WaitForSingleObject(w.sp.proc, windows.INFINITE)
			return code, nil
		default:
			r := w.syscall(dg, nr, a)
			w.tracef("[lc] [%d] %d(%#x, %#x, %#x) = %d\n", dg.pid, nr, a[0], a[1], a[2], r)
			pg.ret = uint64(r)
			if isRealSyscall(nr) {
				dg.ptraceSyscallExit(r) // a stub's own request has no stops, as on entry
			}
			ch.reply(repResult)
		}
	}
}

// newStubChan sets up channel slot idx for a new thread or process of the
// stub proc: a fresh event pair, duplicated into the stub (inheritable for a
// fork, whose child takes them over), their values left in the slot's
// stdio/pinfo fields for the stub to adopt. The channel holds its own handle
// to proc: the process's stubProc may close its handle while this thread is
// still served.
func newStubChan(fs *dfs, idx int, proc windows.Handle, inherit bool) (*hostChan, error) {
	cch := &hostChan{channel: newChannel(fs.mem, idx, 0, fs.done, nil)}
	pg := cch.page
	pg.state, pg.kind, pg.stubSleep, pg.supSleep, pg.rip, pg.alive = 0, 0, 0, 0, 0, 0
	var err error
	if cch.evStub, err = windows.CreateEvent(nil, 0, 0, nil); err != nil {
		return nil, err
	}
	if cch.evSup, err = windows.CreateEvent(nil, 0, 0, nil); err != nil {
		windows.CloseHandle(cch.evStub)
		return nil, err
	}
	cur := windows.CurrentProcess()
	var dStub, dSup windows.Handle
	err1 := windows.DuplicateHandle(cur, cch.evStub, proc, &dStub, 0, inherit, windows.DUPLICATE_SAME_ACCESS)
	err2 := windows.DuplicateHandle(cur, cch.evSup, proc, &dSup, 0, inherit, windows.DUPLICATE_SAME_ACCESS)
	err3 := cch.setProc(proc)
	if err1 != nil || err2 != nil || err3 != nil {
		cch.closeEvents()
		return nil, errors.Join(err1, err2, err3)
	}
	pg.stdio, pg.pinfo = uint64(dStub), uint64(dSup)
	return cch, nil
}

// setProc points the channel at proc through a handle of its own.
func (c *hostChan) setProc(proc windows.Handle) error {
	cur := windows.CurrentProcess()
	var h windows.Handle
	if err := windows.DuplicateHandle(cur, proc, cur, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return err
	}
	c.closeProc()
	c.proc, c.ownProc = h, true
	return nil
}

func (c *hostChan) closeEvents() {
	windows.CloseHandle(c.evStub)
	windows.CloseHandle(c.evSup)
	c.closeProc()
}

func (c *hostChan) closeProc() {
	if c.ownProc {
		windows.CloseHandle(c.proc)
		c.proc, c.ownProc = 0, false
	}
}

// cloneThread creates a guest thread: a channel slot, a tid, its signal
// records and channel events, then a serve goroutine. The REP_CLONE reply
// hands the stub the slot offset and the clone arguments so it can
// NtCreateThreadEx.
func (g *dguest) cloneThread(r cloneReq, cfg Config) int {
	fail := func(e lxErrno) int {
		g.ch.page.ret = errno(e)
		g.ch.reply(repResult)
		return -1
	}
	fs := g.dfs
	idx := fs.allocSlot()
	if idx < 0 {
		return fail(lxEAGAIN)
	}
	cch, err := newStubChan(fs, idx, g.ch.proc, false)
	if err != nil {
		fs.freeSlot(idx)
		return fail(lxEAGAIN)
	}
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
	g.ps.comm[tid] = g.ps.comm[g.pid]
	fs.procs[tid] = &dproc{ospid: g.ps.ospid, ppid: g.pid, ch: cch, ps: g.ps, g: child, thread: true}
	event := g.ptraceFork(child, r)
	fs.mu.Unlock()
	g.sigClone(child)

	fs.wg.Add(1)
	go serveThread(child)

	traced := g.stubTraced()
	g.ch.page.ret = uint64(tid)
	g.ch.page.args = [6]uint64{uint64(idx * slotSize), r.flags, r.stack, r.ptid, r.tls, r.ctid}
	g.ch.reply(repClone)
	if traced {
		g.cloned(tid, tid, event)
	}
	return tid
}

// serveThread runs a thread's syscall loop and retires it when done.
func serveThread(child *dguest) {
	fs := child.dfs
	defer fs.wg.Done()
	defer fs.freeSlot(child.slot)
	defer child.ch.closeEvents()
	code, err := serveGuest(child)
	fs.sigThreadExit(child.pid)
	winUnregisterThread(fs.sigs(), child.pid)
	if !child.isThread {
		// It exec'd and became the process's leader (takeOverGroup).
		endWinProcess(child, code, err)
		return
	}
	child.ptraceThreadExit(code)
	child.release()
	if fs.threadDone(child.ps, child.pid) {
		fs.finishGroup(child.ps, err)
	}
}

// cloneVMProc creates a child process that shares this one's memory (vfork,
// posix_spawn): a thread of this stub with a process's identity, its own pid,
// fd table (unless CLONE_FILES), signal handlers and pending set, and an exit
// status its parent reaps. Its exit ends only that thread; an exec moves it
// into a fresh stub of its own. With CLONE_VFORK the parent is held until
// then; the stub parks the parent off the shared stack.
func (g *dguest) cloneVMProc(r cloneReq, cfg Config) int {
	if w := g.mp.w; w != nil {
		w.run.fill(g.dfs) // a new process is likely to exec
	}
	fail := func(e lxErrno) int {
		g.ch.page.ret = errno(e)
		g.ch.reply(repResult)
		return -1
	}
	fs := g.dfs
	if r.flags&lxCloneParent != 0 && g.ps.tgid == 1 {
		return fail(lxEINVAL)
	}
	idx := fs.allocSlot()
	if idx < 0 {
		return fail(lxEAGAIN)
	}
	cch, err := newStubChan(fs, idx, g.ch.proc, false)
	if err != nil {
		fs.freeSlot(idx)
		return fail(lxEAGAIN)
	}
	gpid := fs.allocPid()
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
	fs.procs[gpid] = &dproc{ospid: g.ps.ospid, ppid: ppid, ch: cch, ps: ps, g: child}
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
	go serveVMProc(child)

	traced := g.stubTraced()
	g.ch.page.ret = uint64(gpid)
	g.ch.page.args = [6]uint64{uint64(idx * slotSize), r.flags, r.stack, r.ptid, r.tls, r.ctid}
	g.ch.reply(repClone)
	switch {
	case vforkDone != nil:
		g.vforkHold(vforkDone, uint64(gpid), event)
	case traced:
		g.cloned(gpid, gpid, event)
	}
	return gpid
}

// stubTraced reports whether g's stub reports a clone: it does while its
// slot carries the traced bit.
func (g *dguest) stubTraced() bool {
	return atomic.LoadUint32(&g.ch.page.alive)&winTraced != 0
}

// serveVMProc runs a CLONE_VM child process's syscall loop; like a thread it
// starts straight in the guest.
func serveVMProc(child *dguest) {
	fs := child.dfs
	defer fs.wg.Done()
	defer fs.freeSlot(child.slot)
	defer child.ch.closeEvents()
	code, err := serveGuest(child)
	winUnregisterThread(fs.sigs(), child.pid)
	endWinProcess(child, code, err)
}

// forkProc forks the process. The supervisor sets up the child (slot, pid,
// fd table, signal records) and replies REP_FORK; the stub clones itself
// with RtlCloneUserProcess and reports the child's OS pid (lcForked), which
// the supervisor opens before the parent's fork returns. The child takes
// over its slot and checks in with MSG_FORKED.
func (g *dguest) forkProc(r cloneReq, cfg Config) int {
	if w := g.mp.w; w != nil {
		w.run.fill(g.dfs) // a new process is likely to exec
	}
	fs := g.dfs
	pg := g.ch.page
	fail := func(e lxErrno) int {
		pg.ret = errno(e)
		g.ch.reply(repResult)
		return -1
	}
	if r.flags&lxCloneParent != 0 && g.ps.tgid == 1 {
		return fail(lxEINVAL)
	}
	w := g.mp.w
	idx := fs.allocSlot()
	if idx < 0 {
		return fail(lxEAGAIN)
	}
	cch, err := newStubChan(fs, idx, w.sp.proc, true)
	if err != nil {
		fs.freeSlot(idx)
		return fail(lxEAGAIN)
	}
	gpid := fs.allocPid()
	child := g.fork(cch, idx, gpid)
	child.mp = newMemProc()
	cw := &wguest{run: w.run, cfg: w.cfg, cache: w.cache, entry: w.entry, exitEntry: w.exitEntry, segs: w.segs, traps: w.traps.clone()}
	w.anon.cloneInto(&cw.anon)
	child.mp.w = cw
	child.mp.forkBacking(g.mp) // the child inherits the shared mappings; keep their backings live

	fs.mu.Lock()
	ppid, sig := g.ps.tgid, r.exitSignal
	if r.flags&lxCloneParent != 0 {
		ppid, sig = g.ps.ppid, g.ps.exitSignal
	}
	ps := g.ps.forkState(gpid, ppid, sig)
	ps.ft = child.ft
	ps.comm[gpid] = g.ps.comm[g.pid]
	child.ps, child.ppid = ps, ppid
	fs.pt[gpid] = ps
	fs.procs[gpid] = &dproc{ppid: ppid, ch: cch, ps: ps, g: child}
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
		put32(b[:], uint32(gpid))
		g.writeMem(r.ptid, b[:])
	}
	abandon := func() {
		child.release()
		fs.forgetProc(ps)
		fs.sigThreadExit(gpid)
		cch.closeEvents()
		fs.freeSlot(idx)
	}

	pg.ret = uint64(gpid)
	pg.args = [6]uint64{uint64(idx * slotSize), r.flags, r.stack, 0, r.tls, r.ctid}
	g.ch.reply(repFork)
	if err := g.ch.wait(); err != nil {
		abandon()
		return -1 // the parent stub is gone; the serve loop sees it next
	}
	if pg.kind == msgSyscall && pg.nr == lcForkQuiesce {
		defer quiesceFork(fs.sigs(), w.st, g.pid)()
		pg.ret = 0
		g.ch.reply(repResult)
		if err := g.ch.wait(); err != nil {
			abandon()
			return -1
		}
	}
	if pg.kind != msgSyscall || pg.nr != lcForked {
		abandon()
		return fail(lxEAGAIN)
	}
	ospid, status := uint32(pg.args[0]), uint32(pg.args[1])
	if ospid == 0 {
		w.tracef("[lc] [%d] RtlCloneUserProcess: %#x\n", g.pid, status)
		abandon()
		return fail(lxEAGAIN)
	}
	h, err := windows.OpenProcess(processAllAccess, false, ospid)
	if err != nil {
		abandon()
		return fail(lxEAGAIN)
	}
	cw.sp = &stubProc{proc: h}
	cw.st = w.st.forked(h)
	if err := cch.setProc(h); err != nil {
		windows.TerminateProcess(h, 128+9)
		cw.sp.close()
		abandon()
		return fail(lxEAGAIN)
	}
	fs.mu.Lock()
	ps.ospid, ps.checkedIn = int(ospid), true
	if p := fs.procs[gpid]; p != nil {
		p.ospid = int(ospid)
	}
	fs.mu.Unlock()
	fs.watchStub(int(ospid), h)
	w.run.code.fork(g.ps.ospid, int(ospid)) // the files it maps as its parent does
	fs.wg.Add(1)
	go serveChild(child)
	w.tracef("[lc] [%d] fork: pid %d, ospid %d\n", g.pid, gpid, ospid)
	if event != 0 {
		g.ptraceEvent(event, uint64(gpid))
	}
	pg.ret = uint64(gpid)
	g.ptraceSyscallExit(int64(gpid))
	g.ch.reply(repResult)
	return gpid
}

// serveChild completes a fork child's check-in (it reports its OS thread id),
// releases it into the guest and runs its syscall loop.
func serveChild(child *dguest) {
	fs := child.dfs
	defer fs.wg.Done()
	defer fs.freeSlot(child.slot)
	defer child.ch.closeEvents()
	ch := child.ch
	w := child.mp.w
	if err := ch.wait(); err != nil || ch.page.kind != msgForked {
		var code uint32
		windows.GetExitCodeProcess(w.sp.proc, &code)
		w.tracef("[lc] [%d] fork child never checked in: %v, status %#x\n", child.pid, err, code)
		windows.TerminateProcess(w.sp.proc, 128+9)
		w.sp.close()
		child.release()
		fs.forgetProc(child.ps)
		fs.sigThreadExit(child.pid)
		return
	}
	winRegisterThread(fs.sigs(), child.pid, uint32(ch.page.args[1]), w.st)
	w.tracef("[lc] [%d] fork child checked in\n", child.pid)
	child.ptraceChildStart()
	ch.reply(repResult)
	code, err := serveGuest(child)
	winUnregisterThread(fs.sigs(), child.pid)
	endWinProcess(child, code, err)
}

// endWinProcess ends a child process whose leader's serve loop returned, and
// closes its stub's handles unless the stub is its parent's.
func endWinProcess(child *dguest, code int, err error) {
	fs := child.dfs
	if err == errLeaderGone {
		// The leader thread exited with others still running; the last one
		// ends the process (finishGroup).
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
	shared := child.sharedStub()
	if errors.Is(err, errExited) && fs.sigs().killedBy(child.tgid) == 0 && child.mp.w != nil && child.mp.w.sp != nil {
		var st uint32
		windows.GetExitCodeProcess(child.mp.w.sp.proc, &st)
		child.mp.w.tracef("[lc] [%d] stub ended without an exit: status %#x\n", child.pid, st)
	}
	fs.childDone(child, code, err)
	if !shared && child.mp.w != nil && child.mp.w.sp != nil {
		child.mp.dropBackings(fs) // the address space is gone: release its shared backings
		child.mp.w.sp.close()
	}
}

// readImage reads all of the program, with its file identity.
func (g *dguest) readImage(s execSrc) (imageSrc, lxErrno) {
	f := s.f
	if f == nil {
		rp, e := g.resolve(s.gp, true)
		if e != 0 {
			return imageSrc{}, e
		}
		if f, e = g.openFile(rp); e != 0 {
			return imageSrc{}, e
		}
		defer f.Close()
	}
	fi, err := fileStat(f)
	if err != nil {
		return imageSrc{}, osErrno(err)
	}
	b := make([]byte, fi.Size())
	n, err := f.ReadAt(b, 0)
	if err != nil && err != io.EOF {
		return imageSrc{}, osErrno(err)
	}
	b = b[:n]
	id, ok := fileIdentity(f)
	return imageSrc{data: b, id: id, hasID: ok}, 0
}

// winArgMax bounds what an execve's argv and envp may hold together: the
// initial stack is 8 MiB.
const winArgMax = 2 << 20

// execve runs an execve for dg. It returns true once the new program runs in
// a fresh stub on dg's slot (its first syscall is the next message), false
// with the errno in page.ret when it fails before the point of no return. An
// error means the process died past that point.
func execve(dg *dguest, dirfd int64, pathAddr, argvAddr, envpAddr uint64, flags int64) (bool, error) {
	pg := dg.ch.page
	fail := func(e lxErrno) (bool, error) {
		pg.ret = errno(e)
		return false, nil
	}
	t, e := dg.execTarget(dirfd, pathAddr, argvAddr, flags)
	if e != 0 {
		return fail(e)
	}
	argv, e := dg.readArgv(argvAddr)
	if e != 0 {
		return fail(e)
	}
	envv, e := dg.readArgv(envpAddr)
	if e != 0 {
		return fail(e)
	}
	argv = append(t.prefix, argv[min(int(t.skip), len(argv)):]...)
	if len(argv) == 0 {
		argv = []string{""} // Linux runs an argv-less exec with argv = { "" }
	}
	total := 0
	for _, a := range append(argv, envv...) {
		if len(a) >= maxArgStrlen {
			return fail(lxE2BIG)
		}
		total += len(a) + 1 + 8
	}
	if total > winArgMax {
		return fail(lxE2BIG)
	}
	src, e := dg.readImage(t.src)
	if e != 0 {
		return fail(e)
	}
	if e := execPreflight(dg, src.data); e != 0 {
		return fail(e)
	}

	// Past the point of no return.
	fs := dg.dfs
	old := dg.mp.w
	shared := dg.sharedStub()
	dg.closeExec()
	execHook(dg)
	fs.mu.Lock()
	for _, p := range fs.procs {
		if p.ps == dg.ps {
			p.ospid = 0 // the old stub's end must not end the process (takeOverGroup retires its threads); boot names the new one
		}
	}
	fs.mu.Unlock()
	if shared {
		if err := dg.endSharedThread(); err != nil {
			return true, err
		}
		dg.mp = newMemProc()
	} else {
		ru := hostRusage(dg.ps.ospid)
		windows.TerminateProcess(old.sp.proc, 0)
		windows.WaitForSingleObject(old.sp.proc, windows.INFINITE)
		fs.mu.Lock()
		dg.ps.ruPrev = dg.ps.ruPrev.plus(ru)
		fs.mu.Unlock()
	}
	fs.mu.Lock()
	dg.ps.shared, dg.ps.forked = false, false
	fs.mu.Unlock()
	oldTid := dg.ptraceExecTid()
	dg.takeOverGroup()
	dg.execDone(path.Base(t.gp))
	dg.noteExec(t.gp, t.gp, argv, nil)
	// A tracer sees the exec stop and the call's exit with the new image in
	// place, before its first instruction.
	w, err := old.run.boot(dg, src, argv, envv, func(entry, sp uint64) { dg.ptraceExec(oldTid, entry, sp) })
	if !shared {
		old.sp.close()
	}
	if err != nil {
		w.tracef("[lc] [%d] exec: %v\n", dg.pid, err)
		fs.setKillSig(dg.ps.tgid, lxSigkill)
		if w != nil && w.sp != nil {
			windows.TerminateProcess(w.sp.proc, 128+9)
		}
		return true, errExited
	}
	w.tracef("[lc] [%d] exec %s\n", dg.pid, t.gp)
	// A kill that came while the process had no stub found nothing to kill.
	if fs.sigs().killedBy(dg.ps.tgid) != 0 {
		windows.TerminateProcess(w.sp.proc, 128+9)
	}
	return true, nil
}

// execPreflight fails an execve the kernel would refuse before the point of
// no return: an ELF that cannot be loaded, or a missing interpreter.
func execPreflight(dg *dguest, data []byte) lxErrno {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || f.Machine != elfMachine || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
		return lxENOEXEC
	}
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		if p.Filesz == 0 || p.Off+p.Filesz > uint64(len(data)) {
			return lxENOEXEC
		}
		ip := string(bytes.TrimRight(data[p.Off:p.Off+p.Filesz], "\x00"))
		rp, e := dg.resolve(ip, true)
		if e != 0 {
			return e
		}
		if _, e := dg.lstatGuest(rp); e != 0 {
			return e
		}
	}
	return 0
}

func (g *wguest) tracef(format string, a ...any) {
	if g != nil && g.cfg.Trace != nil {
		fmt.Fprintf(g.cfg.Trace, format, a...)
	}
}
