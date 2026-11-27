package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// The Linux host of the shared layer. Each guest process is a stub process
// (stub/zig) whose guest code runs natively with its syscalls rewritten; the
// stub posts every syscall it does not serve itself (stdio on the fast path)
// on its thread's channel slot, and the supervisor answers from the shared
// table. The supervisor shapes the stub's memory (mem_linux.go,
// mmap_linux.go) and loads its images (load_linux.go): the stub only runs
// the host syscalls it is asked for (REP_HOST).

// runInfo is what starting and serving the run's stub processes needs.
type runInfo struct {
	stubFile *os.File    // the stub binary (a memfd)
	chanFile *os.File    // the shared channel region (a memfd), the stubs' fd 3
	life     *os.File    // the stubs' fd 4: EOF when the supervisor is gone
	entryOff stubEntries // the stub entry-point offsets from its image base
	entry    uint64      // lc_syscall_entry's absolute address, resolved at boot
	entryGs  uint64      // lc_syscall_entry_gs's, the %gs-anchor fast path
	latekick uint64      // lc_latekick's, the %gs-anchor late-kick delivery
	pgid     int

	xferMu  sync.Mutex
	xfer    *os.File // the supervisor's end of the stubs' fd 5 (fdpass)
	xferSeq uint64   // the last descriptor sent on it, by number (passFd)

	mu     sync.Mutex
	images map[preparedKey]*image // prepared images by file, see loadELF
}

// Run executes the ELF program at path and returns its exit status. With
// Config.Root set, path and the program's interpreter are looked up there.
func Run(ctx context.Context, prog string, cfg Config) (int, error) {
	if len(cfg.Args) == 0 {
		cfg.Args = []string{prog}
	}
	if cfg.Env == nil {
		cfg.Env = []string{} // a nil env is empty, never the supervisor's own
	}
	if cfg.Cache == nil {
		cfg.Cache = defaultCache()
	}
	cfg.Trace = syncTrace(cfg.Trace)
	entryOff, err := stubEntry()
	if err != nil {
		return 0, err
	}

	chanFd, err := unix.MemfdCreate("lc-chan", unix.MFD_CLOEXEC)
	if err != nil {
		return 0, err
	}
	chanFile := os.NewFile(uintptr(chanFd), "lc-chan")
	defer chanFile.Close()
	if err := unix.Ftruncate(chanFd, shmLen); err != nil {
		return 0, err
	}
	mem, err := unix.Mmap(chanFd, 0, shmLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}
	defer unix.Munmap(mem)

	memfd, err := unix.MemfdCreate("lc-stub", unix.MFD_CLOEXEC)
	if err != nil {
		return 0, err
	}
	// The stub execs from /proc/self/fd/N in the child, where fds 3-5 are
	// already the ExtraFiles: N must be above them.
	stubFd, err := unix.FcntlInt(uintptr(memfd), unix.F_DUPFD_CLOEXEC, 10)
	unix.Close(memfd)
	if err != nil {
		return 0, err
	}
	stubFile := os.NewFile(uintptr(stubFd), "lc-stub")
	defer stubFile.Close()
	if _, err := stubFile.Write(chooseStub()); err != nil {
		return 0, err
	}

	tmp, err := newRunTmp()
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	done := make(chan struct{})
	fs, err := newDfs(cfg.RootFS, cfg.Upper, mem, done, tmp)
	if err != nil {
		return 0, err
	}
	defer fs.close()
	if cfg.RootFS == nil {
		if prog, err = fs.bindProgram(prog); err != nil {
			return 0, fmt.Errorf("laboon: program: %w", err)
		}
	}

	// The stubs' fd 4: every stub process exits once it reads EOF here,
	// i.e. when this supervisor is gone however it died.
	lifeline, lifelineW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer lifeline.Close()
	defer lifelineW.Close()
	// The stubs' fd 5, for passing them descriptors to map (passFd).
	xfer, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	xferSup, xferStub := os.NewFile(uintptr(xfer[0]), "xfer"), os.NewFile(uintptr(xfer[1]), "xfer")
	defer xferSup.Close()
	defer xferStub.Close()

	std, err := newStdio(cfg)
	if err != nil {
		return 0, err
	}
	defer std.finish()
	cfg.Stdin, cfg.Stdout, cfg.Stderr = std.files[0], std.files[1], std.files[2]

	cmd := exec.CommandContext(ctx, fmt.Sprintf("/proc/self/fd/%d", stubFd))
	cmd.Args = []string{"lc-stub"}
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{chanFile, lifeline, xferStub}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = std.files[0], std.files[1], std.files[2]
	// The stubs form a process group of their own: the lifeline's SIGIO
	// reaches all of them (see stub.zig), and so does the kill below.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	// Pdeathsig fires when the thread that started the stub exits, not the
	// process: the start happens on a thread locked to a goroutine that
	// lives until the stub is gone.
	var waitErr error
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		waitErr = cmd.Wait()
		close(done)
	}()
	if err := <-started; err != nil {
		return 0, err
	}
	// The main stub's end ends what ran in it. That goes before the channel
	// memory is unmapped, after the stub is killed.
	reaped := make(chan struct{})
	go func() {
		<-done
		fs.hopGone(cmd.Process.Pid, false) // a call waiting on its hop thread returns, as for any stub (watchStub)
		fs.stubGone(cmd.Process.Pid)
		close(reaped)
	}()
	defer func() { <-reaped }()
	defer unix.Kill(-cmd.Process.Pid, unix.SIGKILL)

	fs.run = &runInfo{stubFile: stubFile, chanFile: chanFile, life: lifeline, entryOff: entryOff,
		pgid: cmd.Process.Pid, xfer: xferSup}
	exe := path.Clean("/" + prog)
	fs.initProcfs(cmd.Process.Pid, exe, cfg.Args, cfg.Env, std.files)
	fs.newInitProc(cmd.Process.Pid, prog, cfg.User)
	fs.serveResize(std) // deliver terminal resizes (SIGWINCH) to the guest
	sr := newSigRun(fs, mem, cmd.Process.Pid)
	defer sr.close()

	// join ends the stubs and waits for every worker goroutine (fs.wg) to
	// stop. It must finish before the deferred sr.close() (which deletes the
	// sigRun, so g.sigs() returns nil) and unix.Munmap(mem) (which unmaps the
	// signal area sr.area) -- otherwise a worker still servicing a guest op
	// reads a gone sigRun or unmapped area. On the normal path it is called
	// explicitly below; the defer (run first, before sr.close, on LIFO order)
	// covers an early return or a panic unwinding Run. sync.Once makes the two
	// calls one.
	var joinOnce sync.Once
	join := func() {
		joinOnce.Do(func() {
			revokeControl(cfg) // stop new Signals, and wait out an in-flight one, before freeing the signal subsystem
			unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
			<-done
			sr.killRest()
			fs.killAll()
			fs.killHops()
			fs.wg.Wait()
		})
	}
	defer join()
	fs.abort = func() { unix.Kill(-cmd.Process.Pid, unix.SIGKILL) }

	ch := newChannel(mem, 0, slotsAddr, done, nil)
	dg := newDguest(fs, ch, mem, 0, cfg)
	dg.pid, dg.tgid = 1, 1
	dg.mp = newMemProc(cmd.Process.Pid)
	dg.mp.hopPend = fs.allocHop() // the run's first, so never nil
	fs.adoptHop(cmd.Process.Pid, dg.mp.hopPend)
	fs.mu.Lock()
	dg.ps = fs.pt[1]
	dg.ps.ft = dg.ft
	dg.ft.max = int(dg.ps.rlim[rlimitNofil].cur)
	fs.mu.Unlock()
	fs.addProc(1, &dproc{ospid: cmd.Process.Pid, ch: ch, ps: dg.ps, g: dg})
	defer dg.release()

	src, argv, e := initProgram(dg, exe, cfg.Args)
	if e != 0 {
		return 0, fmt.Errorf("%s: %w", prog, lxErr(e))
	}
	if err := dg.applyInitDir(cfg); err != nil {
		return 0, err
	}
	if err := boot(dg, src, argv, cfg.Env); err != nil {
		return 0, err
	}
	leader := cmd.Process.Pid // every stub of the run is in its process group
	publishControl(cfg, func() int { return leader }, fs)
	defer revokeControl(cfg) // backstop for an early return before join()
	code, err := serveGuest(dg)
	if err == errLeaderGone {
		dg.release()
		code, err = fs.leaderExited(dg, code), nil
	}
	// The rest of the run goes with pid 1, as a pid namespace's does: every
	// process takes SIGKILL, which also ends a wait in the supervisor. join
	// kills the group, reaps (<-done), and waits for the workers, so the exit
	// code below reads settled state.
	join()
	if perr := fs.faulted(); perr != nil {
		return 0, perr
	}
	if errors.Is(err, errExited) {
		if k := sr.killedBy(1); k != 0 {
			return 128 + k, nil
		}
		if c, ok := fs.groupExitCode(1); ok {
			return c, nil
		}
		if ee, ok := waitErr.(*exec.ExitError); ok {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGSYS {
				// The seccomp filter rejected a syscall outright (a bad
				// architecture, or the stub's own out-of-policy call). An
				// unrewritten guest syscall does not reach here: the filter
				// traps it (RET_TRAP) and the supervisor services it.
				return 0, ErrKilled
			}
		}
		return 0, fmt.Errorf("stub died: %v", waitErr)
	}
	if err == nil && code < 0 {
		return 128 - code, nil
	}
	return code, err
}

// initProgram resolves the program's #! chain, as execve does.
func initProgram(dg *dguest, exe string, argv []string) (execSrc, []string, lxErrno) {
	gp := exe
	for depth := 0; ; depth++ {
		rp, e := dg.resolve(gp, true)
		if e != 0 {
			return execSrc{}, nil, e
		}
		s, e := dg.execSource(rp, nil)
		if e != 0 {
			return execSrc{}, nil, e
		}
		head, e := dg.execSrcHead(s)
		if e != 0 {
			return execSrc{}, nil, e
		}
		if len(head) < 2 || head[0] != '#' || head[1] != '!' {
			dg.pi.mu.Lock()
			dg.pi.exe, dg.pi.argv = gp, argv
			dg.pi.mu.Unlock()
			return s, argv, 0
		}
		if depth >= maxInterpDepth {
			return execSrc{}, nil, lxELOOP
		}
		line := head[2:]
		if nl := indexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		interp, arg := splitShebang(string(line))
		if interp == "" {
			return execSrc{}, nil, lxENOEXEC
		}
		np := []string{interp}
		if arg != "" {
			np = append(np, arg)
		}
		argv = append(append(np, gp), argv[1:]...)
		gp = interp
	}
}

// boot loads the program into the stub that reported ready on dg's slot and
// starts it.
func boot(dg *dguest, src execSrc, argv, env []string) error {
	ch := dg.ch
	if err := ch.wait(); err != nil {
		return err
	}
	if ch.page.kind != msgReady {
		return errors.New("stub protocol: expected ready")
	}
	// The stub reports its window base (its load address): the primary for the
	// top-level ET_EXEC, or the free high window the outer placed the PIE at.
	// Adopt it before loading guests so slot addressing and the window
	// exclusion use the live base.
	adoptWindow(ch.page.args[0])
	if s, ok := hostStackOf(int(dg.mp.pid.Load())); ok {
		dg.mp.hostStack.Store(&s)
	}
	dg.noteSpecial()
	dg.run.entry = ch.page.args[0] + dg.run.entryOff.entry
	if dg.run.entryOff.entryGs != 0 {
		dg.run.entryGs = ch.page.args[0] + dg.run.entryOff.entryGs
		dg.run.latekick = ch.page.args[0] + dg.run.entryOff.latekick
	}
	ch.page.self = slotsAddr
	pf, err := dg.openProgram(src)
	if err != nil {
		return err
	}
	lay := dg.drawLayout()
	exe, err := dg.loadELF(pf, lay.exe, lay.mm)
	if err != nil {
		pf.close()
		return err
	}
	defer exe.release()
	var interp *image
	if exe.interp != "" {
		ipf, err := dg.openProgram(execSrc{gp: exe.interp})
		if err != nil {
			return fmt.Errorf("interpreter %s: %w", exe.interp, err)
		}
		if interp, err = dg.loadELF(ipf, lay.exe, lay.mm); err != nil {
			ipf.close()
			return err
		}
		defer interp.release()
	}
	sp, start, err := dg.setupImages(exe, interp, argv, env, lay, false)
	if err != nil {
		return err
	}
	if dg.cfg.Trace != nil {
		n := len(exe.sites)
		if interp != nil {
			n += len(interp.sites)
		}
		fmt.Fprintf(dg.cfg.Trace, "loaded: %d syscall sites rewritten (%d with trampolines), %d stray syscall encodings left to seccomp\n",
			n, dg.mp.fast, dg.mp.strays)
	}
	// The stub starts its hop thread before the guest runs, so from here the
	// process's host calls can go to it.
	h := dg.mp.hopPend
	ch.page.args = [6]uint64{start, sp, dg.stdioMask(), stubParkCost(), uint64(h.idx)}
	dg.mp.hopP.Store(h)
	ch.reply(repStart)
	return nil
}

// stubParkCost is the park cost, in cputicks, handed to the stub so its reply
// spin adapts the same way the supervisor's does. Zero when the adaptive spin
// is off (LABOON_SPIN pinned a fixed count), which keeps the stub on its fixed
// spin -- so one binary runs both sides fixed or both sides adaptive.
func stubParkCost() uint64 {
	if !adaptive {
		return 0
	}
	ensureCalibrated()
	return parkCost()
}

// serveGuest runs one guest thread's syscall loop: the control messages
// (exit, clone, execve, default signal actions) here, the rest from the
// shared table.
func serveGuest(dg *dguest) (code int, err error) {
	defer dg.dfs.contain(&err)
	ch := dg.ch
	dg.attachStdio()
	defer dg.detachStdio()
	for {
		dg.args.n = 0
		if err := ch.wait(); err != nil {
			return 0, err
		}
		pg := ch.page
		if pg.kind == msgForked {
			dg.ptraceChildStart()
			ch.reply(repResult)
			continue
		}
		if pg.kind != msgSyscall {
			return 0, errExited
		}
		dg.dropHostStack() // the stub serves this call on a stack of its own
		// rip 0 marks a trampoline call; anything else came from SIGILL,
		// and must be a site the rewriter wrote.
		if pg.rip != 0 {
			if !dg.mp.isSite(pg.rip) {
				ch.reply(repFault)
				continue
			}
		}
		nr, a := pg.nr, pg.args
		if !dg.ptraceEnter(nr, a) {
			pg.ret = errno(lxEINTR)
			ch.reply(repResult)
			continue
		}
		nr, a = pg.nr, pg.args
		dg.loadArgs()
		if isRealSyscall(nr) && dg.ps.seccomp.Load() == secModeFilter {
			// A seccomp filter may test the instruction pointer (the stub's own
			// filter admits syscalls only from its text). A trampolined syscall
			// reports rip 0; its real site is in the rewritten code, so use the
			// resume pc (guestRip, which sits in that same text) as the IP.
			ip := pg.rip
			if ip == 0 {
				ip = pg.guestRip
			}
			if r, handled := dg.applySeccomp(uint32(nr), a, ip); handled {
				if dg.cfg.Trace != nil {
					fmt.Fprintf(dg.cfg.Trace, "[%d] %d(%#x, %#x, %#x, %#x, %#x, %#x) = %d [seccomp]\n", dg.pid, nr, a[0], a[1], a[2], a[3], a[4], a[5], r)
				}
				pg.ret = uint64(r)
				dg.ptraceSyscallExit(r)
				ch.reply(repResult)
				continue
			}
		}
		gnr, ga, generic := toGeneric(nr, a)
		switch {
		case nr == lxSigDie:
			sig := int(a[0])
			if dg.cfg.Trace != nil && a[2] != 0 {
				fmt.Fprintf(dg.cfg.Trace, "[%d] stub fault: signal %d at %#x, pc %#x\n", dg.pid, sig, a[1], a[2])
			}
			dg.sigDie(sig)
			if dg.sharedStub() {
				dg.endShared(128 + sig)
				return -sig, nil
			}
			pg.nr = unix.SYS_EXIT_GROUP
			pg.args = [6]uint64{uint64(128 + sig)}
			ch.reply(repHost) // the stub ends the process
			return -sig, nil
		case nr == lxSigStop:
			dg.sigStopSelf(int(a[0]))
			pg.ret = 0
			ch.reply(repResult)
		case nr >= lxSigTake && nr <= lxSigRaise:
			pg.ret = uint64(dg.sigCall(nr, a))
			ch.reply(repResult)
		case generic && (gnr == lxClone || gnr == lxClone3):
			dg.traceEntry(gnr, ga)
			var r cloneReq
			var e lxErrno
			if gnr == lxClone {
				r, e = cloneArgs(ga)
			} else {
				r, e = dg.clone3Args(ga[0], ga[1])
			}
			if e != 0 {
				pg.ret = errno(e)
				dg.ptraceSyscallExit(int64(pg.ret))
				ch.reply(repResult)
				break
			}
			dg.clone(r, dg.cfg) // replies (or the stub returns for the parent)
		case generic && (gnr == lxExecve || gnr == lxExecveat):
			dg.traceEntry(gnr, ga)
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
				dg.ptraceSyscallExit(int64(pg.ret))
				ch.reply(repResult) // errno in page.ret; the guest goes on
			}
		case generic && gnr == lxRtSigreturn: // rt_sigreturn is completed by the stub.
			dg.ptraceSyscallExit(int64(pg.ret))
			// repSigreturn (not repResult) tells a stub servicing a raw
			// rt_sigreturn that this layer's guest filter admits the call, so the
			// frame is this layer's to complete; a seccomp-trapped one was already
			// answered above with repResult and never reaches here.
			ch.reply(repSigreturn)
		case generic && gnr == lxExit:
			dg.traceEntry(gnr, ga)
			code := int(ga[0] & 0xff)
			dg.ptraceEvent(ptraceEventExit, uint64(code<<8))
			dg.dfs.mu.Lock()
			others := dg.ps.threads > 1
			dg.dfs.mu.Unlock()
			if dg.sharedStub() {
				dg.exitShared(code)
				return code, nil
			}
			if !dg.isThread && !others {
				// The only thread: its exit is the process's.
				dg.beginExit(code)
				pg.nr = unix.SYS_EXIT_GROUP
				pg.args = [6]uint64{uint64(code)}
				ch.reply(repHost)
				return code, nil
			}
			dg.mp.mu.Lock()
			ctid := dg.mp.clearTid[dg.pid]
			delete(dg.mp.clearTid, dg.pid)
			dg.mp.mu.Unlock()
			// The stub ends this thread, clearing and waking its tid word
			// once nothing of it runs on the guest's stack, and the kernel
			// clears the slot's alive word when it is gone. Its rseq goes
			// first: the joiner the wake lets go may free the area (glibc's
			// is in the thread's stack) while the host could still write it.
			dg.endRseq()
			pg.nr = unix.SYS_EXIT
			pg.args = [6]uint64{uint64(code), ctid}
			ch.reply(repHost)
			ch.awaitGone()
			dg.unmapOwnStack()
			if !dg.isThread {
				return code, errLeaderGone
			}
			return code, nil
		case generic && gnr == lxExitGroup:
			dg.traceEntry(gnr, ga)
			code := int(ga[0] & 0xff)
			dg.ptraceEvent(ptraceEventExit, uint64(code<<8))
			if dg.sharedStub() {
				dg.exitShared(code)
				return code, nil
			}
			dg.beginExit(code)
			pg.nr = unix.SYS_EXIT_GROUP
			pg.args = [6]uint64{uint64(code)}
			ch.reply(repHost) // the stub ends the process; no reply comes
			return code, nil
		default:
			var r int64
			if h, ok := handler(gnr); ok && generic {
				if dg.cfg.Trace != nil {
					r = fromGeneric(nr, a, dg.serveTraced(h, gnr, ga))
				} else {
					r = fromGeneric(nr, a, h(dg, ga))
				}
			} else {
				dg.traceNosys(gnr, ga)
				r = sErr(lxENOSYS)
			}
			if r == sErr(lxEPIPE) && epipeRaises(gnr, ga) {
				dg.raiseSelf(13) // SIGPIPE
			}
			r = dg.outResult(r)
			pg.ret = uint64(r)
			dg.ptraceSyscallExit(r)
			ch.reply(repResult)
		}
	}
}

// killRest marks SIGKILL pending for every process of the run and wakes its
// threads, so a call the supervisor is serving for one ends.
func (sr *sigRun) killRest() {
	sr.mu.Lock()
	ps := make([]*sigProc, 0, len(sr.procs))
	for _, p := range sr.procs {
		ps = append(ps, p)
	}
	sr.mu.Unlock()
	for _, p := range ps {
		sr.queue(&p.q, sigKILL, sigInfo{code: siKernel})
		for _, t := range sr.threadsOf(p) {
			sr.wake(t)
		}
	}
}

// epipeRaises reports whether a call that failed with EPIPE raises SIGPIPE in
// its thread, as Linux's write and send paths do unless told not to.
func epipeRaises(gnr uint64, a [6]uint64) bool {
	const msgNosignal = 0x4000
	switch gnr {
	case 64, 66: // write, writev
		return true
	case 206, 269: // sendto, sendmmsg
		return a[3]&msgNosignal == 0
	case 211: // sendmsg
		return a[2]&msgNosignal == 0
	}
	return false
}

// raiseSelf makes sig pending for g's thread, for the stub to take on the
// way out of the current call.
func (g *dguest) raiseSelf(sig int) {
	sr := g.sigs()
	if t := sr.thread(g.pid); t != nil {
		sr.queue(&t.q, sig, sigInfo{code: siUser, a: uint64(g.tgid)})
	}
}
