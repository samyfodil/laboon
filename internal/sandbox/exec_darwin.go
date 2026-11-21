//go:build darwin

package sandbox

import (
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// execve prepares the exec target and hands the load to the stub. It resolves
// the program within the root (following #! scripts to their interpreter),
// computes the svc sites for the program and its dynamic linker, packs the
// host paths plus any argv prefix a script adds into the channel scratch, and
// replies repExec. The stub reads the rest of argv and the environment from
// the guest's own arrays. It returns true when it has replied repExec (the
// caller must not reply again); false on failure, with the errno already in
// page.ret so the guest's execve returns it (a shell's PATH search then tries
// the next directory).
func (g *dguest) execve(dirfd int64, pathAddr, argvAddr, envpAddr uint64, flags int64) bool {
	fail := func(e lxErrno) bool {
		g.ch.page.ret = errno(e)
		return false
	}
	t, e := g.execTarget(dirfd, pathAddr, argvAddr, flags)
	if e != 0 {
		return fail(e)
	}
	defer t.drop()
	host, prefix, skip, gp := t.src, t.prefix, t.skip, t.gp
	// The dynamic linker is resolved from the process root and made a private
	// copy through the Namespace, the same as the program (execTarget) was.
	linkerHost := func(ip string) (string, error) {
		gp, e := g.walkAt(lxAtFdcwd, ip, true)
		if e == 0 {
			var s execSrc
			if s, e = g.execSource(gp, nil); e == 0 {
				return string(s), nil
			}
		}
		return "", fmt.Errorf("dynamic linker %q: errno %d", ip, e)
	}
	interpHost, ierr := resolveInterp(host, linkerHost)
	if ierr != nil {
		return fail(lxENOENT) // the ELF's dynamic linker is missing
	}
	mainSites, serr := g.writeExecSites(host)
	if serr != nil {
		return fail(lxENOEXEC)
	}
	interpSites := ""
	if interpHost != "" {
		interpSites, serr = g.writeExecSites(interpHost)
		if serr != nil {
			return fail(lxENOEXEC)
		}
	}
	fs := g.dfs
	// A non-PIE low-linked ET_EXEC must run in the VM (the HVF stub): the native
	// stub can't map it (the __PAGEZERO wall), and the in-place reload below is a
	// native-stub operation, so such a target always forces a fresh stub of the
	// right kind -- the per-exec backend handoff.
	targetHvf := needsHvf(host)
	fs.mu.Lock()
	// In-place reload is a native-stub operation, so it is only for a native
	// process execing a native target; any other combination (either side HVF)
	// respawns into a stub of the right kind.
	respawn := (g.ps.forked || g.ps.threads > 1 || g.ps.shared || targetHvf || g.ps.hvf) && fs.run != nil
	var layout uint32
	if g.ps.personality&addrNoRandomize != 0 {
		layout = layoutNorand
	}
	fs.mu.Unlock()
	// The stub that loads the program, this one or the fresh one on this slot,
	// reads how to place it here.
	atomic.StoreUint32(&g.ch.page.alive, layout)
	if respawn {
		return g.execRespawn(&t, host, interpHost, mainSites, interpSites, prefix, argvAddr, skip, envpAddr, gp, targetHvf)
	}

	strs := append([]string{host, interpHost, mainSites, interpSites}, prefix...)
	if !packStrings(g.scratch(), strs) {
		return fail(lxE2BIG)
	}
	// Reading argv and detaching SysV segments use the channel scratch, so
	// the strings are packed again after them.
	var argv []string
	if a, e := g.readArgv(argvAddr); e == 0 {
		argv = append(prefix, a[min(int(skip), len(a)):]...)
	}
	g.mp.detachAll(g)
	g.mp.anon.reset()
	packStrings(g.scratch(), strs)

	g.closeExec() // drop close-on-exec fds; the rest survive the exec
	execHook(g)
	g.execDone(path.Base(gp))
	g.noteExec(gp, gp, argv, g.exePin(&t))
	g.dfs.mu.Lock()
	c := g.ps.cred
	g.dfs.mu.Unlock()
	g.ch.page.args = [6]uint64{
		uint64(len(prefix)), argvAddr, skip, envpAddr,
		uint64(c.ruid) | uint64(c.euid)<<32, uint64(c.rgid) | uint64(c.egid)<<32,
	}
	g.ch.reply(repExec)
	return true
}

// elfMachine is the darwin backend's native guest machine. The backend also
// hosts the other architecture's guest (an x86-64 guest under Rosetta on Apple
// Silicon), detected per guest by guestIsX64, not by this constant.
const elfMachine = elf.EM_AARCH64

// guestIsX64 reports whether the guest ELF at path is x86-64 (so it runs in the
// x86-64 stub, under Rosetta on an arm64 host), rather than the native machine.
func guestIsX64(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return f.Machine == elf.EM_X86_64, nil
}

// execSrc is the host path of the ELF an execve runs.
type execSrc = string

// execSource gives the host path of the program at guest path gp, or of f, the
// open file execveat(AT_EMPTY_PATH) runs. A guest path is opened through the
// Namespace (resolving symlinks, mounts and the overlay there); fexecHost then
// gives the darwin loader a private host copy of that open file — the same
// routed-node, fexecve-like path the linux loader takes, so no guest path is
// mapped to a host path outside the Namespace.
func (g *dguest) execSource(gp string, f *os.File) (execSrc, lxErrno) {
	if f == nil {
		rp, e := g.resolve(gp, true)
		if e != 0 {
			return "", e
		}
		var e2 lxErrno
		if f, e2 = g.openFile(rp); e2 != 0 {
			return "", e2
		}
		defer f.Close()
	}
	return g.fexecHost(f)
}

func (g *dguest) execSrcHead(s execSrc) ([]byte, lxErrno) { return execHead(s) }

// execHead checks that host is something execve may run (a regular file with
// an execute bit; root needs only one) and returns its first bytes.
func execHead(host string) ([]byte, lxErrno) {
	fi, err := os.Stat(host)
	if err != nil {
		return nil, osErrno(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return nil, lxEACCES
	}
	f, err := os.Open(host)
	if err != nil {
		return nil, osErrno(err)
	}
	defer f.Close()
	b := make([]byte, binprmBuf)
	n, err := io.ReadFull(f, b)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, lxEIO
	}
	return b[:n], 0
}

// runInfo is what starting another stub process needs: the signed stub, the
// shared channel file, the run's process group (teardown kills it whole) and
// the run's stdio.
type runInfo struct {
	stub, hvfStub, chanPath string // stub = the guest's map+rewrite stub; hvfStub = VM (HVF)
	x64                     bool   // the guest is x86-64 (runs in the x86-64 stub, under Rosetta on Apple Silicon)
	pgid                    int
	stdin, stdout, stderr   *os.File
	mainGone                func(error) // pid 1's stub is gone: the run is over
	pool                    stubPool
	sites                   map[[32]byte]string // exec site files by content, under dfs.mu
	life                    *os.File            // the stubs' fd 4: EOF when the supervisor is gone
	broker                  *broker             // the stubs' bootstrap port: their mailboxes, for fork
}

// spawn starts a stub process in the run's process group. When that group is
// gone with its last member (pid 1's first stub, say) it starts a new group
// and makes it the run's. mu guards run.pgid.
//
// The new stub gets its own fdlink pairing (mem_darwin.go) as fd 3.
// stubFor returns the signed stub for a backend: the HVF (VM) stub for a guest
// that needs it (a non-PIE low ET_EXEC), else the native map-and-rewrite stub.
func (run *runInfo) stubFor(hvf bool) string {
	if hvf {
		return run.hvfStub
	}
	return run.stub
}

func (run *runInfo) spawn(stub string, args []string, mu *sync.Mutex) (*stubCmd, *memProc, error) {
	mp, link, err := newMemProc()
	if err != nil {
		return nil, nil, err
	}
	defer link.Close()
	mu.Lock()
	pgid := run.pgid
	mu.Unlock()
	cmd, err := run.startStub(stub, args, pgid, link)
	if err == nil {
		return cmd, mp, nil
	}
	if cmd, err = run.startStub(stub, args, 0, link); err != nil {
		unix.Close(mp.sock)
		return nil, nil, err
	}
	mu.Lock()
	run.pgid = cmd.Process.Pid
	mu.Unlock()
	return cmd, mp, nil
}

// startStub starts a stub process with args in process group pgid (0: a new
// group). Its own environment is empty; the guest's travels in args.
func (run *runInfo) startStub(stub string, args []string, pgid int, link *os.File) (*stubCmd, error) {
	cmd := &stubCmd{Path: stub, Args: args, Files: []*os.File{run.stdin, run.stdout, run.stderr, link, run.life}, Pgid: pgid, Bootstrap: run.broker.port}
	return cmd, cmd.Start()
}

// isMainStub reports whether ospid is pid 1's current stub.
func (fs *dfs) isMainStub(ospid int) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	p := fs.pt[1]
	return p != nil && p.ospid == ospid
}

// execRespawn runs an execve in a process whose stub cannot load the new
// program in place: one that came from fork (Darwin keeps x18 intact only for
// a process image exec'd from the stub binary, and the guest's GCC-built code
// uses x18) or one with other threads (exec must end them). The supervisor
// ends the old stub and starts a fresh one on the same channel slot, which
// loads the program and enters it; the guest pid, fds and registry entry
// carry over. argv and envp are read from the old image first, so a bad
// pointer still fails the call with EFAULT. A CLONE_VM child's old stub is
// its parent's: only its thread there ends.
func (g *dguest) execRespawn(t *execTarget, host, interpHost, mainSites, interpSites string, prefix []string, argvAddr, skip, envpAddr uint64, gp string, targetHvf bool) bool {
	fail := func(e lxErrno) bool {
		g.ch.page.ret = errno(e)
		return false
	}
	argv, e := g.readArgv(argvAddr)
	if e != 0 {
		return fail(e)
	}
	envv, e := g.readArgv(envpAddr)
	if e != 0 {
		return fail(e)
	}
	argv = append(prefix, argv[min(int(skip), len(argv)):]...)
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
	if total > darwinArgMax {
		return fail(lxE2BIG)
	}

	// Past the point of no return.
	g.closeExec()
	fs := g.dfs
	shared := g.sharedStub()
	if !shared {
		g.mp.detachAll(g) // the SysV attachments of a shared address space stay its parent's
		g.mp.anon.reset()
	}
	execHook(g)
	fs.mu.Lock()
	old := g.ps.ospid
	atomic.StoreUint64(&g.ch.page.rip, 0)
	for _, p := range fs.procs {
		if p.ps == g.ps {
			p.ospid = 0 // the old stub's end must not end the process: takeOverGroup retires its threads
		}
	}
	g.ps.ospid = 0 // nor the run's watcher pid 1's
	g.ps.shared = false
	g.ps.hvf = targetHvf // this process's new backend, for its next exec's choice
	fs.mu.Unlock()
	var ru rusage
	if shared {
		g.endSharedThread()
	} else {
		ru = hostRusage(old)
		g.ch.page.nr = dwExit
		g.ch.page.args = [6]uint64{}
		g.ch.reply(repHost)
		fs.awaitStubGone(old)
	}
	g.takeOverGroup()
	g.execDone(path.Base(gp))
	g.noteExec(gp, gp, argv, g.exePin(t))

	fs.mu.Lock()
	c := g.ps.cred
	fs.mu.Unlock()
	pg := g.ch.page
	pg.state, pg.kind, pg.stubSleep, pg.supSleep, pg.rip = 0, 0, 0, 0, 0
	run := fs.run
	slotOff := uint64(g.slot * slotSize)
	uids, gids := uint64(c.ruid)|uint64(c.euid)<<32, uint64(c.rgid)|uint64(c.egid)<<32
	var cmd *stubCmd
	var mp *memProc
	var err error
	if !targetHvf { // the pool holds native stubs only; an HVF target spawns fresh
		if p := fs.takePooled(); p != nil {
			job := []string{fmt.Sprintf("%x", slotOff), fmt.Sprintf("%x", uids), fmt.Sprintf("%x", gids),
				fmt.Sprintf("%x", len(argv)), host, interpHost, mainSites, interpSites}
			if p.assign(fs, append(append(job, argv...), envv...)) {
				cmd, mp = p.cmd, p.mp
			} else {
				p.mp.release(g)
			}
		}
	}
	if cmd == nil {
		marker := fmt.Sprintf("lc-stub@%x@%x@%x@%x", slotOff, uids, gids, len(argv))
		args := append(append([]string{marker, run.chanPath, host, interpHost, mainSites, interpSites}, argv...), envv...)
		if cmd, mp, err = run.spawn(run.stubFor(targetHvf), args, &fs.mu); err == nil {
			fs.noteStub(cmd.Process.Pid)
			fs.wg.Add(1)
			go func() {
				defer fs.wg.Done()
				err := cmd.Wait()
				fs.stubEnded(cmd.Process.Pid)
				if fs.isMainStub(cmd.Process.Pid) {
					run.mainGone(err)
				}
			}()
		}
	}
	if err != nil {
		// The process has no stub any more: it dies as Linux kills a process
		// whose exec fails past the point of no return.
		if g.cfg.Trace != nil {
			fmt.Fprintf(g.cfg.Trace, "[pid %d] exec: starting a stub: %v\n", g.pid, err)
		}
		if g.ps.tgid == 1 {
			run.mainGone(err)
		}
		fs.setKillSig(g.ps.tgid, lxSigkill)
		fs.mu.Lock()
		if p := fs.procs[g.pid]; p != nil && p.stop != nil {
			closeStop(p.stop)
		}
		fs.mu.Unlock()
		return true
	}
	if g.cfg.Trace != nil {
		fmt.Fprintf(g.cfg.Trace, "[pid %d] exec in a fresh stub, ospid %d -> %d\n", g.pid, old, cmd.Process.Pid)
	}
	g.mp = g.mp.renew(g, mp)
	fs.mu.Lock()
	g.ps.ospid = cmd.Process.Pid
	g.ps.forked = false
	g.ps.ruPrev = g.ps.ruPrev.plus(ru)
	if p := fs.procs[g.pid]; p != nil {
		p.ospid = cmd.Process.Pid
	}
	fs.mu.Unlock()
	fs.bindStub(cmd.Process.Pid)
	// A kill that came while the process had no stub found nothing to kill.
	if fs.sigs().killedBy(g.ps.tgid) != 0 {
		unix.Kill(cmd.Process.Pid, unix.SIGKILL)
	}
	return true
}

// darwinArgMax is kern.argmax: what a host exec can carry.
const darwinArgMax = 1 << 20

// fexecHost gives an open file a private host path the program loader can map:
// execveat(fd, "", AT_EMPTY_PATH) runs the open file, which may since have been
// unlinked or replaced at its path. One copy (an APFS clone when it can be)
// per file version per run.
func (g *dguest) fexecHost(f *os.File) (string, lxErrno) {
	fi, err := f.Stat()
	if err != nil {
		return "", osErrno(err)
	}
	if !fi.Mode().IsRegular() {
		return "", lxEACCES
	}
	dev, ino := HostDevIno(fi)
	key := sha256.Sum256(fmt.Appendf(nil, "fexec %d %d %d %d", dev, ino, fi.Size(), fi.ModTime().UnixNano()))
	fs := g.dfs
	fs.mu.Lock()
	p, ok := fs.run.sites[key]
	fs.mu.Unlock()
	if ok {
		return p, 0
	}
	p, err = privateCopy(g.dfs.tmpDir, int(f.Fd()), f, fi.Size(), fi.Mode().Perm())
	if err != nil {
		return "", lxEIO
	}
	// The clone of a spilled source (a non-host file) inherits the spill's bare
	// 0600; it is an exec source, verified executable by dacCheck against the
	// guest mode, so give the clone the owner-exec bit execHead expects.
	os.Chmod(p, fi.Mode().Perm()|0o100)
	fs.addTmp(p)
	fs.mu.Lock()
	if fs.run.sites == nil {
		fs.run.sites = map[[32]byte]string{}
	}
	fs.run.sites[key] = p
	fs.mu.Unlock()
	return p, 0
}

// markSrcOwn is a no-op here: execSrc is a host path, not an owned handle.
func markSrcOwn(*execSrc, bool) {}

// layoutNorand in the channel page's alive word asks the stub that runs an
// exec to place the program unrandomized (personality ADDR_NO_RANDOMIZE);
// stub/macos/chan.zig LAYOUT_NORAND.
const layoutNorand = 1
