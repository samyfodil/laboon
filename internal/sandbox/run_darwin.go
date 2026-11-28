//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/internal/namespace"
	"github.com/samyfodil/laboon/internal/rewrite"
	macstub "github.com/samyfodil/laboon/stub/macos"
)

// The macOS supervisor is a syscall broker: it coordinates the guest processes
// over the shared-memory channel but does no guest compute itself (each guest
// runs in its own stub process, which the OS schedules across cores).
//
// The broker ran pinned to GOMAXPROCS(1) for a long time because multithreaded
// guests corrupted nondeterministically at higher parallelism — a forked child
// dying dereferencing mangled memory. That was never a Go data race or an IPC
// race: it was the guest's tpidr_el0 thread pointer being clobbered by the
// kernel on reschedule (fixed by virtualizing tpidr_el0, commit 099b6db). The
// pin was only masking it by reducing scheduler preemption. With that fixed the
// broker runs at the default GOMAXPROCS; the one shared-state hazard left, the
// arm64 decoder's coverage slice, is serialized where it lives (rewrite.A64SegmentSites).
//
// macOS backend. A static linux/arm64 ELF runs end to end: the embedded Zig
// stub (macstub) loads and rewrites the guest in its own task, each guest
// syscall is posted over the shared channel, and this supervisor translates it
// to its Darwin equivalent and replies — performing memory/IO ops in the
// guest's address space via REP_HOST, answering the rest directly. This is the
// shape proven in macos/m7-run/, wired behind the public Run.
//
// Scope today: static and dynamically-linked executables, single-threaded,
// syscalls translated below. A read-only Root resolves the program path (and a
// dynamic guest's PT_INTERP) within the rootfs; threads/fork and the Mach
// exception backstop follow (macos/README.md).

// Darwin BSD syscall numbers the stub performs in-guest.
const (
	dwRead   = 3
	dwWrite  = 4
	dwReadv  = 120
	dwWritev = 121
	dwExit   = 1
)

// rewriteLibSites finds the svc/tpidr/ctr sites of a runtime-loaded library
// (recursive descent over the whole ELF, as for the main image) that fall in
// the just-mapped executable segment, and has the stub rewrite them to islands.
// The segment maps file offset `offset` to guest address `base`.
func (g *dguest) rewriteLibSites(base, length, offset uint64, d *dfile) {
	addrs := libSites(g.cfg.Cache, length, offset, d)
	for i := range addrs {
		addrs[i] += base - offset
	}
	g.sendRewrite(base, addrs)
}

// libSites is the file offsets of d's sites in [offset, offset+length). A
// site is found at its place in the image; the PT_LOAD holding it gives its
// file offset, which a linker may put at another distance from the image
// start than its vaddr (lld's separate code segments, for one).
func libSites(cache *rewrite.Cache, length, offset uint64, d *dfile) []uint64 {
	ef, fi, ok := libFile(d)
	if !ok {
		return nil
	}
	sites, err := computeSitesFile(cache, ef, fi)
	if err != nil {
		return nil // not an ELF (or unreadable): nothing to rewrite
	}
	f, err := elf.NewFile(ef)
	if err != nil {
		return nil
	}
	base := imageBase(f)
	var in []uint64
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		for _, s := range sites {
			v := base + uint64(s)
			if v < p.Vaddr || v >= p.Vaddr+p.Filesz {
				continue
			}
			if o := p.Off + (v - p.Vaddr); o >= offset && o < offset+length {
				in = append(in, o)
			}
		}
	}
	return in
}

// rewriteAskImage is lcRewrite's query of whether a file is an image.
const rewriteAskImage = 2

// isImage reports whether d is an ELF image, whose sites libSites finds.
func isImage(d *dfile) bool {
	ef, _, ok := libFile(d)
	if !ok {
		return false
	}
	_, err := elf.NewFile(ef)
	return err == nil
}

// libFile is what backs a library mapping of d. A non-host file has no host
// fd; its content is in the materialized mapf (mmapFd) the stub mapped.
func libFile(d *dfile) (io.ReaderAt, os.FileInfo, bool) {
	var ef io.ReaderAt
	var fi os.FileInfo
	var err error
	switch {
	case d.f != nil:
		ef = d.f
		fi, err = hostfs.FileStat(d.f)
	case d.mapf != nil:
		ef = d.mapf
		fi, err = hostfs.FileStat(d.mapf)
	case d.vf != nil:
		ef = d.vf
		fi, err = d.vf.Stat()
	default:
		return nil, nil, false
	}
	return ef, fi, err == nil
}

// libFSSites is the x86-64 %fs-relative instructions of d's text that fall
// in the bytes [offset, offset+length) of a mapping of it, as offsets in that
// range. They come from the descent plan of the whole image (analyzeImageFS),
// so data in the text is never taken for an instruction.
func libFSSites(cache *rewrite.Cache, length, offset uint64, d *dfile) []rewrite.FSSite {
	ef, fi, ok := libFile(d)
	if !ok {
		return nil
	}
	f, err := elf.NewFile(ef)
	if err != nil {
		return nil
	}
	base := imageBase(f)
	compute := func() (rewrite.Plan, error) { return analyzeImageFS(f, base) }
	var plan rewrite.Plan
	if id, ok := infoIdentity(fi); ok {
		plan, err = cache.ByID(imageSalt, id, nil, compute)
	} else {
		var b []byte
		if b, err = io.ReadAll(io.NewSectionReader(ef, 0, 1<<62)); err == nil {
			plan, err = cache.Memo(imageSalt, b, compute)
		}
	}
	if err != nil {
		return nil
	}
	var in []rewrite.FSSite
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		for _, s := range plan.FS {
			v := base + uint64(s.Off)
			if v < p.Vaddr || v+uint64(s.Len) > p.Vaddr+p.Filesz {
				continue
			}
			o := p.Off + (v - p.Vaddr)
			if o < offset || o+uint64(s.Len) > offset+length {
				continue
			}
			if o-uint64(s.Steal) < offset {
				s.Steal = 0 // the run before it is outside this mapping
			}
			s.Off = uint32(o - offset)
			in = append(in, s)
		}
	}
	return in
}

// sendRewrite hands the stub the guest addresses to rewrite, in slot-scratch
// batches, with base as the island placement hint (so the site's branch reaches
// the island).
func (g *dguest) sendRewrite(hint uint64, addrs []uint64) {
	const perBatch = scratchLen / 8
	for len(addrs) > 0 {
		n := len(addrs)
		if n > perBatch {
			n = perBatch
		}
		sc := g.scratch()
		for i := 0; i < n; i++ {
			put64(sc[i*8:], addrs[i])
		}
		g.ch.page.args = [6]uint64{uint64(n), hint}
		g.ch.reply(repRewrite)
		if err := g.ch.wait(); err != nil {
			return
		}
		addrs = addrs[n:]
	}
}

// Run executes the static linux/arm64 ELF at path and returns its exit status.
func Run(ctx context.Context, path string, cfg Config) (int, error) {
	if err := initSync(); err != nil {
		return 0, fmt.Errorf("laboon: os_sync unavailable (needs macOS 14.4+): %w", err)
	}
	if cfg.Cache == nil {
		cfg.Cache = defaultCache()
	}
	cfg.Trace = syncTrace(cfg.Trace)
	if cfg.Env == nil {
		cfg.Env = []string{} // a nil env is empty, never the supervisor's own
	}

	// A temp dir for this run's spills and channel, created before the program is
	// resolved so a non-host root can spill into it.
	rtmp, err := newRunTmp()
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(rtmp)

	rootPath, isHost := HostRootPath(cfg.RootFS)
	if isHost && rootPath != "" {
		abs, err := filepath.Abs(rootPath)
		if err != nil {
			return 0, err
		}
		if rootPath, err = filepath.EvalSymlinks(abs); err != nil {
			return 0, fmt.Errorf("laboon: root: %w", err)
		}
	}

	// Shared channel region (a MAP_SHARED temp file whose path the stub maps).
	chanFile, err := os.CreateTemp(rtmp, "lc-chan-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(chanFile.Name())
	defer os.Remove(chanFile.Name() + ".sb") // the stubs' compiled Seatbelt profile
	defer chanFile.Close()
	if err := writeSeatbeltPaths(chanFile.Name()); err != nil {
		return 0, err
	}
	defer os.Remove(chanFile.Name() + ".paths")
	if err := chanFile.Truncate(chanLen); err != nil {
		return 0, err
	}
	mem, err := unix.Mmap(int(chanFile.Fd()), 0, chanLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}
	defer unix.Munmap(mem)
	setMemCap(mem, cfg.MaxBytes) // before a stub maps anything
	if err := publishVdso(mem, cfg.Cache); err != nil {
		return 0, err
	}

	done := make(chan struct{})

	// The shared run state (filesystem + process table) outlives any one guest
	// process, so serve does not own it. Every forked child references it.
	fs, err := newDfs(cfg.RootFS, cfg.Upper, mem, done, rtmp)
	if err != nil {
		return 0, err
	}
	defer fs.close()
	if cfg.RootFS == nil {
		if path, err = fs.bindProgram(path); err != nil {
			return 0, fmt.Errorf("laboon: program: %w", err)
		}
	}

	// The guest program, its #! interpreters and its dynamic linker resolve as
	// the guest's own paths do: through the run's filesystem and its mounts.
	res := &progResolver{tmp: rtmp, ns: fs.progNS(cfg.Mounts)}
	gp := path
	guestPath, err := res.host(gp)
	if err != nil {
		return 0, fmt.Errorf("laboon: guest program: %w", err)
	}
	// Follow a #! script chain to its interpreter before the ELF load, as
	// execve does: an OCI ENTRYPOINT is often docker-entrypoint.sh (#!/bin/sh),
	// which is a script, not an ELF. argv becomes
	// [interp, optional-arg, script-guest-path, original-args[1:]...].
	for depth := 0; ; depth++ {
		head, err := headBytes(guestPath, binprmBuf)
		if err != nil {
			return 0, fmt.Errorf("laboon: read guest program: %w", err)
		}
		if len(head) < 2 || head[0] != '#' || head[1] != '!' {
			break
		}
		if depth >= maxInterpDepth {
			return 0, fmt.Errorf("laboon: %s: too many #! levels", path)
		}
		line := head[2:]
		if nl := bytes.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		interp, arg := splitShebang(string(line))
		if interp == "" {
			return 0, fmt.Errorf("laboon: %s: bad #! interpreter", gp)
		}
		np := []string{interp}
		if arg != "" {
			np = append(np, arg)
		}
		rest := cfg.Args
		if len(rest) > 0 {
			rest = rest[1:]
		}
		cfg.Args = append(append(np, gp), rest...)
		gp = interp
		guestPath, err = res.host(interp)
		if err != nil {
			return 0, fmt.Errorf("laboon: #! interpreter %s: %w", interp, err)
		}
	}

	// A dynamically-linked guest names its interpreter in PT_INTERP (e.g.
	// /lib/ld-musl-aarch64.so.1). Resolve it to a host path within the rootfs
	// so the stub can load it as a second image; "" means a static executable.
	interpHost, err := resolveInterp(guestPath, res.host)
	if err != nil {
		return 0, err
	}

	// Recursive-descent svc sites for each image, passed to the stub so it
	// rewrites real syscalls only (never a 0xd4000001 data word in a literal
	// pool or reloc table — common in real binaries).
	mainSites, err := computeSites(cfg.Cache, guestPath)
	if err != nil {
		return 0, fmt.Errorf("laboon: analyze guest: %w", err)
	}
	mainSitesPath, cleanMain, err := writeSites(rtmp, mainSites)
	if err != nil {
		return 0, err
	}
	defer cleanMain()
	interpSitesPath := ""
	if interpHost != "" {
		interpSites, err := computeSites(cfg.Cache, interpHost)
		if err != nil {
			return 0, fmt.Errorf("laboon: analyze dynamic linker: %w", err)
		}
		p, cleanInterp, err := writeSites(rtmp, interpSites)
		if err != nil {
			return 0, err
		}
		defer cleanInterp()
		interpSitesPath = p
	}

	// A non-PIE low-linked ET_EXEC cannot be mapped in the stub's address space
	// (the __PAGEZERO wall), so it runs in a VM via the HVF stub. The channel and
	// the supervisor-side syscall servicing below are identical for both: the HVF
	// stub speaks the same protocol, reading the channel path and guest path from
	// the same argv slots and ignoring the rewrite sites it does not need.
	// Sign both stubs: the native (map+rewrite) stub and the HVF (VM) stub. The
	// entry uses the one its binary needs; a later execve that crosses into the
	// other -- a native tree running a non-PIE static tool (gcc -> cc1), say --
	// respawns with it (see execve's per-exec handoff).
	guestX64, err := guestIsX64(guestPath)
	if err != nil {
		return 0, err
	}
	guestStub, err := signedStubFor(guestX64)
	if err != nil {
		return 0, err
	}
	hvfStub, err := signedHvfStub()
	if err != nil {
		return 0, err
	}
	entryHvf := needsHvf(guestPath) // false for an x86-64 guest: it maps+rewrites, no HVF VM
	stubPath := guestStub
	if entryHvf {
		stubPath = hvfStub
	}

	// The guest-visible argv (Config.Args, else just the path). It is passed
	// over the stub's own argv tail so the init stack carries the guest names
	// rather than the host path the stub loads from. The guest env rides the
	// stub's environment, which the stub copies onto the init stack.
	guestArgv := cfg.Args
	if len(guestArgv) == 0 {
		guestArgv = []string{path}
	}
	stubArgv := append([]string{"lc-stub", chanFile.Name(), guestPath, interpHost, mainSitesPath, interpSitesPath}, guestArgv...)
	// The stub goes in a process group of its own; every guest it forks
	// inherits the group, so teardown kills the whole tree with one signal to
	// -pgid.
	brk, err := newBroker()
	if err != nil {
		return 0, err
	}
	defer brk.close()
	cmd := &stubCmd{Path: stubPath, Args: stubArgv, Env: cfg.Env, Bootstrap: brk.port}
	// The stub inherits these as its fds 0-2, and the guest's fds 0-2 are
	// descriptions the supervisor holds too (stdioFile), so each is a real
	// file: the caller's own, a pipe to its reader or writer, or /dev/null.
	std, err := newStdio(cfg)
	if err != nil {
		return 0, err
	}
	defer std.finish()
	fs.feed = std.feed
	stdin, stdout, stderr := std.files[0], std.files[1], std.files[2]
	cfg.Stdin, cfg.Stdout, cfg.Stderr = stdin, stdout, stderr
	var term *ttyGuard
	for _, f := range []*os.File{stdin, stdout, stderr} {
		if term = saveTTY(f); term != nil {
			defer term.restore()
			break
		}
	}
	mp, linkEnd, err := newMemProc()
	if err != nil {
		return 0, err
	}
	// Every stub inherits the read end of this pipe as fd 4 and exits when it
	// reads EOF: once this process is gone, even SIGKILLed, its stubs follow.
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		unix.Close(mp.sock)
		linkEnd.Close()
		return 0, err
	}
	defer lifeR.Close()
	defer lifeW.Close()
	cmd.Files = []*os.File{stdin, stdout, stderr, linkEnd, lifeR} // fd 3: the stub's fdlink end
	err = cmd.Start()
	linkEnd.Close()
	if err != nil {
		unix.Close(mp.sock)
		return 0, err
	}
	defer context.AfterFunc(ctx, func() { cmd.Process.Kill() })()

	defer fs.term.close()
	if term != nil {
		fs.adoptCtty(term.fd, 1)
	}
	// /proc/self/exe is the binary the kernel actually loaded, which for a #!
	// script is its interpreter (gp was walked to it above), not the script --
	// matching Linux. uutils coreutils (Ubuntu's env/sh) refuses to run when the
	// invoked utility and the exe disagree, so this must be the interpreter.
	exe := gp
	if rootPath != "" {
		exe = filepath.Clean("/" + gp)
	}
	fs.initProcfs(cmd.Process.Pid, exe, guestArgv, cfg.Env, std.files)
	fs.serveResize(std) // deliver terminal resizes (SIGWINCH) to the guest
	fs.newInitProc(cmd.Process.Pid, path, cfg.User).hvf = entryHvf
	fs.noteStub(cmd.Process.Pid)
	fs.run = &runInfo{
		stub: guestStub, hvfStub: hvfStub, x64: guestX64, chanPath: chanFile.Name(), pgid: cmd.Process.Pid,
		stdin: stdin, stdout: stdout, stderr: stderr,
		life: lifeR, broker: brk,
	}
	fs.abort = func() { unix.Kill(-fs.run.pgid, unix.SIGKILL) }
	sr := newSigRun(fs, mem, cmd.Process.Pid)
	defer sr.close()
	defer sr.forward()()

	var waitErr error
	ch := newChannel(mem, 0, 0, done, nil)
	stop := make(chan struct{})
	ch.stop = stop
	var doneOnce sync.Once
	fs.run.mainGone = func(err error) {
		doneOnce.Do(func() {
			waitErr = err
			ch.end()         // end serve if it is parked on the dead stub's slot
			closeStop(stop)  // the channel reads dead from here, so a woken host wait ends
			fs.wakeWaiters() // a wait4
			fs.killAll()     // a host wait; the rest die with pid 1, as Linux kills a namespace whose init exits
			close(done)      // last: once done is closed, Run unmaps the channel memory
		})
	}
	go func() {
		err := cmd.Wait()
		fs.stubEnded(cmd.Process.Pid)
		if fs.isMainStub(cmd.Process.Pid) { // not when pid 1 exec'd into a new stub
			fs.run.mainGone(err)
		}
	}()

	code, runErr := serve(ch, fs, mp, cfg)

	unix.Kill(-fs.run.pgid, unix.SIGKILL) // kill the whole stub process group
	closeStop(stop)
	fs.killAll() // wake any serve goroutine parked in os_sync on a now-dead stub
	fs.wg.Wait() // let the child serve goroutines unwind
	<-done
	if perr := fs.faulted(); perr != nil {
		return 0, perr
	}

	if errors.Is(runErr, errExited) {
		if k := sr.killedBy(1); k != 0 {
			return 128 + k, nil // the guest died of a signal
		}
		if code, ok := fs.groupExitCode(1); ok {
			return code, nil // exit_group from a thread other than the main one
		}
		if ee, ok := waitErr.(*exec.ExitError); ok {
			if ws, ok := ee.Sys().(unix.WaitStatus); ok && ws.Signaled() {
				// A signal here is the Seatbelt backstop killing a guest whose
				// syscall was never rewritten (the macOS analog of SIGSYS).
				return 0, ErrKilled
			}
		}
		return 0, fmt.Errorf("stub died: %v", waitErr)
	}
	if code < 0 {
		code = 128 - code // killed by signal -code: the shell's 128+n
	}
	return code, runErr
}

// serve handles one guest's syscalls until it exits. It mirrors the Linux
// serve loop in miniature: wait for a request, translate Linux->Darwin,
// perform memory/IO ops in the guest via REP_HOST, answer the rest directly.
// serve runs the main (pid 1) guest process.
func serve(ch *channel, fs *dfs, mp *memProc, cfg Config) (int, error) {
	g := newDguest(fs, ch, fs.mem, 0, cfg)
	g.mp = mp
	g.pid = 1
	g.tgid = 1
	fs.mu.Lock()
	g.ps = fs.pt[1]
	g.ps.ft = g.ft
	g.ft.max = int(g.ps.rlim[rlimitNofil].cur)
	fs.mu.Unlock()
	fs.addProc(1, &dproc{ospid: g.ps.ospid, ch: ch, ps: g.ps, g: g})
	fs.bindStub(g.ps.ospid)
	defer g.release()
	if err := g.applyInitDir(cfg); err != nil {
		return 0, err
	}
	publishControl(cfg, fs.initOspid, fs)
	defer revokeControl(cfg)
	code, err := serveLoop(g, cfg)
	if err == errLeaderGone {
		// The main thread exited first; the run lasts until its last thread.
		return fs.leaderExited(g, code), nil
	}
	return code, err
}

// serveLoop drives one guest process's syscalls until it exits, returning its
// exit code. The main process and every forked child run the same loop; a
// child's caller (serveChild) has already completed the fork handshake, so the
// loop's first wait receives that process's first syscall either way.
func serveLoop(g *dguest, cfg Config) (code int, err error) {
	defer g.dfs.contain(&err)
	ch := g.ch
	g.attachStdio()
	defer g.detachStdio()
	if err := ch.wait(); err != nil {
		return 0, err
	}
	if !guestMsg(ch.page.kind) {
		// The stub self-loads and enters the guest, so the first message is a
		// syscall (or, traced, the report of one it served itself), not a
		// READY handshake. Anything else is a protocol error.
		return 0, fmt.Errorf("stub protocol: unexpected first message %d", ch.page.kind)
	}

	// hostThen performs the already-translated syscall in the guest and
	// replies the result to the guest.
	hostThen := func() error {
		ch.reply(repHost)
		if err := ch.wait(); err != nil {
			return err
		}
		if int64(ch.page.ret) == -int64(unix.EINTR) {
			ch.page.ret = ^uint64(-restartSys - 1) // ERESTARTSYS: a signal's kick: the stub restarts or delivers
		} else {
			ch.page.ret = linuxRet(ch.page.ret)
		}
		g.ptraceSyscallExit(int64(ch.page.ret))
		ch.reply(repResult)
		return nil
	}

	for {
		if ch.page.kind == msgTraceLocal {
			// A syscall the stub already served in-guest. Run the entry and
			// exit stops so a tracer observes it; ptraceSyscallExit leaves the
			// (possibly edited) result in ch.page.ret, which the stub reads back.
			g.ptraceEnter(ch.page.nr, ch.page.args)
			g.ptraceSyscallExit(int64(ch.page.ret))
			ch.reply(repResult)
			if err := ch.wait(); err != nil {
				return 0, err
			}
			if !guestMsg(ch.page.kind) {
				return 0, fmt.Errorf("stub protocol: expected syscall, got %d", ch.page.kind)
			}
			continue
		}
		if ch.page.kind == msgSeccomp {
			g.seccompCheck()
			if err := ch.wait(); err != nil {
				return 0, err
			}
			if !guestMsg(ch.page.kind) {
				return 0, fmt.Errorf("stub protocol: expected syscall, got %d", ch.page.kind)
			}
			continue
		}
		nr := ch.page.nr
		a := ch.page.args
		g.noteOut(ch.page.ret)
		// ptrace syscall-entry stop: a traced thread blocks here until the
		// tracer resumes it, which may edit its registers.
		if !g.ptraceEnter(nr, a) {
			ch.page.ret = errno(lxEINTR)
			ch.reply(repResult)
			if err := ch.wait(); err != nil {
				return 0, err
			}
			if !guestMsg(ch.page.kind) {
				return 0, fmt.Errorf("stub protocol: expected syscall, got %d", ch.page.kind)
			}
			continue
		}
		if ch.page.nr != nr || ch.page.args != a {
			g.outW = ^uint64(0) // a tracer's edit: the stub measured other arguments
		}
		nr, a = ch.page.nr, ch.page.args
		// An x86-64 guest posts x86-64 numbers; translate to the shared table's
		// asm-generic keys (identity for an arm64 guest). The stub sentinels are
		// large private values that pass through unchanged, so they still match
		// below. The arch is the guest's, not the supervisor's build arch.
		gnr, ga, generic := g.toGeneric(nr, a)
		switch gnr {
		case lxExit:
			g.traceEntry(gnr, ga)
			code := int(int32(a[0]))
			if g.isThread {
				// The stub already ended the thread (cleared and woke its tid
				// word, pthread_exit) and only posted this as notice; nothing
				// waits for a reply. Retire the slot; the process lives on.
				if cfg.Trace != nil {
					fmt.Fprintf(cfg.Trace, "[pid %d] thread exit code=%d\n", g.pid, code)
				}
				return code, nil
			}
			if g.sharedStub() {
				return code, errNeverRan // the stub could not start its thread
			}
			g.beginExit(code)
			ch.page.nr = dwExit
			ch.reply(repHost) // stub performs Darwin exit; process ends cleanly
			return code, nil

		case nrThreadGone:
			// The stub ended this thread (exit, not exit_group, with other
			// threads still running) and expects no reply.
			code := int(int32(a[0]))
			if cfg.Trace != nil {
				fmt.Fprintf(cfg.Trace, "[pid %d] thread exit code=%d\n", g.pid, code)
			}
			if !g.isThread && !g.sharedStub() {
				return code, errLeaderGone
			}
			return code, nil

		case lxExitGroup:
			g.traceEntry(gnr, ga)
			code := int(int32(a[0]))
			g.ptraceEvent(ptraceEventExit, uint64(code<<8))
			g.beginExit(code)
			if !g.isThread && g.sharedStub() {
				return code, g.endSharedThread()
			}
			ch.page.nr = dwExit
			ch.reply(repHost) // stub performs Darwin exit; its end ends the other threads' loops
			return code, nil

		case lxWrite:
			// A fd still backed by the stub's own stdio (not redirected to a
			// pipe or file) takes the in-stub fast path; everything else the
			// supervisor performs on the guest's open file.
			if sfd := g.stubFd(int64(a[0])); sfd >= 0 {
				call := g.traceStart(gnr, ga)
				ch.page.nr = dwWrite
				ch.page.args[0] = uint64(sfd)
				if err := hostThen(); err != nil {
					return 0, err
				}
				g.traceEnd(call, int64(ch.page.ret))
			} else {
				if cfg.Trace != nil {
					ch.page.ret = uint64(g.serveTraced(func(g *dguest, a [6]uint64) int64 { return g.writeFile(int64(a[0]), a[1], int64(a[2])) }, gnr, a))
				} else {
					ch.page.ret = uint64(g.writeFile(int64(a[0]), a[1], int64(a[2])))
				}
				ch.reply(repResult)
			}

		case lxRead:
			if sfd := g.stubFd(int64(a[0])); sfd >= 0 {
				call := g.traceStart(gnr, ga)
				ch.page.nr = dwRead
				ch.page.args[0] = uint64(sfd)
				if err := hostThen(); err != nil {
					return 0, err
				}
				g.traceEnd(call, int64(ch.page.ret))
			} else {
				if cfg.Trace != nil {
					ch.page.ret = uint64(g.serveTraced(func(g *dguest, a [6]uint64) int64 { return g.read(int64(a[0]), a[1], int64(a[2])) }, gnr, a))
				} else {
					ch.page.ret = uint64(g.read(int64(a[0]), a[1], int64(a[2])))
				}
				ch.reply(repResult)
			}

		case lxWritev:
			if sfd := g.stubFd(int64(a[0])); sfd >= 0 {
				call := g.traceStart(gnr, ga)
				ch.page.nr = dwWritev
				ch.page.args[0] = uint64(sfd)
				if err := hostThen(); err != nil {
					return 0, err
				}
				g.traceEnd(call, int64(ch.page.ret))
			} else {
				if cfg.Trace != nil {
					ch.page.ret = uint64(g.serveTraced(func(g *dguest, a [6]uint64) int64 { return g.writev(int64(a[0]), a[1], int64(a[2])) }, gnr, a))
				} else {
					ch.page.ret = uint64(g.writev(int64(a[0]), a[1], int64(a[2])))
				}
				ch.reply(repResult)
			}

		case lxReadv:
			if sfd := g.stubFd(int64(a[0])); sfd >= 0 {
				call := g.traceStart(gnr, ga)
				ch.page.nr = dwReadv
				ch.page.args[0] = uint64(sfd)
				if err := hostThen(); err != nil {
					return 0, err
				}
				g.traceEnd(call, int64(ch.page.ret))
			} else {
				if cfg.Trace != nil {
					ch.page.ret = uint64(g.serveTraced(func(g *dguest, a [6]uint64) int64 { return g.readv(int64(a[0]), a[1], int64(a[2])) }, gnr, a))
				} else {
					ch.page.ret = uint64(g.readv(int64(a[0]), a[1], int64(a[2])))
				}
				ch.reply(repResult)
			}

		case lxClone, lxClone3:
			var r cloneReq
			var e lxErrno
			if gnr == lxClone {
				r, e = cloneArgs(ga)
			} else {
				r, e = g.clone3Args(ga[0], ga[1])
			}
			if e != 0 {
				ch.page.ret = errno(e)
				ch.reply(repResult)
				break
			}
			call := g.traceStart(gnr, ga)
			id := g.clone(r, cfg) // replies repClone / repFork (or an error)
			g.traceEnd(call, int64(id))

		case lxExecve, lxExecveat:
			call := g.traceStart(gnr, ga)
			var ok bool
			if gnr == lxExecve {
				ok = g.execve(lxAtFdcwd, ga[0], ga[1], ga[2], 0)
			} else {
				ok = g.execve(int64(int32(ga[0])), ga[1], ga[2], ga[3], int64(int32(ga[4])))
			}
			if ok {
				g.traceEnd(call, 0)
			} else {
				g.traceEnd(call, int64(ch.page.ret))
				ch.reply(repResult) // failed: errno already in page.ret, guest continues
			}
			// On success the new program's first syscall is the next
			// message: execve replied repExec, or started a fresh stub on
			// this slot.

		case lxSigDie: // a signal's default action ends the process
			if !g.isThread && g.sharedStub() {
				return g.sigDie(int(a[0])), g.endSharedThread()
			}
			ch.page.ret = 0
			ch.reply(repResult)
			return g.sigDie(int(a[0])), nil

		case lxSigStop: // stopped before the reply, so the stub halts on it
			g.sigStopSelf(int(a[0]))
			ch.page.ret = 0
			ch.reply(repResult)

		case lxSigTake, lxSigSettle, lxSigFault, lxSigRaise:
			ch.page.ret = uint64(g.sigCall(nr, a))
			ch.reply(repResult)

		case nrChildStop:
			g.ptraceChildStart()
			ch.page.ret = 0
			ch.reply(repResult)

		case nrForked: // a traced clone's report no one waited for (the trace began meanwhile)
			ch.page.ret = a[0]
			ch.reply(repResult)

		case lxExecStop: // a traced respawn: run the ptrace exec-event stop at the new image
			g.ptraceExec(int(g.pid), a[0], a[1])
			ch.page.ret = 0
			ch.reply(repResult)

		case lxStepStop: // an HVF tracee single-stepped one instruction: run the step stop
			g.ptraceStepStop()
			ch.page.ret = 0
			ch.reply(repResult)

		default:
			if h, ok := handler(gnr); ok && generic {
				g.moveRseq()
				if cfg.Trace != nil {
					ch.page.ret = uint64(g.fromGeneric(nr, a, g.serveTraced(h, gnr, ga)))
				} else {
					ch.page.ret = uint64(g.fromGeneric(nr, a, h(g, ga)))
				}
				g.ptraceSyscallExit(int64(ch.page.ret))
				ch.reply(repResult)
				break
			}
			g.traceNosys(gnr, ga)
			ch.page.ret = errno(lxENOSYS)
			g.ptraceSyscallExit(int64(ch.page.ret))
			ch.reply(repResult)
		}

		if err := ch.wait(); err != nil {
			return 0, err
		}
		if !guestMsg(ch.page.kind) {
			return 0, fmt.Errorf("stub protocol: expected syscall, got %d", ch.page.kind)
		}
	}
}

// guestMsg reports whether kind is a message a guest thread posts for its
// call: the call itself, the report of one served in-guest, or a filter check.
func guestMsg(kind uint64) bool {
	return kind == msgSyscall || kind == msgTraceLocal || kind == msgSeccomp
}

// writeSeatbeltPaths writes <chan>.paths, the one host tree the stubs'
// Seatbelt profile lets them read (TMP in stub/macos/sbcache.zig): the run's
// temp directory, holding the site lists and the private copy of every program
// a stub loads. The guest shares the stub's address space and can make the
// profile's calls itself, so no tree of the guest's own is named there, not
// even a host-directory root: a raw read of it would pass by the vfs, its
// whiteouts and its mounts.
func writeSeatbeltPaths(chanPath string) error {
	tmp, err := filepath.EvalSymlinks(filepath.Dir(chanPath))
	if err != nil {
		return err
	}
	return os.WriteFile(chanPath+".paths", []byte(tmp+"\x00"), 0o600)
}

// signedStubFor returns the path of the map+rewrite stub for the guest's
// architecture, ad-hoc codesigned (arm64 refuses to run an unsigned binary):
// the x86-64 stub for an x86-64 guest, which runs under Rosetta, else the arm64
// stub. The supervisor's own architecture does not matter -- a native arm64
// build hosts an x86-64 guest this way. Both get the patchStub Mach-O edits.
func signedStubFor(x64 bool) (string, error) {
	bin, prefix := macstub.BinaryArm64, "stub-"
	if x64 {
		bin, prefix = macstub.BinaryAmd64, "stubx64-"
	}
	b, err := patchStub(bin)
	if err != nil {
		return "", err
	}
	return signAdhoc(b, prefix, "")
}

// signAdhoc writes bin to the user cache directory under its content hash,
// ad-hoc codesigns it, with the entitlements plist ent when it is not empty,
// and returns the path, reusing an already-signed copy: the first exec of a
// newly signed binary costs about 130 ms of signature checking, later execs of
// the same file about 10 ms. Runs signing the same binary at once each sign a
// copy of their own and rename it into place.
func signAdhoc(bin []byte, prefix, ent string) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "laboon")
	sum := sha256.Sum256(bin)
	path := filepath.Join(dir, prefix+hex.EncodeToString(sum[:8]))
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := writeTemp(dir, "."+prefix+"*", bin, 0o755)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp) // a no-op once renamed into place
	args := []string{"-s", "-", "--force", tmp}
	if ent != "" {
		entPath, err := writeTemp(dir, ".entitlements-*.plist", []byte(ent), 0o600)
		if err != nil {
			return "", err
		}
		defer os.Remove(entPath)
		args = append([]string{"--entitlements", entPath}, args...)
	}
	if out, err := exec.Command("codesign", args...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("codesign %s: %v: %s", prefix, err, out)
	}
	return path, os.Rename(tmp, path)
}

// writeTemp writes b to a new file in dir named by pattern, with mode perm,
// and returns its path.
func writeTemp(dir, pattern string, b []byte, perm os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if err := os.Chmod(f.Name(), perm); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// hvfEntitlement grants Hypervisor.framework access; the HVF stub is ad-hoc
// codesigned with it, or hv_vm_create returns HV_DENIED. No Apple provisioning
// or root is needed — the ad-hoc signature carries the entitlement.
const hvfEntitlement = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>
`

// signedHvfStub returns the path of the embedded HVF stub, ad-hoc codesigned
// WITH the hypervisor entitlement and cached under its content hash. Unlike
// the native stub it needs no patchStub edits: the guest's Linux code runs in
// the VM, not in the stub's own registers, so the stub is ordinary macOS code.
func signedHvfStub() (string, error) { return signAdhoc(macstub.HvfBinary, "hvfstub-", hvfEntitlement) }

// pageZeroSize is arm64 macOS's mandatory 4 GiB __PAGEZERO: a non-PIE ET_EXEC
// whose load segments fall inside it cannot be mapped in the stub's own address
// space (see the non-PIE wall), so it runs in a VM via the HVF stub instead.
const pageZeroSize = 4 << 30

// needsHvf reports whether the guest at elfPath is a non-PIE low-linked ET_EXEC
// that the native (map-and-rewrite) stub cannot load. A PIE (ET_DYN) or a
// high-linked ET_EXEC loads fine the native way and returns false.
func needsHvf(elfPath string) bool {
	f, err := elf.Open(elfPath)
	if err != nil {
		return false
	}
	defer f.Close()
	if f.Machine == elf.EM_X86_64 {
		return false // the x86-64 stub maps and rewrites the guest; there is no HVF backend for it
	}
	if f.Type != elf.ET_EXEC {
		return false
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Vaddr < pageZeroSize {
			return true
		}
	}
	return false
}

// patchStub returns a copy of the stub Mach-O edited before the ad-hoc
// re-sign. Its LC_BUILD_VERSION minos and sdk drop to macOS 10.12: Linux arm64
// code uses x18 as an ordinary register, and Darwin zeroes x18 on context
// switch except in binaries linked for an old OS, which Zig's SDK cannot link
// (os_set_custom_x18_abi_enabled is not enough: the kernel drops that
// per-thread opt-in on every block and core migration). Its LC_FUNCTION_STARTS
// is emptied: Zig's linker writes entries pointing into the Mach-O header, and
// Rosetta's ahead-of-time translation of the x86-64 stub trusts them.
//
// The x86-64 stub also gives the guest the low 4 GiB, where a non-PIE x86-64
// program is linked (there is no HVF backend for it): __PAGEZERO shrinks to
// Linux's mmap_min_addr and a last segment, inaccessible until the stub maps
// into it, reserves the rest so Darwin places nothing of its own there. The
// stub loads unslid (MH_PIE cleared), since a slide would move the reserve.
// It goes last so the segment indices the bind opcodes name stay as they are;
// the build leaves header room for it (build.sh -headerpad).
func patchStub(bin []byte) ([]byte, error) {
	const (
		lcSegment64      = 0x19
		lcBuildVersion   = 0x32
		lcFunctionStarts = 0x26
		macos1012        = 10<<16 | 12<<8
		cpuX86_64        = 0x01000007
		mhPIE            = 0x200000
		segSize          = 72
		lowGuest         = 0x10000
		lowTop           = 4 << 30
	)
	b := append([]byte(nil), bin...)
	le := binary.LittleEndian
	x64 := le.Uint32(b[4:]) == cpuX86_64
	ncmds, sizeofcmds := le.Uint32(b[16:]), le.Uint32(b[20:])
	firstData := uint64(len(b))
	pagezero := uint32(0)
	off := uint32(32)
	for i := uint32(0); i < ncmds; i++ {
		cmd, size := le.Uint32(b[off:]), le.Uint32(b[off+4:])
		switch cmd {
		case lcBuildVersion:
			le.PutUint32(b[off+12:], macos1012) // minos
			le.PutUint32(b[off+16:], macos1012) // sdk
		case lcFunctionStarts:
			le.PutUint32(b[off+12:], 0) // datasize
		case lcSegment64:
			if string(bytes.TrimRight(b[off+8:off+24], "\x00")) == "__PAGEZERO" {
				pagezero = off
			}
			nsects := le.Uint32(b[off+64:])
			for k := uint32(0); k < nsects; k++ {
				sect := off + segSize + k*80
				if o := uint64(le.Uint32(b[sect+48:])); o != 0 && o < firstData {
					firstData = o
				}
			}
		}
		off += size
	}
	if !x64 {
		return b, nil
	}
	end := 32 + sizeofcmds
	if pagezero == 0 || uint64(end)+segSize > firstData {
		return nil, fmt.Errorf("x86-64 stub: no header room for the low guest reserve")
	}
	seg := b[end : end+segSize]
	le.PutUint32(seg[0:], lcSegment64)
	le.PutUint32(seg[4:], segSize)
	copy(seg[8:24], "__LOWGUEST")
	le.PutUint64(seg[24:], lowGuest)
	le.PutUint64(seg[32:], lowTop-lowGuest)
	le.PutUint32(seg[56:], 7) // maxprot rwx; initprot none
	le.PutUint64(b[pagezero+32:], lowGuest)
	le.PutUint32(b[16:], ncmds+1)
	le.PutUint32(b[20:], sizeofcmds+segSize)
	le.PutUint32(b[24:], le.Uint32(b[24:])&^mhPIE)
	return b, nil
}

// headBytes reads up to n leading bytes of the host file at p, for the #! check.
func headBytes(p string, n int) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	m, err := f.Read(b)
	if err != nil && m == 0 {
		return nil, err
	}
	return b[:m], nil
}

// progResolver gives the stub a guest program or interpreter to map: resolved
// and opened through the root's Namespace, then a private copy of that open
// file in the run's temp dir (tmp), which the Seatbelt profile grants. The stub
// never maps a path inside the root, and the guest never supplies a host path.
type progResolver struct {
	tmp string
	ns  *namespace.Namespace
}

func (r *progResolver) host(gp string) (string, error) {
	loc, err := r.ns.Resolve(gp, true)
	if err != nil {
		return "", err
	}
	f, err := loc.Node.Open(os.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", gp)
	}
	fd, ok := hostFdOf(f)
	if !ok {
		fd = -1
	}
	return privateCopy(r.tmp, fd, f, info.Size(), info.Mode().Perm())
}

// privateCopy writes a copy of an exec source into dir and returns its path:
// an APFS clone of host descriptor fd when it can be (fd < 0: none), else the
// size bytes read through r.
func privateCopy(dir string, fd int, r io.ReaderAt, size int64, perm os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(dir, "lc-exec-*")
	if err != nil {
		return "", err
	}
	p := tmp.Name()
	tmp.Close()
	os.Remove(p)
	if fd >= 0 && unix.Fclonefileat(fd, unix.AT_FDCWD, p, 0) == nil {
		return p, nil
	}
	out, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm|0o600)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, io.NewSectionReader(r, 0, size))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(p)
		return "", err
	}
	return p, nil
}

// resolveInterp reads the guest ELF's PT_INTERP and maps the interpreter's guest
// path to a host path through hostOf (the same resolution as the program path,
// so a non-host root's dynamic linker is spilled too). It returns "" for a
// static executable.
func resolveInterp(elfPath string, hostOf func(string) (string, error)) (string, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return "", fmt.Errorf("laboon: read guest ELF: %w", err)
	}
	defer f.Close()

	var interp string
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		b := make([]byte, p.Filesz)
		if _, err := p.ReadAt(b, 0); err != nil {
			return "", fmt.Errorf("laboon: read PT_INTERP: %w", err)
		}
		interp = strings.TrimRight(string(b), "\x00")
		break
	}
	if interp == "" {
		return "", nil // static executable
	}
	host, err := hostOf(interp)
	if err != nil {
		return "", fmt.Errorf("laboon: dynamic linker %q: %w", interp, err)
	}
	return host, nil
}
