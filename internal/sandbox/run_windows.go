//go:build windows

package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/internal/rewrite"
)

// Windows backend (x86-64 and arm64): one guest process, one thread. See
// windows/DESIGN.md.
// The stub (stub/windows) runs the guest in its own address space; the
// supervisor loads and rewrites the image from outside through the stub's
// process handle and serves syscalls over a shared-section channel. Linux
// semantics come from the shared layer (lx_*.go) the darwin backend also
// runs: each syscall is translated to its generic form (toGeneric; x86-64
// numbers differ, arm64's are generic already) and served from the shared
// table; this file keeps what the host does itself (memory, exit, clocks).
// What differs per architecture (the rewriter, syscall numbers) is in
// run_windows_amd64.go and run_windows_arm64.go.

// trampArea is a trampoline area: size bytes at base, in branch range of the
// code whose sites it serves.
type trampArea struct{ base, size uint64 }

const (
	stackSize = 8 << 20
	trampSize = 1 << 20
	allocGran = 0x10000 // VirtualAlloc reservation granularity
	pageSize  = 0x1000

	// TEB TLS slots the stub claims; see stub/stub/windows.zig.
	tebSlotStk = 0x1480 + 60*8
	tebSlotTP  = 0x1480 + 63*8

	exeBias    = 0x555555550000
	interpBias = 0x7e0000000000
)

// strictRewrite refuses an image with stray syscall encodings: set with
// LC_STRICT_REWRITE=1.
var strictRewrite = os.Getenv("LC_STRICT_REWRITE") == "1"

// testNoFSIslands, when set by a test, leaves every %fs site to the stub's
// fault handler.
var testNoFSIslands bool

// testUpper, when set by a test, is a writable layer kept across runs.
var testUpper string

// Run executes the Linux program at path (inside the root filesystem) and returns its
// exit status.
func Run(ctx context.Context, prog string, cfg Config) (int, error) {
	if len(cfg.Args) == 0 {
		return 0, errors.New("no argv")
	}
	if cfg.RootFS == nil {
		return 0, errors.New("windows backend needs a root")
	}
	if cfg.Env == nil {
		cfg.Env = []string{} // a nil env is empty, never the supervisor's own
	}
	r := &procRun{cfg: cfg, cache: cfg.Cache}
	if r.cache == nil {
		r.cache = defaultCache()
	}

	// One section holds every process's channel slots, signal records and
	// copy windows; each stub maps it whole (and a fork child inherits the
	// view).
	sec, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, 0, chanLen, nil)
	if err != nil {
		return 0, fmt.Errorf("channel section: %w", err)
	}
	defer windows.CloseHandle(sec)
	r.sec = sec
	view, err := windows.MapViewOfFile(sec, windows.FILE_MAP_WRITE, 0, 0, chanLen)
	if err != nil {
		return 0, err
	}
	defer windows.UnmapViewOfFile(view)
	// view is memory outside the Go heap; read it as a pointer without
	// a uintptr conversion vet would flag.
	mem := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&view))), chanLen)

	tmp, err := os.MkdirTemp("", "lc-run-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	done := make(chan struct{})
	upper := cfg.Upper
	if upper == "" {
		upper = testUpper
	}
	fs, err := newDfs(cfg.RootFS, upper, mem, done, tmp)
	if err != nil {
		return 0, err
	}
	defer fs.close()
	seedLowerOwners(fs)

	stdio, wait, err := stdioFiles(&cfg)
	if err != nil {
		return 0, err
	}
	defer wait()
	defer func() {
		flushPipeEnds(stdio[:]) // before wait: a copier still drains what they write
		if fs.net != nil {
			forgetPipeBus(fs.net)
		}
	}()
	r.cfg = cfg

	// Every stub of the run is in one job; closing it ends them all.
	job, err := newJob(cfg.MaxBytes)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(job)
	r.job = job

	exe := path.Clean("/" + prog)
	fs.initProcfs(0, exe, cfg.Args, cfg.Env, stdio)
	fs.newInitProc(0, prog, cfg.User)
	sr := newSigRun(fs, mem, 0)
	defer sr.close()
	winInstallInjector(sr)
	defer winDropInjector(sr)

	evStub, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(evStub)
	evSup, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(evSup)
	ch := &hostChan{channel: newChannel(mem, 0, 0, done, nil), evStub: evStub, evSup: evSup}
	defer ch.closeProc()
	dg := newDguest(fs, ch, mem, 0, cfg)
	dg.pid, dg.tgid = 1, 1
	dg.mp = newMemProc()
	fs.mu.Lock()
	dg.ps = fs.pt[1]
	dg.ps.ft = dg.ft
	dg.ft.max = int(dg.ps.rlim[rlimitNofil].cur)
	fs.mu.Unlock()
	fs.addProc(1, &dproc{ch: ch, ps: dg.ps, g: dg})
	defer dg.release()
	fs.attachConsole(dg)
	defer fs.term.close()

	ended := make(chan struct{})
	defer close(ended)
	go func() {
		select {
		case <-ctx.Done():
			windows.TerminateJobObject(job, 130)
		case <-ended:
		}
	}()

	src, argv, e := initProgram(dg, exe, cfg.Args)
	if e != 0 {
		return 0, fmt.Errorf("%s: %w", prog, lxErr(e))
	}
	defer func() {
		if w := dg.mp.w; w != nil && w.sp != nil {
			w.sp.close()
		}
	}()
	if err := dg.applyInitDir(cfg); err != nil {
		return 0, err
	}
	if _, err := r.boot(dg, src, argv, cfg.Env, nil); err != nil {
		windows.TerminateJobObject(job, 128+9)
		fs.wg.Wait() // a stub's watcher touches the section
		return 0, err
	}
	publishControl(cfg, 0, fs) // the host leader runs in a job object; Pid is best-effort here
	defer revokeControl(cfg)
	code, err := serveGuest(dg)
	if err == errLeaderGone {
		dg.release()
		code, err = fs.leaderExited(dg, code), nil
	}
	// The rest of the run goes with pid 1, as a pid namespace's does.
	windows.TerminateJobObject(job, 128+9)
	fs.wg.Wait() // let the serve goroutines unwind before the section is unmapped
	close(done)
	if errors.Is(err, errExited) {
		if k := sr.killedBy(1); k != 0 {
			return 128 + k, nil // the guest died of a signal
		}
		if c, ok := fs.groupExitCode(1); ok {
			return c, nil // exit_group from a thread other than the main one
		}
		return 0, dg.mp.w.stubDied(err)
	}
	if err == nil && code < 0 {
		return 128 - code, nil
	}
	return code, err
}

// procRun is a run's host state shared by its processes: the channel section
// every stub maps, the job every stub is in, the loader's configuration.
type procRun struct {
	cfg   Config
	cache *rewrite.Cache
	sec   windows.Handle
	job   windows.Handle
	futex futexTable // futexes on shared memory, across the run's stubs
	pool  stubPool
	code  codeReg // code in shared memory, across the run's stubs (codereg.go)
}

// boot starts a fresh stub for dg's process on dg's channel slot and runs the
// program (data, read from the guest's filesystem) in it with argv and env:
// the stub's handshake, the images and the initial stack. A fork child is
// the only process that does not start here. An exec's ready runs once the
// program is in place and before it starts, with its entry and stack.
func (r *procRun) boot(dg *dguest, src imageSrc, argv, env []string, ready func(entry, sp uint64)) (*wguest, error) {
	w := &wguest{run: r, cfg: r.cfg, cache: r.cache, traps: &codeTraps{}}
	ch := dg.ch
	pg := ch.page
	pg.state, pg.kind, pg.stubSleep, pg.supSleep, pg.rip = 0, 0, 0, 0, 0
	var sp *stubProc
	pooled := r.claim(dg.dfs, ch, dg.slot)
	if pooled != nil {
		sp = pooled.sp
	} else {
		var err error
		if sp, err = startStub(r.job, []windows.Handle{r.sec, ch.evStub, ch.evSup}, uint64(dg.slot*slotSize)); err != nil {
			return nil, err
		}
	}
	w.sp = sp
	if err := ch.setProc(sp.proc); err != nil {
		windows.TerminateProcess(sp.proc, 1)
		sp.close()
		return nil, err
	}
	dg.mp.w = w
	fs := dg.dfs
	if pid, err := windows.GetProcessId(sp.proc); err == nil {
		fs.mu.Lock()
		dg.ps.ospid = int(pid)
		dg.ps.checkedIn = true
		if p := fs.procs[dg.pid]; p != nil {
			p.ospid = int(pid)
		}
		if dg.ps.tgid == 1 {
			fs.pst.stubPid = int(pid)
			fs.sigs().mainOspid = int(pid)
		}
		fs.mu.Unlock()
		fs.watchStub(int(pid), sp.proc)
	}

	err := ch.wait()
	if pooled != nil {
		pooled.release(fs)
		r.fill(fs)
	}
	if err != nil {
		return w, w.stubDied(err)
	}
	if pg.kind != msgReady {
		return w, errProtocol
	}
	w.entry = pg.args[0]
	w.exitEntry = pg.args[5]
	reported := pg.args

	lay := drawWinLayout(dg)
	w.brkGap = lay.brkGap
	img, err := w.loadELF(src, lay.exe)
	if err != nil {
		return w, err
	}
	// A dynamic program starts in its interpreter (ld-musl), which the
	// supervisor loads beside it, as the kernel does; the interpreter maps the
	// libraries itself, and the stub has each executable mapping rewritten.
	entry, base := img.entry, uint64(0)
	ranges := [][2]uint64{{img.lo, img.hi}}
	var interp *wimage
	if img.interp != "" {
		ip, e := dg.walkAt(lxAtFdcwd, img.interp, true)
		if e != 0 {
			return w, fmt.Errorf("interpreter %s: %w", img.interp, lxErr(e))
		}
		isrc, e := dg.readImage(execSrc{gp: ip})
		if e != 0 {
			return w, fmt.Errorf("interpreter %s: %w", img.interp, lxErr(e))
		}
		if interp, err = w.loadELF(isrc, lay.interp); err != nil {
			return w, fmt.Errorf("%s: %w", img.interp, err)
		}
		if interp.interp != "" {
			return w, fmt.Errorf("%s: an interpreter with an interpreter", img.interp)
		}
		entry, base = interp.entry, interp.base
		ranges = append(ranges, [2]uint64{interp.lo, interp.hi})
	}
	// The stub reports its channel-slot base and the signal-delivery entry
	// points; the supervisor reaches a thread through them, redirecting it only
	// while it runs guest code.
	w.st = &winStub{proc: sp.proc, chanBase: reported[1], redirect: uintptr(reported[2]), apc: uintptr(reported[3]), code: ranges}
	winSetThread(fs.sigs(), dg.pid, sp.thread, false, w.st)
	if err := w.mapImage(img, true); err != nil {
		return w, err
	}
	w.traps.set([][2]uint64{{img.lo, img.hi}}, img.traps)
	if interp != nil {
		if err := w.mapImage(interp, false); err != nil {
			return w, err
		}
		w.traps.set([][2]uint64{{interp.lo, interp.hi}}, interp.traps)
	}
	stack, err := sp.alloc(lay.stack-stackSize, stackSize, windows.PAGE_READWRITE)
	if err != nil { // the band is taken: the host chooses
		stack, err = sp.alloc(0, stackSize, windows.PAGE_READWRITE)
	}
	if err != nil {
		return w, fmt.Errorf("guest stack: %w", err)
	}
	var random [16]byte
	rand.Read(random[:])
	auxv := []uint64{
		3, img.phdr, // AT_PHDR
		4, 56, // AT_PHENT
		5, img.phnum, // AT_PHNUM
		6, pageSize, // AT_PAGESZ
		7, base, // AT_BASE
		9, img.entry, // AT_ENTRY
		11, 0, 12, 0, 13, 0, 14, 0, // AT_UID, AT_EUID, AT_GID, AT_EGID
		17, lxUserHZ, // AT_CLKTCK
		23, 0, // AT_SECURE
	}
	if guestArch == "aarch64" {
		hwcap, hwcap2 := hostHwcap()
		auxv = append(auxv, 16, hwcap, 26, hwcap2) // AT_HWCAP, AT_HWCAP2
	}
	top := stack + stackSize
	gsp, sb := layoutStack(top, argv, env, guestArch, auxv)
	if err := sp.writeMem(gsp, sb); err != nil {
		return w, err
	}
	ii := &imgInfo{sp: gsp, mainLo: img.lo, mainHi: img.hi, stackLo: stack, stackHi: top}
	w.segs = img.segs
	if interp != nil {
		ii.interpLo, ii.interpHi = interp.lo, interp.hi
		w.segs = append(w.segs, interp.segs...)
	}
	dg.pi.mu.Lock()
	dg.pi.img, dg.pi.interp = ii, img.interp
	dg.pi.mu.Unlock()
	if ready != nil {
		ready(entry, gsp)
	}
	pg.args = [6]uint64{entry, gsp, top, stack, img.hi + w.brkGap, img.hi + w.brkGap + brkMax}
	ch.reply(repStart)
	return w, nil
}

// wguest is a guest process's stub: the process, the entry points it
// reported, and the loader that fills it. The threads of a process, and a
// CLONE_VM child until it execs, share it (through their memProc).
type wguest struct {
	run   *procRun
	cfg   Config
	cache *rewrite.Cache
	sp    *stubProc
	st    *winStub // the signal injector's record of this stub
	entry uint64
	// exitEntry is the stub's lc_exit_entry (x86-64), where exit sites go
	// once on the stub's stack.
	exitEntry uint64
	segs      []mapEnt   // the images' segments, as hostMaps reports them
	brkGap    uint64     // between the program's end and its brk area, drawn per execve
	anon      anonCode   // what is known of its code made executable at run time (anoncode.go)
	link      *winLink   // its stub's service thread, for the shared-code registry (codereg_windows.go)
	traps     *codeTraps // where the rewriter left traps in its file code (traps_windows.go)
}

// imageSrc is an ELF file to rewrite: its bytes, or the open file they are
// read from. Its identity, when known, keys the plan cache, so a file seen
// before is neither analyzed nor hashed.
type imageSrc struct {
	data  []byte
	f     *os.File
	r     io.ReaderAt // a regular file's File, read in place of f
	id    rewrite.FileID
	hasID bool
}

func (s imageSrc) reader() io.ReaderAt {
	switch {
	case s.f != nil:
		return s.f
	case s.r != nil:
		return s.r
	}
	return bytes.NewReader(s.data)
}

func (s imageSrc) bytes() ([]byte, error) {
	if s.f == nil && s.r == nil {
		return s.data, nil
	}
	return io.ReadAll(io.NewSectionReader(s.reader(), 0, 1<<62))
}

func (s imageSrc) identity() (rewrite.FileID, bool) {
	if s.hasID || s.f == nil {
		return s.id, s.hasID
	}
	return fileIdentity(s.f)
}

func fileIdentity(f *os.File) (rewrite.FileID, bool) {
	fi, err := f.Stat()
	if err != nil {
		return rewrite.FileID{}, false
	}
	st, ok := hostfs.StatOf(fi)
	if !ok || st.Ino() == 0 {
		return rewrite.FileID{}, false
	}
	return rewrite.FileID{Dev: st.Dev(), Ino: st.Ino(), Size: st.Size(), Mtime: TsNano(st.Mtime()), Ctime: TsNano(st.Ctime())}, true
}

// initProgram reads the first program, following #! scripts to their
// interpreter as execve does, and returns its bytes and argv.
func initProgram(dg *dguest, exe string, argv []string) (imageSrc, []string, lxErrno) {
	src, e := dg.readImage(execSrc{gp: exe})
	for depth := 0; e == 0 && bytes.HasPrefix(src.data, []byte("#!")); depth++ {
		if depth >= maxInterpDepth {
			return imageSrc{}, nil, lxELOOP
		}
		line := src.data[2:]
		if nl := bytes.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		interp, arg := splitShebang(string(line))
		if interp == "" {
			return imageSrc{}, nil, lxENOEXEC
		}
		np := []string{interp}
		if arg != "" {
			np = append(np, arg)
		}
		argv = append(append(np, exe), argv[1:]...)
		exe = interp
		src, e = dg.readImage(execSrc{gp: exe})
	}
	if e != 0 {
		return imageSrc{}, nil, e
	}
	dg.pi.mu.Lock()
	dg.pi.exe, dg.pi.argv = exe, argv
	dg.pi.mu.Unlock()
	return src, argv, 0
}

// backstopKill is the exit status the stub dies with when its instrumentation
// callback catches a stray guest syscall (stub/windows/instrcb.zig BACKSTOP_KILL).
const backstopKill = 0x5CA11ED0

// stubDied explains why the stub ended without an exit_group.
func (g *wguest) stubDied(err error) error {
	if !errors.Is(err, errExited) {
		return err
	}
	var code uint32
	windows.GetExitCodeProcess(g.sp.proc, &code)
	if code == backstopKill {
		return ErrKilled // the syscall backstop killed the guest for a stray syscall
	}
	return fmt.Errorf("stub exited unexpectedly: status %#x", code)
}

type wimage struct {
	entry, phdr, phnum uint64
	lo, hi             uint64
	base               uint64 // load bias
	interp             string // PT_INTERP
	bytes              []byte
	prots              []wrun
	segs               []mapEnt // its PT_LOADs for /proc/<pid>/maps: range and file offset
	view               *imgView // from the image cache: bytes is then only what follows the view
	traps              []uint64 // where the rewriter left traps in it (traps_windows.go)
}

type wrun struct {
	lo, hi uint64
	prot   uint32
}

func alignUp(v uint64) uint64 { return (v + pageSize - 1) &^ (pageSize - 1) }

// relocate moves the image by d: its guest addresses, the trampolines'
// included, are all relative to its code.
func (img *wimage) relocate(d uint64) {
	img.entry, img.phdr, img.lo, img.hi, img.base = img.entry+d, img.phdr+d, img.lo+d, img.hi+d, img.base+d
	for i := range img.prots {
		img.prots[i].lo += d
		img.prots[i].hi += d
	}
	for i := range img.segs {
		img.segs[i].lo += d
		img.segs[i].hi += d
	}
	for i := range img.traps {
		img.traps[i] += d
	}
}

// winLayout is where an execve places a program on Windows, as Linux's ASLR
// would, in the host's allocation granularity (64 KiB): a position-
// independent one at exe (exeBias moved up by a random offset of the range
// mmapRndBits pages span), its interpreter at interp (interpBias moved down by
// another), the stack's top at stack (in a band of its own below the
// interpreter's, moved down by stackRndBits pages), and its brk area a random
// part of 1 GiB past its end. The mmap areas are the host's, which places each
// process's anew. ADDR_NO_RANDOMIZE leaves them at their bases.
type winLayout struct {
	exe, interp, stack, brkGap uint64
}

func drawWinLayout(dg *dguest) winLayout {
	dg.dfs.mu.Lock()
	norand := dg.ps.personality&addrNoRandomize != 0
	dg.dfs.mu.Unlock()
	span := uint64(1) << mmapRndBits * 0x1000 / allocGran
	stackBase := interpBias - span*allocGran - 1<<30
	if norand {
		return winLayout{exe: exeBias, interp: interpBias, stack: stackBase, brkGap: brkGap}
	}
	return winLayout{
		exe:    exeBias + randBelow(span)*allocGran,
		interp: interpBias - randBelow(span)*allocGran,
		stack:  stackBase - randBelow(1<<stackRndBits*0x1000/allocGran)*allocGran,
		brkGap: brkGap + randBelow(1<<30/allocGran)*allocGran,
	}
}

// randBelow is a random number below n, a power of two.
func randBelow(n uint64) uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:]) & (n - 1)
}

// loadELF prepares an image, loaded at dynBias if it is ET_DYN: segments,
// rewritten code, and below it the trampoline area the rewriter fills.
func (g *wguest) loadELF(src imageSrc, dynBias uint64) (*wimage, error) {
	cache := g.imgPath(src)
	if cache != "" {
		if img := cachedImage(cache); img != nil {
			if img.base != 0 { // position-independent: it moves whole, trampolines with it
				img.relocate(dynBias - img.base)
			}
			return img, nil
		}
	}
	data := src.data
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if f.Machine != elfMachine {
		return nil, errors.New("not an " + guestArch + " executable")
	}
	var bias uint64
	switch f.Type {
	case elf.ET_EXEC:
	case elf.ET_DYN:
		bias = dynBias
	default:
		return nil, errors.New("not an executable")
	}
	img := &wimage{entry: bias + f.Entry, phnum: uint64(len(f.Progs)), lo: ^uint64(0), base: bias}
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP:
			if p.Filesz == 0 || p.Off+p.Filesz > uint64(len(data)) {
				return nil, errors.New("bad PT_INTERP")
			}
			img.interp = string(bytes.TrimRight(data[p.Off:p.Off+p.Filesz], "\x00"))
		case elf.PT_PHDR:
			img.phdr = bias + p.Vaddr
		case elf.PT_LOAD:
			img.lo = min(img.lo, (bias+p.Vaddr)&^(pageSize-1))
			img.hi = max(img.hi, alignUp(bias+p.Vaddr+p.Memsz))
			if img.phdr == 0 && p.Off == 0 {
				img.phdr = bias + p.Vaddr + getLE64(data[32:])
			}
		}
	}
	if img.hi == 0 {
		return nil, errors.New("no loadable segments")
	}
	rw, err := g.newRewriter(src)
	if err != nil {
		return nil, err
	}
	// The trampolines go just below the image, or just above it when there is
	// no room below (Go's linux/arm64 text starts at 0x10000); an image wider
	// than a branch reaches takes both.
	size := max(trampSize, (rw.need()+allocGran-1)&^(allocGran-1))
	var areas []trampArea
	if img.lo >= size+allocGran {
		img.lo = (img.lo - size) &^ (allocGran - 1)
		areas = append(areas, trampArea{img.lo, size})
	}
	if len(areas) == 0 || img.hi-img.lo > trampReach {
		at := (img.hi + allocGran - 1) &^ (allocGran - 1)
		img.hi = at + size
		areas = append(areas, trampArea{at, size})
	}
	rw.place(areas)
	img.bytes = make([]byte, img.hi-img.lo)
	// What a view of the cached image can hold: everything below the first
	// writable segment, when no read-only one lies past it.
	roEnd, wLo := uint64(0), img.hi
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Flags&elf.PF_W != 0 {
			wLo = min(wLo, (bias+p.Vaddr)&^(pageSize-1))
		} else {
			roEnd = max(roEnd, alignUp(bias+p.Vaddr+p.Memsz))
		}
		if p.Off+p.Filesz > uint64(len(data)) || p.Filesz > p.Memsz {
			return nil, errors.New("segment outside file")
		}
		at := bias + p.Vaddr - img.lo
		seg := img.bytes[at : at+p.Filesz]
		copy(seg, data[p.Off:p.Off+p.Filesz])
		var prot uint64
		if p.Flags&elf.PF_R != 0 {
			prot |= 1
		}
		if p.Flags&elf.PF_W != 0 {
			prot |= 2
		}
		if p.Flags&elf.PF_X != 0 {
			if prot&2 != 0 {
				return nil, errors.New("writable and executable segment refused (W^X)")
			}
			prot |= 4
			if !g.cfg.NoRewrite {
				rw.segment(seg, bias+p.Vaddr, p.Vaddr)
			}
		}
		lo := (bias + p.Vaddr) &^ (pageSize - 1)
		img.prots = append(img.prots, wrun{lo, alignUp(bias + p.Vaddr + p.Memsz), winProt(prot)})
		img.segs = append(img.segs, mapEnt{lo: lo, hi: alignUp(bias + p.Vaddr + p.Filesz), off: p.Off &^ (pageSize - 1), attr: mapFile})
		if end := alignUp(bias + p.Vaddr + p.Memsz); end > alignUp(bias+p.Vaddr+p.Filesz) {
			img.segs = append(img.segs, mapEnt{lo: alignUp(bias + p.Vaddr + p.Filesz), hi: end, attr: mapAnon})
		}
	}
	code, err := rw.finish(img.lo, img.hi)
	if err != nil {
		return nil, err
	}
	img.traps = rw.traps()
	for i, a := range areas {
		copy(img.bytes[a.base-img.lo:], code[i])
		img.prots = append(img.prots, wrun{a.base, a.base + a.size, windows.PAGE_EXECUTE_READ})
	}
	if areas[0].base == img.lo && roEnd <= wLo {
		saveImage(cache, img, wLo-img.lo)
	}
	return img, nil
}

// strayPolicy reports the stray syscall encodings a rewrite left: they are
// not at an instruction boundary (an immediate, a displacement, a data word
// in text), so only a jump into the middle of an instruction runs one. On
// x86-64 the stub's instrumentation-callback backstop (stub/windows/instrcb.zig)
// then kills the guest (ErrKilled), like seccomp on Linux; on arm64 (no backstop
// yet) only the AppContainer bounds it. strictRewrite refuses such an image
// instead, for a provably complete rewrite.
func (g *wguest) strayPolicy(stray []uint64) error {
	for _, a := range stray {
		g.tracef("[lc] stray syscall encoding at %#x left in place\n", a)
	}
	if strictRewrite && len(stray) > 0 {
		return fmt.Errorf("cannot rewrite completely: %d stray syscall encodings (LC_STRICT_REWRITE)", len(stray))
	}
	return nil
}

func getLE64(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// mapImage installs a prepared image in the stub. Gaps between segments stay
// inaccessible.
func (g *wguest) mapImage(img *wimage, brk bool) error {
	// After the program's image, past a gap, the brk area the stub commits
	// as the break grows.
	if brk {
		_, err := g.sp.reserve(img.hi+g.brkGap, brkMax)
		if err != nil && g.brkGap != brkGap {
			// The randomized place is the stub's own memory: the area goes
			// right past the image, as unrandomized.
			g.brkGap = brkGap
			_, err = g.sp.reserve(img.hi+g.brkGap, brkMax)
		}
		if err != nil {
			return fmt.Errorf("brk area at %#x: %w", img.hi+g.brkGap, err)
		}
	}
	if img.view != nil {
		if err := g.mapImageView(img); err != nil {
			return fmt.Errorf("map image at %#x: %w", img.lo, err)
		}
		return nil
	}
	if _, err := g.sp.reserve(img.lo, img.hi-img.lo); err != nil {
		return fmt.Errorf("map image at %#x: %w", img.lo, err)
	}
	if _, err := g.sp.commit(img.lo, img.hi-img.lo, windows.PAGE_READWRITE); err != nil {
		return fmt.Errorf("map image at %#x: %w", img.lo, err)
	}
	if err := g.sp.writeMem(img.lo, img.bytes); err != nil {
		return err
	}
	if err := g.sp.flushCode(img.lo, img.hi-img.lo); err != nil {
		return err
	}
	if err := g.sp.protect(img.lo, img.hi-img.lo, windows.PAGE_NOACCESS); err != nil {
		return err
	}
	for _, r := range img.prots {
		if err := g.sp.protect(r.lo, r.hi-r.lo, r.prot); err != nil {
			return fmt.Errorf("protect %#x: %w", r.lo, err)
		}
	}
	return nil
}

// syscall serves one syscall the stub posts (memory and the per-thread calls
// are served in the stub): the host's own (file mappings, clocks), else the
// shared table through toGeneric. dg is the posting thread.
func (g *wguest) syscall(dg *dguest, nr uint64, a [6]uint64) int64 {
	switch nr {
	case lcMapFill:
		return g.mapFill(dg, a[0], a[1], a[2], a[3])
	case lcMapSection:
		return g.mapSection(dg, a[0], a[1], a[2], a[3])
	case lcSyncBacking:
		return dg.syncBacking(a[0])
	case lcDropBacking:
		return dg.dropBacking(a[0])
	case lcFutex:
		return g.run.futex.serve(dg, a[0], a[1], a[2], a[3], a[4], a[5])
	case lcCodeSize:
		return g.codeSize(dg, a[0], a[1], a[2], a[3])
	case lcMapCode:
		return g.mapCode(dg, a[0], a[1], a[2], a[3], a[4])
	case lcAnonSites:
		return g.anonSites(dg, a[0], a[1], a[2])
	case lcIsTrap:
		return g.isTrap(a[0])
	case lcInsn:
		return g.insn(a[0])
	case lcServiceSlot:
		return g.serviceSlot(dg)
	case lcServiceHeld:
		return int64(g.heldTo(dg, int(a[0])))
	case lcHot, lcCool:
		return g.codeReq(dg, nr, a[0], a[1])
	case lcCodeFile:
		dg.codeKey(a[0])
		return 0
	case lcIdregs:
		// The guest's ID_AA64ISAR0/1/2, from the host features this run
		// presents in AT_HWCAP, for the arm64 stub's mrs trap.
		hwcap, hwcap2 := hostHwcap()
		isar0, isar1, isar2 := isarFromHwcap(hwcap, hwcap2)
		dg.ch.page.args[0], dg.ch.page.args[1], dg.ch.page.args[2] = isar0, isar1, isar2
		return 0
	case wRobust, wYield:
		return 0
	case wSetTid:
		return int64(dg.pid)
	case wClockGettime:
		return g.clockGettime(dg, int64(a[0]), a[1])
	case wGtod:
		if a[0] == 0 {
			return 0
		}
		now := time.Now()
		var b [16]byte
		put64(b[:], uint64(now.Unix()))
		put64(b[8:], uint64(now.Nanosecond()/1000))
		return dg.putMem(a[0], b[:])
	case wTime:
		t := time.Now().Unix()
		if a[0] != 0 {
			var b [8]byte
			put64(b[:], uint64(t))
			if r := dg.putMem(a[0], b[:]); r != 0 {
				return r
			}
		}
		return t
	case wGetrandom:
		b := make([]byte, min(a[1], 1<<16))
		rand.Read(b)
		if r := dg.putMem(a[0], b); r != 0 {
			return r
		}
		return int64(len(b))
	}
	gnr, ga, ok := toGeneric(nr, a)
	if !ok {
		return sErr(lxENOSYS)
	}
	h, ok := handler(gnr)
	if !ok {
		return sErr(lxENOSYS)
	}
	return fromGeneric(nr, a, h(dg, ga))
}

func (g *wguest) clockGettime(dg *dguest, clock int64, addr uint64) int64 {
	d := clockNow(clock)
	var b [16]byte
	put64(b[:], uint64(d/time.Second))
	put64(b[8:], uint64(d%time.Second))
	return dg.putMem(addr, b[:])
}
