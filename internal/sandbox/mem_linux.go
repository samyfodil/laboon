package sandbox

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// Guest memory on Linux is the stub process's own, and the supervisor shapes
// it: the stub runs the mapping calls the supervisor asks for (REP_HOST), and
// the supervisor reads and writes the bytes with process_vm_readv/writev.
// Code is only ever made executable by the supervisor, after rewriting its
// syscall sites (W^X), which is what keeps every executed syscall rewritten.

// memProc is a guest process's memory state, shared by its threads.
type memProc struct {
	mu   sync.Mutex
	pid  atomic.Int64 // a live thread of the stub process (its leader's, until an exec from another thread)
	refs int

	// The stub process's host-op thread (hop_linux.go): hopPend is its entry,
	// hopP the same once the stub runs the thread, which routes host calls.
	hopPend *hop
	hopP    atomic.Pointer[hop]

	hostStack atomic.Pointer[run] // the stack the stub process's exec gave it, until the guest's first call unmaps it

	// vmMu lets writablePrefix read vm and noWrite without mu, which memory
	// calls hold across their host calls: a change to the two holds both
	// locks, and vmMu only for the change itself.
	vmMu sync.RWMutex

	sites      siteSet // syscall sites rewritten to trap, which a trap must hit
	fast       int     // of them, with a trampoline
	strays     int     // stray syscall encodings left to seccomp
	reserved   []run   // ranges the guest may not unmap, remap or reprotect
	fileCode   []fileCode
	vm         vmaSet       // the guest's mappings: execve's teardown, the memory cap and placement
	noWrite    vmaSet       // the mapped ranges the guest cannot write (mapped or protected without PROT_WRITE)
	shMaps     []shMap      // this address space's MAP_SHARED mappings of non-host files, for eviction (shmaps_linux.go)
	special    []specialMap // the kernel's special mappings the guest has, in place or moved aside (vdso_linux.go)
	lay        mmapLayout   // where mappings the guest leaves unplaced go
	used       int64
	brk, brkLo uint64

	stackChunks map[int]bool // the slot stack chunks the stub process has mapped (stacks_linux.go)

	// The initial stack's true bounds (exec sets them). The host kernel may
	// merge this anonymous mapping with adjacent ones in /proc/<pid>/maps, so
	// self-maps carves it back out as a distinct [stack] region: musl's
	// main-thread stack probe (and e.g. PHP's overflow guard above it) takes
	// the containing region's top as the stack base, and a merged top reads as
	// megabytes of phantom stack already consumed.
	stackLo, stackHi uint64

	clearTid map[int]uint64 // by thread: the address its exit clears and wakes (CLONE_CHILD_CLEARTID)
	ownStack map[int]run    // by thread: the stack it unmapped while running on it (unmapOwnStack)

	names  map[uint64]fileName    // for /proc/<pid>/maps (unused on Linux: the host's maps name files)
	shm    map[uint64]*shmAttach  // SysV segments attached, by address
	semadj map[int]map[uint16]int // SEM_UNDO adjustments, by set and semaphore
}

func newMemProc(pid int) *memProc {
	m := &memProc{refs: 1, clearTid: map[int]uint64{}, ownStack: map[int]run{}, names: map[uint64]fileName{},
		shm: map[uint64]*shmAttach{}, semadj: map[int]map[uint16]int{}}
	m.pid.Store(int64(pid))
	return m
}

func (m *memProc) share() *memProc {
	m.mu.Lock()
	m.refs++
	m.mu.Unlock()
	return m
}

// release drops a thread's reference; the last one, the process exiting,
// lets go of its memory and SysV IPC state.
func (m *memProc) release(g *dguest) {
	m.mu.Lock()
	m.refs--
	last := m.refs == 0
	ipc := len(m.shm) > 0 || len(m.semadj) > 0
	m.mu.Unlock()
	if !last {
		return
	}
	g.memUsed.Add(-m.used)
	if ipc {
		m.detachAll(g)
		m.undoSems(g)
	}
}

// read reads guest memory with process_vm_readv.
func (m *memProc) read(addr uint64, b []byte) error {
	for len(b) > 0 {
		n, err := unix.ProcessVMReadv(int(m.pid.Load()),
			[]unix.Iovec{{Base: &b[0], Len: uint64(len(b))}},
			[]unix.RemoteIovec{{Base: uintptr(addr), Len: len(b)}}, 0)
		if err != nil {
			return err
		}
		if n == 0 {
			return unix.EFAULT
		}
		b = b[n:]
		addr += uint64(n)
	}
	return nil
}

// readPrefix reads as much of b at addr as is readable, the bytes before the
// first page that is not, and returns how many.
func (m *memProc) readPrefix(addr uint64, b []byte) int {
	if m.read(addr, b) == nil {
		return len(b)
	}
	done := 0
	for done < len(b) {
		n, err := unix.ProcessVMReadv(int(m.pid.Load()),
			[]unix.Iovec{{Base: &b[done], Len: uint64(len(b) - done)}},
			[]unix.RemoteIovec{{Base: uintptr(addr) + uintptr(done), Len: len(b) - done}}, 0)
		if err != nil || n == 0 {
			break
		}
		done += n
	}
	return done
}

func (m *memProc) write(addr uint64, b []byte) error {
	for len(b) > 0 {
		n, err := unix.ProcessVMWritev(int(m.pid.Load()),
			[]unix.Iovec{{Base: &b[0], Len: uint64(len(b))}},
			[]unix.RemoteIovec{{Base: uintptr(addr), Len: len(b)}}, 0)
		if err != nil {
			return err
		}
		b = b[n:]
		addr += uint64(n)
	}
	return nil
}

// host has the stub run a host syscall in the guest's address space: on the
// process's hop thread when it acts on the whole process, else on the calling
// thread.
func (g *dguest) host(nr uintptr, args ...uint64) int64 {
	if h := g.mp.hopP.Load(); h != nil && hopRuns(nr) {
		return h.call(g.ch, nr, args...)
	}
	r, err := g.ch.host(nr, args...)
	if err != nil {
		return sErr(lxEIO)
	}
	return r
}

// isSite reports whether a trap at pc hit a site the rewriter wrote. Sites
// are published under mu before their traps are written; a miss is checked
// again under mu, which orders it after a change in flight.
func (m *memProc) isSite(pc uint64) bool {
	if m.sites.load().has(pc) {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sites.load().has(pc)
}

// record notes what a rewriter patched in code made executable at run time.
func (g *dguest) record(w *rewrite.Result) {
	g.mp.sites.add(w.Sites)
	g.mp.fast += w.Fast
	g.mp.strays += len(w.Stray)
}

// reserve marks a range the guest may not unmap, remap or reprotect.
func (g *dguest) reserve(lo, n uint64) {
	g.mp.reserved = append(g.mp.reserved, run{lo: lo, hi: lo + n})
}

func (g *dguest) isReserved(addr, n uint64) bool {
	if addr < stubHi && addr+n > stubLo {
		return true
	}
	for _, r := range g.mp.reserved {
		if addr < r.hi && addr+n > r.lo {
			return true
		}
	}
	return false
}

// track records a guest mapping of [addr, addr+n), in place of any there: for
// execve's teardown, the memory cap and placement. g.mp.mu held.
func (g *dguest) track(addr, n uint64) { g.trackAs(addr, n, false) }

// trackAs is track, anon marking private anonymous memory. The new mapping
// is writable until notePerm says otherwise.
func (g *dguest) trackAs(addr, n uint64, anon bool) {
	g.mp.vmMu.Lock()
	defer g.mp.vmMu.Unlock()
	g.addMem(int64(g.mp.vm.add(addr, addr+alignUp(n), anon)))
	g.mp.noWrite.sub(addr, addr+alignUp(n))
}

// untrack forgets the guest mappings in [addr, addr+n). g.mp.mu held.
func (g *dguest) untrack(addr, n uint64) {
	g.mp.vmMu.Lock()
	defer g.mp.vmMu.Unlock()
	g.addMem(-int64(g.mp.vm.sub(addr, addr+alignUp(n))))
	g.mp.noWrite.sub(addr, addr+alignUp(n))
}

// notePerm records whether the guest can write [addr, addr+n), just mapped
// or protected with prot. g.mp.mu held.
func (g *dguest) notePerm(addr, n, prot uint64) {
	g.mp.vmMu.Lock()
	defer g.mp.vmMu.Unlock()
	if prot&unix.PROT_WRITE != 0 {
		g.mp.noWrite.sub(addr, addr+alignUp(n))
	} else {
		g.mp.noWrite.add(addr, addr+alignUp(n), false)
	}
}

// writable reports whether the guest can write all of [lo, hi) as the
// supervisor has its mappings: mapped, and not without PROT_WRITE. m.mu or
// m.vmMu held.
func (m *memProc) writable(lo, hi uint64) bool {
	for at := lo; at < hi; {
		v, ok := m.vm.at(at)
		if !ok {
			return false
		}
		at = v.hi
	}
	i := sort.Search(len(m.noWrite.r), func(i int) bool { return m.noWrite.r[i].hi > lo })
	return i == len(m.noWrite.r) || m.noWrite.r[i].lo >= hi
}

func (g *dguest) addMem(delta int64) {
	g.mp.used += delta
	g.memUsed.Add(delta)
}

// wouldExceed reports whether committing n more bytes passes the memory cap,
// which is sandbox-wide.
func (g *dguest) wouldExceed(n uint64) bool {
	return g.cfg.MaxBytes > 0 && uint64(g.memUsed.Load())+n > g.cfg.MaxBytes
}

// codeSource is the file region runtime code was mapped from, read through r
// (the ELF the rewriter reads). A host file also has its descriptor fd, whose
// identity keys the persistent rewrite cache; a non-host backing (in-memory,
// user-defined, network) has fd -1 and is analyzed by content instead (still
// memoized by the content's hash).
type codeSource struct {
	r   io.ReaderAt
	fd  int
	off uint64
}

// fileCode is a range installCode filled from a file region.
type fileCode struct {
	lo, hi, off uint64
	dev, ino    uint64
}

func fileID(fd int) (dev, ino uint64, ok bool) {
	var st unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &st) != nil {
		return 0, 0, false
	}
	return st.Dev, st.Ino, true
}

// installCode makes [addr, addr+len(code)) executable with the rewritten
// code. The range must already be mapped writable and not executable. src,
// if not nil, is the file region the code was read from. inPlace says the
// range already holds code, so only the rewritten bytes are written.
func (g *dguest) installCode(addr uint64, code []byte, prot uint64, src *codeSource, inPlace bool) int64 {
	if r := g.rewriteInto(addr, code, inPlace, func(w codeRewriter) { g.rewriteCode(w, code, addr, src) }); r < 0 {
		return r
	}
	g.dropFileCode(addr, uint64(len(code)))
	if src != nil {
		if dev, ino, ok := fileID(src.fd); ok {
			g.mp.fileCode = append(g.mp.fileCode, fileCode{lo: addr, hi: addr + uint64(len(code)), off: src.off, dev: dev, ino: ino})
		}
	}
	lo := addr &^ (pageSize - 1)
	return g.host(unix.SYS_MPROTECT, lo, alignUp(addr+uint64(len(code)))-lo, prot)
}

// rewriteInto rewrites code, bound for [addr, addr+len(code)) of the stub,
// with the rewriter apply is given, and writes it there: only the rewritten
// bytes when inPlace, the range already holding code. Its trampolines go in a
// chunk of their own.
func (g *dguest) rewriteInto(addr uint64, code []byte, inPlace bool, apply func(codeRewriter)) int64 {
	if g.cfg.Trace != nil {
		fmt.Fprintf(g.cfg.Trace, "rewriting code at %#x+%#x\n", addr, len(code))
	}
	if !g.cfg.NoRewrite {
		chunk := g.trampChunk(addr, uint64(len(code)))
		size := uint64(chunkSize)
		if chunk == 0 {
			size = 0 // no room nearby: trap sites only
		}
		w := g.newRewriter(chunk, size)
		apply(w)
		g.record(w.Patched())
		if inPlace {
			if err := g.writePatches(appendPatches(nil, w.Patched().Sites, code, addr)); err != nil {
				return sErr(lxEFAULT)
			}
		}
		if chunk != 0 {
			if err := g.writeMem(chunk, w.Trampolines()); err != nil {
				return sErr(lxEFAULT)
			}
			if r := g.host(unix.SYS_MPROTECT, chunk, chunkSize, unix.PROT_READ|unix.PROT_EXEC); r < 0 {
				return r
			}
		}
	}
	if !inPlace {
		if err := g.writeMem(addr, code); err != nil {
			return sErr(lxEFAULT)
		}
	}
	return 0
}

// execNotWritable reports whether all of [addr, addr+n) is mapped
// executable and not writable in the stub. Such memory only ever holds code
// installCode or the loader rewrote, which cannot have changed since.
func (g *dguest) execNotWritable(addr, n uint64) bool {
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", g.mp.pid.Load()))
	if err != nil {
		return false
	}
	end := addr + n
	for line := range strings.Lines(string(maps)) {
		var lo, hi uint64
		var perms string
		if _, err := fmt.Sscanf(line, "%x-%x %s", &lo, &hi, &perms); err != nil || len(perms) < 3 {
			return false
		}
		if hi <= addr {
			continue
		}
		if lo > addr || perms[1] == 'w' || perms[2] != 'x' {
			return false
		}
		if hi >= end {
			return true
		}
		addr = hi
	}
	return false
}

// sameFileCode reports whether mapping n bytes of f at off onto addr would
// install code that is already there: the range was filled from that very
// file region and has been executable and not writable since. glibc on
// arm64 maps every library segment a second time this way to add PROT_BTI.
func (g *dguest) sameFileCode(addr, n uint64, fd int, off uint64) bool {
	dev, ino, ok := fileID(fd)
	if !ok {
		return false
	}
	for _, c := range g.mp.fileCode {
		if c.dev == dev && c.ino == ino && c.lo <= addr && addr+n <= c.hi && c.off+(addr-c.lo) == off {
			return g.execNotWritable(addr, alignUp(n))
		}
	}
	return false
}

// dropFileCode forgets file code records within [addr, addr+n), keeping
// the parts of a record on either side.
func (g *dguest) dropFileCode(addr, n uint64) {
	var keep []fileCode
	for _, c := range g.mp.fileCode {
		if addr >= c.hi || addr+n <= c.lo {
			keep = append(keep, c)
			continue
		}
		if c.lo < addr {
			keep = append(keep, fileCode{lo: c.lo, hi: addr, off: c.off, dev: c.dev, ino: c.ino})
		}
		if addr+n < c.hi {
			keep = append(keep, fileCode{lo: addr + n, hi: c.hi, off: c.off + (addr + n - c.lo), dev: c.dev, ino: c.ino})
		}
	}
	g.mp.fileCode = keep
}

// trampChunk maps a writable trampoline area within branch range of
// [addr, addr+n), probing free address space above and then below it.
// It returns 0 if none is found.
func (g *dguest) trampChunk(addr, n uint64) uint64 {
	const step, tries, reach = 1 << 20, 64, trampReach
	above := (addr + n + step - 1) &^ (step - 1)
	below := (addr &^ (step - 1)) - chunkSize
	for i := range uint64(tries) {
		for _, c := range []uint64{above + i*step, below - i*step} {
			lo, hi := min(c, addr), max(c+chunkSize, addr+n)
			if c < minAddr || hi-lo > reach || g.isReserved(c, chunkSize) || !g.mp.clear(nil, c, c+chunkSize) {
				continue
			}
			r := g.host(unix.SYS_MMAP, c, chunkSize, unix.PROT_READ|unix.PROT_WRITE,
				unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE, ^uint64(0), 0)
			if uint64(r) == c {
				g.reserve(c, chunkSize)
				g.track(c, chunkSize)
				return c
			}
		}
	}
	return 0
}

// otherMaps lists another process's mappings from its stub's, as hostMaps
// lists the caller's.
func (g *dguest) otherMaps(p *dguest) ([]mapEnt, bool) { return p.hostMaps() }

// hostStackOf is the stack the host's exec gave stub process pid, which the
// stub leaves for its own stacks once the guest runs.
func hostStackOf(pid int) (run, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return run{}, false
	}
	for line := range strings.Lines(string(b)) {
		var lo, hi uint64
		if strings.HasSuffix(strings.TrimSpace(line), "[stack]") {
			if _, err := fmt.Sscanf(line, "%x-%x", &lo, &hi); err == nil {
				return run{lo: lo, hi: hi}, true
			}
		}
	}
	return run{}, false
}

// dropHostStack unmaps the stub process's exec stack, once the stub no longer
// runs on it: from the guest's first call on, a Linux process has no such
// mapping, and its range is the guest's.
func (g *dguest) dropHostStack() {
	if g.mp.hostStack.Load() == nil {
		return
	}
	if s := g.mp.hostStack.Swap(nil); s != nil {
		g.host(unix.SYS_MUNMAP, s.lo, s.hi-s.lo)
	}
}

// hostMaps lists the guest's mappings from the stub's own, leaving out the
// stub's.
func (g *dguest) hostMaps() ([]mapEnt, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", g.mp.pid.Load()))
	if err != nil {
		return nil, false
	}
	var out []mapEnt
	for line := range strings.Lines(string(b)) {
		var lo, hi, off uint64
		var perms string
		if _, err := fmt.Sscanf(line, "%x-%x %s %x", &lo, &hi, &perms, &off); err != nil {
			continue
		}
		if lo < stubHi && hi > stubLo {
			continue
		}
		kind := uint64(mapAnon)
		name := strings.TrimSpace(line[strings.LastIndexByte(line, ' ')+1:])
		for k, n := range specialMaps {
			if name == n {
				kind = k
			}
		}
		// attr packs the host protection in bits 0-2, MAP_SHARED in bit 3, and
		// the kind in bits 8+ (see mapEnt). Carry the real protection from the
		// host line: without it every mapping rendered r--p, which among other
		// things hid that the guest's stack is writable, so musl's main-thread
		// stack probe (and PHP's overflow guard on top of it) could not find it.
		attr := kind << 8
		if len(perms) >= 4 {
			if perms[0] == 'r' {
				attr |= 1
			}
			if perms[1] == 'w' {
				attr |= 2
			}
			if perms[2] == 'x' {
				attr |= 4
			}
			if perms[3] == 's' {
				attr |= 8
			}
		}
		out = append(out, mapEnt{lo: lo, hi: hi, off: off, attr: attr})
	}
	// Carve the guest's real stack out of whatever host VMA now contains it
	// (the kernel may have merged it with neighbours), labelled [stack] at its
	// true bounds so a stack probe reads the right top. See memProc.stackLo.
	g.mp.mu.Lock()
	sLo, sHi := g.mp.stackLo, g.mp.stackHi
	g.mp.mu.Unlock()
	if sLo < sHi {
		stackEnt := mapEnt{lo: sLo, hi: sHi, attr: 1 | 2 | uint64(mapStack)<<8}
		var split []mapEnt
		for _, e := range out {
			if e.lo <= sLo && sHi <= e.hi && e.attr>>8 == mapAnon {
				if e.lo < sLo {
					split = append(split, mapEnt{lo: e.lo, hi: sLo, off: e.off, attr: e.attr})
				}
				split = append(split, stackEnt)
				if sHi < e.hi {
					split = append(split, mapEnt{lo: sHi, hi: e.hi, attr: e.attr})
				}
			} else {
				split = append(split, e)
			}
		}
		out = split
	}
	return out, true
}
