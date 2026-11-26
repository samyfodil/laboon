package sandbox

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// The memory syscalls, served in the supervisor: the macOS and Windows stubs
// serve them themselves, the Linux stub has the supervisor do it.

// The generic (arm64) numbers of the memory syscalls; an x86-64 guest's are
// translated to them (toGeneric).
const (
	lxBrk      = 214
	lxMunmap   = 215
	lxMremap   = 216
	lxMmap     = 222
	lxMprotect = 226
	lxMsync    = 227
	lxMadvise  = 233
)

// protIgnored are the mmap/mprotect bits the guest may pass and the host
// would refuse or misread (PROT_BTI, PROT_MTE).
const protIgnored = 0x30

func init() {
	syscalls[lxBrk] = func(g *dguest, a [6]uint64) int64 {
		r := g.sysBrk(a[0])
		g.checkVmas("brk")
		return r
	}
	syscalls[lxMmap] = func(g *dguest, a [6]uint64) int64 {
		a[2] &^= protIgnored
		r := g.mmap(a)
		g.checkVmas("mmap")
		return r
	}
	syscalls[lxMunmap] = func(g *dguest, a [6]uint64) int64 {
		r := g.munmap(a[0], a[1])
		g.checkVmas("munmap")
		return r
	}
	syscalls[lxMprotect] = func(g *dguest, a [6]uint64) int64 { return g.mprotect(a[0], a[1], a[2]&^protIgnored) }
	syscalls[lxMremap] = func(g *dguest, a [6]uint64) int64 {
		r := g.mremap(a)
		g.checkVmas("mremap")
		return r
	}
	syscalls[lxMadvise] = func(g *dguest, a [6]uint64) int64 { return g.advise(unix.SYS_MADVISE, a) }
	syscalls[lxMsync] = func(g *dguest, a [6]uint64) int64 { return g.advise(unix.SYS_MSYNC, a) }
	syscalls[lxMincore] = func(g *dguest, a [6]uint64) int64 { return g.advise(unix.SYS_MINCORE, a) }
}

// advise runs madvise, msync or mincore on the guest's memory. The stub's own
// ranges are not part of it: there they fail as on unmapped memory.
func (g *dguest) advise(nr uintptr, a [6]uint64) int64 {
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	if g.isReserved(a[0], a[1]) {
		return sErr(lxENOMEM)
	}
	if nr == unix.SYS_MSYNC {
		g.dfs.syncSharedMem() // flush a non-host file's shared mapping back to it
	}
	return g.host(nr, a[0], a[1], a[2])
}

func (g *dguest) sysBrk(want uint64) int64 {
	m := g.mp
	m.mu.Lock()
	defer m.mu.Unlock()
	if want < m.brkLo {
		return int64(m.brk)
	}
	if want <= m.brk {
		// The break moves down: the pages past it go, as Linux's brk unmaps
		// them.
		if end, cur := alignUp(want), alignUp(m.brk); end < cur {
			g.host(unix.SYS_MUNMAP, end, cur-end)
			g.untrack(end, cur-end)
		}
		m.brk = want
		return int64(want)
	}
	if g.isReserved(m.brk, want-m.brk) {
		return int64(m.brk)
	}
	end := alignUp(want)
	cur := alignUp(m.brk)
	if end > cur {
		if g.wouldExceed(end - cur) {
			return int64(m.brk) // brk failure: the heap just does not grow
		}
		r := g.host(unix.SYS_MMAP, cur, end-cur, unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE, ^uint64(0), 0)
		if uint64(r) != cur {
			return int64(m.brk)
		}
		g.trackAs(cur, end-cur, true)
	}
	m.brk = want
	return int64(want)
}

func (g *dguest) mmap(a [6]uint64) (r int64) {
	addr, length, prot, flags := a[0], a[1], a[2], a[3]
	if prot&unix.PROT_WRITE != 0 && prot&unix.PROT_EXEC != 0 && g.cfg.RejectRWX {
		return sErr(lxEACCES) // W^X
	}
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	defer func() {
		if r >= 0 {
			g.notePerm(uint64(r), length, prot)
		}
	}()
	if length == 0 || flags&(unix.MAP_FIXED|unix.MAP_FIXED_NOREPLACE) != 0 && g.isReserved(addr, length) {
		return sErr(lxEINVAL)
	}
	if g.wouldExceed(length) {
		return sErr(lxENOMEM)
	}
	if flags&unix.MAP_FIXED != 0 {
		g.mp.dropMirror(addr, addr+length) // a fixed mapping replaces any mirror already here
		g.parkSpecial(addr, addr+alignUp(length))
	}
	if flags&unix.MAP_ANONYMOUS == 0 {
		return g.mmapFile(a)
	}
	g.dropFileCode(addr, length)
	// Anonymous memory starts zeroed, so it holds no code to rewrite.
	// With shared guest RAM on, a sizable non-executable anonymous mapping is
	// memfd-backed so the supervisor sees it directly (sharedmem_linux.go).
	// Mirror only readable/writable data mappings -- never a PROT_NONE reservation
	// (a runtime like Go's reserves a huge range then commits parts with MAP_FIXED,
	// and mirroring the reservation both wastes a memfd and overlaps the commits).
	if shmemEnabled() && prot&(unix.PROT_READ|unix.PROT_WRITE) != 0 && prot&unix.PROT_EXEC == 0 && length >= shmemMin {
		if r, ok := g.mmapMirroredAnon(addr, length, prot, flags); ok {
			return r
		}
	}
	if flags&unix.MAP_SHARED == 0 {
		flags |= unix.MAP_PRIVATE
	}
	r = g.mapAt(addr, length, flags, flags&unix.MAP_SHARED == 0, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, length, prot, unplaced(flags)|fixed, ^uint64(0), 0)
	})
	return g.notReserved(r, length)
}

// unplaced is a guest's mmap flags without the placement ones, which the
// supervisor decides.
func unplaced(flags uint64) uint64 {
	return flags &^ (unix.MAP_FIXED | unix.MAP_FIXED_NOREPLACE | map32bit)
}

// notReserved undoes a mapping that landed on a reserved range. g.mp.mu held.
func (g *dguest) notReserved(r int64, length uint64) int64 {
	if r >= 0 && g.isReserved(uint64(r), length) {
		g.host(unix.SYS_MUNMAP, uint64(r), length)
		g.untrack(uint64(r), length)
		return sErr(lxENOMEM)
	}
	return r
}

func (g *dguest) munmap(addr, length uint64) int64 {
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	if g.isReserved(addr, length) {
		return sErr(lxEINVAL)
	}
	g.untrack(addr, length)
	g.mp.removeShMap(addr, addr+alignUp(length), g.dfs) // release any shared backing this unmaps
	g.dropFileCode(addr, length)
	g.mp.dropMirror(addr, addr+length)
	g.parkSpecial(addr, addr+alignUp(length))
	if g.onOwnStack(addr, length) {
		// A detached musl thread's last acts are unmapping its own stack and
		// exiting (__unmapself): the stack goes once the thread is gone.
		g.mp.ownStack[g.pid] = run{lo: addr, hi: addr + length}
		return 0
	}
	return g.host(unix.SYS_MUNMAP, addr, length)
}

// unmapOwnStack unmaps the stack a thread unmapped while it ran on it, now
// that the thread is gone, except what the guest has mapped there since.
func (g *dguest) unmapOwnStack() {
	g.unmapOwnStackWith(func(a, n uint64) { g.host(unix.SYS_MUNMAP, a, n) })
}

func (g *dguest) unmapOwnStackWith(unmap func(a, n uint64)) {
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	r, ok := g.mp.ownStack[g.pid]
	if !ok {
		return
	}
	delete(g.mp.ownStack, g.pid)
	var taken []run
	for _, v := range g.mp.vm.r {
		if v.lo < r.hi && v.hi > r.lo {
			taken = append(taken, run{lo: v.lo, hi: v.hi})
		}
	}
	slices.SortFunc(taken, func(x, y run) int { return cmp.Compare(x.lo, y.lo) })
	lo := r.lo
	for _, t := range taken {
		if t.lo > lo {
			unmap(lo, t.lo-lo)
		}
		lo = max(lo, t.hi)
	}
	if lo < r.hi {
		unmap(lo, r.hi-lo)
	}
}

// mprotect enforces W^X: memory becomes executable only through
// installCode, which rewrites its current contents first.
func (g *dguest) mprotect(addr, length, prot uint64) (r int64) {
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	defer func() {
		if r == 0 {
			g.notePerm(addr, length, prot)
		}
	}()
	if g.isReserved(addr, length) || addr%pageSize != 0 {
		return sErr(lxEINVAL)
	}
	if prot&unix.PROT_EXEC == 0 {
		return g.host(unix.SYS_MPROTECT, addr, length, prot)
	}
	if prot&unix.PROT_WRITE != 0 {
		// Writable and executable unless RejectRWX: the code is mutable, so
		// it cannot be rewritten; a syscall it makes meets the stub's
		// seccomp filter instead.
		if g.cfg.RejectRWX {
			return sErr(lxEACCES)
		}
		return g.host(unix.SYS_MPROTECT, addr, length, prot)
	}
	length = alignUp(length)
	if g.execNotWritable(addr, length) {
		// Already rewritten and unchanged since: glibc on arm64 does this
		// to every library segment it maps, to add PROT_BTI.
		return g.host(unix.SYS_MPROTECT, addr, length, prot)
	}
	if r := g.host(unix.SYS_MPROTECT, addr, length, unix.PROT_READ|unix.PROT_WRITE); r < 0 {
		return r
	}
	g.notePerm(addr, length, unix.PROT_READ|unix.PROT_WRITE)
	return g.installRange(addr, length, prot)
}

// codeWindow bounds the guest memory the supervisor holds at once to rewrite
// a range made executable.
const codeWindow = 64 << 20

// installRange rewrites the code in [addr, addr+length) and makes it prot. A
// range past codeWindow is rewritten a window at a time, skipping windows the
// guest never wrote: they hold only zeros, so no syscall.
func (g *dguest) installRange(addr, length, prot uint64) int64 {
	if length <= codeWindow {
		code, err := g.readMem(addr, int(length))
		if err != nil {
			return sErr(lxEFAULT)
		}
		return g.installCode(addr, code, prot, nil, true)
	}
	pm := g.pageMap(addr, length)
	defer pm.close()
	buf := make([]byte, codeWindow+pageSize)
	var roots []uint64
	for lo, end := addr, addr+length; lo < end; {
		n := min(codeWindow, end-lo)
		ext := buf[:min(n+pageSize, end-lo)]
		// Only what the guest wrote is read: reading the rest would map the
		// zero page there, which the pagemap then shows as present.
		runs := pm.written(lo, uint64(len(ext)))
		if len(runs) == 0 {
			lo += n
			continue
		}
		clear(ext)
		var spans [][2]int
		nonzero := false
		for _, r := range runs {
			b := ext[r.lo-lo : r.hi-lo]
			if g.mp.read(r.lo, b) != nil {
				return sErr(lxEFAULT)
			}
			spans = append(spans, [2]int{int(r.lo - lo), int(r.hi - lo)})
			nonzero = nonzero || r.lo < lo+n && !zeros(b)
		}
		if !nonzero {
			lo += n
			continue
		}
		var in []uint64
		for _, r := range roots {
			if r >= lo && r < lo+uint64(len(ext)) {
				in = append(in, r)
			}
		}
		plan, used, next := g.windowSites(ext, int(n), lo, in, spans, lo != addr)
		code := ext[:used]
		if r := g.rewriteInto(lo, code, true, func(w codeRewriter) { applyWindow(w, plan, code, lo) }); r < 0 {
			return r
		}
		g.dropFileCode(lo, uint64(used))
		if r := g.host(unix.SYS_MPROTECT, lo, alignUp(uint64(used)), prot); r < 0 {
			return r
		}
		lo += uint64(used)
		roots = slices.DeleteFunc(append(roots, next...), func(r uint64) bool { return r < lo })
	}
	return g.host(unix.SYS_MPROTECT, addr, length, prot)
}

// stubPages answers which pages of a range of the stub's memory may hold
// something other than zeros.
type stubPages struct {
	pagemap *os.File
	files   []run
	ents    []byte
}

// pageMap reads which parts of [addr, addr+length) are file-backed from the
// stub's maps and opens its pagemap for the rest. Without both, every page
// counts as written.
func (g *dguest) pageMap(addr, length uint64) *stubPages {
	pid := g.mp.pid.Load()
	pm := &stubPages{ents: make([]byte, (codeWindow+pageSize)/pageSize*8)}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return pm
	}
	if f, err := os.Open(fmt.Sprintf("/proc/%d/pagemap", pid)); err == nil {
		pm.pagemap = f
	}
	for line := range strings.Lines(string(maps)) {
		var lo, hi, off, ino uint64
		var perms, dev string
		if _, err := fmt.Sscanf(line, "%x-%x %s %x %s %d", &lo, &hi, &perms, &off, &dev, &ino); err != nil {
			pm.close()
			pm.pagemap = nil
			return pm
		}
		if ino != 0 && lo < addr+length && hi > addr {
			pm.files = append(pm.files, run{lo: lo, hi: hi})
		}
	}
	return pm
}

// written returns the runs of the pages of [lo, lo+n) that may hold other
// than zeros: file-backed, or held by the kernel in memory or in swap.
func (pm *stubPages) written(lo, n uint64) []run {
	pages := (n + pageSize - 1) / pageSize
	b := pm.ents[:pages*8]
	if pm.pagemap == nil {
		return []run{{lo: lo, hi: lo + n}}
	}
	if _, err := pm.pagemap.ReadAt(b, int64(lo/pageSize*8)); err != nil {
		return []run{{lo: lo, hi: lo + n}}
	}
	var out []run
	for i := range pages {
		a := lo + i*pageSize
		w := binary.LittleEndian.Uint64(b[i*8:])>>62 != 0 || slices.ContainsFunc(pm.files, func(f run) bool { return f.lo < a+pageSize && f.hi > a })
		switch {
		case !w:
		case len(out) > 0 && out[len(out)-1].hi == a:
			out[len(out)-1].hi = min(a+pageSize, lo+n)
		default:
			out = append(out, run{lo: a, hi: min(a+pageSize, lo+n)})
		}
	}
	return out
}

// zeros reports whether b holds only zero bytes.
func zeros(b []byte) bool {
	var z [4096]byte
	for len(b) > 0 {
		k := min(len(b), len(z))
		if !bytes.Equal(b[:k], z[:k]) {
			return false
		}
		b = b[k:]
	}
	return true
}

func (pm *stubPages) close() {
	if pm.pagemap != nil {
		pm.pagemap.Close()
	}
}

func (g *dguest) mremap(a [6]uint64) int64 {
	old, oldLen, newLen, flags := a[0], a[1], a[2], a[3]
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	if g.isReserved(old, oldLen) || flags&unix.MREMAP_FIXED != 0 && g.isReserved(a[4], newLen) {
		return sErr(lxEINVAL)
	}
	if newLen > oldLen && g.wouldExceed(newLen-oldLen) {
		return sErr(lxENOMEM)
	}
	g.mp.dropMirror(old, old+oldLen) // a moved/resized region falls back to process_vm
	if flags&unix.MREMAP_FIXED != 0 {
		g.parkSpecial(a[4], a[4]+alignUp(newLen))
	}
	v, _ := g.mp.vm.at(old)
	ro := !g.mp.writable(old, old+max(oldLen, 1))
	var r int64
	if flags&unix.MREMAP_MAYMOVE != 0 && flags&(unix.MREMAP_FIXED|unix.MREMAP_DONTUNMAP) == 0 && alignUp(newLen) > alignUp(oldLen) {
		r = g.mremapMove(old, oldLen, newLen, flags, v.anon)
	} else {
		r = g.host(unix.SYS_MREMAP, old, oldLen, newLen, flags, a[4])
	}
	if r < 0 {
		return r
	}
	sb := g.mp.shMapAt(old) // a shared backing moving with the mapping, if any
	if flags&unix.MREMAP_DONTUNMAP == 0 {
		g.untrack(old, oldLen)
	}
	g.dropFileCode(old, oldLen)
	if g.movedSpecial(old, oldLen, uint64(r)) {
		return r
	}
	g.trackAs(uint64(r), newLen, v.anon)
	if sb != nil {
		// Carry the shared mapping to its new address: reserve the new pages
		// before releasing the old, so our own mapping keeps the backing live
		// throughout and it is never momentarily unmapped.
		sb.reserve(int64(alignUp(newLen) / pageSize))
		if flags&unix.MREMAP_DONTUNMAP == 0 {
			g.mp.removeShMap(old, old+alignUp(oldLen), g.dfs)
		}
		g.mp.addShMap(uint64(r), uint64(r)+alignUp(newLen), sb, g.dfs)
	}
	if ro {
		g.notePerm(uint64(r), newLen, unix.PROT_NONE) // one mapping moved: its protection with it
	}
	return r
}

// mremapMove grows a mapping in place when the pages above are free, as
// vma_expandable, else moves it where get_unmapped_area puts a mapping that
// long: the target is claimed with a placeholder first, so MREMAP_FIXED only
// ever replaces what the supervisor just mapped. g.mp.mu held.
func (g *dguest) mremapMove(old, oldLen, newLen, flags uint64, anon bool) int64 {
	m := g.mp
	if m.clear(m.obstacles(), old+alignUp(oldLen), old+alignUp(newLen)) {
		if r := g.host(unix.SYS_MREMAP, old, oldLen, newLen, flags&^unix.MREMAP_MAYMOVE, 0); r != -int64(unix.ENOMEM) {
			return r
		}
	}
	n := alignUp(newLen)
	for range 64 {
		at, ok := m.place(0, n, 0, anon)
		if !ok {
			return sErr(lxENOMEM)
		}
		p := g.host(unix.SYS_MMAP, at, n, unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE, ^uint64(0), 0)
		if p >= 0 && uint64(p) != at {
			g.host(unix.SYS_MUNMAP, uint64(p), n)
			p = -int64(unix.EEXIST)
		}
		if p == -int64(unix.EEXIST) {
			m.vm.addForeign(at, at+n)
			continue
		}
		if p < 0 {
			return p
		}
		r := g.host(unix.SYS_MREMAP, old, oldLen, newLen, flags|unix.MREMAP_FIXED, at)
		if r < 0 {
			g.host(unix.SYS_MUNMAP, at, n)
		}
		return r
	}
	return sErr(lxENOMEM)
}

// mmapFile maps a guest file. Executable mappings are rewritten before they
// become executable. g.mp.mu held.
func (g *dguest) mmapFile(a [6]uint64) int64 {
	d, ok := g.ft.get(int(int32(a[4])))
	if !ok {
		return sErr(lxEBADF)
	}
	if d.nonHost() {
		return g.mmapVF(d, a) // a non-host regular file (in-memory, user-defined, network)
	}
	if d.ev != nil || d.ep != nil || d.sk != nil {
		return sErr(lxENODEV)
	}
	if d.f != nil {
		return g.mmapHostFd(hostFd(d.f), d.f, a) // a supervisor-owned file or device
	}
	if fd, ok := d.hostFd(); ok {
		return g.mmapHostFd(fd, d.vf, a) // a host-backed regular file: the file itself
	}
	return sErr(lxENODEV)
}

// mmapVF maps a non-host regular file (in-memory, user-defined, network-backed)
// into the guest. The guest never touches the real backing: the supervisor reads
// the content into a memfd of its own through the file's ReadAt and has the stub
// map that memfd. A MAP_SHARED mapping maps the one shared backing the file's
// vnode keeps (sharedBacking), so every mapping — across processes and fork
// children — is coherent and the writes are flushed back to the file; a
// MAP_PRIVATE mapping is a private copy-on-write of the range. An executable
// mapping is rewritten first (mmapVFExec). Any backing is mappable the same way.
func (g *dguest) mmapVF(d *dfile, a [6]uint64) int64 {
	if a[2]&unix.PROT_EXEC != 0 {
		return g.mmapVFExec(d, a)
	}
	if a[3]&unix.MAP_SHARED != 0 && d.vn != nil {
		pages := int64(alignUp(a[1]) / pageSize)
		sb, e := g.sharedBacking(d, int64(a[5])+int64(a[1]), pages)
		if e != 0 {
			return sErr(e)
		}
		r := g.mmapShared(sb.fd(), a) // the whole-file memfd; a[5] is the file offset into it
		if r < 0 {
			g.dfs.release(sb, pages) // the mapping did not take: undo the reservation
			return r
		}
		g.mp.addShMap(uint64(r), uint64(r)+alignUp(a[1]), sb, g.dfs)
		return r
	}
	length := a[1]
	mfd, err := unix.MemfdCreate("lc-mmap", unix.MFD_CLOEXEC)
	if err != nil {
		return sErr(osErrno(err))
	}
	defer unix.Close(mfd)
	if err := unix.Ftruncate(mfd, int64(length)); err != nil {
		return sErr(osErrno(err))
	}
	// Read the file's current bytes — the live shared backing if there is one, so
	// a private mapping sees writes made through a shared mapping — not a stale
	// snapshot of the backend.
	if e := g.fillMemfd(mfd, d.content(), int64(a[5]), int64(length)); e != 0 {
		return sErr(e)
	}
	b := a
	b[5] = 0 // the content starts at offset 0 in the memfd
	return g.mmapShared(mfd, b)
}

// sharedBacking returns the one backing that every MAP_SHARED mapping of d's
// vnode maps (a memfd here), creating it (filled from the file through ReadAt) on
// first use and growing it to cover minEnd. It is keyed by vnode on the shared
// dfs, so two independent opens and a fork child all map the same object, and it
// reserves pages for the mapping about to be made so the backing stays live
// until that mapping is released. The coherence, write-back and eviction logic
// lives in sharedback.go. g.mp.mu held.
func (g *dguest) sharedBacking(d *dfile, minEnd, pages int64) (*shBacking, lxErrno) {
	fs := g.dfs
	id := d.vn.ID()
	fs.shMu.Lock()
	defer fs.shMu.Unlock()
	if sb := fs.shared[id]; sb != nil {
		sb.mu.Lock()
		err := sb.growLocked(minEnd)
		sb.mu.Unlock()
		if err != nil {
			return nil, osErrno(err)
		}
		sb.reserve(pages)
		return sb, 0
	}
	at, err := d.vn.Stat()
	if err != nil {
		return nil, osErrno(err)
	}
	size := max(at.Size, minEnd)
	fd, err := unix.MemfdCreate("lc-shmem", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, osErrno(err)
	}
	f := os.NewFile(uintptr(fd), "lc-shmem")
	if err := f.Truncate(size); err != nil {
		f.Close()
		return nil, osErrno(err)
	}
	// Fill from the backend directly: the backing is being created, so content()
	// would just return the backend anyway, and reading it avoids any recursion.
	if e := g.fillMemfd(fd, d.vf, 0, at.Size); e != 0 {
		f.Close()
		return nil, e
	}
	sb := &shBacking{f: f, vf: d.vf, size: size, eof: at.Size}
	sb.reserve(pages)
	fs.putBacking(id, sb)
	return sb, 0
}

// mmapVFExec maps an executable region of a non-host file. Executable code must
// be rewritten before it runs (W^X), and rewriting needs private memory the
// supervisor can edit, so the region is copied into a memfd and mapped from it
// exactly as a private executable mapping of a host file is (mmapPrivate); a
// small one is read into anonymous memory instead. The code source reads the
// ELF back through the file itself so the rewriter can descend it precisely.
// Bytes past the end of the file stay zero. g.mp.mu held.
func (g *dguest) mmapVFExec(d *dfile, a [6]uint64) int64 {
	addr, length, prot, flags, off := a[0], a[1], a[2], a[3], int64(a[5])
	size, err := d.size0()
	if err != nil {
		return sErr(lxEIO)
	}
	n := codeSpan(size, off, length)
	g.dropFileCode(addr, length)
	src := d.content() // the live shared backing if there is one, else the backend
	cs := &codeSource{r: src, fd: -1, off: uint64(off)}
	if length >= directMapMin && n > 0 {
		mfd, err := unix.MemfdCreate("lc-code", unix.MFD_CLOEXEC)
		if err != nil {
			return sErr(osErrno(err))
		}
		defer unix.Close(mfd)
		if err := unix.Ftruncate(mfd, int64(n)); err != nil {
			return sErr(osErrno(err))
		}
		if e := g.fillMemfd(mfd, src, off, int64(n)); e != 0 {
			return sErr(e)
		}
		b := a
		b[5] = 0
		if r, ok := g.mmapPrivate(mfd, cs, b); ok {
			return r
		}
		return sErr(lxENOMEM)
	}
	data := make([]byte, n)
	if _, err := src.ReadAt(data, off); err != nil && err != io.EOF {
		return sErr(lxEIO)
	}
	r := g.notReserved(g.mapAt(addr, length, flags, false, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, length, unix.PROT_READ|unix.PROT_WRITE, fixed|unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
	}), length)
	if r < 0 {
		return r
	}
	if res := g.installCode(uint64(r), data, prot, cs, false); res < 0 {
		return res
	}
	if res := g.protectTail(uint64(r), uint64(len(data)), length, prot); res < 0 {
		return res
	}
	return r
}

// fileView maps n bytes of fd at off, which need not be page-aligned, private
// and writable into the supervisor: the file's own pages, not a copy.
func fileView(fd int, off int64, n int) (view, data []byte, err error) {
	if n == 0 {
		return nil, nil, nil
	}
	lead := off % int64(pageSize)
	view, err = unix.Mmap(fd, off-lead, int(lead)+n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		return nil, nil, err
	}
	return view, view[lead:], nil
}

// protectTail gives the part of a mapping at addr past the n bytes read from
// its file the mapping's protection, which installCode set only up to n.
func (g *dguest) protectTail(addr, n, length, prot uint64) int64 {
	if lo, hi := alignUp(addr+n), alignUp(addr+length); hi > lo {
		return g.host(unix.SYS_MPROTECT, lo, hi-lo, prot)
	}
	return 0
}

// fillMemfd writes length bytes of r starting at off into the memfd mfd; any
// range past the end of the content stays zero, as a file mapping's tail does.
func (g *dguest) fillMemfd(mfd int, r io.ReaderAt, off, length int64) lxErrno {
	buf := g.ioBuf(int(min(length, ioChunk)))
	for pos := int64(0); pos < length; {
		b := buf[:min(length-pos, int64(len(buf)))]
		n, err := r.ReadAt(b, off+pos)
		if n > 0 {
			if _, werr := unix.Pwrite(mfd, b[:n], pos); werr != nil {
				return osErrno(werr)
			}
			pos += int64(n)
		}
		if err != nil || n == 0 {
			break
		}
	}
	return 0
}

// mmapHostFd maps a host file into the guest: a shared mapping is the host's own
// (its descriptor passed to the stub), a fixed executable re-map reuses the code
// already there, and a private mapping is the file mapped directly (mmapPrivate)
// or read into an anonymous region and rewritten if executable.
func (g *dguest) mmapHostFd(fd int, f io.ReaderAt, a [6]uint64) (r int64) {
	addr, length, prot, flags, off := a[0], a[1], a[2], a[3], int64(a[5])
	if flags&unix.MAP_SHARED != 0 {
		return g.mmapShared(fd, a)
	}
	if flags&unix.MAP_FIXED != 0 && prot&unix.PROT_EXEC != 0 && prot&unix.PROT_WRITE == 0 &&
		uint64(off) == uint64(off)&^(pageSize-1) && g.sameFileCode(addr, length, fd, uint64(off)) {
		if r := g.host(unix.SYS_MPROTECT, addr, alignUp(length), prot); r < 0 {
			return r
		}
		return int64(addr)
	}
	g.dropFileCode(addr, length)
	if r, ok := g.mmapPrivate(fd, &codeSource{r: f, fd: fd, off: uint64(off)}, a); ok {
		return r
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return sErr(osErrno(err))
	}
	view, data, err := fileView(fd, off, codeSpan(st.Size, off, length))
	if err != nil {
		return sErr(osErrno(err))
	}
	if view != nil {
		defer unix.Munmap(view)
	}
	// A file truncated underfoot faults the view: fail the mapping, not the
	// supervisor.
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if recover() != nil {
			r = sErr(lxEIO)
		}
	}()
	r = g.notReserved(g.mapAt(addr, length, flags, false, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, length, unix.PROT_READ|unix.PROT_WRITE, fixed|unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
	}), length)
	if r < 0 {
		return r
	}
	if prot&unix.PROT_EXEC != 0 {
		if res := g.installCode(uint64(r), data, prot, &codeSource{r: f, fd: fd, off: uint64(off)}, false); res < 0 {
			return res
		}
		if res := g.protectTail(uint64(r), uint64(len(data)), length, prot); res < 0 {
			return res
		}
		return r
	}
	if err := g.writeMem(uint64(r), data); err != nil {
		return sErr(lxEFAULT)
	}
	if res := g.host(unix.SYS_MPROTECT, uint64(r), alignUp(length), prot); res < 0 {
		return res
	}
	return r
}

// Shared file mappings are the host's own: the supervisor passes its
// descriptor of the file to the stub over the socket at the stub's fd 5
// (SCM_RIGHTS), and the stub maps it, so writes reach the file and every
// process mapping it. The stub receives with a recvmsg the supervisor asks
// for, its message header built in a scratch area of the thread's slot.
const (
	xferFd  = 5    // XFER in stub.zig
	xferOff = 3840 // XFER_OFF in stub/zig/sig.zig
)

// passFd gives the stub a descriptor of f; it returns the stub's fd number.
func (g *dguest) passFd(fd int) (int, lxErrno) {
	g.run.xferMu.Lock()
	defer g.run.xferMu.Unlock()
	// Every stub shares the socket. A stub killed between the send and its
	// receive leaves that descriptor queued, so each carries its number and
	// an older one is closed and skipped.
	g.run.xferSeq++
	seq := g.run.xferSeq
	var tag [8]byte
	put64(tag[:], seq)
	if err := unix.Sendmsg(hostFd(g.run.xfer), tag[:], unix.UnixRights(fd), nil, 0); err != nil {
		return -1, osErrno(err)
	}
	base := g.slot*slotSize + xferOff
	at := slotsAddr + uint64(base)
	m := g.mem[base : base+128]
	for range 64 {
		clear(m)
		// struct msghdr at 0, its iovec at 64 over the tag at 80, and room
		// for one descriptor's cmsg at 96.
		put64(m[16:], at+64)
		put64(m[24:], 1)
		put64(m[32:], at+96)
		put64(m[40:], uint64(unix.CmsgSpace(4)))
		put64(m[64:], at+80)
		put64(m[72:], 8)
		r := g.host(unix.SYS_RECVMSG, xferFd, at, unix.MSG_CMSG_CLOEXEC)
		if r == -int64(unix.EINTR) {
			continue // a kick
		}
		if r < 0 {
			return -1, lxErrno(-r)
		}
		if le64(m[96:]) < uint64(unix.CmsgLen(4)) || le32(m[104:]) != unix.SOL_SOCKET || le32(m[108:]) != unix.SCM_RIGHTS {
			return -1, lxEIO
		}
		fd := int(le32(m[112:]))
		if le64(m[80:]) == seq {
			return fd, 0
		}
		g.host(unix.SYS_CLOSE, uint64(fd))
	}
	return -1, lxEIO
}

// stubFd gives the stub a descriptor of d's file; the caller has it closed.
func (m *memProc) stubFd(g *dguest, d *dfile) (int, lxErrno) {
	fd, ok := d.hostFd()
	if !ok {
		return 0, lxENODEV
	}
	return g.passFd(fd)
}

func (g *dguest) mmapShared(fd int, a [6]uint64) int64 {
	addr, length := a[0], a[1]
	sfd, e := g.passFd(fd)
	if e != 0 {
		return sErr(e)
	}
	g.dropFileCode(addr, length)
	r := g.mapAt(addr, length, a[3], false, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, length, a[2], unplaced(a[3])|fixed, uint64(sfd), a[5])
	})
	g.host(unix.SYS_CLOSE, uint64(sfd))
	return g.notReserved(r, length)
}

// directMapMin is the smallest private file mapping the stub maps from the
// file itself; below it, copying the bytes costs less than passing the fd.
const directMapMin = 64 << 10

// mmapPrivate maps a private copy of a file region in the stub from the file,
// as the kernel does, so pages the guest never touches are never read and
// executable code is rewritten in place. Pages past the end of the file read
// as zero, as the copy made them. ok is false when the region is not suited
// (small, unaligned, or all past the end of the file), for the caller to copy
// it instead.
func (g *dguest) mmapPrivate(fd int, src *codeSource, a [6]uint64) (r int64, ok bool) {
	addr, length, prot, flags, off := a[0], a[1], a[2], a[3], a[5]
	var st unix.Stat_t
	if length < directMapMin || off%pageSize != 0 || unix.Fstat(fd, &st) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || off >= alignUp(uint64(st.Size)) {
		return 0, false
	}
	inFile := min(length, alignUp(uint64(st.Size))-off)
	exec := prot&unix.PROT_EXEC != 0
	sfd, e := g.passFd(fd)
	if e != 0 {
		return 0, false
	}
	mprot := prot
	if exec {
		mprot = unix.PROT_READ | unix.PROT_WRITE
	}
	r = g.mapAt(addr, length, flags, false, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, length, mprot, fixed|unix.MAP_PRIVATE, uint64(sfd), off)
	})
	g.host(unix.SYS_CLOSE, uint64(sfd))
	if r = g.notReserved(r, length); r < 0 {
		return r, true
	}
	if inFile < length {
		tail := uint64(r) + inFile
		if t := g.host(unix.SYS_MMAP, tail, length-inFile, mprot, unix.MAP_FIXED|unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0); uint64(t) != tail {
			return sErr(lxENOMEM), true
		}
	}
	if exec {
		if res := g.installFileCode(uint64(r), fd, src, off, length, inFile, prot); res < 0 {
			return res, true
		}
	}
	return r, true
}

// installFileCode rewrites code the stub mapped from n bytes of fd at off, of
// which the first inFile are in the file; src is where the code came from. The supervisor maps the same region
// copy-on-write to rewrite it, so only the pages with sites are read.
func (g *dguest) installFileCode(addr uint64, fd int, src *codeSource, off, n, inFile uint64, prot uint64) (res int64) {
	view, err := unix.Mmap(fd, int64(off), int(inFile), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		return sErr(lxEIO)
	}
	defer unix.Munmap(view)
	// A file truncated underfoot faults the view: fail the mapping, not the
	// supervisor.
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if recover() != nil {
			res = sErr(lxEIO)
		}
	}()
	if res := g.installCode(addr, view, prot, src, true); res < 0 {
		return res
	}
	return g.protectTail(addr, inFile, n, prot)
}

// The macOS stub's SysV attach requests: the Linux stub makes none, so the
// table entries for them are never reached.
const (
	lcShmat       = 0x4c430003
	lcShmAttached = 0x4c430004
	lcShmGone     = 0x4c430005
)

// stubFiles tracks host fds lent to stubs, which the Linux stub does not
// cache: a passed fd is closed once mapped.
var stubFiles noStubFiles

type noStubFiles struct{}

func (noStubFiles) closed(*dfile) {}
