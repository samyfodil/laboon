package sandbox

import (
	"cmp"
	"io"
	"os"
	"runtime/debug"
	"slices"

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
	code, err := g.readMem(addr, int(length))
	if err != nil {
		return sErr(lxEFAULT)
	}
	return g.installCode(addr, code, prot, nil, true)
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
	if flags&unix.MREMAP_DONTUNMAP == 0 {
		g.untrack(old, oldLen)
	}
	g.dropFileCode(old, oldLen)
	if g.movedSpecial(old, oldLen, uint64(r)) {
		return r
	}
	g.trackAs(uint64(r), newLen, v.anon)
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
	if d.vf != nil {
		return g.mmapVF(d, a) // a non-host regular file (in-memory, user-defined, network)
	}
	if d.ev != nil || d.ep != nil || d.sk != nil || d.f == nil {
		return sErr(lxENODEV)
	}
	return g.mmapHostFd(d.f, a) // a device or other host fd that is not a regular file
}

// mmapVF maps a non-host regular file (in-memory, user-defined, network-backed)
// into the guest. The guest never touches the real backing: the supervisor reads
// the mapped range into a memfd of its own through the file's ReadAt and has the
// stub map that memfd. So any backing is mappable the same way — MAP_SHARED is
// coherent through the memfd, MAP_PRIVATE is a copy-on-write of it. An executable
// mapping is rewritten first (mmapVFExec), so a binary or shared library served
// by such a filesystem runs like one on a host file.
func (g *dguest) mmapVF(d *dfile, a [6]uint64) int64 {
	if a[2]&unix.PROT_EXEC != 0 {
		return g.mmapVFExec(d, a)
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
	if e := g.fillMemfd(mfd, d.vf, int64(a[5]), int64(length)); e != 0 {
		return sErr(e)
	}
	b := a
	b[5] = 0 // the content starts at offset 0 in the memfd
	return g.mmapShared(mfd, b)
}

// mmapVFExec maps an executable region of a non-host file. Executable code must
// be rewritten before it runs (W^X), and rewriting needs private memory the
// supervisor can edit, so — exactly as a private executable mapping of a host
// file — the mapped range is read through the file's ReadAt into anonymous
// memory and rewritten in place (installCode). The code source reads the ELF
// back through the same file so the rewriter can descend it precisely. Bytes
// past the end of the file stay zero, as the zeroed region leaves them.
// g.mp.mu held.
func (g *dguest) mmapVFExec(d *dfile, a [6]uint64) int64 {
	addr, length, prot, flags, off := a[0], a[1], a[2], a[3], int64(a[5])
	g.dropFileCode(addr, length)
	data := make([]byte, length)
	if _, err := d.vf.ReadAt(data, off); err != nil && err != io.EOF {
		return sErr(lxEIO)
	}
	r := g.notReserved(g.mapAt(addr, length, flags, false, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, length, unix.PROT_READ|unix.PROT_WRITE, fixed|unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
	}), length)
	if r < 0 {
		return r
	}
	if res := g.installCode(uint64(r), data, prot, &codeSource{r: d.vf, off: uint64(off)}, false); res < 0 {
		return res
	}
	return r
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
func (g *dguest) mmapHostFd(f *os.File, a [6]uint64) int64 {
	addr, length, prot, flags, off := a[0], a[1], a[2], a[3], int64(a[5])
	if flags&unix.MAP_SHARED != 0 {
		return g.mmapShared(hostFd(f), a)
	}
	if flags&unix.MAP_FIXED != 0 && prot&unix.PROT_EXEC != 0 && prot&unix.PROT_WRITE == 0 &&
		uint64(off) == uint64(off)&^(pageSize-1) && g.sameFileCode(addr, length, f, uint64(off)) {
		if r := g.host(unix.SYS_MPROTECT, addr, alignUp(length), prot); r < 0 {
			return r
		}
		return int64(addr)
	}
	g.dropFileCode(addr, length)
	if r, ok := g.mmapPrivate(f, a); ok {
		return r
	}
	data := make([]byte, length)
	if _, err := f.ReadAt(data, off); err != nil && err != io.EOF {
		return sErr(lxEIO)
	}
	r := g.notReserved(g.mapAt(addr, length, flags, false, func(at, fixed uint64) int64 {
		return g.host(unix.SYS_MMAP, at, length, unix.PROT_READ|unix.PROT_WRITE, fixed|unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
	}), length)
	if r < 0 {
		return r
	}
	if prot&unix.PROT_EXEC != 0 {
		if res := g.installCode(uint64(r), data, prot, &codeSource{r: f, f: f, off: uint64(off)}, false); res < 0 {
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
	if d.f == nil {
		return 0, lxENODEV
	}
	return g.passFd(hostFd(d.f))
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
func (g *dguest) mmapPrivate(f *os.File, a [6]uint64) (r int64, ok bool) {
	addr, length, prot, flags, off := a[0], a[1], a[2], a[3], a[5]
	var st unix.Stat_t
	if length < directMapMin || off%pageSize != 0 || unix.Fstat(hostFd(f), &st) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || off >= alignUp(uint64(st.Size)) {
		return 0, false
	}
	inFile := min(length, alignUp(uint64(st.Size))-off)
	exec := prot&unix.PROT_EXEC != 0
	sfd, e := g.passFd(hostFd(f))
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
		if res := g.installFileCode(uint64(r), f, off, length, inFile, prot); res < 0 {
			return res, true
		}
	}
	return r, true
}

// installFileCode rewrites code the stub mapped from n bytes of f at off, of
// which the first inFile are in the file. The supervisor maps the same region
// copy-on-write to rewrite it, so only the pages with sites are read.
func (g *dguest) installFileCode(addr uint64, f *os.File, off, n, inFile uint64, prot uint64) (res int64) {
	view, err := unix.Mmap(hostFd(f), int64(off), int(inFile), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		return sErr(lxEIO)
	}
	defer unix.Munmap(view)
	code := view
	if inFile < n {
		code = make([]byte, n)
		copy(code, view)
	}
	// A file truncated underfoot faults the view: fail the mapping, not the
	// supervisor.
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if recover() != nil {
			res = sErr(lxEIO)
		}
	}()
	return g.installCode(addr, code, prot, &codeSource{r: f, f: f, off: off}, true)
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
