package sandbox

import (
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"slices"
	"sync"

	"golang.org/x/sys/unix"
)

// execve in place: the stub stays, the supervisor loads the new program into
// its address space and has it jump there (REP_EXEC).

// execArgMax bounds what an execve's argv and envp may hold together, as the
// initial stack (stackSize) must hold them.
const execArgMax = 2 << 20

// execve runs an execve for dg. It returns true once the new program runs
// (its first syscall is the next message), false with the errno in page.ret
// when it fails before the point of no return. An error means the process
// died past that point.
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
	if total > execArgMax {
		return fail(lxE2BIG)
	}
	// The images load before the point of no return, so a program that
	// cannot run (or a missing interpreter) fails the call instead.
	pf, err := dg.openProgram(t.src)
	if err != nil {
		return fail(osErrno(err))
	}
	lay := dg.drawLayout()
	exe, err := dg.loadELF(pf, lay.exe, lay.mm)
	if err != nil {
		pf.close()
		return fail(lxENOEXEC)
	}
	defer exe.release()
	var interp *image
	if exe.interp != "" {
		ip, e := dg.walkAt(lxAtFdcwd, exe.interp, true)
		if e != 0 {
			return fail(e)
		}
		ipf, err := dg.openProgram(execSrc{gp: ip})
		if err != nil {
			return fail(osErrno(err))
		}
		if interp, err = dg.loadELF(ipf, lay.exe, lay.mm); err != nil {
			ipf.close()
			return fail(lxENOEXEC)
		}
		defer interp.release()
	}

	// Past the point of no return. A CLONE_VM child first moves into a stub
	// process of its own, leaving its parent's memory as it was.
	if dg.sharedStub() {
		if err := dg.vforkExec(); err != nil {
			return true, err
		}
	}
	// The old mappings stay: the stub runs this
	// call on the guest's stack, which must not go underfoot; the new image
	// replaces the old one in place (MAP_FIXED) and the old regions go with
	// the process.
	dg.closeExec()
	execHook(dg)
	if dg.isThread {
		// The leader's host thread ends with the other threads, and the
		// stub's memory is reached through a live one.
		dg.mp.pid.Store(int64(le32(dg.mem[dg.slot*slotSize+stubHostTid:])))
	}
	oldTid := dg.ptraceExecTid()
	dg.takeOverGroup()
	dg.execDone(path.Base(t.gp))
	dg.noteExec(t.gp, t.gp, argv, pinExeFD(pf.f))
	dg.mp.detachAll(dg) // exec detaches every SysV segment
	m := dg.mp
	m.mu.Lock()
	old := make([][2]uint64, 0, len(m.vm.r))
	for _, v := range m.vm.r {
		old = append(old, [2]uint64{v.lo, v.hi - v.lo})
	}
	dg.memUsed.Add(-m.used)
	m.used = 0
	m.dropShMaps(dg.dfs) // execve clears the address space: release its shared backings
	m.vm.r = nil         // the foreign ranges are the stub process's and stay
	m.noWrite = vmaSet{}
	clear(m.ownStack)
	m.reserved = nil
	m.fileCode = nil
	m.sites = siteSet{}
	m.fast, m.strays = 0, 0
	for _, img := range []*image{exe, interp} {
		if img != nil {
			m.sites.addList(img.sites)
			m.fast += img.fast
			m.strays += img.strays
		}
	}
	m.mu.Unlock()
	// Move the stub onto its exec stack, then clear the old address space.
	// A real execve replaces it; the new image maps over its own range, but
	// one loaded at a different address than the old (a laboon stub, whose
	// fixed range does not overlap the Go image it forked from) would leave
	// the old mappings in the way of a later load into this process. The exec
	// stack is in the stub window, never a guest mapping, so unmapping every
	// old VMA cannot pull it out from under the servicing stub.
	dg.ch.reply(repExecPrepare)
	if err := dg.ch.wait(); err != nil || dg.ch.page.kind != msgHostRet {
		return true, errExited
	}
	dg.endRseq()
	m.mu.Lock()
	dg.parkMoved()
	m.mu.Unlock()
	for _, v := range old {
		dg.host(unix.SYS_MUNMAP, v[0], v[1])
	}
	sp, start, err := dg.setupImages(exe, interp, argv, envv, lay, true)
	if err != nil {
		if dg.cfg.Trace != nil {
			fmt.Fprintf(dg.cfg.Trace, "[%d] execve %s: %v\n", dg.pid, t.gp, err)
		}
		dg.beginExit(127)
		pg.nr = unix.SYS_EXIT_GROUP
		pg.args = [6]uint64{127}
		dg.ch.reply(repHost)
		return true, errExited
	}
	dg.ptraceExec(oldTid, start, sp)
	pg.args = [6]uint64{start, sp}
	dg.ch.reply(repExec)
	return true, nil
}

// rseqAuxv is the host's AT_RSEQ_FEATURE_SIZE and AT_RSEQ_ALIGN: the guest's
// restartable sequences are the host kernel's (rseq), so its libc sizes and
// aligns its area for that kernel.
var rseqAuxv = sync.OnceValue(func() []uint64 { return readHostAuxv(27, 28) })

// readHostAuxv is the host auxv's entries with the given tags, as tag, value
// pairs: the supervisor's own, from the same kernel as the stub's.
func readHostAuxv(tags ...uint64) []uint64 {
	b, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return nil
	}
	var out []uint64
	for i := 0; i+16 <= len(b); i += 16 {
		if tag := binary.LittleEndian.Uint64(b[i:]); slices.Contains(tags, tag) {
			out = append(out, tag, binary.LittleEndian.Uint64(b[i+8:]))
		}
	}
	return out
}

// setupImages maps exe (and interp) and a stack holding argv and env,
// returning the stack pointer and where the program starts. replace maps
// over what the images' ranges hold.
func (dg *dguest) setupImages(exe, interp *image, argv, env []string, lay layout, replace bool) (sp, start uint64, err error) {
	for _, img := range []*image{exe, interp} {
		if img == nil {
			continue
		}
		if err := dg.mapImage(img, replace); err != nil {
			return 0, 0, err
		}
		dg.mp.mu.Lock()
		dg.track(img.lo, img.hi-img.lo)
		dg.notePerm(img.lo, img.hi-img.lo, unix.PROT_NONE)
		for _, p := range img.prots {
			dg.notePerm(p.lo, p.hi-p.lo, uint64(p.prot))
		}
		dg.mp.mu.Unlock()
	}
	dg.mp.mu.Lock()
	dg.mp.lay = lay.mm
	brk := lay.brkBase(exe) + lay.brkRnd
	dg.mp.brk, dg.mp.brkLo = brk, brk
	// The stack where the layout drew it; one of the stub process's own
	// mappings up there (its host stack, the vDSO) is taken space, and the top
	// is drawn again, as get_unmapped_area passes over a mapping.
	var r int64
	for top, tries := lay.stack, 0; ; tries++ {
		r = dg.host(unix.SYS_MMAP, top-stackSize, stackSize, unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE, ^uint64(0), 0)
		if r >= 0 && uint64(r) != top-stackSize { // a host that took NOREPLACE as a hint
			dg.host(unix.SYS_MUNMAP, uint64(r), stackSize)
			r = -int64(unix.EEXIST)
		}
		if r != -int64(unix.EEXIST) || lay.mm.norand || tries == 64 {
			break
		}
		top = vmTaskSize - randPages(1<<stackRndBits)
	}
	if r < 0 { // the band is taken (a nested run's outer holds it): the host chooses
		r = dg.host(unix.SYS_MMAP, 0, stackSize, unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
	}
	if r >= 0 {
		dg.trackAs(uint64(r), stackSize, true)
		dg.mp.stackLo, dg.mp.stackHi = uint64(r), uint64(r)+stackSize
	}
	dg.mp.mu.Unlock()
	if r < 0 {
		return 0, 0, lxErr(lxErrno(-r))
	}
	var interpBase uint64
	start = exe.entry
	if interp != nil {
		interpBase, start = interp.bias, interp.entry
	}
	auxv := []uint64{
		3, exe.phdr, // AT_PHDR
		4, 56, // AT_PHENT
		5, exe.phnum, // AT_PHNUM
		6, pageSize, // AT_PAGESZ
		7, interpBase, // AT_BASE
		9, exe.entry, // AT_ENTRY
		11, 0, 12, 0, 13, 0, 14, 0, // AT_UID, AT_EUID, AT_GID, AT_EGID
		17, lxUserHZ, // AT_CLKTCK
		23, 0, // AT_SECURE
	}
	dg.mp.mu.Lock()
	dg.restoreSpecial()
	dg.mp.mu.Unlock()
	v := dg.vdso()
	if v == 0 && len(dg.mp.special) == 0 {
		dg.mapVdso()
		dg.noteSpecial()
		v = dg.vdso()
	}
	if v != 0 {
		auxv = append(auxv, 33, v) // AT_SYSINFO_EHDR
	}
	auxv = append(auxv, rseqAuxv()...)
	sp, stack := layoutStack(uint64(r)+stackSize, argv, env, platform, append(auxv, archAuxv()...))
	if err := dg.writeMem(sp, stack); err != nil {
		return 0, 0, err
	}
	return sp, start, nil
}
