package sandbox

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"slices"
)

const (
	lxPtrace             = 117
	ptraceTraceme        = 0
	ptracePeektext       = 1
	ptracePeekdata       = 2
	ptracePeekuser       = 3
	ptracePoketext       = 4
	ptracePokedata       = 5
	ptracePokeuser       = 6
	ptraceSinglestep     = 9
	ptraceSetregs        = 13
	ptraceSetregset      = 0x4205
	ptraceCont           = 7
	ptraceKill           = 8
	ptraceAttach         = 16
	ptraceGetregs        = 12
	ptraceDetach         = 17
	ptraceSyscall        = 24
	ptraceSetoptions     = 0x4200
	ptraceGeteventmsg    = 0x4201
	ptraceGetsiginfo     = 0x4202
	ptraceGetregset      = 0x4204
	ptraceGetsyscallinfo = 0x420e
	ptraceSeize          = 0x4206
	ptraceInterrupt      = 0x4207
	ptraceListen         = 0x4208
	ptraceNTPrstatus     = 1

	ptraceOTracesysgood   = 1
	ptraceOTracefork      = 2
	ptraceOTracevfork     = 4
	ptraceOTraceclone     = 8
	ptraceOTraceexec      = 16
	ptraceOTracevforkdone = 32
	ptraceOTraceexit      = 64
	ptraceOExitkill       = 0x100000
	ptraceOptions         = ptraceOTracesysgood | ptraceOTracefork | ptraceOTracevfork | ptraceOTraceclone | ptraceOTraceexec | ptraceOTracevforkdone | ptraceOTraceexit | ptraceOExitkill

	ptraceEventFork      = 1
	ptraceEventVfork     = 2
	ptraceEventClone     = 3
	ptraceEventExec      = 4
	ptraceEventVforkDone = 5
	ptraceEventExit      = 6
	ptraceEventStop      = 128
	ptraceInfoNone       = 0
	ptraceInfoEntry      = 1
	ptraceInfoExit       = 2
	sigTRAP              = 5
)

type ptraceCall struct {
	nr     uint64
	args   [6]uint64
	ip, sp uint64
	ret    int64
}

// All fields, including stop snapshots, are guarded by dfs.mu.
type tracee struct {
	ps      *pstate
	g       *dguest
	tracer  int
	options uint64

	attached  bool
	stopped   bool
	pending   bool
	syscall   bool
	newborn   bool
	final     bool
	group     bool
	seized    bool // attached by PTRACE_SEIZE: group stops and traps are PTRACE_EVENT_STOP
	listening bool // PTRACE_LISTEN: held in its group stop, re-trapping when it changes

	status int
	inject int
	op     uint8
	event  uint64
	sig    int
	si     sigInfo
	call   ptraceCall
	mem    *memProc
	regs   []byte
	dirty  bool
	dr6    uint64
	steps  []stepTrap // an arm64 software single-step's breakpoints (armStep)
}

type stepTrap struct {
	at   uint64
	orig [4]byte
}

type ptraceRun struct {
	fs    *dfs
	tasks map[int]*tracee
}

func (fs *dfs) ptraceRun() *ptraceRun {
	if fs.tracing == nil {
		return nil
	}
	return fs.tracing.(*ptraceRun)
}

func init() {
	openProcMem = func(r, target *dguest) (procMemIO, lxErrno) {
		r.dfs.mu.Lock()
		defer r.dfs.mu.Unlock()
		if target.ps.zombie || !ptraceMayAccess(r.ps, target.ps) {
			return nil, lxEACCES
		}
		return func(addr uint64, b []byte, write bool) error {
			r.dfs.mu.Lock()
			defer r.dfs.mu.Unlock()
			if target.ps.zombie || target.ch.dead() {
				return lxErr(lxEIO)
			}
			if ptraceStubGuard(addr, len(b)) {
				return lxErr(lxEIO)
			}
			return ptraceAccess(target, addr, b, write)
		}, 0
	}

	ptraceReturn = func(g *dguest, ret int64) { g.ptraceSyscallExit(ret) }
	// Registered only where the host's dispatch and stub drive the stops.
	// Windows is not wired yet, so ptrace stays ENOSYS there rather than
	// accepting a trace it cannot deliver.
	if ptraceEnabled {
		syscalls[lxPtrace] = func(g *dguest, a [6]uint64) int64 { return g.ptrace(a) }
	}
}

func (g *dguest) ptrace(a [6]uint64) int64 {
	fs := g.dfs
	pid := 0
	if a[0] != ptraceTraceme {
		var ok bool
		pid, ok = g.nsToGlobal(int(int32(a[1])))
		if !ok {
			return sErr(lxESRCH)
		}
	}
	switch a[0] {
	case ptraceAttach:
		return g.ptraceAttachTo(pid, false, 0)
	case ptraceSeize:
		if a[2] != 0 || a[3]&^uint64(ptraceOptions) != 0 {
			return sErr(lxEIO)
		}
		return g.ptraceAttachTo(pid, true, a[3])
	case ptraceInterrupt:
		return g.ptraceInterrupt(pid)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	pr := fs.ptraceRun()
	if a[0] == ptraceTraceme {
		parent := fs.pt[g.ps.ppid]
		if parent == nil || parent.zombie || parent == g.ps || !ptraceMayAccess(parent, g.ps) || pr != nil && pr.traced(g.pid) {
			return sErr(lxEPERM)
		}
		if pr == nil {
			pr = &ptraceRun{fs: fs, tasks: map[int]*tracee{}}
			fs.tracing = pr
		}
		pr.tasks[g.pid] = &tracee{ps: g.ps, g: g, tracer: parent.tgid, attached: true}
		g.ptraceAttach()
		return 0
	}
	if pr == nil {
		return sErr(lxESRCH)
	}
	t := pr.tasks[pid]
	if t == nil || !t.attached || t.tracer != g.tgid || t.final || !t.stopped || t.pending || t.listening {
		return sErr(lxESRCH)
	}
	switch a[0] {
	case ptraceListen:
		if !t.seized || (t.status>>16)&0xff != ptraceEventStop {
			return sErr(lxEIO)
		}
		t.listening = true
		// A change that came during the stop re-traps it at once.
		if st := g.sigs().thread(pid); st != nil && g.sigs().takeTrap(st) {
			pr.retrap(pid, t)
		}
	case ptraceSetoptions:
		if a[3]&^uint64(ptraceOptions) != 0 {
			return sErr(lxEINVAL)
		}
		t.options = a[3]
	case ptraceCont, ptraceSyscall, ptraceDetach, ptraceKill, ptraceSinglestep:
		if a[0] == ptraceSinglestep && !t.g.ps.hvf {
			if runtime.GOARCH == "arm64" {
				if !t.armStep() {
					return sErr(lxEIO)
				}
			} else if !t.canStep() {
				return sErr(lxEIO)
			}
		}
		if a[0] != ptraceKill && a[3] > 64 {
			return sErr(lxEIO)
		}
		t.inject = int(a[3])
		if a[0] == ptraceKill {
			t.inject = sigKILL
		}
		if runtime.GOARCH == "amd64" {
			flags := le64(t.regs[18*8:]) &^ uint64(0x100)
			if a[0] == ptraceSinglestep {
				flags |= 0x100
			}
			if flags != le64(t.regs[18*8:]) {
				put64(t.regs[18*8:], flags)
				t.dirty = true
			}
		}
		t.syscall = a[0] == ptraceSyscall
		if t.g.ps.hvf { // an HVF tracee single-steps via the stdio word, not TF
			m := t.g.stdioMask()
			if a[0] == ptraceSinglestep {
				m |= stdioSinglestep
			}
			t.g.storeStdio(m)
		}
		if a[0] == ptraceDetach {
			pr.detach(pid, t)
		}
		t.stopped = false
		fs.cond.Broadcast()
	case ptracePeektext, ptracePeekdata:
		b := make([]byte, 8)
		if t.memory(a[2], b, false) != nil {
			return sErr(lxEIO)
		}
		if g.writeMem(a[3], b) != nil {
			return sErr(lxEFAULT)
		}
	case ptracePoketext, ptracePokedata:
		if t.memory(a[2], ptraceEncode(a[3]), true) != nil {
			return sErr(lxEIO)
		}
	case ptracePeekuser:
		if runtime.GOARCH == "amd64" && a[2] >= 848 && a[2] < 912 && a[2]%8 == 0 {
			var v uint64
			switch (a[2] - 848) / 8 {
			case 6:
				v = t.dr6
			case 7:
				v = 0x400
			}
			if g.writeMem(a[3], ptraceEncode(v)) != nil {
				return sErr(lxEFAULT)
			}
			break
		}
		b := t.registers()
		if a[2]%8 != 0 || a[2] > uint64(len(b)-8) {
			return sErr(lxEIO)
		}
		if g.writeMem(a[3], b[a[2]:a[2]+8]) != nil {
			return sErr(lxEFAULT)
		}
	case ptracePokeuser:
		if runtime.GOARCH == "amd64" && a[2] == 848+6*8 {
			t.dr6 = a[3]
			break
		}
		if runtime.GOARCH == "amd64" && a[2] == 848+7*8 && a[3]&^uint64(0x400) == 0 {
			break
		}
		b := append([]byte(nil), t.regs...)
		if a[2]%8 != 0 || a[2] > uint64(len(b)-8) {
			return sErr(lxEIO)
		}
		put64(b[a[2]:], a[3])
		if !t.setRegisters(b) {
			return sErr(lxEIO)
		}
	case ptraceSetregs:
		if runtime.GOARCH != "amd64" {
			return sErr(lxEIO)
		}
		b, err := g.readMem(a[3], len(t.regs))
		if err != nil {
			return sErr(lxEFAULT)
		}
		if !t.setRegisters(b) {
			return sErr(lxEIO)
		}
	case ptraceGetregs:
		if runtime.GOARCH != "amd64" {
			return sErr(lxEIO)
		}
		if g.writeMem(a[3], t.registers()) != nil {
			return sErr(lxEFAULT)
		}
	case ptraceGetregset, ptraceSetregset:
		if a[2] != ptraceNTPrstatus {
			return sErr(lxEINVAL)
		}
		b, err := g.readMem(a[3], 16)
		if err != nil {
			return sErr(lxEFAULT)
		}
		var iov struct{ Base, Len uint64 }
		if binary.Read(bytes.NewReader(b), binary.LittleEndian, &iov) != nil {
			return sErr(lxEFAULT)
		}
		if iov.Len%8 != 0 {
			return sErr(lxEINVAL)
		}
		regs := t.registers()
		iov.Len = min(iov.Len, uint64(len(regs)))
		if a[0] == ptraceSetregset {
			b, err := g.readMem(iov.Base, int(iov.Len))
			if err != nil {
				return sErr(lxEFAULT)
			}
			next := append([]byte(nil), regs...)
			copy(next, b)
			if !t.setRegisters(next) {
				return sErr(lxEIO)
			}
		} else if iov.Len != 0 && g.writeMem(iov.Base, regs[:iov.Len]) != nil {
			return sErr(lxEFAULT)
		}
		if g.writeMem(a[3], ptraceEncode(iov)) != nil {
			return sErr(lxEFAULT)
		}
	case ptraceGetsyscallinfo:
		b := t.syscallInfo()
		if n := min(a[2], uint64(len(b))); n != 0 && g.writeMem(a[3], b[:n]) != nil {
			return sErr(lxEFAULT)
		}
		return int64(len(b))
	case ptraceGeteventmsg:
		if g.writeMem(a[3], ptraceEncode(t.event)) != nil {
			return sErr(lxEFAULT)
		}
	case ptraceGetsiginfo:
		if t.group {
			return sErr(lxEINVAL)
		}
		var info struct {
			Signo, Errno, Code int32
			Pad                uint32
			A, B               uint64
			Rest               [96]byte
		}
		info.Signo, info.Errno, info.Code = int32(t.sig), t.si.errno, t.si.code
		info.A, info.B = t.si.a, t.si.b
		if t.op != ptraceInfoNone {
			info.Signo = sigTRAP
		}
		if g.writeMem(a[3], ptraceEncode(info)) != nil {
			return sErr(lxEFAULT)
		}
	default:
		return sErr(lxEIO)
	}
	return 0
}

func ptraceEncode(v any) []byte {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func (t *tracee) syscallInfo() []byte {
	op := t.op
	if t.options&ptraceOTracesysgood == 0 {
		op = ptraceInfoNone
	}
	head := struct {
		Op     uint8
		Pad    [3]byte
		Arch   uint32
		IP, SP uint64
	}{Op: op, Arch: auditArch(), IP: t.call.ip, SP: t.call.sp}
	b := ptraceEncode(head)
	switch op {
	case ptraceInfoEntry:
		b = append(b, ptraceEncode(struct {
			Nr   uint64
			Args [6]uint64
		}{t.call.nr, t.call.args})...)
	case ptraceInfoExit:
		isError := uint8(0)
		if t.call.ret < 0 && t.call.ret >= -4095 {
			isError = 1
		}
		b = append(b, ptraceEncode(struct {
			Ret   int64
			Error uint8
		}{t.call.ret, isError})...)
	}
	return b
}

// trace.zig stores the native NT_PRSTATUS image outside syscall scratch.
const traceRegsOff = 256

func (g *dguest) traceFrame() []byte {
	o := slotsLen + tOff(g.slot) + traceRegsOff
	return g.mem[o : o+16+34*8]
}

func registerSize() int {
	if runtime.GOARCH == "amd64" {
		return 27 * 8
	}
	return 34 * 8
}

func resultOffset() int {
	if runtime.GOARCH == "amd64" {
		return 10 * 8
	}
	return 0
}

func (t *tracee) registers() []byte { return t.regs }

func (t *tracee) canStep() bool {
	if runtime.GOARCH != "amd64" || t.op == ptraceInfoEntry || !ptraceStepOK {
		return false
	}
	pc := le64(t.regs[16*8:])
	m := t.mem
	internal := func(pc uint64) bool {
		return pc >= ptStubLo && pc < ptStubHi || m.ptraceInternalPC(pc)
	}
	if internal(pc) {
		return false
	}
	var b [5]byte
	if t.memory(pc, b[:], false) == nil && b[0] == 0xe9 {
		target := uint64(int64(pc+5) + int64(int32(le32(b[1:]))))
		if internal(target) {
			return false
		}
	}
	return true
}

// armStep single-steps an arm64 tracee in software, as a debugger does where
// it cannot have the processor step: a brk at each place the instruction at
// pc can go next, taken out again at its next stop (unstep). A syscall site
// goes through the supervisor and comes back past itself.
func (t *tracee) armStep() bool {
	if t.op == ptraceInfoEntry {
		return false
	}
	pc := le64(t.regs[32*8:])
	m := t.mem
	internal := func(a uint64) bool { return a >= ptStubLo && a < ptStubHi || m.ptraceInternalPC(a) }
	var w [4]byte
	if internal(pc) || t.memory(pc, w[:], false) != nil {
		return false
	}
	next := a64Next(le32(w[:]), pc, func(r int) uint64 {
		if r == 31 {
			return 0
		}
		return le64(t.regs[r*8:])
	})
	brk := [4]byte{0x00, 0x00, 0x20, 0xd4}
	for _, n := range next {
		if internal(n) {
			n = pc + 4
		}
		if slices.ContainsFunc(t.steps, func(s stepTrap) bool { return s.at == n }) {
			continue
		}
		s := stepTrap{at: n}
		if t.memory(n, s.orig[:], false) != nil || t.memory(n, brk[:], true) != nil {
			continue
		}
		t.steps = append(t.steps, s)
	}
	return len(t.steps) > 0
}

// unstep takes out a software single-step's breakpoints, reporting whether
// the tracee stopped on one, at pc.
func (t *tracee) unstep(pc uint64) bool {
	hit := false
	for _, s := range t.steps {
		hit = hit || s.at == pc
		t.memory(s.at, s.orig[:], true)
	}
	t.steps = nil
	return hit
}

func (t *tracee) setRegisters(b []byte) bool {
	limit := uint64(1) << 48
	if runtime.GOARCH == "amd64" {
		limit = 1 << 47
	}
	addrOK := func(a uint64) bool { return a < limit && (a < ptStubLo || a >= ptStubHi) }
	if runtime.GOARCH == "amd64" {
		if !addrOK(le64(b[16*8:])) || !addrOK(le64(b[19*8:])) || !addrOK(le64(b[21*8:])) ||
			le64(b[17*8:]) != 0x33 || le64(b[20*8:]) != 0x2b || le64(b[22*8:]) != 0 {
			return false
		}
		for i := 23; i < 27; i++ {
			if le64(b[i*8:]) != 0 {
				return false
			}
		}
		const mask = uint64(0x44dd5)
		put64(b[18*8:], (le64(t.regs[18*8:])&^mask)|(le64(b[18*8:])&mask))
	} else {
		if !addrOK(le64(b[31*8:])) || !addrOK(le64(b[32*8:])) || le64(b[32*8:])%4 != 0 || le64(b[33*8:])&^uint64(0xf0000c00) != 0 {
			return false
		}
	}
	t.regs, t.dirty = b, true
	return true
}

func (pr *ptraceRun) traced(tid int) bool {
	t := pr.tasks[tid]
	return t != nil && t.attached
}

func (pr *ptraceRun) traceStopped(tid int) bool {
	t := pr.tasks[tid]
	return t != nil && t.attached && t.stopped
}

func (pr *ptraceRun) owns(ps *pstate) bool {
	for _, t := range pr.tasks {
		if t.ps == ps && t.attached {
			return true
		}
	}
	return false
}

func (pr *ptraceRun) detach(tid int, t *tracee) {
	t.attached, t.stopped, t.pending = false, false, false
	t.g.traced.Store(false)
	t.g.clearTraced()
	delete(pr.tasks, tid)
}

func (pr *ptraceRun) stop(g *dguest, t *tracee, sig, event int, msg uint64, op uint8, si sigInfo) int {
	// A final task's exit is already decided (an exec retired it before its
	// channel died); a stop would overwrite the exit status its tracer awaits.
	if !t.attached || t.final || g.ch.dead() {
		return 0
	}
	frame := g.traceFrame()
	if len(t.steps) > 0 && t.unstep(le64(frame[16+32*8:])) && sig == sigTRAP && event == 0 && op == ptraceInfoNone {
		si = sigInfo{code: 2} // TRAP_TRACE
	}
	t.stopped, t.pending, t.inject = true, true, 0
	t.status, t.event, t.op = (sig|event<<8)<<8|0x7f, msg, op
	t.sig, t.si, t.mem = sig, si, g.mp
	t.regs = append(t.regs[:0], frame[16:16+registerSize()]...)
	t.dirty = false
	if op == ptraceInfoNone {
		if runtime.GOARCH == "amd64" {
			t.call.ip, t.call.sp = le64(t.regs[16*8:]), le64(t.regs[19*8:])
		} else {
			t.call.ip, t.call.sp = le64(t.regs[32*8:]), le64(t.regs[31*8:])
		}
	}
	if sig == sigTRAP && si.code == 2 {
		t.dr6 = 0xffff4ff0
	}
	if op == ptraceInfoEntry && runtime.GOARCH == "amd64" {
		put64(t.regs[resultOffset():], errno(lxENOSYS))
	}
	pr.fs.cond.Broadcast()
	code := cldTrapped
	if event == ptraceEventStop {
		code = cldStopped
	}
	pr.notify(g.pid, t, code, sig|event<<8)
	for t.stopped && t.attached && !g.ch.dead() {
		if !g.condWaitIntrMask(pr.fs.cond, sigBit(sigKILL)) {
			break
		}
	}
	if !t.attached {
		// Let go while its process is stopped by job control, it goes back to
		// that stop before it runs on, as Linux's __ptrace_unlink.
		pr.fs.mu.Unlock()
		sr := g.sigs()
		if _, stopped := sr.jobStop(g.tgid); stopped {
			if p, st := sr.proc(g.tgid), sr.thread(g.pid); p != nil && st != nil {
				sr.hostStopThread(p, st)
			}
		}
		pr.fs.mu.Lock()
	}
	if t.dirty {
		copy(frame[16:], t.regs)
		put64(frame[8:], 1)
	}
	return t.inject
}

func (pr *ptraceRun) signal(g *dguest, sig int, si sigInfo) (int, sigInfo) {
	t := pr.tasks[g.pid]
	if t == nil || !t.attached {
		return sig, si
	}
	if g.ch.page.nr == lxSigFault {
		t.call.ip, t.call.sp = g.ch.page.args[4], g.ch.page.args[5]
	}
	injected := pr.stop(g, t, sig, 0, 0, ptraceInfoNone, si)
	if injected != sig {
		si = sigInfo{code: siUser, a: uint64(t.tracer)}
	}
	return injected, si
}

func (g *dguest) ptraceInject(sig int) {
	if sig == sigKILL {
		procSignal(g.dfs, g.tgid, sig)
	}
}

func (g *dguest) ptraceEnter(nr uint64, args [6]uint64) bool {
	if !g.traced.Load() || !isRealSyscall(nr) {
		return true
	}
	fs := g.dfs
	fs.mu.Lock()
	pr := fs.ptraceRun()
	inject := 0
	if pr != nil {
		if t := pr.tasks[g.pid]; t != nil && t.attached {
			t.call = ptraceCall{nr: nr, args: args, ip: g.ch.page.guestRip, sp: ptraceSP(g), ret: -int64(lxENOSYS)}
			if t.syscall {
				sig := sigTRAP
				if t.options&ptraceOTracesysgood != 0 {
					sig |= 0x80
				}
				inject = pr.stop(g, t, sig, 0, 0, ptraceInfoEntry, sigInfo{code: int32(sig)})
				if t.dirty {
					b := t.regs
					if runtime.GOARCH == "amd64" {
						t.call.nr = le64(b[15*8:])
						for i, j := range []int{14, 13, 12, 7, 9, 8} {
							t.call.args[i] = le64(b[j*8:])
						}
					} else {
						t.call.nr = le64(b[8*8:])
						for i := range t.call.args {
							t.call.args[i] = le64(b[i*8:])
						}
					}
					g.ch.page.nr, g.ch.page.args = t.call.nr, t.call.args
				}
			}
		}
	}
	fs.mu.Unlock()
	g.ptraceInject(inject)
	return g.sigs().killedBy(g.tgid) == 0 && !g.ch.dead()
}

func (g *dguest) ptraceSyscallExit(ret int64) {
	if !g.traced.Load() || g.sigs().killedBy(g.tgid) != 0 {
		return
	}
	g.flushOuts() // traced since the call began: the stop shows its results
	fs := g.dfs
	fs.mu.Lock()
	inject := 0
	if pr := fs.ptraceRun(); pr != nil {
		if t := pr.tasks[g.pid]; t != nil && t.attached {
			t.call.ret = ret
			frame := g.traceFrame()
			put64(frame[16+resultOffset():], uint64(ret))
			if t.syscall {
				sig := sigTRAP
				if t.options&ptraceOTracesysgood != 0 {
					sig |= 0x80
				}
				inject = pr.stop(g, t, sig, 0, 0, ptraceInfoExit, sigInfo{code: int32(sig)})
				g.ch.page.ret = le64(frame[16+resultOffset():])
			}
		}
	}
	fs.mu.Unlock()
	g.ptraceInject(inject)
}

func (g *dguest) ptraceEvent(event int, msg uint64) {
	if !g.traced.Load() {
		return
	}
	fs := g.dfs
	fs.mu.Lock()
	inject := 0
	if pr := fs.ptraceRun(); pr != nil {
		if t := pr.tasks[g.pid]; t != nil && t.attached && t.options&(1<<event) != 0 {
			if event == ptraceEventFork || event == ptraceEventVfork || event == ptraceEventClone || event == ptraceEventVforkDone {
				if tracer := fs.pt[t.tracer]; tracer != nil {
					msg = uint64(tracer.ns.localOf(int(msg)))
				}
			}
			inject = pr.stop(g, t, sigTRAP, event, msg, ptraceInfoNone, sigInfo{code: int32(sigTRAP | event<<8)})
		}
	}
	fs.mu.Unlock()
	g.ptraceInject(inject)
}

func (g *dguest) ptraceExec(old int, ip, sp uint64) {
	fs := g.dfs
	fs.mu.Lock()
	inject := 0
	if pr := fs.ptraceRun(); pr != nil {
		if t := pr.tasks[g.pid]; t != nil && t.attached {
			t.call.ip, t.call.sp = ip, sp
			frame := g.traceFrame()
			clear(frame)
			put64(frame, 3)
			put64(frame[8:], 1)
			b := frame[16:]
			if runtime.GOARCH == "amd64" {
				put64(b[15*8:], ^uint64(0))
				put64(b[16*8:], ip)
				put64(b[17*8:], 0x33)
				put64(b[18*8:], 0x202)
				put64(b[19*8:], sp)
				put64(b[20*8:], 0x2b)
			} else {
				put64(b[31*8:], sp)
				put64(b[32*8:], ip)
			}
			event, msg := 0, uint64(0)
			if t.options&ptraceOTraceexec != 0 {
				event = ptraceEventExec
				msg = uint64(old)
			}
			// Only an attaching tracer gets the legacy SIGTRAP.
			if event != 0 || !t.seized {
				inject = pr.stop(g, t, sigTRAP, event, msg, ptraceInfoNone, sigInfo{code: int32(sigTRAP | event<<8)})
			}
		}
	}
	fs.mu.Unlock()
	g.ptraceInject(inject)
	g.ptraceSyscallExit(0)
}

// ptraceStepStop reports the SIGTRAP stop after an HVF tracee single-stepped one
// instruction. The stub has published the registers at the new pc into the trace
// frame; snapshot them and stop with si_code TRAP_TRACE.
func (g *dguest) ptraceStepStop() {
	fs := g.dfs
	fs.mu.Lock()
	inject := 0
	if pr := fs.ptraceRun(); pr != nil {
		if t := pr.tasks[g.pid]; t != nil && t.attached {
			t.regs = append(t.regs[:0], g.traceFrame()[16:16+registerSize()]...)
			t.dirty = false
			inject = pr.stop(g, t, sigTRAP, 0, 0, ptraceInfoNone, sigInfo{code: 2}) // TRAP_TRACE
		}
	}
	fs.mu.Unlock()
	g.ptraceInject(inject)
}

// Called before a child can run, with fs.mu held.
func (g *dguest) ptraceFork(child *dguest, r cloneReq) int {
	pr := g.dfs.ptraceRun()
	if pr == nil {
		return 0
	}
	t := pr.tasks[g.pid]
	if t == nil || !t.attached {
		return 0
	}
	event := ptraceEventClone
	if r.flags&lxCloneVfork != 0 {
		event = ptraceEventVfork
	} else if r.exitSignal == sigCHLD {
		event = ptraceEventFork
	}
	if t.options&(1<<event) == 0 {
		return 0
	}
	pr.tasks[child.pid] = &tracee{ps: child.ps, g: child, tracer: t.tracer, options: t.options, attached: true, seized: t.seized, newborn: true, call: t.call}
	frame := child.traceFrame()
	copy(frame, g.traceFrame())
	put64(frame[8:], 1)
	b := frame[16:]
	put64(b[resultOffset():], 0)
	spoff := 31 * 8
	if runtime.GOARCH == "amd64" {
		spoff = 19 * 8
		if r.flags&lxCloneSettls != 0 {
			put64(b[21*8:], r.tls)
		}
	}
	if r.stack != 0 {
		put64(b[spoff:], r.stack)
	}
	child.ptraceAttach()
	return event
}

// ptraceChildStart is an auto-attached task's first stop, before its first
// instruction: a SIGSTOP for an attaching tracer, a trap (PTRACE_EVENT_STOP)
// for a seizing one.
func (g *dguest) ptraceChildStart() {
	sig := g.trapSig()
	fs := g.dfs
	fs.mu.Lock()
	inject := 0
	if pr := fs.ptraceRun(); pr != nil {
		if t := pr.tasks[g.pid]; t != nil && t.newborn {
			t.newborn = false
			if t.seized {
				inject = pr.stop(g, t, sig, ptraceEventStop, 0, ptraceInfoNone, sigInfo{code: int32(sig | ptraceEventStop<<8)})
				if inject != sigKILL {
					inject = 0 // a trap takes no signal
				}
			} else {
				inject = pr.stop(g, t, sigSTOP, 0, 0, ptraceInfoNone, sigInfo{code: siUser})
			}
		}
	}
	fs.mu.Unlock()
	g.ptraceInject(inject)
}

func (pr *ptraceRun) takeOver(g *dguest, old int) {
	t := pr.tasks[old]
	for tid, other := range pr.tasks {
		if other.ps == g.ps && tid != old {
			if tid == g.pid {
				pr.detach(tid, other)
			} else {
				other.final, other.pending, other.status = true, true, 0
				other.g.traced.Store(false)
				other.g.clearTraced()
			}
		}
	}
	if t != nil && old != g.pid {
		delete(pr.tasks, old)
		pr.tasks[g.pid] = t
	}
	pr.fs.cond.Broadcast()
}

// processExit ends ps's traces and its tracing of others. It returns the
// processes to kill (PTRACE_O_EXITKILL) and the exited ones whose real parent
// now learns of the exit, held back while ps traced them.
func (pr *ptraceRun) processExit(ps *pstate) (kill, release []int) {
	for tid, t := range pr.tasks {
		if t.tracer == ps.tgid {
			if t.options&ptraceOExitkill != 0 && !t.final {
				t.inject = sigKILL
				kill = append(kill, t.ps.tgid)
			}
			if pr.held(tid, t) && t.ps.zombie {
				release = append(release, tid)
			}
			pr.detach(tid, t)
		} else if t.ps == ps && !t.final {
			t.final, t.stopped, t.pending, t.status = true, false, true, ps.status
		}
	}
	pr.fs.cond.Broadcast()
	return kill, release
}

// holdsExit reports whether ps's exit goes to a tracer other than its parent
// first: its parent is told only once the tracer lets the zombie go, as Linux
// defers do_notify_parent.
func (pr *ptraceRun) holdsExit(ps *pstate) bool {
	t := pr.tasks[ps.tgid]
	return t != nil && pr.held(ps.tgid, t)
}

func (pr *ptraceRun) held(tid int, t *tracee) bool {
	return t.attached && tid == t.ps.tgid && t.tracer != t.ps.ppid
}

func (g *dguest) ptraceThreadExit(code int) {
	fs := g.dfs
	fs.mu.Lock()
	if pr := fs.ptraceRun(); pr != nil {
		if t := pr.tasks[g.pid]; t != nil && t.g == g && !t.final {
			t.final, t.stopped, t.pending, t.status = true, false, true, (code&0xff)<<8
			fs.cond.Broadcast()
			pr.notify(g.pid, t, cldExited, code&0xff)
		}
	}
	fs.mu.Unlock()
}

func (pr *ptraceRun) wait(g *dguest, w waitSel, exited bool) (waitEvent, bool, bool) {
	found := false
	for tid, t := range pr.tasks {
		if !t.attached || t.tracer != g.tgid || w.pid > 0 && w.pid != tid || w.pid == 0 && w.pgid > 0 && w.pgid != t.ps.pgid {
			continue
		}
		found = true
		if !t.pending || t.final && !exited {
			continue
		}
		if t.final && tid == t.ps.tgid && pr.othersLeft(t.ps, tid) {
			continue // as Linux delays a group leader's exit until its other threads are reaped
		}
		ev := waitEvent{pid: g.ps.ns.localOf(tid), uid: t.ps.cred.ruid, status: t.status, code: cldTrapped, sistat: t.status >> 8}
		if t.final {
			ev.code, ev.sistat = cldExited, (t.status>>8)&0xff
			if t.status&0x7f != 0 {
				ev.code, ev.sistat = cldKilled, t.status&0x7f
				if t.status&0x80 != 0 {
					ev.code = cldDumped
				}
			}
			if tid == t.ps.tgid {
				ev.ru = t.ps.ru.plus(t.ps.cru)
			}
		}
		if w.opts&wNowait == 0 {
			t.pending = false
			if t.final {
				release := pr.held(tid, t) && t.ps.zombie
				delete(pr.tasks, tid)
				if tid != t.ps.tgid {
					t.ps.ns.deregister(tid)
				} else if t.ps.ppid == g.tgid && t.ps.zombie {
					g.ps.cru = g.ps.cru.plus(ev.ru)
					delete(pr.fs.pt, tid)
					t.ps.ns.deregister(tid)
				}
				pr.fs.cond.Broadcast()
				if release {
					pr.fs.mu.Unlock()
					pr.fs.ptraceReleased(tid)
					pr.fs.mu.Lock()
				}
			}
		}
		return ev, true, true
	}
	return waitEvent{}, found, false
}

// othersLeft reports whether a traced thread of ps other than leader is still
// to be reaped by its tracer.
func (pr *ptraceRun) othersLeft(ps *pstate, leader int) bool {
	for tid, t := range pr.tasks {
		if tid != leader && t.ps == ps && t.attached {
			return true
		}
	}
	return false
}

// ptraceStubGuard reports whether a memory range overlaps the stub's own text,
// which ptrace must never touch, or wraps the address space.
func ptraceStubGuard(addr uint64, n int) bool {
	return addr > ^uint64(0)-uint64(n) || addr < ptStubHi && addr+uint64(n) > ptStubLo
}

// memory reads or writes the tracee's address space for PEEK/POKE and the
// instruction-stepping checks. ptraceAccess is the per-host transport.
func (t *tracee) memory(addr uint64, b []byte, write bool) error {
	if ptraceStubGuard(addr, len(b)) {
		return lxErr(lxEIO)
	}
	return ptraceAccess(t.g, addr, b, write)
}

// fs.mu is released while signal routing takes its own locks.
func (pr *ptraceRun) notify(tid int, t *tracee, code, status int) {
	parent := pr.fs.pt[t.tracer]
	if parent == nil || parent.zombie {
		return
	}
	pid, tracer := parent.ns.localOf(tid), t.tracer
	uid := t.ps.cred.ruid
	pr.fs.mu.Unlock()
	sr := pr.fs.sigs()
	if p := sr.proc(tracer); p != nil {
		sr.send(p, nil, sigCHLD, sigInfo{code: int32(code), a: uint64(uint32(pid)) | uint64(uid)<<32, b: uint64(uint32(status))}, nil)
	}
	pr.fs.mu.Lock()
}

func (pr *ptraceRun) notifyExit(ps *pstate) {
	pr.fs.mu.Lock()
	defer pr.fs.mu.Unlock()
	for tid, t := range pr.tasks {
		if t.ps != ps || !t.final || t.tracer == ps.ppid {
			continue
		}
		code, status := cldExited, (t.status>>8)&0xff
		if t.status&0x7f != 0 {
			code, status = cldKilled, t.status&0x7f
		}
		pr.notify(tid, t, code, status)
	}
}

func (g *dguest) ptraceExecTid() int {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	if pr := g.dfs.ptraceRun(); pr != nil {
		if t := pr.tasks[g.pid]; t != nil {
			if tracer := g.dfs.pt[t.tracer]; tracer != nil {
				return tracer.ns.localOf(g.pid)
			}
		}
	}
	return g.pid
}

func (pr *ptraceRun) groupStop(g *dguest, sig int) bool {
	t := pr.tasks[g.pid]
	if t == nil || !t.attached {
		return false
	}
	var inject int
	if t.seized {
		inject = pr.stop(g, t, sig, ptraceEventStop, 0, ptraceInfoNone, sigInfo{code: int32(sig | ptraceEventStop<<8)})
	} else {
		t.group = true
		inject = pr.stop(g, t, sig, 0, 0, ptraceInfoNone, sigInfo{})
		t.group = false
	}
	if inject == sigKILL {
		pr.fs.mu.Unlock()
		g.ptraceInject(inject)
		pr.fs.mu.Lock()
	}
	return true
}

// ptraceAttachTo makes g the tracer of thread tid. PTRACE_ATTACH sends it a
// SIGSTOP, whose signal-delivery stop is the first stop the tracer sees;
// PTRACE_SEIZE (seize, with its options) leaves it running. Either way a task
// stopped by job control re-traps into its group stop for the tracer, as
// Linux's ptrace_attach does.
func (g *dguest) ptraceAttachTo(tid int, seize bool, options uint64) int64 {
	fs := g.dfs
	fs.mu.Lock()
	dp := fs.procs[tid]
	if dp == nil || dp.g == nil || dp.ps == nil || dp.ps.zombie {
		fs.mu.Unlock()
		return sErr(lxESRCH)
	}
	target := dp.g
	pr := fs.ptraceRun()
	if dp.ps == g.ps || pr != nil && pr.traced(tid) || !ptraceMayAccess(g.ps, dp.ps) {
		fs.mu.Unlock()
		return sErr(lxEPERM)
	}
	if pr == nil {
		pr = &ptraceRun{fs: fs, tasks: map[int]*tracee{}}
		fs.tracing = pr
	}
	pr.tasks[tid] = &tracee{ps: dp.ps, g: target, tracer: g.tgid, attached: true, seized: seize, options: options}
	target.ptraceAttach()
	fs.mu.Unlock()
	sr := g.sigs()
	t := sr.thread(tid)
	if t == nil {
		return 0 // it ended meanwhile: the tracer's wait reports that
	}
	p := sr.proc(t.tgid)
	if p == nil {
		return 0
	}
	if !seize {
		sr.send(p, t, sigSTOP, sigInfo{code: siKernel}, g)
	}
	if _, stopped := sr.jobStop(t.tgid); stopped {
		// The task is held by the host stop of its process. It takes the trap
		// where the stop caught it, before any guest code, once the host lets
		// it go. One thread among several goes on alone where host stops are
		// per thread; where they are per process only a SIGCONT lets it go,
		// since the others would run on too.
		sr.setTrap(t)
		if len(sr.threadsOf(p)) == 1 {
			sr.hostCont(p)
		} else {
			sr.hostContThread(p, t)
		}
	}
	return 0
}

// ptraceInterrupt is PTRACE_INTERRUPT: a seized tracee takes a trap
// (PTRACE_EVENT_STOP) where it next looks for signals; a blocking call it is
// in is cut short and restarted after the stop. A listening tracee re-traps
// at once.
func (g *dguest) ptraceInterrupt(tid int) int64 {
	fs := g.dfs
	fs.mu.Lock()
	pr := fs.ptraceRun()
	var t *tracee
	if pr != nil {
		t = pr.tasks[tid]
	}
	if t == nil || !t.attached || t.tracer != g.tgid || t.final {
		fs.mu.Unlock()
		return sErr(lxESRCH)
	}
	if !t.seized {
		fs.mu.Unlock()
		return sErr(lxEIO)
	}
	if t.listening {
		pr.retrap(tid, t)
		fs.mu.Unlock()
		return 0
	}
	fs.mu.Unlock()
	if st := g.sigs().thread(tid); st != nil {
		g.sigs().setTrap(st)
	}
	return 0
}

// trapSig is the signal a seized task's trap reports: its group stop's while
// its process is stopped, else SIGTRAP, as Linux's do_jobctl_trap.
func (g *dguest) trapSig() int {
	if sig, stopped := g.sigs().jobStop(g.tgid); stopped {
		return sig
	}
	return sigTRAP
}

// ptraceTrap takes the trap a tracer asked of g (PTRACE_INTERRUPT, an attach
// to a stopped task, a seized task's SIGCONT): PTRACE_EVENT_STOP for a
// seizing tracer, a plain group stop for an attaching one.
func (g *dguest) ptraceTrap() {
	sig, stopped := g.sigs().jobStop(g.tgid)
	fs := g.dfs
	fs.mu.Lock()
	inject := 0
	if pr := fs.ptraceRun(); pr != nil {
		if t := pr.tasks[g.pid]; t != nil && t.attached && !t.final {
			switch {
			case t.seized:
				if !stopped {
					sig = sigTRAP
				}
				inject = pr.stop(g, t, sig, ptraceEventStop, 0, ptraceInfoNone, sigInfo{code: int32(sig | ptraceEventStop<<8)})
			case stopped:
				t.group = true
				inject = pr.stop(g, t, sig, 0, 0, ptraceInfoNone, sigInfo{})
				t.group = false
			}
		}
	}
	fs.mu.Unlock()
	if inject == sigKILL {
		g.ptraceInject(inject)
	}
}

// retrap reports a listening tracee's PTRACE_EVENT_STOP again: it stays
// stopped, and its tracer's next wait sees it.
func (pr *ptraceRun) retrap(tid int, t *tracee) {
	sig := t.g.trapSig()
	t.listening, t.pending = false, true
	t.sig, t.si = sig, sigInfo{code: int32(sig | ptraceEventStop<<8)}
	t.status = (sig|ptraceEventStop<<8)<<8 | 0x7f
	pr.fs.cond.Broadcast()
	pr.notify(tid, t, cldStopped, sig|ptraceEventStop<<8)
}

// ptraceContinued runs on a SIGCONT to process tgid: a listening seized
// tracee re-traps at once, and the other seized ones are returned to take a
// trap where they next look for signals, as Linux's ptrace_trap_notify.
func (fs *dfs) ptraceContinued(tgid int) []int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	pr := fs.ptraceRun()
	if pr == nil {
		return nil
	}
	var trap, listening []int
	for tid, t := range pr.tasks {
		if t.ps.tgid != tgid || !t.attached || !t.seized || t.final {
			continue
		}
		if t.listening {
			listening = append(listening, tid)
		} else {
			trap = append(trap, tid)
		}
	}
	for _, tid := range listening {
		if t := pr.tasks[tid]; t != nil && t.listening {
			pr.retrap(tid, t)
		}
	}
	return trap
}

func (g *dguest) ptraceAttach() {
	stdioSlots.Lock()
	g.traced.Store(true)
	g.storeStdio(stdioTraced)
	stdioSlots.Unlock()
}

func (pr *ptraceRun) forget(ps *pstate) {
	for tid, t := range pr.tasks {
		if t.ps == ps {
			pr.detach(tid, t)
		}
	}
	pr.fs.cond.Broadcast()
}

func (pr *ptraceRun) tracer(tid int) int {
	if t := pr.tasks[tid]; t != nil && t.attached {
		return t.tracer
	}
	return 0
}
