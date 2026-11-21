//go:build darwin || linux || windows

package sandbox

import "runtime"

// Seccomp-BPF enforcement. A guest installs a classic-BPF program that the
// kernel runs on every syscall to decide its fate; the supervisor already sees
// every syscall, so it runs the same program and applies the verdict. This is
// the guest's own sandbox between its processes (the browser trusting its
// renderers less than itself), layered under the supervisor's own mediation.

// seccomp return actions (SECCOMP_RET_*), high 16 bits the action.
const (
	secRetKillProcess = 0x80000000
	secRetKillThread  = 0x00000000
	secRetTrap        = 0x00030000
	secRetErrno       = 0x00050000
	secRetUserNotif   = 0x7fc00000
	secRetTrace       = 0x7ff00000
	secRetLog         = 0x7ffc0000
	secRetAllow       = 0x7fff0000

	secRetActionFull = 0xffff0000 // the action bits
	secRetData       = 0x0000ffff // the data bits (errno, trap number)
	secMaxErrno      = 4095

	secModeFilter = 2 // SECCOMP_MODE_FILTER, the seccomp mode once a filter is set

	seccompDataLen = 64 // sizeof(struct seccomp_data): nr+arch+ip+6 args
)

// seccompData is the input the kernel hands a filter: the syscall number, the
// audit arch, the instruction pointer and the six arguments.
type seccompData struct {
	nr   uint32
	arch uint32
	ip   uint64
	args [6]uint64
}

// auditArch is the AUDIT_ARCH value for the guest, which a filter checks before
// trusting the syscall numbers. The guest runs the host's instruction set.
func auditArch() uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return 0xC000003E // AUDIT_ARCH_X86_64
	case "arm64":
		return 0xC00000B7 // AUDIT_ARCH_AARCH64
	}
	return 0
}

// word loads a 32-bit word from the seccomp_data at byte offset off; ok is
// false for an out-of-range load, which a filter treats as fatal.
func (d *seccompData) word(off uint32) (uint32, bool) {
	switch {
	case off == 0:
		return d.nr, true
	case off == 4:
		return d.arch, true
	case off == 8:
		return uint32(d.ip), true
	case off == 12:
		return uint32(d.ip >> 32), true
	case off >= 16 && off < 16+48 && off%4 == 0:
		i := (off - 16) / 8
		if (off-16)%8 == 0 {
			return uint32(d.args[i]), true
		}
		return uint32(d.args[i] >> 32), true
	}
	return 0, false
}

// bpfRun runs one classic-BPF filter over d and returns its action word. It
// implements the complete instruction set the kernel permits in a seccomp
// filter (every form seccomp_check_filter accepts), so any guest's filter runs
// as Linux would run it -- not a subset tuned to one program. A filter is
// validated when installed (bpfValidate), so an unmodelled opcode never reaches
// here; if one somehow does, the verdict is fail-closed (kill), never allow.
func bpfRun(prog []byte, d *seccompData) uint32 {
	var a, x uint32
	var m [16]uint32 // BPF scratch memory M[0..15]
	n := len(prog) / 8
	for pc := 0; pc < n; pc++ {
		o := pc * 8
		code := rd16(prog[o:])
		jt, jf := prog[o+2], prog[o+3]
		k := le32(prog[o+4:])
		switch code {
		case 0x20: // BPF_LD|BPF_W|BPF_ABS
			v, ok := d.word(k)
			if !ok {
				return secRetKillProcess
			}
			a = v
		case 0x00: // BPF_LD|BPF_IMM
			a = k
		case 0x01: // BPF_LDX|BPF_IMM
			x = k
		case 0x21: // BPF_LDX|BPF_W|BPF_ABS
			v, ok := d.word(k)
			if !ok {
				return secRetKillProcess
			}
			x = v
		case 0x04: // BPF_ALU|BPF_ADD|BPF_K
			a += k
		case 0x14: // BPF_ALU|BPF_SUB|BPF_K
			a -= k
		case 0x54: // BPF_ALU|BPF_AND|BPF_K
			a &= k
		case 0x44: // BPF_ALU|BPF_OR|BPF_K
			a |= k
		case 0x74: // BPF_ALU|BPF_RSH|BPF_K
			a >>= k
		case 0x64: // BPF_ALU|BPF_LSH|BPF_K
			a <<= k
		case 0x05: // BPF_JMP|BPF_JA
			pc += int(k)
		case 0x15: // BPF_JMP|BPF_JEQ|BPF_K
			pc += int(cond(a == k, jt, jf))
		case 0x25: // BPF_JMP|BPF_JGT|BPF_K
			pc += int(cond(a > k, jt, jf))
		case 0x35: // BPF_JMP|BPF_JGE|BPF_K
			pc += int(cond(a >= k, jt, jf))
		case 0x45: // BPF_JMP|BPF_JSET|BPF_K
			pc += int(cond(a&k != 0, jt, jf))
		case 0x1d: // BPF_JMP|BPF_JEQ|BPF_X
			pc += int(cond(a == x, jt, jf))
		case 0x2d: // BPF_JMP|BPF_JGT|BPF_X
			pc += int(cond(a > x, jt, jf))
		case 0x3d: // BPF_JMP|BPF_JGE|BPF_X
			pc += int(cond(a >= x, jt, jf))
		case 0x4d: // BPF_JMP|BPF_JSET|BPF_X
			pc += int(cond(a&x != 0, jt, jf))
		case 0x06: // BPF_RET|BPF_K
			return k
		case 0x16: // BPF_RET|BPF_A
			return a
		case 0x07: // BPF_MISC|BPF_TAX
			x = a
		case 0x87: // BPF_MISC|BPF_TXA
			a = x
		case 0x60: // BPF_LD|BPF_MEM
			a = m[k&0xf]
		case 0x61: // BPF_LDX|BPF_MEM
			x = m[k&0xf]
		case 0x80: // BPF_LD|BPF_W|BPF_LEN
			a = seccompDataLen
		case 0x81: // BPF_LDX|BPF_W|BPF_LEN
			x = seccompDataLen
		case 0x02: // BPF_ST
			m[k&0xf] = a
		case 0x03: // BPF_STX
			m[k&0xf] = x
		case 0x0c: // BPF_ALU|BPF_ADD|BPF_X
			a += x
		case 0x1c: // BPF_ALU|BPF_SUB|BPF_X
			a -= x
		case 0x24: // BPF_ALU|BPF_MUL|BPF_K
			a *= k
		case 0x2c: // BPF_ALU|BPF_MUL|BPF_X
			a *= x
		case 0x34: // BPF_ALU|BPF_DIV|BPF_K
			if k == 0 { // Linux (eBPF): divide by zero yields 0 and continues
				a = 0
			} else {
				a /= k
			}
		case 0x3c: // BPF_ALU|BPF_DIV|BPF_X
			if x == 0 {
				a = 0
			} else {
				a /= x
			}
		case 0x4c: // BPF_ALU|BPF_OR|BPF_X
			a |= x
		case 0x5c: // BPF_ALU|BPF_AND|BPF_X
			a &= x
		case 0x6c: // BPF_ALU|BPF_LSH|BPF_X
			a <<= x
		case 0x7c: // BPF_ALU|BPF_RSH|BPF_X
			a >>= x
		case 0x84: // BPF_ALU|BPF_NEG
			a = -a
		case 0xa4: // BPF_ALU|BPF_XOR|BPF_K
			a ^= k
		case 0xac: // BPF_ALU|BPF_XOR|BPF_X
			a ^= x
		default:
			// A validated filter never reaches here; fail closed, never allow.
			return secRetKillProcess
		}
	}
	return secRetKillProcess // a well-formed filter always returns first
}

// bpfAllowed is every opcode the kernel permits in a seccomp filter
// (seccomp_check_filter): the loads, stores, ALU, jumps, returns and the two
// MISC transfers. value is true for operand-less opcodes; opcodes whose operand
// needs a bounds check are handled explicitly in bpfValidate.
var bpfAllowed = map[uint16]bool{
	0x00: true, 0x01: true, 0x80: true, 0x81: true, // LD/LDX IMM, LD/LDX LEN
	0x04: true, 0x0c: true, 0x14: true, 0x1c: true, // ALU ADD/SUB (K,X)
	0x24: true, 0x2c: true, // ALU MUL (K,X)
	0x44: true, 0x4c: true, 0x54: true, 0x5c: true, // ALU OR/AND (K,X)
	0x64: true, 0x6c: true, 0x74: true, 0x7c: true, // ALU LSH/RSH (K,X)
	0x84: true, 0xa4: true, 0xac: true, // ALU NEG, XOR (K,X)
	0x06: true, 0x16: true, // RET K, A
	0x07: true, 0x87: true, // MISC TAX, TXA
}

// bpfValidate reports whether prog is a well-formed seccomp classic-BPF filter:
// every instruction is one the kernel permits, and its loads, scratch slots and
// jump targets are in range. The kernel rejects anything else at install with
// EINVAL (seccomp_check_filter + bpf_check_classic), so laboon must too --
// otherwise an unmodelled instruction would silently leave the guest's own
// sandbox off. Division by zero is a runtime value, not a validation error.
func bpfValidate(prog []byte) bool {
	if len(prog) == 0 || len(prog)%8 != 0 {
		return false
	}
	n := len(prog) / 8
	for pc := 0; pc < n; pc++ {
		o := pc * 8
		code := rd16(prog[o:])
		jt, jf := uint64(prog[o+2]), uint64(prog[o+3])
		k := le32(prog[o+4:])
		switch code {
		case 0x20, 0x21: // LD/LDX W ABS: aligned, within seccomp_data
			if k >= seccompDataLen || k&3 != 0 {
				return false
			}
		case 0x60, 0x61, 0x02, 0x03: // LD/LDX MEM, ST, STX: scratch slot in range
			if k >= 16 {
				return false
			}
		case 0x05: // JA: unsigned jump, target within the program
			if uint64(pc)+1+uint64(k) >= uint64(n) {
				return false
			}
		case 0x15, 0x25, 0x35, 0x45, 0x1d, 0x2d, 0x3d, 0x4d: // conditional jumps
			if uint64(pc)+1+jt >= uint64(n) || uint64(pc)+1+jf >= uint64(n) {
				return false
			}
		default:
			if !bpfAllowed[code] {
				return false
			}
		}
	}
	return true
}

func cond(c bool, jt, jf uint8) uint8 {
	if c {
		return jt
	}
	return jf
}

func rd16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

// seccompVerdict runs every installed filter over (nr, args) and returns the
// combined action: filters stack, and the kernel takes the most restrictive
// result, which is the smallest action value (a process kill overriding all).
// It returns secRetAllow when no filter is installed.
func (g *dguest) seccompVerdict(nr uint32, args [6]uint64, ip uint64) uint32 {
	g.dfs.mu.Lock()
	progs := g.ps.seccompProg
	g.dfs.mu.Unlock()
	if len(progs) == 0 {
		return secRetAllow
	}
	d := seccompData{nr: nr, arch: auditArch(), ip: ip, args: args}
	worst := uint32(secRetAllow)
	killProc := false
	for _, p := range progs {
		r := bpfRun(p, &d)
		if r&secRetActionFull == secRetKillProcess&secRetActionFull {
			killProc = true
		}
		if r < worst {
			worst = r
		}
	}
	if killProc {
		return secRetKillProcess
	}
	return worst
}

// applySeccomp runs the installed filters on a real guest syscall and reports
// how to answer it: handled is true when the syscall must not run, with ret the
// value the guest sees.
func (g *dguest) applySeccomp(nr uint32, args [6]uint64, ip uint64) (ret int64, handled bool) {
	v := g.seccompVerdict(nr, args, ip)
	switch v & secRetActionFull {
	case secRetAllow & secRetActionFull, secRetLog & secRetActionFull:
		return 0, false
	case secRetErrno & secRetActionFull:
		e := v & secRetData
		if e > secMaxErrno {
			e = secMaxErrno
		}
		return -int64(e), true
	case secRetTrace & secRetActionFull, secRetUserNotif & secRetActionFull:
		// No tracer or notifier is attached, so the syscall fails with ENOSYS.
		return -int64(lxENOSYS), true
	default:
		// SECCOMP_RET_TRAP, or a kill: deliver SIGSYS and, as a trapped
		// syscall does, do not run it. si_errno carries the filter's
		// SECCOMP_RET_DATA (a nested stub's own trap backstop tags its traps
		// there, and its SIGSYS handler checks it); si_code is SYS_SECCOMP, and
		// a/b the call address, syscall number and arch a SIGSYS handler reads.
		// The result keeps the syscall number, which the kernel leaves in the
		// register a handler reads (not ENOSYS).
		const sysSeccomp = 1
		si := sigInfo{errno: int32(v & secRetData), code: sysSeccomp, a: ip, b: uint64(nr) | uint64(auditArch())<<32}
		sr := g.sigs()
		t, p := sr.thread(g.pid), sr.proc(g.tgid)
		if t == nil || p == nil {
			return int64(nr), true
		}
		if a := v & secRetActionFull; a == secRetKillProcess&secRetActionFull || a == secRetKillThread {
			// A kill is neither caught nor blocked: SIGSYS takes its default
			// action, which ends the process, as Linux's seccomp kill does.
			sr.sq.Lock()
			p.acts[31-1].handler = 0
			sr.sq.Unlock()
			o := tOff(t.slot)
			sr.st(o+stMask, sr.ld(o+stMask)&^sigBit(31))
		}
		sr.queue(&t.q, 31, si)
		return int64(nr), true
	}
}

// seccompCheck answers a stub's msgSeccomp: the filters' verdict on the call
// it is about to serve. A tracer sees a call the filters let through at its
// usual stops, where it is served.
func (g *dguest) seccompCheck() {
	pg := g.ch.page
	r, handled := g.applySeccomp(uint32(pg.nr), pg.args, pg.guestRip)
	pg.args[0] = 0
	if handled {
		pg.args[0], pg.ret = 1, uint64(r)
	}
	g.ch.reply(repResult)
}

// readFilter reads a struct sock_fprog {u16 len; sock_filter *filter} and the
// len instructions it points at (8 bytes each) into a flat program. A filter
// over the kernel's instruction cap is rejected.
func (g *dguest) readFilter(fprog uint64) ([]byte, lxErrno) {
	b, err := g.readMem(fprog, 16)
	if err != nil {
		return nil, lxEFAULT
	}
	n := int(rd16(b))
	ptr := le64(b[8:])
	if n == 0 || n > 4096 { // BPF_MAXINSNS
		return nil, lxEINVAL
	}
	prog, err := g.readMem(ptr, n*8)
	if err != nil {
		return nil, lxEFAULT
	}
	return append([]byte(nil), prog...), 0
}

// isRealSyscall reports whether nr is a syscall the guest issued, as opposed to
// one of the stub's internal pseudo-syscalls (fatal-signal, stop, vfork wait),
// which carry values far above the Linux syscall range and must not be filtered.
func isRealSyscall(nr uint64) bool { return nr < 0x10000 }
