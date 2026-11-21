package stub

import (
	"debug/elf"
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

const (
	retKill  = 0x80000000
	retAllow = 0x7fff0000

	auditX86_64  = 0xc000003e
	auditAArch64 = 0xc00000b7

	forkFlags   = 0x8000 | 17 // CLONE_PARENT|SIGCHLD
	threadFlags = 0x210f00    // CLONE_VM|FS|FILES|SIGHAND|THREAD|CHILD_CLEARTID
	sigURG      = 23
	xferFd      = 5 // XFER in zig/stub.zig
)

type filterArch struct {
	bin          string
	audit, wrong uint32
	clone        uint32
	tgkill       uint32
	recvmsg      uint32
	close        uint32
	seccomp      uint32
	allowed      []uint32
	// guest is what a guest thread may call besides clone, tgkill and the
	// stdio read, write and writev; stdio are those three.
	guest []uint32
	stdio []uint32
}

var filterArches = []filterArch{
	{
		bin: "stub-amd64.bin", audit: auditX86_64, wrong: auditAArch64,
		clone: 56, tgkill: 234, recvmsg: 47, close: 3, seccomp: 317,
		// read write writev mmap mprotect munmap mremap madvise getpid gettid
		// futex rt_sigreturn rt_sigprocmask arch_prctl exit exit_group sigaltstack
		// msync mincore clock_gettime clock_getres gettimeofday getrusage getcpu
		// rseq restart_syscall membarrier set_tid_address
		allowed: []uint32{0, 1, 20, 9, 10, 11, 25, 28, 39, 186, 202, 15, 14, 158, 60, 231, 131,
			26, 27, 228, 229, 96, 98, 309, 334, 219, 324, 218},
		// getpid gettid futex rt_sigreturn rt_sigprocmask arch_prctl exit
		// exit_group sigaltstack clock_gettime clock_getres gettimeofday
		// getrusage getcpu rseq restart_syscall
		guest: []uint32{39, 186, 202, 15, 14, 158, 60, 231, 131, 228, 229, 96, 98, 309, 334, 219},
		stdio: []uint32{0, 1, 20},
	},
	{
		bin: "stub-arm64.bin", audit: auditAArch64, wrong: auditX86_64,
		clone: 220, tgkill: 131, recvmsg: 212, close: 57, seccomp: 277,
		// read write writev mmap mprotect munmap mremap madvise getpid gettid
		// futex rt_sigreturn rt_sigprocmask exit exit_group sigaltstack
		// msync mincore clock_gettime clock_getres gettimeofday getrusage getcpu
		// rseq restart_syscall membarrier set_tid_address
		allowed: []uint32{63, 64, 66, 222, 226, 215, 216, 233, 172, 178, 98, 139, 135, 93, 94, 132,
			227, 232, 113, 114, 169, 165, 168, 293, 128, 283, 96},
		// getpid gettid futex rt_sigreturn rt_sigprocmask exit exit_group
		// sigaltstack clock_gettime clock_getres gettimeofday getrusage getcpu
		// rseq restart_syscall
		guest: []uint32{172, 178, 98, 139, 135, 93, 94, 132, 113, 114, 169, 165, 168, 293, 128},
		stdio: []uint32{63, 64, 66},
	},
}

// selfPid is the pid the loaded guest policy names as its own, in place of
// the SELF_PID mark the stub fills in with its process's when it loads it.
const (
	selfPidMark = 0xffff_fff0
	selfPid     = 1234
)

// loadFilter reads a policy the stub installs behind its text-range check,
// lc_seccomp_filter or lc_seccomp_guest_filter, from a built stub, as loaded
// by process selfPid.
func loadFilter(t *testing.T, bin, name string) *bpf.VM {
	f, err := elf.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for _, s := range syms {
		if s.Name != name {
			continue
		}
		sec := f.Sections[s.Section]
		data, err := sec.Data()
		if err != nil {
			t.Fatal(err)
		}
		off := s.Value - sec.Addr
		raw = data[off : off+s.Size]
	}
	if len(raw) == 0 || len(raw)%8 != 0 {
		t.Fatalf("%s: %s missing or malformed (%d bytes)", bin, name, len(raw))
	}
	var prog []bpf.Instruction
	for i := 0; i < len(raw); i += 8 {
		raw := bpf.RawInstruction{
			Op: binary.LittleEndian.Uint16(raw[i:]),
			Jt: raw[i+2],
			Jf: raw[i+3],
			K:  binary.LittleEndian.Uint32(raw[i+4:]),
		}
		if raw.Op == 0x15 && raw.K == selfPidMark { // BPF_JMP|BPF_JEQ|BPF_K
			raw.K = selfPid
		}
		ins := raw.Disassemble()
		// The VM below reads words big-endian, so seccomp_data is encoded
		// word by word to match; only aligned word loads keep that faithful.
		if ld, ok := ins.(bpf.LoadAbsolute); ok && (ld.Size != 4 || ld.Off%4 != 0) {
			t.Fatalf("%s: instruction %d: %v", bin, i/8, ins)
		}
		if _, ok := ins.(bpf.RawInstruction); ok {
			t.Fatalf("%s: instruction %d does not decode", bin, i/8)
		}
		prog = append(prog, ins)
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatalf("%s: %v", bin, err)
	}
	return vm
}

// seccompData encodes struct seccomp_data (instruction_pointer left 0) as the
// kernel's little-endian words, each stored big-endian for the VM.
func seccompData(audit, nr uint32, args ...uint64) []byte {
	words := make([]uint32, 16)
	words[0], words[1] = nr, audit
	for i, a := range args {
		words[4+2*i] = uint32(a)
		words[5+2*i] = uint32(a >> 32)
	}
	b := make([]byte, 64)
	for i, w := range words {
		binary.BigEndian.PutUint32(b[4*i:], w)
	}
	return b
}

// checker runs a policy on one syscall and compares the action.
func checker(t *testing.T, vm *bpf.VM) func(want uint32, what string, audit, nr uint32, args ...uint64) {
	return func(want uint32, what string, audit, nr uint32, args ...uint64) {
		t.Helper()
		r, err := vm.Run(seccompData(audit, nr, args...))
		if err != nil {
			t.Fatal(err)
		}
		if got := uint32(r); got != want {
			t.Errorf("%s (nr %d, args %#x): got %#x, want %#x", what, nr, args, got, want)
		}
	}
}

func TestSeccompFilter(t *testing.T) {
	for _, a := range filterArches {
		t.Run(a.bin, func(t *testing.T) {
			check := checker(t, loadFilter(t, a.bin, "lc_seccomp_filter"))

			allowed := map[uint32]bool{a.clone: true, a.tgkill: true, a.recvmsg: true, a.close: true}
			for _, n := range a.allowed {
				allowed[n] = true
			}
			for n := uint32(0); n < 1024; n++ {
				want := uint32(retKill)
				if allowed[n] {
					want = retAllow
				}
				var args []uint64
				switch n {
				case a.clone:
					args = []uint64{forkFlags}
				case a.tgkill:
					args = []uint64{1, 1, sigURG}
				case a.recvmsg:
					args = []uint64{xferFd}
				case a.close:
					args = []uint64{xferFd + 1}
				default:
					args = []uint64{^uint64(0), 1 << 40, 7, 9, 0, 3}
				}
				check(want, "syscall", a.audit, n, args...)
				check(retKill, "foreign arch", a.wrong, n, args...)
			}

			check(retAllow, "fork", a.audit, a.clone, forkFlags)
			check(retAllow, "thread", a.audit, a.clone, threadFlags, 0x7fff0000, 0, 0, 0)
			for _, flags := range []uint64{
				0,
				forkFlags | 0x10000000,              // CLONE_NEWUSER
				forkFlags | 0x00020000,              // CLONE_NEWNS
				forkFlags | 0x20000000,              // CLONE_NEWPID
				threadFlags | 0x00080000,            // CLONE_SETTLS
				threadFlags &^ 0x00010000,           // no CLONE_THREAD
				threadFlags &^ 0x00200000,           // no CLONE_CHILD_CLEARTID
				0x00004000 | 0x00000100 | forkFlags, // CLONE_VFORK|CLONE_VM
				forkFlags | 1<<32,
				threadFlags | 1<<63,
				9, // SIGKILL as exit signal
			} {
				check(retKill, "clone", a.audit, a.clone, flags)
			}

			check(retAllow, "recvmsg", a.audit, a.recvmsg, xferFd, 0x7fff0000, 0x40000000)
			for _, fd := range []uint64{0, 1, 3, 4, 6, xferFd | 1<<32} {
				check(retKill, "recvmsg", a.audit, a.recvmsg, fd)
			}
			check(retAllow, "close", a.audit, a.close, 3)
			check(retAllow, "close", a.audit, a.close, 6)
			check(retAllow, "close", a.audit, a.close, 1000)
			for _, fd := range []uint64{0, 1, 2, 4, xferFd, 6 | 1<<32, 3 | 1<<32, ^uint64(0)} {
				check(retKill, "close", a.audit, a.close, fd)
			}

			check(retAllow, "kick", a.audit, a.tgkill, 1234, 5678, sigURG)
			for _, sig := range []uint64{0, 1, 9, 10, 15, 17, 19, sigURG | 1<<32, 1 << 32} {
				check(retKill, "tgkill", a.audit, a.tgkill, 1234, 5678, sig)
			}

			// A filter for the calling thread only: never another mode, and
			// never TSYNC, which would put it on every thread.
			check(retAllow, "seccomp", a.audit, a.seccomp, 1, 0, 0x7fff0000)
			for _, args := range [][]uint64{{0, 0}, {2, 0}, {3, 0}, {1, 1}, {1, 8}, {1 | 1<<32, 0}, {1, 1 << 32}} {
				check(retKill, "seccomp", a.audit, a.seccomp, args...)
			}
		})
	}
}

// TestSeccompGuestFilter checks what a guest thread may call: nothing that
// maps memory, holds a descriptor or forks, which it could otherwise reach by
// branching into the stub's own syscall instructions.
func TestSeccompGuestFilter(t *testing.T) {
	for _, a := range filterArches {
		t.Run(a.bin, func(t *testing.T) {
			check := checker(t, loadFilter(t, a.bin, "lc_seccomp_guest_filter"))
			allowed := map[uint32]bool{}
			for _, n := range a.guest {
				allowed[n] = true
			}
			pinned := map[uint32]bool{a.clone: true, a.tgkill: true}
			for _, n := range a.stdio {
				pinned[n] = true
			}
			for n := uint32(0); n < 1024; n++ {
				if pinned[n] {
					continue
				}
				want := uint32(retKill)
				if allowed[n] {
					want = retAllow
				}
				args := []uint64{^uint64(0), 1 << 40, 7, 9, 0, 3}
				check(want, "syscall", a.audit, n, args...)
				check(retKill, "foreign arch", a.wrong, n, args...)
			}

			check(retAllow, "thread", a.audit, a.clone, threadFlags, 0x7fff0000, 0, 0, 0)
			for _, flags := range []uint64{forkFlags, 0, threadFlags | 1<<32, threadFlags &^ 0x00010000} {
				check(retKill, "clone", a.audit, a.clone, flags)
			}
			check(retAllow, "kick", a.audit, a.tgkill, selfPid, 5678, sigURG)
			check(retKill, "tgkill", a.audit, a.tgkill, selfPid, 5678, 9)
			for _, pid := range []uint64{selfPid + 1, 1, selfPidMark, selfPid | 1<<32, ^uint64(0)} {
				check(retKill, "kick another process", a.audit, a.tgkill, pid, 5678, sigURG)
			}
			for _, n := range a.stdio {
				for _, fd := range []uint64{0, 1, 2} {
					check(retAllow, "stdio", a.audit, n, fd, 0x7fff0000, 8)
				}
				for _, fd := range []uint64{3, xferFd, 4, ^uint64(0), 1 << 32} {
					check(retKill, "stdio", a.audit, n, fd, 0x7fff0000, 8)
				}
			}
			for _, n := range []uint32{a.recvmsg, a.close, a.seccomp} {
				check(retKill, "base only", a.audit, n, xferFd, 0, 0)
			}
		})
	}
}
