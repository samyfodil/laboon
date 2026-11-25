//go:build darwin || linux || windows

package sandbox

import "syscall"

// guestABI is what the shared layer does differently per guest architecture.
// It is the guest's, not the supervisor's build architecture: on macOS a
// native arm64 supervisor hosts x86-64 guests (in the x86-64 stub, under
// Rosetta), so g.abi is the guest's own.
type guestABI struct {
	x64            bool
	machine        string // uname's machine
	auditArch      uint32 // AUDIT_ARCH, which a seccomp filter checks before trusting syscall numbers
	epollEventSize int    // sizeof(struct epoll_event)
	// struct semid64_ds: the offsets of sem_ctime and sem_nsems, and its size
	semdsCtime, semdsNsems, semdsLen int
	mmapRndBits                      uint64 // the kernel's default vm.mmap_rnd_bits
	stat                             func(*lxStat) []byte
	oflags                           func(uint64) uint64 // open flags to the shared table's generic values
}

// The arm64 (asm-generic) ABI.
const (
	a64EpollEventSize = 16 // its u64 data is aligned
	a64SemdsCtime     = 56 // sem_otime, sem_ctime, sem_nsems after the 48-byte ipc64_perm, then two unused words
	a64SemdsNsems     = 64
	a64SemdsLen       = 88
	a64MmapRndBits    = 18
	a64Machine        = "aarch64"
)

var abiA64 = guestABI{
	machine:        a64Machine,
	auditArch:      0xC00000B7, // AUDIT_ARCH_AARCH64
	epollEventSize: a64EpollEventSize,
	semdsCtime:     a64SemdsCtime, semdsNsems: a64SemdsNsems, semdsLen: a64SemdsLen,
	mmapRndBits: a64MmapRndBits,
	stat:        statA64,
	oflags:      func(f uint64) uint64 { return f },
}

// statA64 is a Linux arm64 (asm-generic) struct stat.
func statA64(s *lxStat) []byte {
	var b [128]byte
	put64(b[0:], s.dev)
	put64(b[8:], s.ino)
	put32(b[16:], s.mode)
	put32(b[20:], s.nlink)
	put32(b[24:], s.uid)
	put32(b[28:], s.gid)
	put64(b[32:], s.rdev)
	put64(b[48:], uint64(s.size))
	put32(b[56:], s.blksize)
	put64(b[64:], uint64(s.blocks))
	for i, t := range []syscall.Timespec{s.atime, s.mtime, s.ctime} {
		put64(b[72+16*i:], uint64(t.Sec))
		put64(b[80+16*i:], uint64(t.Nsec))
	}
	return b[:]
}
