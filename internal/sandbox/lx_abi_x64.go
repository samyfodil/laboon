//go:build (amd64 && (darwin || linux || windows)) || (darwin && arm64)

package sandbox

import "syscall"

// The x86-64 ABI.
const (
	x64EpollEventSize = 12 // struct epoll_event is packed
	x64SemdsCtime     = 64 // a padding word follows sem_otime and sem_ctime (asm/sembuf.h)
	x64SemdsNsems     = 80
	x64SemdsLen       = 104
	x64MmapRndBits    = 28
	x64Machine        = "x86_64"
)

var abiX64 = guestABI{
	x64:            true,
	machine:        x64Machine,
	auditArch:      0xC000003E, // AUDIT_ARCH_X86_64
	epollEventSize: x64EpollEventSize,
	semdsCtime:     x64SemdsCtime, semdsNsems: x64SemdsNsems, semdsLen: x64SemdsLen,
	mmapRndBits: x64MmapRndBits,
	stat:        statX64,
	// open and openat get this swap through toGeneric on their register
	// argument; openat2's flags come from a struct in guest memory.
	oflags: func(f uint64) uint64 { return swapOFlags(f, true) },
}

// statX64 is a Linux x86-64 struct stat.
func statX64(s *lxStat) []byte {
	var b [144]byte
	put64(b[0:], s.dev)
	put64(b[8:], s.ino)
	put64(b[16:], uint64(s.nlink))
	put32(b[24:], s.mode)
	put32(b[28:], s.uid)
	put32(b[32:], s.gid)
	put64(b[40:], s.rdev)
	put64(b[48:], uint64(s.size))
	put64(b[56:], uint64(s.blksize))
	put64(b[64:], uint64(s.blocks))
	for i, t := range []syscall.Timespec{s.atime, s.mtime, s.ctime} {
		put64(b[72+16*i:], uint64(t.Sec))
		put64(b[80+16*i:], uint64(t.Nsec))
	}
	return b[:]
}
