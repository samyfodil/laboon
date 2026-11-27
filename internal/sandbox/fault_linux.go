package sandbox

import (
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// faultPage is an inaccessible page: the host kernel faults copying from it,
// as Linux faults on a guest buffer that runs into memory it cannot read.
var faultPage = sync.OnceValue(func() []byte {
	b, err := unix.Mmap(-1, 0, int(pageSize), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		panic(err)
	}
	return b
})

// readPrefix reads as much of b from guest memory at addr as is readable:
// the bytes before the first page that is not, where a kernel copy from
// guest memory stops.
func (g *dguest) readPrefix(addr uint64, b []byte) int { return g.mp.readPrefix(addr, b) }

// writeFaulting writes buf to f followed by tail bytes that cannot be read,
// as the guest's buffer has them: one host writev whose last vector is the
// inaccessible page, so the host kernel stops where Linux stops on the
// guest's memory, keeping what a file got and dropping the page a pipe was
// filling. It blocks, unless nonblock, as writeIntr does, and returns what it
// wrote before the fault, or the fault.
func (g *dguest) writeFaulting(f *os.File, buf []byte, tail int, nonblock bool) (int, error) {
	done := 0
	for {
		if !nonblock && g.sigIntr() {
			if done > 0 {
				return done, nil
			}
			return 0, errSigIntr
		}
		iov := []unix.Iovec{{Base: &faultPage()[0], Len: uint64(tail)}}
		if rest := buf[done:]; len(rest) > 0 {
			iov = append([]unix.Iovec{{Base: &rest[0], Len: uint64(len(rest))}}, iov...)
		}
		n, _, en := unix.Syscall(unix.SYS_WRITEV, uintptr(hostFd(f)), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)))
		switch {
		case en == unix.EAGAIN && !nonblock:
			if err := g.sigWaitFd(hostFd(f), unix.POLLOUT); err != nil && err != errSigIntr {
				return done, err
			}
			continue
		case en != 0:
			if done > 0 {
				return done, nil
			}
			return 0, en
		}
		done += int(n)
		if int(n) == 0 || done >= len(buf) && nonblock {
			return done, nil
		}
	}
}

// readFaulting reads from f into buf followed by tail bytes the guest cannot
// write, as its buffer has them: one host readv whose last vector is the
// inaccessible page, so the host kernel stops where Linux stops on the
// guest's memory, leaving in a pipe or socket what did not fit and moving a
// file's offset past only what it read. It blocks, unless nonblock, as
// readIntr does.
func (g *dguest) readFaulting(f *os.File, buf []byte, tail int, nonblock bool) (int, error) {
	readv := func(fd int) (int, error) {
		iov := []unix.Iovec{{Base: &faultPage()[0], Len: uint64(tail)}}
		if len(buf) > 0 {
			iov = append([]unix.Iovec{{Base: &buf[0], Len: uint64(len(buf))}}, iov...)
		}
		n, _, en := unix.Syscall(unix.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)))
		if en != 0 {
			return 0, en
		}
		return int(n), nil
	}
	for {
		if !nonblock && g.sigIntr() {
			return 0, errSigIntr
		}
		n, err := readNonblockVia(f, readv, kindUnknown)
		if err != unix.EAGAIN || nonblock {
			return n, err
		}
		if err := g.sigWaitFd(hostFd(f), unix.POLLIN); err != nil && err != errSigIntr {
			return 0, err
		}
	}
}

// writableVecPrefix is how many of the first n bytes of the guest's iovecs v
// it can write from the start (writablePrefix).
func (g *dguest) writableVecPrefix(v [][2]uint64, n int) int {
	w := 0
	for _, x := range v {
		l := min(int(min(x[1], maxRW)), n-w)
		if l == 0 {
			continue
		}
		p := int(g.writablePrefix(x[0], uint64(l)))
		if w += p; p < l || w == n {
			break
		}
	}
	return w
}

// writablePrefix is how much of [addr, addr+n) the guest can write from its
// start, where a kernel copy into guest memory would fault: all of it when
// the supervisor's record of the guest's mappings says so, else what the
// host's mappings say, page by page.
func (g *dguest) writablePrefix(addr, n uint64) uint64 {
	if n == 0 {
		return 0
	}
	m := g.mp
	m.vmMu.RLock()
	ok := m.writable(addr, addr+n)
	m.vmMu.RUnlock()
	if ok {
		return n
	}
	es, ok := g.hostMaps()
	if !ok {
		return n
	}
	at := addr
	for _, e := range es {
		if e.hi <= at {
			continue
		}
		if e.lo > at || e.attr&2 == 0 {
			break
		}
		if at = e.hi; at >= addr+n {
			return n
		}
	}
	return at - addr
}
