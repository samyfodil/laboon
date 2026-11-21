//go:build darwin || linux

package sandbox

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Guest stdio. The stub inherits the run's stdio as its own fds 0-2, and each
// guest process starts with fds 0-2 pointing at descriptions the supervisor
// also holds (a dup of the same host open file, so offsets and flags are
// shared). That makes them ordinary open files to epoll, poll, fstat and the
// tty ioctls. The hot path stays in the stub: while a guest fd 0-2 still refers
// to the original description in blocking mode, the stub reads and writes its
// own fd directly (stdio.zig), with no supervisor round trip. The slot's stdio
// word tells it which: bit i allows write/writev on fd i, bit 8+i read/readv.
//
// Reads from a terminal never take the stub path: the stub runs in its own
// process group, a background group to the terminal, and a background read
// from a terminal stops the reader (SIGTTIN). The supervisor, in the
// foreground group, reads it instead.

const (
	stdioWriteBits = 0
	stdioReadBits  = 8
)

// stdioFile wraps the stub's host stdio file f (as installed at fd n) as an
// open-file description: the supervisor's own dup of the same host open file.
func stdioFile(f *os.File, n int) *dfile {
	if f == nil {
		return &dfile{stub: -1}
	}
	src := hostFd(f)
	fd, err := unix.Dup(src)
	if err != nil {
		return &dfile{stub: -1}
	}
	unix.CloseOnExec(fd)
	name := f.Name()
	tty := isHostTTY(fd)
	gp := "pipe:"
	if tty {
		if p, err := hostTTYName(fd); err == nil {
			name = p
			gp = guestTTYName(p)
		}
	} else if fi, err := f.Stat(); err == nil && (fi.Mode().IsRegular() || fi.Mode()&os.ModeCharDevice != 0) {
		gp = "" // a file, or a device such as the /dev/null of discarded stdio
	}
	return &dfile{f: os.NewFile(uintptr(fd), name), gp: gp, stub: n, tty: tty}
}

// guestTTYName maps a host terminal path to the guest's name for it: a host
// pty slave /dev/ttysNNN is /dev/pts/N.
func guestTTYName(host string) string {
	if n, ok := hostPtsNum(host); ok {
		return fmt.Sprintf("/dev/pts/%d", n)
	}
	return host
}

// storeStdio publishes the slot's stdio word.
func (g *dguest) storeStdio(m uint64) { atomic.StoreUint64(&g.ch.page.stdio, m) }

// clearTraced drops any stub-visible traced marker on detach. The unix stub
// reads the traced bit from the stdio word, which stdioMask recomputes, so
// there is nothing to clear here; Windows carries it separately.
func (g *dguest) clearTraced() {}

func (g *dguest) stdioMask() uint64 {
	var m uint64
	if g.ps.cpus.Load() != hostCPUMask() || g.vcpu != 0 {
		m |= stdioAffinity
	}
	if g.traced.Load() {
		return m | stdioTraced
	}
	if g.ps.seccomp.Load() == secModeFilter {
		m |= stdioSeccomp
	}
	g.ft.mu.Lock()
	defer g.ft.mu.Unlock()
	for i := 0; i < 3; i++ {
		d := g.ft.fds[i]
		if d == nil || d.stub != i || d.nonblock.Load() {
			continue
		}
		m |= 1 << (stdioWriteBits + i)
		if !d.tty {
			m |= 1 << (stdioReadBits + i)
		}
	}
	return m
}

// stdioRead reads a stdio description through the supervisor's dup. That host
// fd is blocking and shared with whoever else holds the terminal or pipe, so
// O_NONBLOCK is emulated with a zero-timeout poll rather than set on the host,
// and a blocking read waits in slices so a torn-down guest does not leave this
// goroutine parked in the kernel.
//
// A regular file never waits. Neither does a blocking read of a terminal in
// non-canonical mode with VMIN 0: the host read applies VTIME itself.
func (g *dguest) stdioRead(d *dfile, bufAddr uint64, n int64) int64 {
	fd := hostFd(d.f)
	r, watch := pollReqOf(d)
	nonblock := d.nonblock.Load()
	if watch && d.tty && !nonblock {
		if t, err := unix.IoctlGetTermios(fd, ioctlGetTermios); err == nil && t.Lflag&unix.ICANON == 0 && t.Cc[unix.VMIN] == 0 {
			watch = false
		}
	}
	if watch {
		timeout := time.Duration(-1)
		if nonblock {
			timeout = 0
		}
		r.in = true
		res, e := g.hostPoll([]pollReq{r}, []bool{false}, timeout, nil)
		if e != 0 {
			return sErr(e)
		}
		if !res[0].in && !res[0].hup {
			return sErr(lxEAGAIN)
		}
	}
	buf := make([]byte, n)
	m, err := unix.Read(fd, buf)
	if err != nil {
		return sErr(osErrno(err))
	}
	if err := g.writeMem(bufAddr, buf[:m]); err != nil {
		return sErr(lxEFAULT)
	}
	return int64(m)
}

// ttyGuard restores the run's terminal settings when the guest leaves, as a
// shell would after a job that put the terminal in raw mode and died.
type ttyGuard struct {
	fd int
	t  *unix.Termios
}

func saveTTY(f *os.File) *ttyGuard {
	if f == nil {
		return nil
	}
	fd := hostFd(f)
	t, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil
	}
	return &ttyGuard{fd: fd, t: t}
}

// restore puts the saved settings back if the guest changed them. Only a
// foreground process may: from the background, tcsetattr stops the whole
// supervisor with SIGTTOU.
func (t *ttyGuard) restore() {
	cur, err := unix.IoctlGetTermios(t.fd, ioctlGetTermios)
	if err != nil || termiosEqual(cur, t.t) {
		return
	}
	fg, err := unix.IoctlGetInt(t.fd, unix.TIOCGPGRP)
	if err != nil || fg != unix.Getpgrp() {
		return
	}
	unix.IoctlSetTermios(t.fd, ioctlSetTermiosW, t.t)
}

// termiosEqual ignores PENDIN, which Darwin sets on its own.
func termiosEqual(a, b *unix.Termios) bool {
	x, y := *a, *b
	x.Lflag &^= unix.PENDIN
	y.Lflag &^= unix.PENDIN
	return x == y
}
