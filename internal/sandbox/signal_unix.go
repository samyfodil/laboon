//go:build darwin || linux

package sandbox

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// wakeFd is the read end of this thread's wake pipe, which every signal sent
// to it and its teardown make readable, for a kqueue or poll wait to include;
// the wait gives it back with putWake on the returned thread. Without one
// nothing could end such a wait: a retiring thread gets EINTR, a pipe that
// cannot be made EMFILE.
func (g *dguest) wakeFd() (*sigThread, int, lxErrno) {
	t := g.sigs().thread(g.pid)
	if t == nil {
		return nil, -1, lxEINTR
	}
	fd, e := t.wakeFd()
	return t, fd, e
}

// waitMs is the poll timeout, in whole milliseconds rounded up, that ends at
// deadline; -1 (no limit) for a zero deadline.
func waitMs(deadline time.Time) int {
	if deadline.IsZero() {
		return -1
	}
	return int(max(time.Until(deadline)+time.Millisecond-1, 0) / time.Millisecond)
}

// drainWake empties the wake pipe read end fd.
func drainWake(fd int) {
	var b [64]byte
	for {
		if n, _ := unix.Read(fd, b[:]); n < len(b) {
			return
		}
	}
}

// wakeFd takes t's wake pipe for a wait, making it on first use. A retired
// thread's teardown (closeWake) closes the pipe only once no wait holds it:
// a wait must never poll a descriptor closed under it, which by then may be
// another file's.
func (t *sigThread) wakeFd() (int, lxErrno) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.retired {
		return -1, lxEINTR
	}
	if t.wr < 0 {
		var p [2]int
		if err := unix.Pipe(p[:]); err != nil {
			return -1, lxEMFILE
		}
		for _, fd := range p {
			unix.SetNonblock(fd, true)
			unix.CloseOnExec(fd)
		}
		t.wr, t.ww = p[0], p[1]
	}
	t.waits++
	return t.wr, 0
}

// putWake gives back the pipe a wait took with wakeFd.
func (t *sigThread) putWake() {
	t.mu.Lock()
	t.waits--
	if t.retired && t.waits == 0 {
		t.closePipe()
	}
	t.mu.Unlock()
}

// closeWake retires t's wake pipe. A wait still holding it is woken and the
// last one closes it.
func (t *sigThread) closeWake() {
	t.mu.Lock()
	t.retired = true
	if t.waits > 0 {
		unix.Write(t.ww, []byte{0})
	} else {
		t.closePipe()
	}
	t.mu.Unlock()
}

func (t *sigThread) closePipe() {
	if t.wr >= 0 {
		unix.Close(t.wr)
		unix.Close(t.ww)
		t.wr, t.ww = -1, -1
	}
	if t.wep >= 0 {
		unix.Close(t.wep)
		t.wep, t.wepOn = -1, nil
	}
}

// sigWaitFd blocks until fd is ready for events, or returns errSigIntr when a
// signal for this thread arrives first or the guest is torn down: both write
// the thread's wake pipe (sr.wake), which stays readable until drained, so
// one that comes after the check below still ends the poll.
func (g *dguest) sigWaitFd(fd int, events int16) error {
	t := g.sigs().thread(g.pid)
	if t == nil {
		return errSigIntr // the thread is being retired
	}
	wr, e := t.wakeFd()
	if e == lxEINTR {
		return errSigIntr
	} else if e != 0 {
		return unix.EMFILE
	}
	defer t.putWake()
	var drain [64]byte
	for {
		if g.sigIntr() || g.ch.dead() {
			return errSigIntr
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: events}, {Fd: int32(wr), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, -1); err != nil && err != unix.EINTR {
			return err
		}
		if fds[1].Revents != 0 {
			unix.Read(wr, drain[:])
		}
		if fds[0].Revents != 0 {
			return nil
		}
	}
}

// forward relays the supervisor's own SIGINT/SIGQUIT/SIGWINCH (terminal
// signals, which on Linux reach the whole foreground process group) to every
// guest process, and SIGTERM/SIGHUP to the main one, until the returned stop
// is called.
func (sr *sigRun) forward() func() {
	c := make(chan os.Signal, 16)
	signal.Notify(c, unix.SIGINT, unix.SIGQUIT, unix.SIGWINCH, unix.SIGTERM, unix.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-c:
				sr.forwardHost(s.(syscall.Signal))
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(c)
		close(done)
	}
}

func (sr *sigRun) forwardHost(s syscall.Signal) {
	all := true
	var sig int
	si := sigInfo{code: siKernel}
	switch s {
	case unix.SIGINT:
		sig = sigINT
	case unix.SIGQUIT:
		sig = sigQUIT
	case unix.SIGWINCH:
		sig = sigWINCH
	case unix.SIGTERM:
		sig, all, si.code = sigTERM, false, siUser
	case unix.SIGHUP:
		sig, all, si.code = sigHUP, false, siUser
	default:
		return
	}
	var ps []*sigProc
	sr.mu.Lock()
	for _, p := range sr.procs {
		if all || p.tgid == 1 {
			ps = append(ps, p)
		}
	}
	sr.mu.Unlock()
	for _, p := range ps {
		sr.send(p, nil, sig, si, nil)
	}
}

// wakeWrite makes t's wake pipe readable, if it has one.
func (t *sigThread) wakeWrite() {
	t.mu.Lock()
	if t.ww >= 0 {
		unix.Write(t.ww, []byte{0})
	}
	t.mu.Unlock()
}

// hostInterruptibleRead performs the blocking read inside readIntr: a
// non-blocking read, and while there is nothing to read a wait on the file
// and this thread's own wake pipe. A signal ends the wait as a deadline
// would, for readIntr to see it. A deadline on the file itself would not do:
// several threads (of several processes) can block on one pipe, and the
// first to wake would clear the deadline set for the others.
// hostInterruptibleWrite is the write counterpart of hostInterruptibleRead: a
// non-blocking write, and while the pipe is full a wait on the file (POLLOUT)
// and this thread's wake pipe, which a signal ends. It polls rather than
// relying on a blocking f.Write so a full pipe blocks the same way on every
// host — a non-blocking fd's f.Write surfaces EAGAIN on macOS instead of
// waiting — and so the wait is interruptible.
func (g *dguest) hostInterruptibleWrite(f *os.File, buf []byte) (int, error) {
	for {
		n, err := writeNonblock(f, buf)
		if err != unix.EAGAIN {
			return n, err
		}
		if err := g.sigWaitFd(hostFd(f), unix.POLLOUT); err == errSigIntr {
			return 0, os.ErrDeadlineExceeded
		} else if err != nil {
			return 0, err
		}
	}
}

func (g *dguest) hostInterruptibleRead(f *os.File, buf []byte, k readKind) (int, error) {
	for {
		n, err := readNonblockKind(f, buf, k)
		if err != unix.EAGAIN {
			return n, err
		}
		if err := g.sigWaitFd(hostFd(f), unix.POLLIN); err == errSigIntr {
			return 0, os.ErrDeadlineExceeded
		} else if err != nil {
			return 0, err
		}
	}
}
