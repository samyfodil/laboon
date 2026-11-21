//go:build darwin || linux

package sandbox

import (
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

// ppoll and pselect6 over the host fds behind the guest's open files. Darwin's
// poll(2) does not support devices (a terminal reports POLLNVAL), so the wait
// is a throwaway kqueue, which does; a file kqueue cannot watch (a regular
// file, /dev/null) is always ready, as Linux reports it.

// pollReq is one readiness question about a host fd pair; pollRes the answer.
// pollReq is one fd to wait on. hup also watches for hangup when in is
// unset (poll always reports it); fifo marks a pipe or terminal, which at
// hangup with nothing left to read is not readable; wronly a pipe's write
// end, which never hangs up (a gone reader is POLLERR, from the write side).
// pri and rdhup are the guest's requests for priority data and peer
// read-shutdown: Linux watches and reports them distinctly, Darwin folds pri
// into readability and synthesizes hangup from socket state (fdpoll_darwin.go).
// sock marks a stream socket: Darwin watches it with EVFILT_SOCK so a wait
// wakes the moment it finishes hanging up, instead of re-querying on a timer.
type pollReq struct {
	rfd, wfd   int
	xfd        int // a second fd readable data comes on, or -1: a socket's side of the run's own loopback (vlo_unix.go)
	in, out    bool
	pri, rdhup bool
	hup        bool
	fifo       bool
	wronly     bool
	sock       bool
}

type pollRes struct{ in, out, pri, rdhup, hup, err bool }

// pollReqOf maps an open-file description to the host fds that carry its
// readiness. ok is false for one with nothing to watch (always ready).
func pollReqOf(d *dfile) (pollReq, bool) {
	if d.f == nil {
		return pollReq{}, false
	}
	rfd, wfd := kqFds(d)
	r := pollReq{rfd: rfd, wfd: wfd, xfd: vloFd(d)}
	if _, ring := ringOf(d); d.ep == nil && d.ev == nil && d.tfd == nil && d.pty == nil && !ring {
		var st unix.Stat_t
		if unix.Fstat(rfd, &st) == nil {
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFREG, unix.S_IFDIR:
				return pollReq{}, false
			case unix.S_IFIFO, unix.S_IFCHR:
				r.fifo = true
				fl, err := unix.FcntlInt(uintptr(rfd), unix.F_GETFL, 0)
				r.wronly = err == nil && fl&unix.O_ACCMODE == unix.O_WRONLY
			}
		}
	}
	r.sock = d.sk != nil && d.sk.typ == lxSockStream
	return r, true
}

func (g *dguest) ppoll(fdsAddr, nfds, tmo uint64) int64 {
	timeout, e := g.timeoutAt(tmo)
	if e != 0 {
		return sErr(e)
	}
	return g.pollFor(fdsAddr, nfds, timeout, tmo)
}

// pollFor is ppoll with its timeout read: the time left goes back to the
// timespec at tmo, if any.
func (g *dguest) pollFor(fdsAddr, nfds uint64, timeout time.Duration, tmo uint64) int64 {
	if nfds > 1<<16 {
		return sErr(lxEINVAL)
	}
	start := time.Now()
	var b []byte
	if nfds > 0 {
		var err error
		if b, err = g.argRead(fdsAddr, int(8*nfds)); err != nil {
			return sErr(lxEFAULT)
		}
	}
	reqs := make([]pollReq, nfds)
	always := make([]bool, nfds)
	skip := make([]bool, nfds)
	ds := make([]*dfile, nfds)
	synth := make([]uint16, nfds)
	var nval []int
	for i := range reqs {
		fd := int32(le32(b[8*i:]))
		ev := uint16(b[8*i+4]) | uint16(b[8*i+5])<<8
		b[8*i+6], b[8*i+7] = 0, 0
		if fd < 0 {
			skip[i], always[i] = true, true
			continue
		}
		d, ok := g.ft.get(int(fd))
		if !ok {
			nval = append(nval, i)
			skip[i], always[i] = true, true
			continue
		}
		r, watch := pollReqOf(d)
		r.in = ev&(lxPollIn|lxPollRdnorm) != 0
		r.pri = ev&lxPollPri != 0
		r.rdhup = ev&lxPollRdhup != 0
		r.out = ev&(lxPollOut|lxPollWrnorm) != 0
		r.hup = true
		if d.tfd != nil {
			r.out = false
		}
		reqs[i], always[i], ds[i] = r, !watch, d
		if st, ok := g.pollHangup(d); ok {
			synth[i], always[i] = st&(ev|lxPollHup), true
		}
	}
	if len(nval) > 0 || slices.ContainsFunc(synth, func(v uint16) bool { return v != 0 }) {
		timeout = 0
	}
	// A host readiness that maps to nothing the guest asked for (a half-closed
	// socket polled for events it cannot report yet) must not end the wait, so
	// readiness is the guest-visible mapping, not any host event. hostPoll
	// blocks on one kqueue until that holds, the timeout passes, or a signal
	// or teardown arrives; on Darwin an EVFILT_SOCK watch wakes it the moment
	// such a socket finishes hanging up, so there is no timed re-query.
	ready := func(res []pollRes) bool {
		for i := range reqs {
			if skip[i] {
				continue
			}
			if synth[i] != 0 {
				return true
			}
			ev := uint16(b[8*i+4]) | uint16(b[8*i+5])<<8
			if pollRevents(res[i], ev, ds[i]) != 0 {
				return true
			}
		}
		return false
	}
	res, e := g.hostPoll(reqs, always, timeout, ready)
	if e == errRestart {
		e = errRestartNoHand
	}
	if e != 0 {
		return sErr(e)
	}
	for i := range reqs {
		var rev uint16
		if synth[i] != 0 {
			rev = synth[i]
		} else if !skip[i] {
			ev := uint16(b[8*i+4]) | uint16(b[8*i+5])<<8
			rev = pollRevents(res[i], ev, ds[i])
		}
		b[8*i+6], b[8*i+7] = byte(rev), byte(rev>>8)
	}
	for _, i := range nval {
		b[8*i+6] = lxPollNval
	}
	count := 0
	for i := range reqs {
		if b[8*i+6] != 0 || b[8*i+7] != 0 {
			count++
		}
	}
	if nfds > 0 {
		if err := g.putOut(fdsAddr, b); err != nil {
			return sErr(lxEFAULT)
		}
	}
	g.writeRemaining(tmo, timeout, start)
	return int64(count)
}

// pollRevents (fdpoll_linux.go, fdpoll_darwin.go) maps one hostPoll answer to
// the guest revents for a request for events ev on d. pollHangup lets Darwin
// report a stream socket's hangup that its host poll cannot; on Linux the
// kernel's revents are authoritative, so it reports none.

func (g *dguest) pselect6(nfds int64, rAddr, wAddr, xAddr, tmo uint64) int64 {
	timeout, e := g.timeoutAt(tmo)
	if e != 0 {
		return sErr(e)
	}
	return g.selectFor(nfds, rAddr, wAddr, xAddr, timeout, tmo)
}

// selectFor is pselect6 with its timeout read: the time left goes back to the
// timespec at tmo, if any.
func (g *dguest) selectFor(nfds int64, rAddr, wAddr, xAddr uint64, timeout time.Duration, tmo uint64) int64 {
	if nfds < 0 || nfds > 1<<16 {
		return sErr(lxEINVAL)
	}
	start := time.Now()
	words := int((nfds + 63) / 64)
	sets := [3][]byte{}
	for i, addr := range []uint64{rAddr, wAddr, xAddr} {
		if addr == 0 || words == 0 {
			continue
		}
		b, err := g.argRead(addr, 8*words)
		if err != nil {
			return sErr(lxEFAULT)
		}
		sets[i] = b
	}
	isSet := func(s []byte, fd int) bool { return s != nil && s[fd/8]&(1<<(fd%8)) != 0 }
	var reqs []pollReq
	var always []bool
	var fds []int
	var ds []*dfile
	var synth []uint16
	for fd := 0; fd < int(nfds); fd++ {
		in, out := isSet(sets[0], fd), isSet(sets[1], fd)
		if !in && !out && !isSet(sets[2], fd) {
			continue
		}
		d, ok := g.ft.get(fd)
		if !ok {
			return sErr(lxEBADF)
		}
		r, watch := pollReqOf(d)
		r.in, r.out = in, out && d.tfd == nil
		var st uint16
		if s, ok := g.pollHangup(d); ok {
			st, watch = s, false
		}
		reqs = append(reqs, r)
		always = append(always, !watch)
		fds = append(fds, fd)
		ds = append(ds, d)
		synth = append(synth, st)
		if st != 0 {
			timeout = 0
		}
	}
	res, e := g.hostPoll(reqs, always, timeout, nil)
	if e == errRestart {
		e = errRestartNoHand
	}
	if e != 0 {
		return sErr(e)
	}
	for _, s := range sets {
		clear(s)
	}
	count := 0
	mark := func(s []byte, fd int) {
		if s != nil {
			s[fd/8] |= 1 << (fd % 8)
			count++
		}
	}
	for i, fd := range fds {
		if synth[i] != 0 {
			res[i] = pollRes{in: true, out: synth[i]&lxPollOut != 0}
		}
		if st, ok := ringPollState(ds[i]); ok {
			m := st.mask
			res[i] = pollRes{in: m&lxPollIn != 0, out: m&lxPollOut != 0, hup: m&lxPollHup != 0, err: m&lxPollErr != 0}
		}
		// select counts an error (a pipe's write end without readers) as
		// readable and writable, as Linux does.
		if reqs[i].in && (res[i].in || res[i].hup || res[i].err) {
			mark(sets[0], fd)
		}
		if reqs[i].out && (res[i].out || res[i].err) {
			mark(sets[1], fd)
		}
	}
	for i, addr := range []uint64{rAddr, wAddr, xAddr} {
		if sets[i] != nil {
			if err := g.putOut(addr, sets[i]); err != nil {
				return sErr(lxEFAULT)
			}
		}
	}
	g.writeRemaining(tmo, timeout, start)
	return int64(count)
}

// kqFds returns the host fds a kqueue watches for d's read and write
// readiness. An eventfd's readiness lives on its pipe: read end for IN, write
// end for OUT; a terminal's on its side's two pipes (tty_unix.go).
func kqFds(d *dfile) (rfd, wfd int) {
	if d.ev != nil {
		return hostFd(d.f), hostFd(d.ev.w)
	}
	if d.pty != nil {
		return hostFd(d.f), d.pty.readyOut()
	}
	if r, w, ok := ringFds(d); ok {
		return r, w
	}
	fd := hostFd(d.f)
	return fd, fd
}
