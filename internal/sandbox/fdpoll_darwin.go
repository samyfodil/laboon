//go:build darwin

package sandbox

import (
	"time"

	"golang.org/x/sys/unix"
)

// Darwin's poll(2) does not support devices (a terminal reports POLLNVAL),
// so hostPoll waits on a throwaway kqueue, which does; a file kqueue cannot
// watch (a regular file, /dev/null) is always ready, as Linux reports it.

// hostPoll waits until one of reqs is ready or timeout passes (negative: no
// limit). always marks entries that are ready without asking the host. The
// kqueue also watches this thread's wake pipe, so a signal or the guest's
// teardown ends the wait at once.
func (g *dguest) hostPoll(reqs []pollReq, always []bool, timeout time.Duration, ready func([]pollRes) bool) ([]pollRes, lxErrno) {
	if ready == nil {
		ready = func(res []pollRes) bool {
			for _, r := range res {
				if r != (pollRes{}) {
					return true
				}
			}
			return false
		}
	}
	res := make([]pollRes, len(reqs))
	hot := false
	for i, r := range reqs {
		if always[i] {
			res[i] = pollRes{in: r.in, out: r.out}
			hot = hot || r.in || r.out
		}
	}
	if hot {
		timeout = 0
	}
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, hostErrno(err.(unix.Errno))
	}
	defer unix.Close(kq)
	type key struct {
		fd     int
		filter int16
	}
	byKey := map[key][]int{}
	var keys []key
	level := map[key]bool{}
	for i, r := range reqs {
		if always[i] {
			continue
		}
		add := func(fd int, filter int16, lvl bool) {
			k := key{fd, filter}
			if byKey[k] == nil {
				keys = append(keys, k)
			}
			byKey[k] = append(byKey[k], i)
			level[k] = level[k] || lvl
		}
		if r.wronly {
			// A pipe's write end is never readable and its gone reader is
			// POLLERR, asked for or not: the write filter's EOF.
			add(r.wfd, unix.EVFILT_WRITE, r.out)
			continue
		}
		if r.in || r.pri || r.hup {
			add(r.rfd, unix.EVFILT_READ, r.in || r.pri)
		}
		if r.xfd >= 0 && r.in {
			add(r.xfd, unix.EVFILT_READ, true)
		}
		if r.out {
			add(r.wfd, unix.EVFILT_WRITE, true)
		}
	}
	// A read filter that only watches for hangup is edge-triggered, so
	// pending data does not keep waking the wait.
	changes := make([]unix.Kevent_t, 0, len(keys))
	for _, k := range keys {
		flags := uint16(unix.EV_ADD | unix.EV_RECEIPT)
		if !level[k] {
			flags |= unix.EV_CLEAR
		}
		changes = append(changes, unix.Kevent_t{Ident: uint64(k.fd), Filter: k.filter, Flags: flags})
	}
	// A stream socket's hangup progresses in two steps on Darwin: the kqueue's
	// read filter reports EOF when one direction ends, but Linux reports a
	// hangup only once both do. EVFILT_SOCK, edge-triggered, wakes the wait
	// again when the second direction closes (or the peer resets), so the
	// hangup is noticed the moment it completes instead of on a re-query timer.
	// EVFILT_SOCK and its notes are macOS-private (xnu bsd/sys/event_private.h).
	const evfiltSock = -13
	const sockHangup = 0x1 | 0x2 | 0x4 | 0x1000 // CONNRESET|READCLOSED|WRITECLOSED|DISCONNECTED
	for i, r := range reqs {
		if always[i] || !r.sock {
			continue
		}
		changes = append(changes, unix.Kevent_t{
			Ident:  uint64(r.rfd),
			Filter: evfiltSock,
			Flags:  unix.EV_ADD | unix.EV_CLEAR | unix.EV_RECEIPT,
			Fflags: sockHangup,
		})
	}
	wt, wake, e := g.wakeFd()
	if e != 0 {
		return nil, e
	}
	defer wt.putWake()
	changes = append(changes, unix.Kevent_t{Ident: uint64(wake), Filter: unix.EVFILT_READ, Flags: unix.EV_ADD | unix.EV_RECEIPT})
	if len(changes) > 0 {
		out := make([]unix.Kevent_t, len(changes))
		n, err := unix.Kevent(kq, changes, out, nil)
		if err != nil {
			return nil, hostErrno(err.(unix.Errno))
		}
		for _, k := range out[:n] {
			if k.Flags&unix.EV_ERROR == 0 || k.Data == 0 {
				continue
			}
			// The host cannot watch this file: report it ready.
			for _, i := range byKey[key{int(k.Ident), k.Filter}] {
				if k.Filter == unix.EVFILT_READ && reqs[i].in {
					res[i].in, hot = true, true
				}
				if k.Filter == unix.EVFILT_WRITE && reqs[i].out {
					res[i].out, hot = true, true
				}
			}
		}
	}
	if hot {
		timeout = 0
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	kev := make([]unix.Kevent_t, max(len(changes), 1))
	// The first pass only collects what is ready: a signal already pending
	// (one the call's own mask unblocked) has no wake byte to end a wait. A
	// signal or teardown after the checks at the bottom writes the wake pipe.
	for first := true; ; first = false {
		var tsp *unix.Timespec
		if first || timeout >= 0 {
			wait := time.Duration(0)
			if !first {
				wait = max(time.Until(deadline), 0)
			}
			ts := unix.NsecToTimespec(int64(wait))
			tsp = &ts
		}
		n, err := unix.Kevent(kq, nil, kev, tsp)
		if err != nil && err != unix.EINTR {
			return nil, hostErrno(err.(unix.Errno))
		}
		for _, k := range kev[:max(n, 0)] {
			if int(k.Ident) == wake {
				drainWake(wake)
				continue
			}
			for _, i := range byKey[key{int(k.Ident), k.Filter}] {
				switch k.Filter {
				case unix.EVFILT_READ:
					eof := k.Flags&unix.EV_EOF != 0
					if reqs[i].in && !(eof && k.Data == 0 && reqs[i].fifo) {
						res[i].in = true
					}
					if eof {
						res[i].hup = true
					}
				case unix.EVFILT_WRITE:
					res[i].out = reqs[i].out
					if k.Flags&unix.EV_EOF != 0 {
						res[i].err = true
					}
				}
			}
		}
		if ready(res) || (timeout >= 0 && !time.Now().Before(deadline)) {
			return res, 0
		}
		if g.sigIntr() {
			return nil, errRestart
		}
		if g.ch.dead() {
			return nil, lxEINTR
		}
	}
}

// pollHangup reports a stream socket's hangup the way Linux's poll would, for
// when Darwin's host poll cannot say it directly (see sockPollState). ok is
// false when nothing need be synthesized.
func (g *dguest) pollHangup(d *dfile) (uint16, bool) {
	if st, ok := sockPollState(d, false); ok && st&lxPollHup != 0 {
		return st, true
	}
	return 0, false
}

// pollRevents maps one hostPoll answer to the guest revents for a request for
// events ev on d. A socket hangup is reinterpreted through sockPollState
// because Darwin and Linux disagree on when a stream socket has hung up.
func pollRevents(r pollRes, ev uint16, d *dfile) uint16 {
	if d != nil && d.pty != nil {
		return d.pty.pollState().mask & (ev | lxPollHup | lxPollErr)
	}
	if st, ok := ringPollState(d); ok {
		return st.mask & (ev | lxPollHup | lxPollErr)
	}
	var rev uint16
	if r.in {
		rev |= ev & (lxPollIn | lxPollRdnorm)
	}
	if r.out {
		rev |= ev & (lxPollOut | lxPollWrnorm)
	}
	if r.err && !(d.sk != nil && d.sk.virt) { // a vnet socket's stream ends where TCP has no error
		rev |= lxPollErr
	}
	if r.hup {
		if st, ok := sockPollState(d, true); ok {
			rev = st&(ev|lxPollHup) | rev&lxPollErr
		} else if d.sk != nil && !r.err {
			rev |= ev & (lxPollIn | lxPollRdnorm | lxPollRdhup)
		} else {
			rev |= lxPollHup | ev&lxPollRdhup
		}
	}
	return rev
}
