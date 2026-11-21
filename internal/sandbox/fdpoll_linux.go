package sandbox

import (
	"time"

	"golang.org/x/sys/unix"
)

// hostPoll waits until one of reqs is ready or timeout passes (negative: no
// limit). always marks entries that are ready without asking the host. The
// poll also watches this thread's wake pipe, so a signal or the guest's
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
	var fds []unix.PollFd
	var of []int // the request each pollfd asks about
	for i, r := range reqs {
		if always[i] {
			res[i] = pollRes{in: r.in, out: r.out}
			hot = hot || r.in || r.out
			continue
		}
		var ev int16
		if r.in {
			ev |= unix.POLLIN
		}
		if r.pri {
			ev |= unix.POLLPRI
		}
		if r.rdhup {
			ev |= unix.POLLRDHUP
		}
		if ev != 0 || (r.hup && !r.wronly) {
			fds = append(fds, unix.PollFd{Fd: int32(r.rfd), Events: ev})
			of = append(of, i)
		}
		if r.xfd >= 0 && r.in {
			fds = append(fds, unix.PollFd{Fd: int32(r.xfd), Events: unix.POLLIN})
			of = append(of, i)
		}
		if r.out {
			fds = append(fds, unix.PollFd{Fd: int32(r.wfd), Events: unix.POLLOUT})
			of = append(of, i)
		}
	}
	nreq := len(fds)
	wt, wake, e := g.wakeFd()
	if e != 0 {
		return nil, e
	}
	defer wt.putWake()
	fds = append(fds, unix.PollFd{Fd: int32(wake), Events: unix.POLLIN})
	if hot {
		timeout = 0
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	// The first pass only collects what is ready: a signal already pending
	// (one the call's own mask unblocked) has no wake byte to end a wait. A
	// signal or teardown after the checks at the bottom writes the wake pipe.
	for first := true; ; first = false {
		ms := waitMs(deadline)
		if first {
			ms = 0
		}
		n, err := unix.Poll(fds, ms)
		if err != nil && err != unix.EINTR {
			return nil, hostErrno(err.(unix.Errno))
		}
		if n > 0 {
			for k, p := range fds[:nreq] {
				i, re := of[k], p.Revents
				switch {
				case re&unix.POLLNVAL != 0:
					// The host cannot watch this file: report it ready.
					res[i].in, res[i].out = reqs[i].in, reqs[i].out
				case fds[k].Events&unix.POLLOUT != 0:
					if re&(unix.POLLOUT|unix.POLLERR) != 0 {
						res[i].out = true
					}
					if re&unix.POLLERR != 0 {
						res[i].err = true
					}
				default:
					if re&unix.POLLIN != 0 {
						res[i].in = true
					}
					if re&unix.POLLPRI != 0 {
						res[i].pri = true
					}
					if re&unix.POLLRDHUP != 0 {
						res[i].rdhup = true
					}
					if re&unix.POLLHUP != 0 {
						res[i].hup = true
					}
					if re&unix.POLLERR != 0 {
						res[i].err = true // a pipe's write end whose readers are gone
					}
				}
			}
			if fds[nreq].Revents != 0 {
				drainWake(wake)
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

// pollHangup is a no-op on Linux: the host poll's revents already carry the
// hangup the guest should see, so nothing is synthesized from socket state.
//
// A vnet TCP socket whose peer closed while its own write side is open is the
// exception (vnetHalfOpen): its readiness is TCP's CLOSE_WAIT, readable and
// writable, without the hangup the unix stream behind it reports, which is
// then not watched, as it would end every wait.
func (g *dguest) pollHangup(d *dfile) (uint16, bool) {
	if !vnetHalfOpen(d) {
		return 0, false
	}
	pfd := []unix.PollFd{{Fd: int32(hostFd(d.f))}}
	if n, err := unix.Poll(pfd, 0); err != nil || n == 0 || pfd[0].Revents&unix.POLLHUP == 0 {
		return 0, false
	}
	return lxPollIn | lxPollRdnorm | lxPollRdhup | lxPollOut | lxPollWrnorm, true
}

// vnetHalfOpen reports whether d is a connected vnet TCP socket whose own
// write side is open. When its peer closes, the unix stream behind it hangs
// up (Linux's unix_release_sock shuts both its directions), where TCP (CLOSE_WAIT) reads the end and stays writable, and hangs up
// only once its own write side is shut too.
func vnetHalfOpen(d *dfile) bool {
	if !vnetStream(d) {
		return false
	}
	d.sk.mu.Lock()
	defer d.sk.mu.Unlock()
	return d.sk.peer != nil && !d.sk.listening && !d.sk.wrShut
}

// pollRevents maps one hostPoll answer to the guest revents for a request for
// events ev. The host poll already reports Linux semantics, so each result bit
// is just masked to what the guest asked for, with HUP and ERR always
// delivered. Because every result bit comes from a watch the guest requested
// (or is HUP/ERR), a non-empty result never maps to zero, so pollFor never
// mutes an fd here. A terminal's state is the supervisor's; its pipes only
// wake the wait.
func pollRevents(r pollRes, ev uint16, d *dfile) uint16 {
	if d != nil && d.pty != nil {
		return d.pty.pollState().mask & (ev | lxPollHup | lxPollErr)
	}
	var rev uint16
	if r.in {
		rev |= ev & (lxPollIn | lxPollRdnorm)
	}
	if r.pri {
		rev |= ev & lxPollPri
	}
	if r.out {
		rev |= ev & (lxPollOut | lxPollWrnorm)
	}
	if r.rdhup {
		rev |= ev & lxPollRdhup
	}
	if r.err {
		rev |= lxPollErr
	}
	if r.hup {
		rev |= lxPollHup | ev&lxPollRdhup
	}
	return rev
}
