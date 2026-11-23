//go:build darwin

package sandbox

import (
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// epoll and eventfd for the macOS backend, the readiness layer libuv (Node's
// event loop) is built on. A guest epoll instance is a host kqueue owned by the
// supervisor, watching the host fds behind the guest's open files; an eventfd
// is a counter whose readiness is mirrored onto a host pipe so the same kqueue
// can watch it.

// epoll is a guest epoll instance. interest maps a guest fd to its
// registration; the open file it was added with is kept so a closed-and-reused
// fd number is recognized as a different file.
type epoll struct {
	kq       int
	mu       sync.Mutex
	interest map[int]epollReg
	byHost   map[int][]int // host fd -> guest fds on it; nil after a change
	pending  []pendEv      // ready edge/oneshot events held back when a wait had no room for them
}

// pendEv is a ready event: the guest fd, the description it was registered
// with, its events and the registration's data.
type pendEv struct {
	gfd  int
	d    *dfile
	ev   uint32
	data uint64
}

// kevBufs holds kevent result buffers for epollWait, which would otherwise
// allocate 64 KB per call for libuv's 1024 events.
var kevBufs = sync.Pool{New: func() any { return new([2048]unix.Kevent_t) }}

type epollReg struct {
	d      *dfile
	events uint32
	data   uint64
}

func (g *dguest) epollCreate1(flags int64) int64 {
	kq, err := unix.Kqueue()
	if err != nil {
		return sErr(osErrno(err))
	}
	unix.CloseOnExec(kq)
	ep := &epoll{kq: kq, interest: map[int]epollReg{}}
	fd := g.ft.add(&dfile{f: os.NewFile(uintptr(kq), "anon_inode:[eventpoll]"), gp: "anon_inode:[eventpoll]", stub: -1, ep: ep}, 0)
	if flags&lxOCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	return int64(fd)
}

func (g *dguest) epollCtl(epfd int64, op int64, fd int64, evAddr uint64) int64 {
	epd, ok := g.ft.get(int(epfd))
	if !ok || epd.ep == nil {
		return sErr(lxEBADF)
	}
	ep := epd.ep
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	if d.f == nil || d == epd {
		return sErr(lxEPERM)
	}
	var events uint32
	var data uint64
	if op != lxEpollCtlDel {
		b, err := g.readMem(evAddr, epollEventSize)
		if err != nil {
			return sErr(lxEFAULT)
		}
		events, data = le32(b), le64(b[epollEventSize-8:])
	}

	ep.mu.Lock()
	defer ep.mu.Unlock()
	cur, have := ep.interest[int(fd)]
	if have && cur.d != d {
		cur.d.epw.done(ep)
		delete(ep.interest, int(fd))
		have = false // the fd number was closed and reused: the old one is gone
	}
	switch op {
	case lxEpollCtlAdd:
		if have {
			return sErr(lxEEXIST)
		}
	case lxEpollCtlMod, lxEpollCtlDel:
		if !have {
			return sErr(lxENOENT)
		}
	default:
		return sErr(lxEINVAL)
	}

	rfd, wfd := kqFds(d)
	flags := uint16(unix.EV_ADD | unix.EV_ENABLE)
	if events&lxEpollEt != 0 {
		flags |= unix.EV_CLEAR
	}
	if events&lxEpollOneshot != 0 {
		flags |= unix.EV_ONESHOT
	}
	want := func(on bool, fd int, filter int16) unix.Kevent_t {
		k := unix.Kevent_t{Ident: uint64(fd), Filter: filter, Flags: unix.EV_DELETE}
		if on {
			k.Flags = flags
		}
		return k
	}
	del := op == lxEpollCtlDel
	var changes []unix.Kevent_t
	if op == lxEpollCtlMod {
		// A filter added again keeps how it triggers: one that turns
		// edge-triggered or oneshot is a new filter.
		changes = append(changes, want(false, rfd, unix.EVFILT_READ), want(false, wfd, unix.EVFILT_WRITE))
		if x := vloFd(d); x >= 0 {
			changes = append(changes, want(false, x, unix.EVFILT_READ))
		}
	}
	changes = append(changes,
		want(!del && events&lxEpollIn != 0, rfd, unix.EVFILT_READ),
		want(!del && events&lxEpollOut != 0, wfd, unix.EVFILT_WRITE),
	)
	if x := vloFd(d); x >= 0 {
		changes = append(changes, want(!del && events&lxEpollIn != 0, x, unix.EVFILT_READ))
	}
	for _, c := range changes {
		// EV_DELETE of a filter that was never added reports ENOENT; that is
		// the expected no-op for a registration that never wanted it.
		if _, err := unix.Kevent(ep.kq, []unix.Kevent_t{c}, nil, nil); err != nil && c.Flags&unix.EV_DELETE == 0 {
			return sErr(osErrno(err))
		}
	}
	if del {
		delete(ep.interest, int(fd))
		d.epw.done(ep)
	} else {
		if !have {
			d.epw.add(ep)
		}
		ep.interest[int(fd)] = epollReg{d: d, events: events, data: data}
	}
	ep.byHost = nil
	return 0
}

// forget drops every registration of description d, which is being released:
// its filters leave the kqueue before its host fds close and can be reused.
func (ep *epoll) forget(d *dfile) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for gfd, r := range ep.interest {
		if r.d != d {
			continue
		}
		rfd, wfd := kqFds(d)
		dels := []unix.Kevent_t{{Ident: uint64(rfd), Filter: unix.EVFILT_READ, Flags: unix.EV_DELETE}, {Ident: uint64(wfd), Filter: unix.EVFILT_WRITE, Flags: unix.EV_DELETE}}
		if x := vloFd(d); x >= 0 {
			dels = append(dels, unix.Kevent_t{Ident: uint64(x), Filter: unix.EVFILT_READ, Flags: unix.EV_DELETE})
		}
		for _, k := range dels {
			unix.Kevent(ep.kq, []unix.Kevent_t{k}, nil, nil)
		}
		delete(ep.interest, gfd)
		d.epw.done(ep)
	}
	ep.byHost = nil
}

// epollWait blocks up to timeout ms (-1 = forever) for readiness and writes
// the ready registrations as struct epoll_event. The wait includes the
// thread's wake pipe, so a signal or the guest's teardown ends it.
func (g *dguest) epollWait(epfd int64, evAddr uint64, maxEvents int64, timeout int64) int64 {
	epd, ok := g.ft.get(int(epfd))
	if !ok || epd.ep == nil {
		return sErr(lxEBADF)
	}
	if maxEvents <= 0 || maxEvents > epMaxEvents {
		return sErr(lxEINVAL)
	}
	ep := epd.ep
	// The events the guest's buffer has room for before it stops being
	// writable: Linux copies them one at a time and puts back on the ready
	// list the ones from the first it cannot write on, failing with EFAULT if
	// it wrote none.
	fit := int(g.writablePrefix(evAddr, uint64(maxEvents)*epollEventSize) / epollEventSize)
	room := max(fit, 1)
	if evs := ep.takePending(room); len(evs) > 0 {
		return g.epollDeliver(ep, evAddr, evs, fit)
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(time.Duration(timeout) * time.Millisecond)
	}
	wt, wake, e := g.wakeFd()
	if e != 0 {
		return sErr(e)
	}
	defer wt.putWake()
	kb := kevBufs.Get().(*[2048]unix.Kevent_t)
	defer kevBufs.Put(kb)
	nbuf := 2 * int64(room)
	if nbuf > int64(len(kb)) {
		nbuf = int64(len(kb)) // chunk a large maxevents; the kqueue keeps the rest for the next wait
	}
	kev := kb[:nbuf]
	fds := []unix.PollFd{{Fd: int32(ep.kq), Events: unix.POLLIN}, {Fd: int32(wake), Events: unix.POLLIN}}
	var zero unix.Timespec
	for first := true; ; first = false {
		// A signal or teardown after this check writes the wake pipe, which
		// ends the poll; a signal already pending has none, so the first
		// pass only collects.
		intr := g.sigIntr() || g.ch.dead()
		if !intr && !first {
			if _, err := unix.Poll(fds, waitMs(deadline)); err != nil && err != unix.EINTR {
				return sErr(osErrno(err))
			}
			if fds[1].Revents != 0 {
				drainWake(wake)
			}
		}
		n, err := unix.Kevent(ep.kq, nil, kev, &zero)
		if err != nil && err != unix.EINTR {
			return sErr(osErrno(err))
		}
		if n > 0 {
			if evs := ep.collect(kev[:n], room); len(evs) > 0 {
				return g.epollDeliver(ep, evAddr, evs, fit)
			}
		}
		if intr {
			return sErr(lxEINTR)
		}
		if timeout >= 0 && !time.Now().Before(deadline) {
			return 0
		}
	}
}

// epollDeliver writes the ready events evs to the guest's buffer at evAddr,
// which has room for fit of them; with none, the call fails with EFAULT, as
// on Linux, and the edge-triggered and oneshot ones wait for the next call
// (the kqueue reports a level-triggered one again while it is ready).
func (g *dguest) epollDeliver(ep *epoll, evAddr uint64, evs []pendEv, fit int) int64 {
	if fit == 0 {
		ep.mu.Lock()
		var back []pendEv
		for _, p := range evs {
			if ep.interest[p.gfd].events&(lxEpollEt|lxEpollOneshot) != 0 {
				back = append(back, p)
			}
		}
		ep.pending = append(back, ep.pending...)
		ep.mu.Unlock()
		return sErr(lxEFAULT)
	}
	if err := g.writeMem(evAddr, encodeEvents(evs)); err != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(evs))
}

// encodeEvents lays out evs as struct epoll_event. Each carries the data its
// registration had when it was taken: one deleted since still reports, as on
// Linux, where the delete waits for the wait's copy-out.
func encodeEvents(evs []pendEv) []byte {
	out := make([]byte, 0, len(evs)*epollEventSize)
	for _, p := range evs {
		var b [epollEventSize]byte
		put32(b[:], p.ev)
		put64(b[epollEventSize-8:], p.data)
		out = append(out, b[:]...)
	}
	return out
}

// takePending returns up to max events held over from an earlier wait,
// dropping any whose registration is gone.
func (ep *epoll) takePending(max int) []pendEv {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if len(ep.pending) == 0 {
		return nil
	}
	var out []pendEv
	kept := ep.pending[:0]
	for _, p := range ep.pending {
		r, ok := ep.interest[p.gfd]
		if !ok || r.d != p.d {
			continue
		}
		p.data = r.data
		if len(out) < max {
			out = append(out, p)
		} else {
			kept = append(kept, p)
		}
	}
	ep.pending = kept
	return out
}

// collect folds kqueue's per-filter events into one ready event per guest
// fd, up to max of them. The kqueue reports an edge-triggered or oneshot
// event once: the ones past max are held back for the next wait rather than
// lost; a level-triggered one is reported again on its own.
func (ep *epoll) collect(kev []unix.Kevent_t, max int) []pendEv {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.byHost == nil {
		ep.byHost = map[int][]int{}
		for gfd, r := range ep.interest {
			rfd, wfd := kqFds(r.d)
			ep.byHost[rfd] = append(ep.byHost[rfd], gfd)
			if wfd != rfd {
				ep.byHost[wfd] = append(ep.byHost[wfd], gfd)
			}
			if x := vloFd(r.d); x >= 0 {
				ep.byHost[x] = append(ep.byHost[x], gfd)
			}
		}
	}
	byHost := ep.byHost
	ready := map[int]uint32{}
	var order []int
	for _, k := range kev {
		for _, gfd := range byHost[int(k.Ident)] {
			r := ep.interest[gfd]
			var ev uint32
			switch k.Filter {
			case unix.EVFILT_READ:
				if r.events&lxEpollIn == 0 {
					continue
				}
				ev = lxEpollIn
				if k.Flags&unix.EV_EOF != 0 {
					ev |= lxEpollRdhup & r.events
					if r.d.sk == nil {
						ev |= lxEpollHup // a pipe's writers are gone
					} else if st, ok := sockPollState(r.d, true); ok {
						ev |= uint32(st) & lxEpollHup // a socket hangs up once both directions end
					}
				}
			case unix.EVFILT_WRITE:
				if r.events&lxEpollOut == 0 {
					continue
				}
				ev = lxEpollOut
				if k.Flags&unix.EV_EOF != 0 && r.d.sk != nil && r.d.sk.virt {
					// A vnet socket's stream ends where TCP has no error.
					if st, ok := vnetSockState(r.d, peekEOF(hostFd(r.d.f))); ok {
						ev |= uint32(st) & lxEpollHup
					}
				} else if k.Flags&unix.EV_EOF != 0 {
					if r.d.sk == nil || k.Fflags != 0 {
						ev |= lxEpollErr
					}
					if st, ok := sockPollState(r.d, true); r.d.sk != nil && (k.Fflags != 0 || !ok || st&lxPollHup != 0) {
						ev |= lxEpollHup
					}
				}
			}
			if r.d.pty != nil { // a terminal's pipes only wake the wait
				if ev = uint32(r.d.pty.pollState().mask) & (r.events | lxEpollErr | lxEpollHup); ev == 0 {
					continue
				}
			} else if st, ok := ringPollState(r.d); ok { // so do a supervisor pipe's
				if ev = uint32(st.mask) & (r.events | lxEpollErr | lxEpollHup); ev == 0 {
					continue
				}
			}
			if _, seen := ready[gfd]; !seen {
				order = append(order, gfd)
			}
			ready[gfd] |= ev
		}
	}
	if len(order) > max {
		for _, gfd := range order[max:] {
			if r := ep.interest[gfd]; r.events&(lxEpollEt|lxEpollOneshot) != 0 {
				ep.pending = append(ep.pending, pendEv{gfd: gfd, d: r.d, ev: ready[gfd], data: r.data})
			}
		}
		order = order[:max]
	}
	out := make([]pendEv, 0, len(order))
	for _, gfd := range order {
		r := ep.interest[gfd]
		out = append(out, pendEv{gfd: gfd, d: r.d, ev: ready[gfd], data: r.data})
	}
	return out
}

// rewatch adds d's registrations' filters on the host fds now behind it,
// which changed (vlo_unix.go); a closed fd's filters leave the kqueue with it.
func (ep *epoll) rewatch(d *dfile) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for _, r := range ep.interest {
		if r.d != d {
			continue
		}
		flags := uint16(unix.EV_ADD | unix.EV_ENABLE)
		if r.events&lxEpollEt != 0 {
			flags |= unix.EV_CLEAR
		}
		if r.events&lxEpollOneshot != 0 {
			flags |= unix.EV_ONESHOT
		}
		rfd, wfd := kqFds(d)
		var adds []unix.Kevent_t
		if r.events&lxEpollIn != 0 {
			adds = append(adds, unix.Kevent_t{Ident: uint64(rfd), Filter: unix.EVFILT_READ, Flags: flags})
			if x := vloFd(d); x >= 0 {
				adds = append(adds, unix.Kevent_t{Ident: uint64(x), Filter: unix.EVFILT_READ, Flags: flags})
			}
		}
		if r.events&lxEpollOut != 0 {
			adds = append(adds, unix.Kevent_t{Ident: uint64(wfd), Filter: unix.EVFILT_WRITE, Flags: flags})
		}
		for _, k := range adds {
			unix.Kevent(ep.kq, []unix.Kevent_t{k}, nil, nil)
		}
	}
	ep.byHost = nil
}

// close releases what the instance holds besides its kqueue: its place in
// the watched descriptions.
func (ep *epoll) close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for gfd, r := range ep.interest {
		delete(ep.interest, gfd)
		r.d.epw.done(ep)
	}
}
