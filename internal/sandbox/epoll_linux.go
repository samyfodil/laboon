package sandbox

import (
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// A guest epoll instance is a host epoll owned by the supervisor, watching
// the host fds behind the guest's open files (an eventfd's readiness pipe for
// one). A registration watches the description's own host fd, or a private dup
// of it when that fd is already in the epoll: two guest fds can share a
// description, which a host epoll registers once. As in the kernel, a
// description's registrations last until it is released -- closing one of
// several fds keeps them -- and its last close removes them from every epoll
// (epollRelease), so the epoll never holds the file open.

type epoll struct {
	epfd     int
	mu       sync.Mutex
	interest map[int]epollReg
	seq      uint32
	pending  []pendEv // ready edge/oneshot events held back when a wait filled up
}

// pendEv is one ready fd held over to the next epoll_wait: the host reports an
// edge-triggered or oneshot event once, so an event that does not fit the
// guest's maxevents must be kept rather than dropped.
type pendEv struct {
	gfd  int
	id   uint32
	ev   uint32
	data uint64
}

type epollReg struct {
	d          *dfile
	events     uint32
	data       uint64
	id         uint32 // in the host events' data, with the guest fd
	rfd, wfd   int    // the host fds watched; wfd is -1 when rfd carries both
	xfd        int    // a second fd readable data comes on, or -1: a socket's side of the run's own loopback (vlo_unix.go)
	dupR, dupW bool   // rfd or wfd is a private dup, which the registration closes
	dupX       bool
	hostEvents uint32
}

func (g *dguest) epollCreate1(flags int64) int64 {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return sErr(osErrno(err))
	}
	ep := &epoll{epfd: epfd, interest: map[int]epollReg{}}
	fd := g.ft.add(&dfile{f: os.NewFile(uintptr(epfd), "anon_inode:[eventpoll]"), gp: "anon_inode:[eventpoll]", stub: -1, ep: ep}, 0)
	if flags&lxOCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	return int64(fd)
}

// The guest's event bits are the host's; these pass through.
const epollPassed = unix.EPOLLIN | unix.EPOLLOUT | unix.EPOLLPRI | unix.EPOLLRDHUP | unix.EPOLLET | unix.EPOLLONESHOT

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
		b, err := g.argRead(evAddr, epollEventSize)
		if err != nil {
			return sErr(lxEFAULT)
		}
		events, data = le32(b), le64(b[epollEventSize-8:])
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	cur, have := ep.interest[int(fd)]
	if have && cur.d != d {
		ep.drop(int(fd), cur) // the fd number was closed and reused: the old one is gone
		have = false
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
	if op == lxEpollCtlMod {
		// A registration watching one host fd changes in place, as the
		// host's does, keeping its id.
		if hostRfd, hostWfd := kqFds(d); hostWfd == hostRfd && cur.wfd < 0 && cur.xfd < 0 && vloFd(d) < 0 {
			ev := events & epollPassed
			if err := unix.EpollCtl(ep.epfd, unix.EPOLL_CTL_MOD, cur.rfd, &unix.EpollEvent{Events: ev, Fd: int32(fd), Pad: int32(cur.id)}); err != nil {
				return sErr(osErrno(err))
			}
			cur.events, cur.data, cur.hostEvents = events, data, ev
			ep.interest[int(fd)] = cur
			return 0
		}
	}
	if have {
		ep.drop(int(fd), cur)
	}
	if op == lxEpollCtlDel {
		return 0
	}
	ep.seq++
	r, err := ep.register(d, int(fd), events, data, ep.seq)
	if err != nil {
		return sErr(osErrno(err))
	}
	ep.interest[int(fd)] = r
	d.epw.add(ep)
	return 0
}

// register watches the host fds behind d for guest fd gfd's registration id.
// ep.mu held.
func (ep *epoll) register(d *dfile, gfd int, events uint32, data uint64, id uint32) (epollReg, error) {
	r := epollReg{d: d, events: events, data: data, id: id, rfd: -1, wfd: -1, xfd: -1}
	hostRfd, hostWfd := kqFds(d)
	ev := events & epollPassed
	var err error
	if hostWfd != hostRfd && events&lxEpollOut != 0 {
		// An eventfd: readable from its pipe's read end, writable from the
		// write end.
		ev &^= unix.EPOLLOUT
		wev := events&epollPassed&^(unix.EPOLLIN|unix.EPOLLPRI|unix.EPOLLRDHUP) | unix.EPOLLOUT
		if r.wfd, r.dupW, err = ep.watch(hostWfd, wev, gfd, id); err != nil {
			return r, err
		}
	}
	r.hostEvents = ev
	if r.rfd, r.dupR, err = ep.watch(hostRfd, ev, gfd, id); err != nil {
		ep.unwatch(r.wfd, r.dupW)
		return r, err
	}
	if x := vloFd(d); x >= 0 && events&lxEpollIn != 0 {
		xev := events&epollPassed&^(unix.EPOLLOUT|unix.EPOLLRDHUP) | unix.EPOLLIN
		if r.xfd, r.dupX, err = ep.watch(x, xev, gfd, id); err != nil {
			ep.unwatch(r.rfd, r.dupR)
			ep.unwatch(r.wfd, r.dupW)
			return r, err
		}
	}
	return r, nil
}

// rewatch moves d's registrations to the host fds now behind it, which
// changed (vlo_unix.go): the old ones leave the epoll before they close.
func (ep *epoll) rewatch(d *dfile) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for gfd, r := range ep.interest {
		if r.d != d {
			continue
		}
		ep.unwatch(r.rfd, r.dupR)
		ep.unwatch(r.wfd, r.dupW)
		ep.unwatch(r.xfd, r.dupX)
		nr, err := ep.register(d, gfd, r.events, r.data, r.id)
		if err != nil {
			delete(ep.interest, gfd)
			d.epw.done(ep)
			continue
		}
		ep.interest[gfd] = nr
	}
}

// watch adds host fd h to the epoll for guest fd gfd's registration id, or a
// dup of it when h is in the epoll already. It returns the fd watched and
// whether it is a dup. ep.mu held.
func (ep *epoll) watch(h int, ev uint32, gfd int, id uint32) (int, bool, error) {
	e := &unix.EpollEvent{Events: ev, Fd: int32(gfd), Pad: int32(id)}
	err := unix.EpollCtl(ep.epfd, unix.EPOLL_CTL_ADD, h, e)
	if err != unix.EEXIST {
		return h, false, err
	}
	dup, err := unix.FcntlInt(uintptr(h), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, false, err
	}
	if err := unix.EpollCtl(ep.epfd, unix.EPOLL_CTL_ADD, dup, e); err != nil {
		unix.Close(dup)
		return -1, false, err
	}
	return dup, true, nil
}

// unwatch takes host fd h out of the epoll, closing it if it is a dup. ep.mu
// held.
func (ep *epoll) unwatch(h int, dup bool) {
	if h < 0 {
		return
	}
	unix.EpollCtl(ep.epfd, unix.EPOLL_CTL_DEL, h, nil)
	if dup {
		unix.Close(h)
	}
}

// close drops the registrations; the host epoll is the dfile's.
func (ep *epoll) close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for fd, r := range ep.interest {
		ep.drop(fd, r)
	}
}

// drop removes fd's registration r. ep.mu held.
func (ep *epoll) drop(fd int, r epollReg) {
	ep.unwatch(r.rfd, r.dupR)
	ep.unwatch(r.wfd, r.dupW)
	ep.unwatch(r.xfd, r.dupX)
	delete(ep.interest, fd)
	r.d.epw.done(ep)
}

// forget drops every registration of description d, which is being released.
func (ep *epoll) forget(d *dfile) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for fd, r := range ep.interest {
		if r.d == d {
			ep.drop(fd, r)
		}
	}
}

// epScratch is one epoll_wait's working memory, pooled so a wait allocates
// nothing: the host events, the ready events folded from them and their
// struct epoll_event bytes.
type epScratch struct {
	hev  [epollBufMax]unix.EpollEvent
	evs  []pendEv
	out  []byte
	fold map[int]int // guest fd to its index in evs, for registrations on several host fds
}

var epScratches = sync.Pool{New: func() any { return &epScratch{fold: map[int]int{}} }}

// epSkipRun is how many waits after one that blocked go straight to blocking
// (epollWait).
const epSkipRun = 8

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
	// Deliver any events held back from an earlier wait before polling again.
	if evs := ep.takePending(room); len(evs) > 0 {
		return g.epollDeliver(ep, evAddr, evs, fit, nil)
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(time.Duration(timeout) * time.Millisecond)
	}
	s := epScratches.Get().(*epScratch)
	defer epScratches.Put(s)
	hev := s.hev[:min(2*maxEvents, epollBufMax)]
	wake, wep := -1, -1
	if timeout != 0 {
		wt, fd, e := g.wakeFd()
		if e != 0 {
			return sErr(e)
		}
		defer wt.putWake()
		wake, wep = fd, wt.waitEpoll(ep)
	}
	// A thread whose wait had to block likely blocks again: its next waits
	// skip the first collect-only pass and wait at once, on a wait epoll that
	// holds ep's, so ep being ready already ends the wait. A skipping wait
	// cannot tell whether it blocked, so the run ends and the next wait
	// collects first again, as a busy loop wants.
	skip := g.epSkips > 0 && wep >= 0
	for first := true; ; first = false {
		// A signal or teardown after this check writes the wake pipe, which
		// ends the wait; a signal already pending has none, so then the call
		// only collects.
		intr := g.sigIntr() || g.ch.dead()
		if !intr && timeout != 0 && (!first || skip) {
			if err := waitReady(ep.epfd, wake, wep, waitMs(deadline)); err != nil {
				return sErr(osErrno(err))
			}
		}
		n, err := unix.EpollWait(ep.epfd, hev, 0)
		if err != nil && err != unix.EINTR {
			return sErr(osErrno(err))
		}
		if n > 0 {
			if evs := ep.collect(hev[:n], room, s); len(evs) > 0 {
				if !first {
					g.epSkips = epSkipRun
				} else if skip {
					g.epSkips--
				}
				return g.epollDeliver(ep, evAddr, evs, fit, s)
			}
		}
		if intr {
			return sErr(lxEINTR)
		}
		if timeout >= 0 && !time.Now().Before(deadline) {
			if timeout != 0 {
				g.epSkips = epSkipRun
			}
			return 0
		}
	}
}

// waitReady blocks up to ms (-1 = forever) until the host epoll epfd or the
// wake pipe wake is readable, draining the pipe. wep, the thread's wait epoll
// (waitEpoll), makes that one host call; without one (-1) it polls the two.
func waitReady(epfd, wake, wep, ms int) error {
	if wep >= 0 {
		var tev [2]unix.EpollEvent
		n, err := unix.EpollWait(wep, tev[:], ms)
		if err != nil && err != unix.EINTR {
			return err
		}
		for _, e := range tev[:max(n, 0)] {
			if int(e.Fd) == wake {
				drainWake(wake)
			}
		}
		return nil
	}
	fds := [2]unix.PollFd{{Fd: int32(epfd), Events: unix.POLLIN}, {Fd: int32(wake), Events: unix.POLLIN}}
	if _, err := unix.Poll(fds[:], ms); err != nil && err != unix.EINTR {
		return err
	}
	if fds[1].Revents != 0 {
		drainWake(wake)
	}
	return nil
}

// waitEpoll returns t's wait epoll: a host epoll of its own holding its wake
// pipe and the host epoll of ep, the guest epoll it waits on, so a blocking
// wait is one host call. It is made on first use and keeps the last guest
// epoll, replaced when the thread waits on another; ep's own epoll is never
// given the pipe, as other threads wait on it too. It returns -1 when ep's
// cannot be added (one nested too deep), and the wait polls instead. The
// caller holds the pipe (wakeFd), whose teardown closes the wait epoll.
func (t *sigThread) waitEpoll(ep *epoll) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.wep < 0 {
		wep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
		if err != nil {
			return -1
		}
		if err := unix.EpollCtl(wep, unix.EPOLL_CTL_ADD, t.wr, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(t.wr)}); err != nil {
			unix.Close(wep)
			return -1
		}
		t.wep = wep
	}
	if t.wepOn == ep {
		return t.wep
	}
	if t.wepOn != nil {
		// If that epoll's file closed, it left the wait epoll with it, and
		// its number now names a file the wait epoll does not hold: the
		// delete fails, harmlessly.
		unix.EpollCtl(t.wep, unix.EPOLL_CTL_DEL, t.wepOn.epfd, nil)
		t.wepOn = nil
	}
	if err := unix.EpollCtl(t.wep, unix.EPOLL_CTL_ADD, ep.epfd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(ep.epfd)}); err != nil {
		return -1
	}
	t.wepOn = ep
	return t.wep
}

// epollDeliver writes the ready events evs to the guest's buffer at evAddr,
// which has room for fit of them; with none, the call fails with EFAULT, as
// on Linux, and the edge-triggered and oneshot ones wait for the next call
// (the host reports a level-triggered one again while it is ready). s, when
// not nil, lends the encoding its buffer.
func (g *dguest) epollDeliver(ep *epoll, evAddr uint64, evs []pendEv, fit int, s *epScratch) int64 {
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
	var buf []byte
	if s != nil {
		buf = encodeEvents(s.out[:0], evs)
		s.out = buf
	} else {
		buf = encodeEvents(nil, evs)
	}
	if err := g.putOut(evAddr, buf); err != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(evs))
}

// encodeEvents appends evs to out as struct epoll_event. Each carries the data
// its registration had when it was taken: one deleted since still reports, as
// on Linux, where the delete waits for the wait's copy-out.
func encodeEvents(out []byte, evs []pendEv) []byte {
	for _, p := range evs {
		var b [epollEventSize]byte
		put32(b[:], p.ev)
		put64(b[epollEventSize-8:], p.data)
		out = append(out, b[:]...)
	}
	return out
}

// collect folds the host events into one ready event per guest fd, in s's
// buffer: copies taken under the lock, for the calling wait alone.
func (ep *epoll) collect(hev []unix.EpollEvent, max int, s *epScratch) []pendEv {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	evs := s.evs[:0]
	for _, e := range hev {
		gfd := int(e.Fd)
		r, ok := ep.interest[gfd]
		if !ok || r.id != uint32(e.Pad) {
			continue // a registration since dropped
		}
		ev := e.Events & (r.events | unix.EPOLLERR | unix.EPOLLHUP)
		if r.d.pty != nil { // a terminal's pipes only wake the wait
			ev = uint32(r.d.pty.pollState().mask) & (r.events | unix.EPOLLERR | unix.EPOLLHUP)
		}
		if ev&unix.EPOLLHUP != 0 && vnetHalfOpen(r.d) {
			// TCP's CLOSE_WAIT has not hung up (vnetHalfOpen). Asked for
			// nothing it reports, it is watched edge-triggered from now, so
			// the host's level hangup stops ending the wait.
			if ev &^= unix.EPOLLHUP; ev == 0 && r.events&lxEpollEt == 0 {
				e := &unix.EpollEvent{Events: r.hostEvents | unix.EPOLLET, Fd: int32(gfd), Pad: int32(r.id)}
				unix.EpollCtl(ep.epfd, unix.EPOLL_CTL_MOD, r.rfd, e)
			}
		}
		if ev == 0 {
			continue
		}
		// The host reports each of its fds once a wait, so only a
		// registration on several comes up more than once.
		if r.wfd >= 0 || r.xfd >= 0 {
			if i, seen := s.fold[gfd]; seen {
				evs[i].ev |= ev
				continue
			}
			s.fold[gfd] = len(evs)
		}
		evs = append(evs, pendEv{gfd: gfd, id: r.id, ev: ev, data: r.data})
	}
	if len(s.fold) > 0 {
		clear(s.fold)
	}
	if len(evs) > max {
		// The host reports an edge-triggered or oneshot event once; hold back
		// the ones that do not fit so the next wait delivers them, rather than
		// losing the wakeup. A level-triggered fd re-reports on its own.
		for _, p := range evs[max:] {
			if ep.interest[p.gfd].events&(lxEpollEt|lxEpollOneshot) != 0 {
				ep.pending = append(ep.pending, p)
			}
		}
		evs = evs[:max]
	}
	s.evs = evs
	return evs
}

// takePending returns up to max events held over from an earlier wait, dropping
// any whose registration is gone.
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
		if !ok || r.id != p.id {
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
