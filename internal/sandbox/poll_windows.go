//go:build windows

package sandbox

import (
	"os"
	"slices"
	"sync"
	"time"
)

// Readiness on Windows: poll, ppoll, select, pselect6, epoll and eventfd.
// Pipes (the guest's and the host's, pipeend_windows.go), sockets, eventfds,
// timerfds, signalfds, inotify and terminals publish changes to the run bus.
// Other files are always ready.

const (
	lxPollRdband = 0x80
	lxPollWrband = 0x200

	// x86-64 poll(2), select(2), pause(2) arrive under these keys
	// (run_windows_amd64.go).
	winPoll   = 0x4c43f007
	winSelect = 0x4c43f017
)

func init() {
	syscalls[winPoll] = func(g *dguest, a [6]uint64) int64 {
		ms := int64(int32(a[2]))
		timeout := time.Duration(-1)
		if ms >= 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
		r, e := g.pollFds(a[0], a[1], timeout)
		if e == errRestart {
			e = errRestartNoHand
		}
		if e != 0 {
			return sErr(e)
		}
		return r
	}
	syscalls[winSelect] = func(g *dguest, a [6]uint64) int64 {
		timeout := time.Duration(-1)
		if a[4] != 0 {
			b, err := g.readMem(a[4], 16)
			if err != nil {
				return sErr(lxEFAULT)
			}
			sec, usec := int64(le64(b)), int64(le64(b[8:]))
			if sec < 0 || usec < 0 {
				return sErr(lxEINVAL)
			}
			timeout = time.Duration(sec)*time.Second + time.Duration(min(usec, 999999))*time.Microsecond
		}
		start := time.Now()
		r := g.selectFds(int64(int32(a[0])), a[1], a[2], a[3], timeout)
		if a[4] != 0 && r != sErr(lxEFAULT) {
			left := max(timeout-time.Since(start), 0)
			g.writeMem(a[4], timevalBytes(left))
		}
		return r
	}
}

// pollState is d's Linux poll mask now and a stamp that changes whenever the
// mask may have (for EPOLLET).
type pollState struct {
	mask  uint16
	stamp uint64
}

const (
	pollInSet  = lxPollIn | lxPollRdnorm
	pollOutSet = lxPollOut | lxPollWrnorm
)

func (g *dguest) pollOf(d *dfile) pollState {
	switch {
	case d.pipe != nil && d.pipe.io != nil:
		switch p := d.pipe.io.(type) {
		case *bufferPipe:
			return p.poll(d.fx.oflags & lxOAccmod)
		case *pipeEnd:
			return p.poll(g.netState())
		}
	case d.sk != nil:
		n := d.sk.n
		n.mu.Lock()
		defer n.mu.Unlock()
		return pollState{mask: d.sk.pollMask(), stamp: d.sk.stamp}
	case d.ev != nil:
		n := d.ev.n
		n.mu.Lock()
		defer n.mu.Unlock()
		var m uint16
		if d.ev.count > 0 {
			m |= pollInSet
		}
		if d.ev.count < eventfdMax {
			m |= pollOutSet
		}
		return pollState{mask: m, stamp: d.ev.stamp}
	case d.tfd != nil:
		t := d.tfd
		t.mu.Lock()
		defer t.mu.Unlock()
		return noteState(t.count != 0, t.stamp)
	case d.sf != nil:
		sf := d.sf
		sf.mu.Lock()
		defer sf.mu.Unlock()
		return noteState(sf.armed, sf.stamp)
	case d.fx.in != nil:
		in := d.fx.in
		in.mu.Lock()
		defer in.mu.Unlock()
		return noteState(len(in.q) != 0, in.stamp)
	case d.pty != nil:
		return d.pty.pollState()
	case d.ep != nil:
		st := d.ep.levelState(g)
		if st.mask != 0 {
			st.mask = pollInSet
		}
		return st
	}
	return pollState{mask: pollInSet | pollOutSet}
}

func noteState(ready bool, stamp uint64) pollState {
	st := pollState{stamp: stamp}
	if ready {
		st.mask = pollInSet
	}
	return st
}

// pollMask is the socket's Linux poll mask. n.mu is held.
func (s *dsock) pollMask() uint16 {
	var m uint16
	if s.soErr != 0 {
		m |= lxPollErr
	}
	if s.state == skListening {
		if len(s.backlog) > 0 || s.acceptE != 0 {
			m |= pollInSet
		}
		return m
	}
	if s.typ == lxSockDgram {
		if len(s.rx.segs) > 0 {
			m |= pollInSet
		}
		return m | pollOutSet
	}
	switch s.state {
	case skConnecting:
		return m
	case skNew:
		return m | pollOutSet | lxPollHup
	}
	if len(s.rx.segs) > 0 || s.rx.eof || s.rx.err != 0 || s.shutRd {
		m |= pollInSet
	}
	if s.rx.eof || s.shutRd {
		m |= lxPollRdhup
	}
	switch {
	case s.local():
		if p := s.pair; p == nil || p.closed || p.rx.n < sockRcvBuf {
			m |= pollOutSet
		}
		if s.peerGone || s.shutRd && s.shutWr {
			m |= lxPollHup
		}
	default:
		if s.txErr != 0 || !s.shutWr && len(s.tx) < sockSndBuf {
			m |= pollOutSet
		}
		if s.rx.err != 0 || s.shutWr && s.rx.eof {
			m |= lxPollHup
		}
	}
	return m
}

// ---- poll / select --------------------------------------------------------------

func (g *dguest) ppoll(fdsAddr, nfds, tmo uint64) int64 {
	timeout, e := g.timeoutAt(tmo)
	if e != 0 {
		return sErr(e)
	}
	start := time.Now()
	r, e := g.pollFds(fdsAddr, nfds, timeout)
	if e == errRestart {
		e = errRestartNoHand
	}
	if e != 0 {
		return sErr(e)
	}
	g.writeRemaining(tmo, timeout, start)
	return r
}

// pollFds is the poll(2) loop over the guest's pollfd array; timeout < 0 has
// no limit.
func (g *dguest) pollFds(fdsAddr, nfds uint64, timeout time.Duration) (int64, lxErrno) {
	if nfds > 1<<16 {
		return 0, lxEINVAL
	}
	var b []byte
	if nfds > 0 {
		var err error
		if b, err = g.readMem(fdsAddr, int(8*nfds)); err != nil {
			return 0, lxEFAULT
		}
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	n := g.netState()
	for {
		ch := n.watch()
		count := 0
		for i := 0; i < int(nfds); i++ {
			fd := int32(le32(b[8*i:]))
			ev := uint16(b[8*i+4]) | uint16(b[8*i+5])<<8
			var rev uint16
			if fd >= 0 {
				if d, ok := g.ft.get(int(fd)); !ok {
					rev = lxPollNval
				} else {
					st := g.pollOf(d)
					rev = st.mask & (ev | lxPollErr | lxPollHup)
				}
			}
			b[8*i+6], b[8*i+7] = byte(rev), byte(rev>>8)
			if rev != 0 {
				count++
			}
		}
		if count > 0 || timeout == 0 {
			if nfds > 0 {
				if err := g.writeMem(fdsAddr, b); err != nil {
					return 0, lxEFAULT
				}
			}
			return int64(count), 0
		}
		switch e := g.waitOn(ch, deadline); e {
		case 0:
		case lxEAGAIN:
			timeout = 0
		default:
			return 0, e
		}
	}
}

func (g *dguest) pselect6(nfds int64, rAddr, wAddr, xAddr, tmo uint64) int64 {
	timeout, e := g.timeoutAt(tmo)
	if e != 0 {
		return sErr(e)
	}
	start := time.Now()
	r := g.selectFds(nfds, rAddr, wAddr, xAddr, timeout)
	if r >= 0 {
		g.writeRemaining(tmo, timeout, start)
	}
	return r
}

// selectFds is the select(2) loop over the guest's fd sets.
func (g *dguest) selectFds(nfds int64, rAddr, wAddr, xAddr uint64, timeout time.Duration) int64 {
	if nfds < 0 || nfds > 1<<16 {
		return sErr(lxEINVAL)
	}
	words := int((nfds + 63) / 64)
	var sets, outs [3][]byte
	for i, addr := range []uint64{rAddr, wAddr, xAddr} {
		if addr == 0 || words == 0 {
			continue
		}
		b, err := g.readMem(addr, 8*words)
		if err != nil {
			return sErr(lxEFAULT)
		}
		sets[i], outs[i] = b, make([]byte, len(b))
	}
	isSet := func(s []byte, fd int) bool { return s != nil && s[fd/8]&(1<<(fd%8)) != 0 }
	var fds []int
	var ds []*dfile
	for fd := 0; fd < int(nfds); fd++ {
		if !isSet(sets[0], fd) && !isSet(sets[1], fd) && !isSet(sets[2], fd) {
			continue
		}
		d, ok := g.ft.get(fd)
		if !ok {
			return sErr(lxEBADF)
		}
		fds, ds = append(fds, fd), append(ds, d)
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	n := g.netState()
	for {
		ch := n.watch()
		count := 0
		for i := range outs {
			clear(outs[i])
		}
		mark := func(k, fd int) {
			outs[k][fd/8] |= 1 << (fd % 8)
			count++
		}
		for i, fd := range fds {
			st := g.pollOf(ds[i])
			if isSet(sets[0], fd) && st.mask&(pollInSet|lxPollHup|lxPollErr) != 0 {
				mark(0, fd)
			}
			if isSet(sets[1], fd) && st.mask&(pollOutSet|lxPollErr) != 0 {
				mark(1, fd)
			}
			if isSet(sets[2], fd) && st.mask&lxPollPri != 0 {
				mark(2, fd)
			}
		}
		if count > 0 || timeout == 0 {
			for i, addr := range []uint64{rAddr, wAddr, xAddr} {
				if outs[i] != nil {
					if err := g.writeMem(addr, outs[i]); err != nil {
						return sErr(lxEFAULT)
					}
				}
			}
			return int64(count)
		}
		switch e := g.waitOn(ch, deadline); e {
		case 0:
		case lxEAGAIN:
			timeout = 0
		case errRestart:
			return sErr(errRestartNoHand)
		default:
			return sErr(e)
		}
	}
}

// ---- eventfd --------------------------------------------------------------------

// eventfd is a guest eventfd: a counter under the run's socket lock, so its
// changes wake the same waiters. w is unused (the shared close path closes
// it).
type eventfd struct {
	n     *dnet
	count uint64
	sem   bool
	stamp uint64
	w     *os.File
}

const eventfdMax = ^uint64(0) - 1

func (g *dguest) eventfd2(initval uint64, flags int64) int64 {
	if flags&^(lxONonblock|lxOCloexec|lxEfdSemaphore) != 0 {
		return sErr(lxEINVAL)
	}
	f, e := hostless("anon_inode:[eventfd]")
	if e != 0 {
		return sErr(e)
	}
	ev := &eventfd{n: g.netState(), count: initval, sem: flags&lxEfdSemaphore != 0}
	d := &dfile{f: f, gp: "anon_inode:[eventfd]", stub: -1, ev: ev}
	d.nonblock.Store(flags&lxONonblock != 0)
	fd := g.ft.add(d, 0)
	if fd >= 0 && flags&lxOCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	return int64(fd)
}

func (ev *eventfd) touch() {
	ev.n.seq++
	ev.stamp = ev.n.seq
	ev.n.notify()
}

func (g *dguest) eventfdRead(d *dfile, bufAddr uint64, size int64) int64 {
	if size < 8 {
		return sErr(lxEINVAL)
	}
	ev := d.ev
	n := ev.n
	n.mu.Lock()
	for ev.count == 0 {
		if d.nonblock.Load() {
			n.mu.Unlock()
			return sErr(lxEAGAIN)
		}
		if e := g.wait(n, time.Time{}); e != 0 {
			n.mu.Unlock()
			return sErr(e)
		}
	}
	v := ev.count
	if ev.sem {
		v = 1
	}
	ev.count -= v
	ev.touch()
	n.mu.Unlock()
	var b [8]byte
	put64(b[:], v)
	if err := g.writeMem(bufAddr, b[:]); err != nil {
		return sErr(lxEFAULT)
	}
	return 8
}

func (g *dguest) eventfdWrite(d *dfile, bufAddr uint64, size int64) int64 {
	if size < 8 {
		return sErr(lxEINVAL)
	}
	b, err := g.readMem(bufAddr, 8)
	if err != nil {
		return sErr(lxEFAULT)
	}
	v := le64(b)
	if v == ^uint64(0) {
		return sErr(lxEINVAL)
	}
	ev := d.ev
	n := ev.n
	n.mu.Lock()
	defer n.mu.Unlock()
	for ev.count > eventfdMax-v {
		if d.nonblock.Load() {
			return sErr(lxEAGAIN)
		}
		if e := g.wait(n, time.Time{}); e != 0 {
			return sErr(e)
		}
	}
	ev.count += v
	ev.touch()
	return 8
}

// ---- epoll ----------------------------------------------------------------------

// epoll is a guest epoll instance: its interest list by guest fd, each with
// the description it was added with (so a closed and reused fd number is a
// different file).
type epoll struct {
	mu       sync.Mutex
	interest map[int]*epollReg
}

type epollReg struct {
	d      *dfile
	events uint32
	data   uint64
	stamp  uint64 // the readiness stamp last reported (EPOLLET)
}

const (
	lxEpollPri       = 0x2
	lxEpollRdnorm    = 0x40
	lxEpollWrnorm    = 0x100
	lxEpollExclusive = 1 << 28
	lxEpollWakeup    = 1 << 29
	unreported       = ^uint64(0)
)

func (g *dguest) epollCreate1(flags int64) int64 {
	if flags&^lxOCloexec != 0 {
		return sErr(lxEINVAL)
	}
	f, e := hostless("anon_inode:[eventpoll]")
	if e != 0 {
		return sErr(e)
	}
	ep := &epoll{interest: map[int]*epollReg{}}
	fd := g.ft.add(&dfile{f: f, gp: "anon_inode:[eventpoll]", stub: -1, ep: ep}, 0)
	if fd >= 0 && flags&lxOCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	return int64(fd)
}

func (g *dguest) epollCtl(epfd, op, fd int64, evAddr uint64) int64 {
	ed, ok := g.ft.get(int(epfd))
	if !ok {
		return sErr(lxEBADF)
	}
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	if ed.ep == nil || epfd == fd {
		return sErr(lxEINVAL)
	}
	if d.vf != nil {
		return sErr(lxEPERM) // a regular file is always ready
	}
	if d.ep == nil && d.sk == nil && d.ev == nil && d.f != nil && !d.isPipe() && d.tfd == nil && d.sf == nil && d.fx.in == nil {
		if mode, _, err := d.hostStat(); err == nil && (mode.IsRegular() || mode.IsDir()) {
			return sErr(lxEPERM)
		}
	}
	var events uint32
	var data uint64
	if op != lxEpollCtlDel {
		b, err := g.readMem(evAddr, epollEventSize)
		if err != nil {
			return sErr(lxEFAULT)
		}
		events = le32(b)
		data = le64(b[epollEventSize-8:])
	}
	ep := ed.ep
	ep.mu.Lock()
	defer ep.mu.Unlock()
	reg, have := ep.interest[int(fd)]
	if have && reg.d != d {
		delete(ep.interest, int(fd)) // the fd was closed and reused
		reg.d.epw.done(ep)
		have = false
	}
	switch op {
	case lxEpollCtlAdd:
		if have {
			return sErr(lxEEXIST)
		}
		ep.interest[int(fd)] = &epollReg{d: d, events: events, data: data, stamp: unreported}
		d.epw.add(ep)
	case lxEpollCtlMod:
		if !have {
			return sErr(lxENOENT)
		}
		if reg.events&lxEpollExclusive != 0 {
			return sErr(lxEINVAL)
		}
		reg.events, reg.data, reg.stamp = events, data, unreported
	case lxEpollCtlDel:
		if !have {
			return sErr(lxENOENT)
		}
		delete(ep.interest, int(fd))
		d.epw.done(ep)
	default:
		return sErr(lxEINVAL)
	}
	return 0
}

// levelState is whether any registration is ready, ignoring EPOLLET, for an
// epoll instance polled itself.
func (ep *epoll) levelState(g *dguest) pollState {
	ep.mu.Lock()
	regs := make([]*epollReg, 0, len(ep.interest))
	for _, r := range ep.interest {
		regs = append(regs, r)
	}
	ep.mu.Unlock()
	var st pollState
	for _, r := range regs {
		if r.d.refs.Load() <= 0 || r.d.ep == ep {
			continue
		}
		s := g.pollOf(r.d)
		st.stamp += s.stamp
		if s.mask&uint16(r.events|lxEpollErr|lxEpollHup) != 0 {
			st.mask = pollInSet
		}
	}
	return st
}

// collect reports up to max ready registrations as packed epoll_events,
// applying EPOLLET and EPOLLONESHOT unless only looking (consume false).
func (ep *epoll) collect(g *dguest, max int, consume bool) (out []byte) {
	ep.mu.Lock()
	fds := make([]int, 0, len(ep.interest))
	for fd, r := range ep.interest {
		if r.d.refs.Load() <= 0 {
			delete(ep.interest, fd)
			continue
		}
		fds = append(fds, fd)
	}
	ep.mu.Unlock()
	slices.Sort(fds)
	for _, fd := range fds {
		ep.mu.Lock()
		r, ok := ep.interest[fd]
		ep.mu.Unlock()
		if !ok || r.events&^(lxEpollEt|lxEpollOneshot|lxEpollExclusive|lxEpollWakeup) == 0 {
			continue
		}
		st := g.pollOf(r.d)
		mask := uint32(st.mask) & (r.events | lxEpollErr | lxEpollHup)
		if mask == 0 {
			continue
		}
		ep.mu.Lock()
		if r.events&lxEpollEt != 0 && st.stamp == r.stamp {
			ep.mu.Unlock()
			continue
		}
		if consume {
			r.stamp = st.stamp
			if r.events&lxEpollOneshot != 0 {
				r.events &= lxEpollEt | lxEpollOneshot | lxEpollExclusive | lxEpollWakeup
			}
		}
		data := r.data
		ep.mu.Unlock()
		e := make([]byte, epollEventSize)
		put32(e, mask)
		put64(e[epollEventSize-8:], data)
		out = append(out, e...)
		if len(out)/epollEventSize >= max {
			break
		}
	}
	return out
}

func (g *dguest) epollWait(epfd int64, evAddr uint64, maxEvents, timeout int64) int64 {
	ed, ok := g.ft.get(int(epfd))
	if !ok {
		return sErr(lxEBADF)
	}
	if ed.ep == nil || maxEvents <= 0 || maxEvents > 1<<20 {
		return sErr(lxEINVAL)
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(time.Duration(timeout) * time.Millisecond)
	}
	// The events the guest's buffer has room for before it stops being
	// writable: Linux copies them one at a time and leaves on the ready list
	// the ones from the first it cannot write on, failing with EFAULT if it
	// wrote none.
	fit := int(g.writablePrefix(evAddr, uint64(maxEvents)*epollEventSize) / epollEventSize)
	n := g.netState()
	for {
		ch := n.watch()
		out := ed.ep.collect(g, max(fit, 1), fit > 0)
		if len(out) > 0 && fit == 0 {
			return sErr(lxEFAULT)
		}
		if len(out) > 0 || timeout == 0 {
			if len(out) > 0 {
				if err := g.writeMem(evAddr, out); err != nil {
					return sErr(lxEFAULT)
				}
			}
			return int64(len(out) / epollEventSize)
		}
		switch e := g.waitOn(ch, deadline); e {
		case 0:
		case lxEAGAIN:
			timeout = 0
		case errRestart:
			return sErr(lxEINTR)
		default:
			return sErr(e)
		}
	}
}

// close releases what the instance holds besides its file: its place in the
// watched descriptions.
func (ep *epoll) close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for gfd, r := range ep.interest {
		delete(ep.interest, gfd)
		r.d.epw.done(ep)
	}
}

// forget drops every registration of description d, which is being released.
func (ep *epoll) forget(d *dfile) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for gfd, r := range ep.interest {
		if r.d == d {
			delete(ep.interest, gfd)
			d.epw.done(ep)
		}
	}
}
