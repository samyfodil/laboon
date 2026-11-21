//go:build darwin || linux

package sandbox

import (
	"os"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A guest pty (/dev/ptmx, /dev/pts/N) is a supervisor terminal (tty.go). The
// run's stdio terminal, when it is one, stays the host terminal it is: its
// line discipline is the host's (termios_unix.go), it keeps its host pty
// number in /dev/pts, and guest ptys never take that number.

// ttyHub is a terminal's lock, the channel its next change closes, and the
// host pipes its sides' readiness is mirrored on, so the host poll and epoll
// behind the guest's wait on them.
type ttyHub struct {
	mu   sync.Mutex
	bus  chan struct{}
	side [2]ttyReady // master, slave
}

func (h *ttyHub) mutex() *sync.Mutex { return &h.mu }

// ttyReady mirrors one side's poll mask on two host pipes: in holds a byte
// while the side is readable (or hung up), out is filled while it is not
// writable. A description's host file is a dup of in's read end; out's write
// end is what is watched for writability.
type ttyReady struct {
	inR, inW, outR, outW *os.File
	in, full             bool
}

func (r *ttyReady) set(mask uint16) {
	in := mask&(pollInSet|lxPollHup|lxPollErr) != 0
	full := mask&(pollOutSet|lxPollHup|lxPollErr) == 0
	if in != r.in {
		if in {
			r.inW.Write([]byte{1})
		} else {
			drainPipe(r.inR)
		}
		r.in = in
	}
	if full != r.full {
		if full {
			fillPipe(r.outW)
		} else {
			drainPipe(r.outR)
		}
		r.full = full
	}
}

func (r *ttyReady) close() {
	for _, f := range []*os.File{r.inR, r.inW, r.outR, r.outW} {
		if f != nil {
			f.Close()
		}
	}
}

func newTTYHub() (*ttyHub, lxErrno) {
	h := &ttyHub{bus: make(chan struct{})}
	for i := range h.side {
		r := &h.side[i]
		var err error
		if r.inR, r.inW, err = os.Pipe(); err == nil {
			r.outR, r.outW, err = os.Pipe()
		}
		if err != nil {
			h.free()
			return nil, osErrno(err)
		}
	}
	return h, 0
}

func (h *ttyHub) free() {
	for i := range h.side {
		h.side[i].close()
	}
}

// termState is a run's terminal state; it lives on the dfs so it dies with
// the run: its guest ptys by index, and the job-control state of the host
// terminals it uses as controlling terminals, by host rdev.
type termState struct {
	mu   sync.Mutex
	devs map[int]*ttyDev
	ctl  map[uint64]*ttyCtl
}

// touch wakes every waiter on d and mirrors its new readiness. d.mu is held.
func (d *ttyDev) touch() {
	d.stamp++
	close(d.bus)
	d.bus = make(chan struct{})
	d.side[0].set(d.mask(true))
	d.side[1].set(d.mask(false))
}

// ttyWait parks until the next change on d, a signal, the deadline or
// teardown. It is called and returns with d.mu held. 0 means look again.
func (g *dguest) ttyWait(d *ttyDev, deadline time.Time) lxErrno {
	ch := d.bus
	d.mu.Unlock()
	e := g.waitOn(ch, deadline)
	d.mu.Lock()
	return e
}

// waitOn parks until ch closes, a signal is pending (errRestart), deadline
// passes (lxEAGAIN; zero is none) or the guest is torn down (lxEINTR). A
// signal or teardown after the checks below kicks the thread, and the kick
// channel holds it.
func (g *dguest) waitOn(ch <-chan struct{}, deadline time.Time) lxErrno {
	var kick chan struct{}
	if t := g.sigs().thread(g.pid); t != nil {
		kick = t.kick()
	}
	if g.sigIntr() {
		return errRestart
	}
	if g.ch.dead() {
		return lxEINTR
	}
	var expired <-chan time.Time
	if !deadline.IsZero() {
		left := time.Until(deadline)
		if left <= 0 {
			return lxEAGAIN
		}
		tm := time.NewTimer(left)
		defer tm.Stop()
		expired = tm.C
	}
	select {
	case <-ch:
	case <-kick:
	case <-expired:
	case <-g.ch.done:
		return lxEINTR
	case <-g.ch.stop:
		return lxEINTR
	}
	if g.ch.dead() {
		return lxEINTR
	}
	if g.sigIntr() {
		return errRestart
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return lxEAGAIN
	}
	return 0
}

func (g *dguest) newTTY() (*ttyDev, lxErrno) {
	h, e := newTTYHub()
	if e != 0 {
		return nil, e
	}
	skip, ok := hostPtsNum(g.cttyPath())
	if !ok {
		skip = -1
	}
	d := g.term.newDev(g.dfs, h, skip)
	d.mu.Lock()
	d.touch()
	d.mu.Unlock()
	return d, 0
}

// sideFile is the host file behind a description of d's master or slave
// side: its own dup of the side's readiness pipe.
func (d *ttyDev) sideFile(master bool, gp string) (*os.File, lxErrno) {
	r := &d.side[1]
	if master {
		r = &d.side[0]
	}
	fd, err := unix.Dup(hostFd(r.inR))
	if err != nil {
		return nil, osErrno(err)
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), gp), 0
}

// readyOut is the host fd whose writability is the description's.
func (p *ptmx) readyOut() int {
	if p.master {
		return hostFd(p.dev.side[0].outW)
	}
	return hostFd(p.dev.side[1].outW)
}

// openTTY opens the guest terminal device gp, reporting false when gp is not
// one of them. A terminal is told by the device the path resolves to, as the
// kernel picks a driver by device number: the pty multiplexor, the controlling
// terminal, or a pty slave.
func (g *dguest) openTTY(gp string, flags int64) (int64, bool) {
	n, e, ok := g.pseudo(gp)
	if !ok || e != 0 || n.kind != pDev {
		return 0, false
	}
	switch major, minor := lxMajor(n.rdev), lxMinor(n.rdev); {
	case major == 5 && minor == 2:
		return g.openPtmx(flags), true
	case major == 5 && minor == 0:
		if d := g.term.cttyOf(g.mySid()); d != nil {
			return g.openSlave(d, "/dev/tty", flags|lxONoctty), true
		}
		ctty := g.cttyPath()
		if ctty == "" {
			return sErr(lxENXIO), true
		}
		return g.openTTYPath(ctty, flags), true
	case major == 136:
		if d := g.term.dev(int(minor)); d != nil {
			return g.openSlave(d, "/dev/pts/"+strconv.Itoa(int(minor)), flags), true
		}
		if n.host == "" {
			return sErr(lxENOENT), true
		}
		return g.openTTYPath(n.host, flags), true
	}
	return 0, false
}

// cttyPath is the host path of the run's stdio terminal (the host's /dev/tty
// is a different device node, so its fds would not match the terminal's).
func (g *dguest) cttyPath() string {
	for _, r := range []any{g.cfg.Stdin, g.cfg.Stdout, g.cfg.Stderr} {
		if f, ok := r.(*os.File); ok && f != nil && isHostTTY(hostFd(f)) {
			if p, err := hostTTYName(hostFd(f)); err == nil {
				return p
			}
		}
	}
	return ""
}

// ttyLstat stats a host terminal device the guest sees (the run's stdio
// terminal, /dev/tty, /dev/ptmx) on the host, so stat of its path and fstat of
// an fd open on it agree (ttyname compares them). Guest ptys have no host
// node; their stat is their pseudo node's.
func (g *dguest) ttyLstat(gp string) (os.FileInfo, lxErrno, bool) {
	n, e, ok := g.pseudo(gp)
	if !ok || e != 0 || n.kind != pDev || n.host == "" {
		return nil, 0, false
	}
	if major, minor := lxMajor(n.rdev), lxMinor(n.rdev); major != 136 && !(major == 5 && (minor == 0 || minor == 2)) {
		return nil, 0, false
	}
	fi, err := os.Stat(n.host)
	if err != nil {
		return nil, osErrno(err), true
	}
	return fi, 0, true
}

// openTTYPath opens a host terminal (never as the supervisor's controlling
// terminal) and installs it as a guest fd.
func (g *dguest) openTTYPath(host string, flags int64) int64 {
	f, err := os.OpenFile(host, goOpenFlags(flags)&^os.O_CREATE|syscall.O_NOCTTY, 0)
	if err != nil {
		return sErr(osErrno(err))
	}
	return g.installTTY(&dfile{f: f, gp: guestTTYName(host), stub: -1, tty: true}, flags)
}

// ptsDir is a devpts instance: ptmx, the run's guest ptys, and its stdio
// terminal under its host number.
func (g *dguest) ptsDir() *pnode {
	ts := &g.term
	node := func(i int) *pnode {
		if ts.dev(i) != nil {
			return &pnode{kind: pDev, perm: 0o620, rdev: lxMakedev(136, uint64(i))}
		}
		if m, ok := hostPtsNum(g.cttyPath()); ok && m == i {
			return &pnode{kind: pDev, perm: 0o620, host: hostPtsPath(i), rdev: lxMakedev(136, uint64(i))}
		}
		return nil
	}
	nums := func() []int {
		ts.mu.Lock()
		ns := make([]int, 0, len(ts.devs)+1)
		for i := range ts.devs {
			ns = append(ns, i)
		}
		ts.mu.Unlock()
		if m, ok := hostPtsNum(g.cttyPath()); ok && !slices.Contains(ns, m) {
			ns = append(ns, m)
		}
		slices.Sort(ns)
		return ns
	}
	return &pnode{
		kind: pDir, perm: 0o755,
		kids: func() []pchild {
			out := []pchild{{"ptmx", devNode("ptmx")}}
			for _, i := range nums() {
				if n := node(i); n != nil {
					out = append(out, pchild{strconv.Itoa(i), n})
				}
			}
			return out
		},
		look: func(name string) *pnode {
			if name == "ptmx" {
				return devNode("ptmx")
			}
			if name == "" || len(name) > 6 || len(name) > 1 && name[0] == '0' {
				return nil
			}
			i, err := strconv.Atoi(name)
			if err != nil || i < 0 {
				return nil
			}
			return node(i)
		},
	}
}
