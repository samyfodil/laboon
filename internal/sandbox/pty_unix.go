//go:build darwin || linux

package sandbox

import (
	"os"
	"slices"
	"strconv"
	"sync"
	"syscall"
)

// Guest terminals: /dev/ptmx, /dev/pts/N and /dev/tty. Each is a host terminal
// the supervisor opens: /dev/ptmx a host pty master, /dev/pts/N the host slave
// /dev/ttysNNN (N is the host's pty index, so names agree both ways), /dev/tty
// the supervisor's controlling terminal. Their line discipline is the host's.

// ptmx is the state of a guest pty master: its index and Linux's slave lock,
// kept here (the host slave is unlocked at once, since Darwin cannot re-lock).
//
// Until the guest first opens the slave the supervisor holds it open: a
// Darwin master whose slave was never opened rejects the terminal ioctls and
// blocks writes, where Linux serves and buffers them. The guest's first open
// releases it, so the master still sees the hangup when the guest's last
// slave fd closes.
type ptmx struct {
	ts     *termState
	n      int
	slave  string // host path of the slave
	locked bool
	hold   *os.File
}

// termState is a run's terminal state; it lives on the dfs so it dies with
// the run. ptmx are the pty masters this run created: their slaves, and the
// run's own stdio terminal, are the only host terminals a guest may open.
type termState struct {
	mu   sync.Mutex
	ptmx map[int]*ptmx
	ctl  map[uint64]*ttyCtl // controlling terminals by host rdev
}

// close releases what the guest left open when the run ends.
func (ts *termState) close() {
	ts.mu.Lock()
	ps := ts.ptmx
	ts.ptmx = nil
	ts.mu.Unlock()
	for _, p := range ps {
		p.release()
	}
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
		ctty := g.cttyPath()
		if ctty == "" {
			return sErr(lxENXIO), true
		}
		return g.openTTYPath(ctty, flags), true
	case major == 136:
		g.term.mu.Lock()
		p := g.term.ptmx[int(minor)]
		locked := p != nil && p.locked
		g.term.mu.Unlock()
		if locked {
			return sErr(lxEIO), true
		}
		fd := g.openTTYPath(n.host, flags)
		if p != nil && fd >= 0 {
			p.release()
		}
		return fd, true
	}
	return 0, false
}

// ptsVisible parses a /dev/pts entry name and reports whether the guest may see
// it: a slave of a ptmx this run created, or the run's stdio terminal. Other
// host terminals belong to other sessions of the user.
func (g *dguest) ptsVisible(s string) (int, bool) {
	if s == "" || len(s) > 6 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	for _, m := range g.ptsNums() {
		if m == n {
			return n, true
		}
	}
	return 0, false
}

// ptsNums are the pty slaves the guest may see, in order.
func (g *dguest) ptsNums() []int {
	g.term.mu.Lock()
	ns := make([]int, 0, len(g.term.ptmx)+1)
	for n := range g.term.ptmx {
		ns = append(ns, n)
	}
	g.term.mu.Unlock()
	if m, ok := hostPtsNum(g.cttyPath()); ok && !slices.Contains(ns, m) {
		ns = append(ns, m)
	}
	slices.Sort(ns)
	return ns
}

// cttyPath is the host path of the guest's controlling terminal: the run's
// stdio terminal (the host's /dev/tty is a different device node, so its fds
// would not match the terminal's).
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

// ttyLstat stats a guest terminal device on the host, so stat of its path and
// fstat of an fd open on it agree (ttyname compares them).
func (g *dguest) ttyLstat(gp string) (os.FileInfo, lxErrno, bool) {
	n, e, ok := g.pseudo(gp)
	if !ok || e != 0 || n.kind != pDev {
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

func (g *dguest) installTTY(d *dfile, flags int64) int64 {
	d.nonblock.Store(flags&lxONonblock != 0)
	d.fx.oflags, d.fx.hasFlags = flags&lxOStatusKeep|lxOLargefile, true
	fd := g.ft.add(d, 0)
	if flags&lxOCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	return int64(fd)
}

// openPtmx creates a pty pair on the host and returns its master. As on Linux
// the slave starts locked until TIOCSPTLCK clears it (unlockpt).
func (g *dguest) openPtmx(flags int64) int64 {
	f, slave, e := hostPtyOpen()
	if e != 0 {
		return sErr(e)
	}
	n, ok := hostPtsNum(slave)
	if !ok {
		f.Close()
		return sErr(lxEIO)
	}
	hold, err := os.OpenFile(slave, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		f.Close()
		return sErr(osErrno(err))
	}
	p := &ptmx{ts: &g.term, n: n, slave: slave, locked: true, hold: hold}
	g.term.mu.Lock()
	if g.term.ptmx == nil {
		g.term.ptmx = map[int]*ptmx{}
	}
	g.term.ptmx[n] = p
	g.term.mu.Unlock()
	return g.installTTY(&dfile{f: f, gp: "/dev/ptmx", stub: -1, tty: true, pty: p}, flags)
}

// close forgets a master once its description is gone.
func (p *ptmx) close() {
	p.release()
	p.ts.mu.Lock()
	if p.ts.ptmx[p.n] == p {
		delete(p.ts.ptmx, p.n)
	}
	p.ts.mu.Unlock()
}

func (p *ptmx) release() {
	p.ts.mu.Lock()
	h := p.hold
	p.hold = nil
	p.ts.mu.Unlock()
	if h != nil {
		h.Close()
	}
}

// ptmxIoctl serves the requests specific to a pty master; the rest (termios,
// window size) fall through to the terminal ones, which act on the pair.
func (g *dguest) ptmxIoctl(d *dfile, req, arg uint64) (int64, bool) {
	p := d.pty
	switch req {
	case lxTIOCGPTN:
		return g.ttyPutU32(arg, uint32(p.n)), true
	case lxTIOCSPTLCK:
		b, err := g.readMem(arg, 4)
		if err != nil {
			return sErr(lxEFAULT), true
		}
		lock := le32(b) != 0
		p.ts.mu.Lock()
		p.locked = lock
		p.ts.mu.Unlock()
		return 0, true
	case lxTIOCGPTLCK:
		p.ts.mu.Lock()
		v := uint32(0)
		if p.locked {
			v = 1
		}
		p.ts.mu.Unlock()
		return g.ttyPutU32(arg, v), true
	case lxTIOCGPTPEER:
		p.ts.mu.Lock()
		locked := p.locked
		p.ts.mu.Unlock()
		if locked {
			return sErr(lxEIO), true
		}
		fd := g.openTTYPath(p.slave, int64(arg))
		if fd >= 0 {
			p.release()
		}
		return fd, true
	}
	return 0, false
}

// termRead and termWrite serve a terminal's IO in the supervisor; darwin's
// terminals are host ones, read and written through their host files.
func (g *dguest) termRead(d *dfile, bufAddr uint64, n int64) (int64, bool) { return 0, false }

func (g *dguest) termWrite(d *dfile, bufAddr uint64, n int64) (int64, bool) { return 0, false }

// ptsDir is a devpts instance: ptmx and the pty slaves the guest may see, each
// backed by its host terminal.
func (g *dguest) ptsDir() *pnode {
	slave := func(n int) *pnode {
		return &pnode{kind: pDev, perm: 0o620, host: hostPtsPath(n), rdev: lxMakedev(136, uint64(n))}
	}
	return &pnode{
		kind: pDir, perm: 0o755,
		kids: func() []pchild {
			out := []pchild{{"ptmx", devNode("ptmx")}}
			for _, n := range g.ptsNums() {
				out = append(out, pchild{strconv.Itoa(n), slave(n)})
			}
			return out
		},
		look: func(name string) *pnode {
			if name == "ptmx" {
				return devNode("ptmx")
			}
			if n, ok := g.ptsVisible(name); ok {
				return slave(n)
			}
			return nil
		},
	}
}
