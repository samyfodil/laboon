package sandbox

import (
	"strconv"
	"sync"
	"time"
)

// Guest terminals are supervisor objects: a pty pair (/dev/ptmx, /dev/pts/N)
// is a line discipline (lx_ldisc.go) between two queues, so its echo, signals,
// job control and window size follow Linux whatever the host's terminals do.
// A Windows host console, when the run's stdio is one, is the same with the
// console in raw VT mode on the other side (console_windows.go). Each device
// sits under its hub (tty_unix.go, tty_windows.go), which wakes reads, writes
// and readiness waits on it.

// ttyDev is one terminal: /dev/pts/<idx>.
type ttyDev struct {
	*ttyHub
	ts  *termState
	fs  *dfs
	mu  *sync.Mutex // the hub's lock, held for everything below
	idx int
	ld  *ldisc

	sid, pgrp int // the session it controls (0: none) and its foreground group

	locked    bool // the slave cannot be opened until TIOCSPTLCK clears it
	masters   int  // open master descriptions
	slaves    int  // open slave descriptions
	slaveSeen bool // a slave was opened: the master reads EIO once all close
	hungup    bool // the master is gone: slaves read EOF and fail writes
	stamp     uint64
	excl      bool

	con ttyConsole // the host console behind it; nil for a pty
}

// ttyConsole is a host console a terminal's slave side writes to directly.
type ttyConsole interface {
	write(d *ttyDev, b []byte) lxErrno
	flush(d *ttyDev)
	close()
}

// ptyOutMax bounds a pty's output a master has not read; writers wait.
const ptyOutMax = 64 << 10

// pollState is a Linux poll mask now and a stamp that changes whenever the
// mask may have (for EPOLLET).
type pollState struct {
	mask  uint16
	stamp uint64
}

const (
	pollInSet  = lxPollIn | lxPollRdnorm
	pollOutSet = lxPollOut | lxPollWrnorm
)

func (ts *termState) close() {
	ts.mu.Lock()
	devs := ts.devs
	ts.devs = nil
	ts.mu.Unlock()
	for _, d := range devs {
		if d.con != nil {
			d.con.close()
		}
		d.free()
	}
}

// newDev registers a terminal on hub at the lowest free index other than
// skip.
func (ts *termState) newDev(fs *dfs, hub *ttyHub, skip int) *ttyDev {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.devs == nil {
		ts.devs = map[int]*ttyDev{}
	}
	i := 0
	for ts.devs[i] != nil || i == skip {
		i++
	}
	d := &ttyDev{ttyHub: hub, ts: ts, fs: fs, mu: hub.mutex(), idx: i, ld: newLdisc()}
	ts.devs[i] = d
	return d
}

func (ts *termState) dev(i int) *ttyDev {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.devs[i]
}

// cttyOf is session sid's controlling terminal, nil if it has none.
func (ts *termState) cttyOf(sid int) *ttyDev {
	if sid == 0 {
		return nil
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for _, d := range ts.devs {
		d.mu.Lock()
		s := d.sid
		d.mu.Unlock()
		if s == sid {
			return d
		}
	}
	return nil
}

func (d *ttyDev) name() string { return "/dev/pts/" + strconv.Itoa(d.idx) }

// ptmx is one open description of a terminal: its master side or a slave
// side (a /dev/pts/N, /dev/tty or the console as stdio).
type ptmx struct {
	dev    *ttyDev
	master bool
}

func (p *ptmx) close() {
	d := p.dev
	d.mu.Lock()
	if p.master {
		d.masters--
		if d.masters == 0 {
			d.hungup = true
		}
	} else {
		d.slaves--
	}
	gone := d.masters == 0 && d.slaves == 0 && d.con == nil
	sid, fg := d.sid, d.pgrp
	if p.master && d.masters == 0 {
		d.sid, d.pgrp = 0, 0
	}
	d.touch()
	d.mu.Unlock()
	if p.master && d.masters == 0 && sid != 0 {
		// A hangup: the session's foreground group gets SIGHUP and SIGCONT.
		if fg > 0 {
			d.fs.signalPgrp(fg, sigHUP)
			d.fs.signalPgrp(fg, sigCONT)
		}
	}
	if gone {
		d.ts.mu.Lock()
		mine := d.ts.devs[d.idx] == d
		if mine {
			delete(d.ts.devs, d.idx)
		}
		d.ts.mu.Unlock()
		if mine {
			d.free()
		}
	}
}

// signalPgrp sends sig to every process of guest process group pgrp, as a
// terminal signals its foreground group.
func (fs *dfs) signalPgrp(pgrp, sig int) {
	sr := fs.sigs()
	if sr == nil || pgrp <= 0 {
		return
	}
	for _, pid := range fs.pidsInPgrp(pgrp) {
		if p := sr.proc(pid); p != nil {
			sr.send(p, nil, sig, sigInfo{code: siKernel}, nil)
		}
	}
}

// endSession runs when the controlling process of session sid exits: its
// terminal's foreground group gets SIGHUP and the terminal no longer belongs
// to the session.
func (fs *dfs) endSession(sid int) {
	d := fs.term.cttyOf(sid)
	if d == nil {
		return
	}
	d.mu.Lock()
	fg := d.pgrp
	if d.sid == sid {
		d.sid, d.pgrp = 0, 0
	}
	d.mu.Unlock()
	if fg > 0 && fg != sid {
		fs.signalPgrp(fg, sigHUP)
	}
}

// ---- opening ------------------------------------------------------------------

// ptsDev parses a /dev/pts entry name.
func (g *dguest) ptsDev(s string) *ttyDev {
	if s == "" || len(s) > 6 || len(s) > 1 && s[0] == '0' {
		return nil
	}
	i, err := strconv.Atoi(s)
	if err != nil || i < 0 {
		return nil
	}
	return g.term.dev(i)
}

func (g *dguest) mySid() int {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	return g.ps.sid
}

func (g *dguest) myGroup() (pgid, sid int) {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	return g.ps.pgid, g.ps.sid
}

func (g *dguest) openPtmx(flags int64) int64 {
	d, e := g.newTTY()
	if e != 0 {
		return sErr(e)
	}
	d.mu.Lock()
	d.locked, d.masters = true, 1
	d.mu.Unlock()
	p := &ptmx{dev: d, master: true}
	f, e := d.sideFile(true, "/dev/ptmx")
	if e != 0 {
		p.close()
		return sErr(e)
	}
	return g.installTTY(&dfile{f: f, gp: "/dev/ptmx", stub: -1, tty: true, pty: p}, flags)
}

// openSlave opens a slave side of d named gp. Without O_NOCTTY a session
// leader with no controlling terminal acquires d, as on Linux.
func (g *dguest) openSlave(d *ttyDev, gp string, flags int64) int64 {
	d.mu.Lock()
	if d.locked || d.hungup && d.con == nil {
		d.mu.Unlock()
		return sErr(lxEIO)
	}
	d.slaves++
	d.slaveSeen = true
	d.touch()
	d.mu.Unlock()
	p := &ptmx{dev: d}
	f, e := d.sideFile(false, gp)
	if e != 0 {
		p.close()
		return sErr(e)
	}
	fd := g.installTTY(&dfile{f: f, gp: gp, stub: -1, tty: true, pty: p}, flags)
	if fd >= 0 && flags&lxONoctty == 0 {
		g.acquireCtty(d, false)
	}
	return fd
}

func (g *dguest) installTTY(d *dfile, flags int64) int64 {
	d.nonblock.Store(flags&lxONonblock != 0)
	d.fx.oflags, d.fx.hasFlags = flags&lxOStatusKeep|lxOLargefile, true
	fd := g.ft.add(d, 0)
	if fd >= 0 && flags&lxOCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	return int64(fd)
}

// acquireCtty makes d the caller's session's controlling terminal when the
// caller leads a session without one and d controls none (or steal, for
// TIOCSCTTY with arg 1). It reports Linux's errno for TIOCSCTTY.
func (g *dguest) acquireCtty(d *ttyDev, steal bool) lxErrno {
	pgid, sid := g.myGroup()
	if sid != g.tgid {
		return lxEPERM
	}
	if cur := g.term.cttyOf(sid); cur != nil {
		if cur == d {
			return 0
		}
		return lxEPERM
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sid != 0 && d.sid != sid && !steal {
		return lxEPERM
	}
	d.sid, d.pgrp = sid, pgid
	return 0
}

// ptyStat is fstat of a terminal description: the device its name resolves
// to, so it matches stat of that name (ttyname compares the two).
func (g *dguest) ptyStat(d *dfile) (lxStat, lxErrno) {
	return g.statGuest(d.gp)
}

// ---- job control ----------------------------------------------------------------

// jobCheck applies Linux's rules for a process outside the foreground group of
// its controlling terminal d: a read (SIGTTIN), or a write or a settings
// change (SIGTTOU) stops its group, unless the signal is ignored or blocked,
// which makes a read fail with EIO and lets the rest go ahead. ok means go
// ahead; otherwise r is the syscall's result.
func (g *dguest) jobCheck(d *ttyDev, sig int) (r int64, ok bool) {
	pgid, sid := g.myGroup()
	d.mu.Lock()
	mine := d.sid != 0 && d.sid == sid
	fg := d.pgrp
	d.mu.Unlock()
	if !mine || fg == pgid {
		return 0, true
	}
	sr := g.sigs()
	p := sr.proc(g.tgid)
	if p == nil {
		return 0, true
	}
	if sr.act(p, sig).handler == sigIgn || sr.ld(tOff(g.slot)+stMask)&sigBit(sig) != 0 {
		if sig == sigTTIN {
			return sErr(lxEIO), false
		}
		return 0, true
	}
	g.dfs.signalPgrp(pgid, sig)
	return restartSys, false
}

// ---- reading and writing ----------------------------------------------------------

func (g *dguest) termRead(df *dfile, bufAddr uint64, n int64) (int64, bool) {
	if df.pty == nil {
		return 0, false
	}
	if df.pty.master {
		return g.masterRead(df, bufAddr, n), true
	}
	return g.slaveRead(df, bufAddr, n), true
}

func (g *dguest) termWrite(df *dfile, bufAddr uint64, n int64) (int64, bool) {
	if df.pty == nil {
		return 0, false
	}
	if df.pty.master {
		return g.masterWrite(df, bufAddr, n), true
	}
	return g.slaveWrite(df, bufAddr, n), true
}

// waitErr turns a terminal wait's result into a read or write's.
func waitErr(e lxErrno) int64 {
	if e == errRestart {
		return restartSys
	}
	return sErr(e)
}

func (g *dguest) slaveRead(df *dfile, bufAddr uint64, n int64) int64 {
	d := df.pty.dev
	if r, ok := g.jobCheck(d, sigTTIN); !ok {
		return r
	}
	d.mu.Lock()
	var deadline time.Time
	last := 0
	if l := d.ld; !l.canon() && l.cc(lxVMIN) == 0 && l.cc(lxVTIME) > 0 {
		deadline = time.Now().Add(time.Duration(l.cc(lxVTIME)) * 100 * time.Millisecond)
	}
	var b []byte
	for {
		l := d.ld
		if d.hungup && d.con == nil {
			d.mu.Unlock()
			return 0
		}
		if l.canon() && l.readable() {
			var eof bool
			if b, eof = l.take(int(n)); eof {
				d.touch()
				d.mu.Unlock()
				return 0
			}
			break
		}
		if !l.canon() {
			vmin, vtime := int(l.cc(lxVMIN)), time.Duration(l.cc(lxVTIME))*100*time.Millisecond
			have := len(l.ready)
			if vmin > 0 && vtime > 0 && have > last {
				deadline, last = time.Now().Add(vtime), have // the inter-byte timer
			}
			expired := !deadline.IsZero() && !time.Now().Before(deadline)
			if vmin == 0 && vtime == 0 || have > 0 && have >= min(vmin, int(n)) || expired ||
				have > 0 && df.nonblock.Load() {
				b, _ = l.take(int(n))
				break
			}
		}
		if df.nonblock.Load() {
			d.mu.Unlock()
			return sErr(lxEAGAIN)
		}
		if e := g.ttyWait(d, deadline); e != 0 && e != lxEAGAIN {
			d.mu.Unlock()
			return waitErr(e)
		}
	}
	if len(b) > 0 {
		d.touch()
	}
	d.mu.Unlock()
	if len(b) > 0 && g.putBuf(bufAddr, b) != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(b))
}

func (g *dguest) slaveWrite(df *dfile, bufAddr uint64, n int64) int64 {
	d := df.pty.dev
	if n < 0 {
		return sErr(lxEINVAL)
	}
	d.mu.Lock()
	tostop := d.ld.t.lflag&lxTOSTOP != 0
	d.mu.Unlock()
	if tostop {
		if r, ok := g.jobCheck(d, sigTTOU); !ok {
			return r
		}
	}
	var total int64
	for total < n || n == 0 {
		buf := g.ioBuf(int(min(n-total, 4096)))
		if err := g.getBuf(bufAddr+uint64(total), buf); err != nil {
			if total == 0 {
				return sErr(lxEFAULT)
			}
			break
		}
		var e lxErrno
		if d.con != nil {
			e = d.con.write(d, buf)
		} else {
			e = g.ptyOut(df, buf)
		}
		if e != 0 {
			if total > 0 {
				break
			}
			if e == errRestart {
				return restartSys
			}
			return sErr(e)
		}
		total += int64(len(buf))
		if n == 0 {
			break
		}
	}
	return total
}

// ptyOut queues a slave's write for the master, waiting while the master
// has a full buffer unread.
func (g *dguest) ptyOut(df *dfile, b []byte) lxErrno {
	d := df.pty.dev
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		if d.hungup {
			return lxEIO
		}
		if len(d.ld.out) < ptyOutMax {
			break
		}
		if df.nonblock.Load() {
			return lxEAGAIN
		}
		if e := g.ttyWait(d, time.Time{}); e != 0 {
			return e
		}
	}
	d.ld.output(b)
	d.touch()
	return 0
}

func (g *dguest) masterRead(df *dfile, bufAddr uint64, n int64) int64 {
	d := df.pty.dev
	d.mu.Lock()
	var b []byte
	for {
		if b = d.ld.takeOut(int(n)); len(b) > 0 {
			d.touch()
			break
		}
		if d.slaveSeen && d.slaves == 0 {
			d.mu.Unlock()
			return sErr(lxEIO)
		}
		if df.nonblock.Load() {
			d.mu.Unlock()
			return sErr(lxEAGAIN)
		}
		if e := g.ttyWait(d, time.Time{}); e != 0 {
			d.mu.Unlock()
			return waitErr(e)
		}
	}
	d.mu.Unlock()
	if g.putBuf(bufAddr, b) != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(b))
}

func (g *dguest) masterWrite(df *dfile, bufAddr uint64, n int64) int64 {
	d := df.pty.dev
	if n < 0 {
		return sErr(lxEINVAL)
	}
	var total int64
	for total < n {
		buf := g.ioBuf(int(min(n-total, 4096)))
		if err := g.getBuf(bufAddr+uint64(total), buf); err != nil {
			if total == 0 {
				return sErr(lxEFAULT)
			}
			break
		}
		d.mu.Lock()
		for d.ld.room() == 0 && !d.ld.canon() {
			if df.nonblock.Load() || total > 0 {
				d.mu.Unlock()
				if total > 0 {
					return total
				}
				return sErr(lxEAGAIN)
			}
			if e := g.ttyWait(d, time.Time{}); e != 0 {
				d.mu.Unlock()
				return waitErr(e)
			}
		}
		if !d.ld.canon() {
			buf = buf[:min(len(buf), d.ld.room())]
		}
		sigs := d.ld.receive(buf)
		fg := d.pgrp
		d.touch()
		d.mu.Unlock()
		for _, s := range sigs {
			g.dfs.signalPgrp(fg, s)
		}
		total += int64(len(buf))
	}
	return total
}

// ---- readiness ----------------------------------------------------------------

func (p *ptmx) pollState() pollState {
	d := p.dev
	d.mu.Lock()
	defer d.mu.Unlock()
	return pollState{mask: d.mask(p.master), stamp: d.stamp}
}

// mask is the poll mask of d's master or slave side. d.mu is held.
func (d *ttyDev) mask(master bool) uint16 {
	var m uint16
	if master {
		if len(d.ld.out) > 0 && !d.ld.stopped {
			m |= pollInSet
		}
		if d.slaveSeen && d.slaves == 0 {
			m |= lxPollHup
		}
		if d.ld.canon() || d.ld.room() > 0 {
			m |= pollOutSet
		}
		return m
	}
	if d.hungup && d.con == nil {
		return pollInSet | pollOutSet | lxPollHup | lxPollErr
	}
	if d.ld.readable() {
		m |= pollInSet
	}
	if d.con != nil || len(d.ld.out) < ptyOutMax {
		m |= pollOutSet
	}
	return m
}

// ---- ioctls -------------------------------------------------------------------

// ptyIoctl serves the terminal requests on a supervisor terminal.
func (g *dguest) ptyIoctl(df *dfile, req, arg uint64) int64 {
	req = uint64(uint32(req)) // the kernel takes an unsigned int; musl's sign-extends
	p := df.pty
	d := p.dev
	if p.master {
		switch req {
		case lxTIOCGPTN:
			return g.ttyPutU32(arg, uint32(d.idx))
		case lxTIOCSPTLCK:
			b, err := g.readMem(arg, 4)
			if err != nil {
				return sErr(lxEFAULT)
			}
			d.mu.Lock()
			d.locked = le32(b) != 0
			d.mu.Unlock()
			return 0
		case lxTIOCGPTLCK:
			d.mu.Lock()
			v := uint32(0)
			if d.locked {
				v = 1
			}
			d.mu.Unlock()
			return g.ttyPutU32(arg, v)
		case lxTIOCGPTPEER:
			d.mu.Lock()
			locked := d.locked
			d.mu.Unlock()
			if locked {
				return sErr(lxEIO)
			}
			return g.openSlave(d, d.name(), int64(arg)|lxONoctty)
		}
	} else {
		switch req {
		case lxTIOCGPTN, lxTIOCSPTLCK, lxTIOCGPTLCK, lxTIOCGPTPEER:
			return sErr(lxENOTTY)
		}
	}
	switch req {
	case lxTCGETS, lxTCGETS2:
		d.mu.Lock()
		b := d.ld.t.encode(req == lxTCGETS2)
		d.mu.Unlock()
		return g.putMem(arg, b)
	case lxTCSETS, lxTCSETSW, lxTCSETSF, lxTCSETS2, lxTCSETSW2, lxTCSETSF2:
		two := req >= lxTCSETS2
		size := 36
		if two {
			size = 44
		}
		b, err := g.readMem(arg, size)
		if err != nil {
			return sErr(lxEFAULT)
		}
		if !p.master {
			if r, ok := g.jobCheck(d, sigTTOU); !ok {
				return r
			}
		}
		d.mu.Lock()
		t := d.ld.t
		t.setFrom(decodeLxTermios(b), two)
		if d.con == nil {
			// A Linux pty keeps 8 bits and the receiver on, with no parity.
			t.cflag = t.cflag&^(lxCSIZE|lxPARENB) | lxCS8 | lxCREAD
		}
		if req == lxTCSETSF || req == lxTCSETSF2 {
			d.ld.flushIn()
		}
		d.ld.setTermios(t)
		d.touch()
		d.mu.Unlock()
		return 0
	case lxTIOCGWINSZ:
		d.mu.Lock()
		ws := d.ld.ws
		d.mu.Unlock()
		var b [8]byte
		for i, v := range ws {
			b[2*i], b[2*i+1] = byte(v), byte(v>>8)
		}
		return g.putMem(arg, b[:])
	case lxTIOCSWINSZ:
		b, err := g.readMem(arg, 8)
		if err != nil {
			return sErr(lxEFAULT)
		}
		var ws [4]uint16
		for i := range ws {
			ws[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		d.setWinsize(ws)
		return 0
	case lxFIONREAD:
		d.mu.Lock()
		v := d.ld.avail()
		if p.master {
			v = len(d.ld.out)
		}
		d.mu.Unlock()
		return g.ttyPutU32(arg, uint32(v))
	case lxTIOCOUTQ:
		d.mu.Lock()
		v := len(d.ld.out)
		if p.master {
			v = 0
		}
		d.mu.Unlock()
		return g.ttyPutU32(arg, uint32(v))
	case lxTCFLSH:
		if arg > 2 {
			return sErr(lxEINVAL)
		}
		if !p.master {
			if r, ok := g.jobCheck(d, sigTTOU); !ok {
				return r
			}
		}
		in, out := arg == 0 || arg == 2, arg == 1 || arg == 2
		if p.master {
			in, out = out, in
		}
		d.mu.Lock()
		if in {
			d.ld.flushIn()
		}
		if out {
			d.ld.out = nil
		}
		d.touch()
		d.mu.Unlock()
		return 0
	case lxTCXONC:
		if arg > 3 {
			return sErr(lxEINVAL)
		}
		d.mu.Lock()
		switch arg {
		case 0:
			d.ld.stopped = true
		case 1:
			d.ld.stopped = false
		case 2, 3:
			c := d.ld.cc(lxVSTOP)
			if arg == 3 {
				c = d.ld.cc(lxVSTART)
			}
			if c != 0 && !p.master {
				d.ld.out = append(d.ld.out, c)
			}
		}
		d.touch()
		d.mu.Unlock()
		if d.con != nil {
			d.con.flush(d)
		}
		return 0
	case lxTCSBRK, lxTCSBRKP:
		if arg == 0 || req == lxTCSBRKP {
			ms := 250
			if req == lxTCSBRKP && arg != 0 {
				ms = int(arg) * 100
			}
			g.sleepIntr(time.Duration(ms) * time.Millisecond)
		}
		return 0
	case lxTIOCSBRK, lxTIOCCBRK:
		return 0
	case lxTIOCEXCL, lxTIOCNXCL:
		d.mu.Lock()
		d.excl = req == lxTIOCEXCL
		d.mu.Unlock()
		return 0
	case lxTIOCGEXCL:
		d.mu.Lock()
		v := uint32(0)
		if d.excl {
			v = 1
		}
		d.mu.Unlock()
		return g.ttyPutU32(arg, v)
	case lxTIOCSTI:
		return sErr(lxEIO) // as Linux with legacy_tiocsti=0
	case lxTIOCGETD:
		return g.ttyPutU32(arg, 0) // N_TTY
	case lxTIOCSETD:
		b, err := g.readMem(arg, 4)
		if err != nil {
			return sErr(lxEFAULT)
		}
		if le32(b) != 0 {
			return sErr(lxEINVAL)
		}
		return 0
	case lxTIOCGPGRP, lxTIOCGSID:
		_, sid := g.myGroup()
		d.mu.Lock()
		dsid, fg := d.sid, d.pgrp
		d.mu.Unlock()
		if !p.master && (dsid == 0 || dsid != sid) || dsid == 0 {
			return sErr(lxENOTTY)
		}
		v := fg
		if req == lxTIOCGSID {
			v = dsid
		}
		return g.ttyPutU32(arg, uint32(v))
	case lxTIOCSPGRP:
		_, sid := g.myGroup()
		d.mu.Lock()
		dsid := d.sid
		d.mu.Unlock()
		if dsid == 0 || dsid != sid {
			return sErr(lxENOTTY)
		}
		if r, ok := g.jobCheck(d, sigTTOU); !ok {
			return r
		}
		b, err := g.readMem(arg, 4)
		if err != nil {
			return sErr(lxEFAULT)
		}
		pg := int(int32(le32(b)))
		if pg < 0 {
			return sErr(lxEINVAL)
		}
		if e := g.groupInSession(pg, sid); e != 0 {
			return sErr(e)
		}
		d.mu.Lock()
		d.pgrp = pg
		d.mu.Unlock()
		return 0
	case lxTIOCSCTTY:
		return sErr(g.acquireCtty(d, arg == 1))
	case lxTIOCNOTTY:
		_, sid := g.myGroup()
		d.mu.Lock()
		mine := d.sid != 0 && d.sid == sid
		fg := d.pgrp
		if mine && sid == g.tgid {
			d.sid, d.pgrp = 0, 0
		}
		d.mu.Unlock()
		if !mine {
			return sErr(lxENOTTY)
		}
		if sid == g.tgid && fg > 0 {
			g.dfs.signalPgrp(fg, sigHUP)
			g.dfs.signalPgrp(fg, sigCONT)
		}
		return 0
	}
	return sErr(lxENOTTY)
}

// groupInSession checks that process group pg exists (ESRCH) and is in
// session sid (EPERM), as TIOCSPGRP requires.
func (g *dguest) groupInSession(pg, sid int) lxErrno {
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	e := lxESRCH
	for _, p := range fs.pt {
		if !p.zombie && p.pgid == pg {
			if p.sid == sid {
				return 0
			}
			e = lxEPERM
		}
	}
	return e
}

// setWinsize records a new window size; a change sends SIGWINCH to the
// foreground group.
func (d *ttyDev) setWinsize(ws [4]uint16) {
	d.mu.Lock()
	changed := d.ld.ws != ws
	d.ld.ws = ws
	fg := d.pgrp
	d.mu.Unlock()
	if changed && fg > 0 {
		d.fs.signalPgrp(fg, sigWINCH)
	}
}

func (g *dguest) ttyPutU32(addr uint64, v uint32) int64 {
	var b [4]byte
	put32(b[:], v)
	return g.putMem(addr, b[:])
}
