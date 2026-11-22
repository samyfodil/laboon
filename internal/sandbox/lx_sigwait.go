package sandbox

import "time"

// sigsuspend and sigtimedwait served on the signal records, for a stub that
// does not serve them itself: Linux's, and darwin's HVF stub.

const (
	lxRtSigsuspend   = 133
	lxRtSigtimedwait = 137
)

func init() {
	syscalls[lxRtSigsuspend] = func(g *dguest, a [6]uint64) int64 { return g.rtSigsuspend(a[0], a[1]) }
	syscalls[lxRtSigtimedwait] = func(g *dguest, a [6]uint64) int64 { return g.rtSigtimedwait(a[0], a[1], a[2], a[3]) }
}

// rtSigsuspend waits under the given mask until a signal is to be taken; the
// stub delivers it and restores the real mask on the way out.
func (g *dguest) rtSigsuspend(maskAddr, size uint64) int64 {
	if e := g.sigSwapMask(maskAddr, size); e != 0 {
		return sErr(e)
	}
	g.waitSignal(-1)
	return sErr(errRestartNoHand)
}

// waitSignal blocks until a signal is to be taken or d passes (negative: no
// limit).
func (g *dguest) waitSignal(d time.Duration) {
	var deadline time.Time
	if d >= 0 {
		deadline = time.Now().Add(d)
	}
	t := g.sigs().thread(g.pid)
	for !g.sigIntr() {
		if !g.awaitKick(t, deadline) {
			return
		}
	}
}

// awaitKick blocks until t is kicked (a signal for it was sent; the kick
// channel holds one), the guest is torn down, or deadline passes (zero: none).
// It reports whether to look again: false once the deadline or the guest is
// gone.
func (g *dguest) awaitKick(t *sigThread, deadline time.Time) bool {
	var kick chan struct{}
	if t != nil {
		kick = t.kick()
	}
	var expired <-chan time.Time
	if !deadline.IsZero() {
		left := time.Until(deadline)
		if left <= 0 {
			return false
		}
		tm := time.NewTimer(left)
		defer tm.Stop()
		expired = tm.C
	}
	select {
	case <-kick:
		return true
	case <-g.ch.done:
	case <-g.ch.stop:
	case <-expired:
	}
	return false
}

// rtSigtimedwait takes a pending signal in set, waiting for one up to the
// timeout. The signals of set wake the wait although blocked (the waitset).
func (g *dguest) rtSigtimedwait(setAddr, infoAddr, tsAddr, size uint64) int64 {
	if size != 8 {
		return sErr(lxEINVAL)
	}
	b, err := g.argRead(setAddr, 8)
	if err != nil {
		return sErr(lxEFAULT)
	}
	set := le64(b) &^ killStopMask
	d := time.Duration(-1)
	if tsAddr != 0 {
		ts, err := g.argRead(tsAddr, 16)
		if err != nil {
			return sErr(lxEFAULT)
		}
		d = time.Duration(le64(ts))*time.Second + time.Duration(le64(ts[8:]))
	}
	sr := g.sigs()
	o := tOff(g.slot)
	sr.st(o+stWaitset, set)
	defer sr.st(o+stWaitset, 0)
	var deadline time.Time
	if d >= 0 {
		deadline = time.Now().Add(d)
	}
	t := sr.thread(g.pid)
	for {
		if s, si := g.dequeue(set); s != 0 {
			if infoAddr != 0 {
				var ib [128]byte
				put32(ib[:], uint32(s))
				put32(ib[4:], uint32(si.errno))
				put32(ib[8:], uint32(si.code))
				put64(ib[16:], si.a)
				put64(ib[24:], si.b)
				if err := g.writeMem(infoAddr, ib[:]); err != nil {
					return sErr(lxEFAULT)
				}
			}
			return int64(s)
		}
		if g.sigIntr() || g.ch.dead() {
			return sErr(lxEINTR)
		}
		if !g.awaitKick(t, deadline) {
			if g.ch.dead() {
				return sErr(lxEINTR)
			}
			return sErr(lxEAGAIN)
		}
	}
}
