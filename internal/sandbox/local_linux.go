package sandbox

import (
	"crypto/rand"
	"time"

	"golang.org/x/sys/unix"
)

// The calls the macOS and Windows stubs serve without the supervisor (clocks,
// sleeps, futexes, the thread's tid address), served here for the Linux
// stub. Futexes are the host's own: the guest's memory is the stub's, so a
// futex call run in the stub thread (REP_HOST) waits and wakes natively,
// across processes for shared memory too.

const (
	lxSetTidAddress  = 96
	lxFutex          = 98
	lxNanosleep      = 101
	lxClockGettime   = 113
	lxClockGetres    = 114
	lxClockNanosleep = 115
	lxSchedYield     = 124
	lxGettimeofday   = 169
	lxGetrandom      = 278
)

func init() {
	syscalls[lxSetTidAddress] = func(g *dguest, a [6]uint64) int64 {
		g.mp.mu.Lock()
		g.mp.clearTid[g.pid] = a[0]
		g.mp.mu.Unlock()
		return int64(g.pid)
	}
	syscalls[lxFutex] = func(g *dguest, a [6]uint64) int64 { return g.futex(a) }
	syscalls[lxClockGettime] = func(g *dguest, a [6]uint64) int64 {
		if a[0] < 12 {
			return g.host(unix.SYS_CLOCK_GETTIME, a[0], a[1])
		}
		return g.putTimespec(a[1], clockNow(int64(int32(a[0]))))
	}
	syscalls[lxClockGetres] = func(g *dguest, a [6]uint64) int64 {
		if a[0] < 12 {
			return g.host(unix.SYS_CLOCK_GETRES, a[0], a[1])
		}
		if a[1] == 0 {
			return 0
		}
		return g.putTimespec(a[1], time.Nanosecond)
	}
	syscalls[lxGettimeofday] = func(g *dguest, a [6]uint64) int64 {
		if a[0] == 0 {
			return 0
		}
		now := time.Now()
		var b [16]byte
		put64(b[:], uint64(now.Unix()))
		put64(b[8:], uint64(now.Nanosecond()/1000))
		if g.writeMem(a[0], b[:]) != nil {
			return sErr(lxEFAULT)
		}
		return 0
	}
	syscalls[lxNanosleep] = func(g *dguest, a [6]uint64) int64 { return g.nanosleep(1, 0, a[0], a[1]) }
	syscalls[lxClockNanosleep] = func(g *dguest, a [6]uint64) int64 {
		return g.nanosleep(int64(int32(a[0])), a[1], a[2], a[3])
	}
	syscalls[lxSchedYield] = func(g *dguest, a [6]uint64) int64 { return 0 }
	syscalls[lxGetrandom] = func(g *dguest, a [6]uint64) int64 {
		b := make([]byte, min(a[1], 1<<20))
		rand.Read(b)
		if g.writeMem(a[0], b) != nil {
			return sErr(lxEFAULT)
		}
		return int64(len(b))
	}
	syscalls[lxMembarrier] = func(g *dguest, a [6]uint64) int64 {
		// The global barrier is host-wide: the supervisor issues it. The
		// private expedited barrier and its registration act on the guest's
		// process, so its hop thread issues them, in the guest's mm.
		const query, global, privExpedited, regPrivExpedited = 0, 1, 8, 16
		switch a[0] {
		case query:
			if a[1] != 0 {
				return sErr(lxEINVAL)
			}
			r, _, en := unix.Syscall(unix.SYS_MEMBARRIER, query, 0, 0)
			if en != 0 {
				return global
			}
			return int64(r) & (global | privExpedited | regPrivExpedited)
		case global:
			if _, _, en := unix.Syscall(unix.SYS_MEMBARRIER, global, 0, 0); en != 0 {
				return sErr(lxErrno(en))
			}
			return 0
		case privExpedited, regPrivExpedited:
			return g.host(unix.SYS_MEMBARRIER, a[0], a[1], a[2])
		}
		return sErr(lxEINVAL)
	}
}

const rseqUnregister = 1 // RSEQ_FLAG_UNREGISTER

// rseq registers the thread's restartable-sequence area with the host kernel,
// on the thread itself, which is the guest's: the host keeps its CPU number
// and aborts its critical sections, as Linux does. The registration is kept
// for a fork child, which inherits it, and for an execve, which ends it.
func (g *dguest) rseq(a [6]uint64) int64 {
	r := g.host(unix.SYS_RSEQ, a[0], a[1], a[2], a[3])
	if r == 0 {
		g.rseqReg = [3]uint64{a[0], a[1], a[3]}
		if a[2]&rseqUnregister != 0 {
			g.rseqReg = [3]uint64{}
		}
	}
	return r
}

// inheritRseq gives a fork child's thread the registration the forking thread
// had, which a copy of the stub's hop thread lacks.
func (g *dguest) inheritRseq() {
	if r := g.rseqReg; r[0] != 0 {
		g.host(unix.SYS_RSEQ, r[0], r[1], 0, r[2])
	}
}

// endRseq ends the thread's registration as an execve does, before the area
// goes with the old address space (the host would fault the thread writing
// its CPU number there).
func (g *dguest) endRseq() {
	if r := g.rseqReg; r[0] != 0 {
		g.host(unix.SYS_RSEQ, r[0], r[1], rseqUnregister, r[2])
		g.rseqReg = [3]uint64{}
	}
}

// getcpu runs on the guest's own thread, which is the host thread it names.
func (g *dguest) getcpu(cpu, node uint64) int64 { return g.host(unix.SYS_GETCPU, cpu, node, 0) }

func (g *dguest) putTimespec(addr uint64, d time.Duration) int64 {
	var b [16]byte
	put64(b[:], uint64(d/time.Second))
	put64(b[8:], uint64(d%time.Second))
	if g.writeMem(addr, b[:]) != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

// futex runs the guest's futex call natively in its stub thread. A wait a
// signal interrupts comes back as a restart, for the stub to deliver and
// restart or fail as the handler asks.
func (g *dguest) futex(a [6]uint64) int64 {
	r := g.host(unix.SYS_FUTEX, a[0], a[1], a[2], a[3], a[4], a[5])
	if r == -int64(unix.EINTR) {
		return sErr(errRestart)
	}
	return r
}

// nanosleep sleeps for the timespec at reqAddr on clock (absolute with
// TIMER_ABSTIME).
func (g *dguest) nanosleep(clock int64, flags, reqAddr, remAddr uint64) int64 {
	b, err := g.argRead(reqAddr, 16)
	if err != nil {
		return sErr(lxEFAULT)
	}
	sec, nsec := int64(le64(b)), int64(le64(b[8:]))
	if sec < 0 || nsec < 0 || nsec >= 1e9 {
		return sErr(lxEINVAL)
	}
	d := time.Duration(sec)*time.Second + time.Duration(nsec)
	if flags&timerAbstime != 0 {
		if d -= clockNow(clock); d <= 0 {
			return 0 // the time has passed (a negative wait has no limit)
		}
		return g.sleepUntil(time.Now().Add(d), 0, true)
	}
	return g.sleepUntil(time.Now().Add(d), remAddr, false)
}

// sleepUntil sleeps until end, or until a signal the stub must take (a
// handler, an end of the process, or any for a tracer to see) is pending; one
// ignored or stopping the process is acted on and the sleep goes on. Cut
// short, a relative sleep reports the time left to remAddr and returns
// ERESTART_RESTARTBLOCK with the rest of it as the thread's restart_syscall
// (a handler makes it EINTR), and an absolute one ERESTARTNOHAND, as Linux's
// hrtimer_nanosleep.
func (g *dguest) sleepUntil(end time.Time, remAddr uint64, absolute bool) int64 {
	for {
		left := time.Until(end)
		if left <= 0 {
			return 0
		}
		g.waitSignal(left)
		if g.ch.dead() {
			return 0
		}
		if left = time.Until(end); left <= 0 || !g.sigIntr() || !g.settle(^g.sigs().ld(tOff(g.slot)+stMask)) {
			continue
		}
		if absolute {
			return sErr(errRestartNoHand)
		}
		if remAddr != 0 && g.putTimespec(remAddr, left) != 0 {
			return sErr(lxEFAULT)
		}
		g.restart = func() int64 { return g.sleepUntil(end, remAddr, false) }
		return sErr(errRestartBlock)
	}
}
