//go:build darwin || linux || windows

package sandbox

import "time"

const (
	lxClockGettime = 113
	lxClockGetres  = 114
)

// A CPU-time clock is CLOCK_PROCESS_CPUTIME_ID (2) or CLOCK_THREAD_CPUTIME_ID
// (3) of the caller, or a negative id naming a process or thread as Linux
// encodes it: ^pid<<3 | perthread<<2 | which, pid 0 meaning the caller.
const (
	cpuclockProf  = 0 // user + system time
	cpuclockVirt  = 1 // user time
	cpuclockSched = 2 // user + system time, to the nanosecond
)

func init() {
	syscalls[lxClockGettime] = func(g *dguest, a [6]uint64) int64 { return g.clockGettime(int32(a[0]), a[1]) }
	syscalls[lxClockGetres] = func(g *dguest, a [6]uint64) int64 { return g.clockGetres(int32(a[0]), a[1]) }
}

func isCPUClock(id int32) bool { return id == 2 || id == 3 || id < 0 }

// wallClock reports whether id is one of the clocks every process reads
// alike (realtime, monotonic, boot time and their variants).
func wallClock(id int32) bool { return id >= 0 && id <= 11 && !isCPUClock(id) && id != 10 }

func (g *dguest) clockGettime(id int32, addr uint64) int64 {
	if r, ok := g.hostClockGettime(id, addr); ok {
		return r
	}
	var d time.Duration
	switch {
	case wallClock(id):
		d = clockNow(int64(id))
	case isCPUClock(id):
		var e lxErrno
		if d, e = g.cpuClock(id); e != 0 {
			return sErr(e)
		}
	default:
		return sErr(lxEINVAL)
	}
	return g.putTimespec(addr, d)
}

func (g *dguest) clockGetres(id int32, addr uint64) int64 {
	if r, ok := g.hostClockGetres(id, addr); ok {
		return r
	}
	res := time.Nanosecond
	switch {
	case id == 5 || id == 6: // the coarse clocks tick
		res = time.Second / lxUserHZ
	case wallClock(id):
	case isCPUClock(id):
		which, _, _, e := g.cpuClockTarget(id, false)
		if e != 0 {
			return sErr(e)
		}
		if which != cpuclockSched {
			res = time.Second / lxUserHZ
		}
	default:
		return sErr(lxEINVAL)
	}
	if addr == 0 {
		return 0
	}
	return g.putTimespec(addr, res)
}

// cpuClockTarget decodes CPU-time clock id into what it measures and whose:
// a thread t, or a process ps. As on Linux, a thread clock names a thread of
// the caller's own process, and a process clock a process, except that
// clock_gettime takes the caller's own thread id for its process.
func (g *dguest) cpuClockTarget(id int32, gettime bool) (which int32, t *dguest, ps *pstate, e lxErrno) {
	var pid int
	thread := false
	switch {
	case id == 2:
		which = cpuclockSched
	case id == 3:
		which, thread = cpuclockSched, true
	case id < 0 && id&3 != 3:
		pid, thread, which = int(^(id >> 3)), id&4 != 0, id&3
	default:
		return 0, nil, nil, lxEINVAL
	}
	if pid == 0 {
		if thread {
			return which, g, nil, 0
		}
		return which, nil, g.ps, 0
	}
	gp, ok := g.nsToGlobal(pid)
	if !ok {
		return 0, nil, nil, lxEINVAL
	}
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if thread {
		if d := fs.procs[gp]; d != nil && d.g != nil && d.ps == g.ps {
			return which, d.g, nil, 0
		}
		return 0, nil, nil, lxEINVAL
	}
	if gettime && gp == g.pid {
		return which, nil, g.ps, 0
	}
	if p := fs.pt[gp]; p != nil {
		return which, nil, p, 0
	}
	return 0, nil, nil, lxEINVAL
}

// cpuClock reads CPU-time clock id from the host thread or process that
// runs its guest thread or process.
func (g *dguest) cpuClock(id int32) (time.Duration, lxErrno) {
	which, t, ps, e := g.cpuClockTarget(id, true)
	if e != 0 {
		return 0, e
	}
	var user, total time.Duration
	if t != nil {
		var ok bool
		if user, total, ok = t.threadCPU(); !ok {
			return 0, lxEINVAL
		}
	} else {
		user, total = g.procCPU(ps)
	}
	if which == cpuclockVirt {
		return user, 0
	}
	return total, 0
}

// procCPU is process ps's CPU time, user and total: its stub's, plus that of
// the stubs it exec'd away from; a process that has begun to exit keeps what
// it had used.
func (g *dguest) procCPU(ps *pstate) (user, total time.Duration) {
	fs := g.dfs
	fs.mu.Lock()
	exiting, ru, ospid, prev := ps.exiting, ps.ru, ps.ospid, ps.ruPrev
	fs.mu.Unlock()
	if exiting {
		return time.Duration(ru.utime), time.Duration(ru.utime + ru.stime)
	}
	user, total = hostProcCPU(ospid)
	return user + time.Duration(prev.utime), total + time.Duration(prev.utime+prev.stime)
}

func (g *dguest) putTimespec(addr uint64, d time.Duration) int64 {
	var b [16]byte
	put64(b[:], uint64(d/time.Second))
	put64(b[8:], uint64(d%time.Second))
	if g.writeMem(addr, b[:]) != nil {
		return sErr(lxEFAULT)
	}
	return 0
}
