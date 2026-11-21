//go:build darwin || linux || windows

package sandbox

import (
	"runtime"
	"time"
)

// Resource limits, usage accounting and scheduling attributes, kept per
// process in its pstate. Limits are inherited across fork and exec; the
// RLIMIT_NOFILE soft limit is enforced by the process's fd table. CPU usage is
// read from the host (proc_pid_rusage on the stub process).

const (
	lxSchedSetparam       = 118
	lxSchedSetscheduler   = 119
	lxSchedGetscheduler   = 120
	lxSchedGetparam       = 121
	lxSchedSetaffinity    = 122
	lxSchedGetaffinity    = 123
	lxSchedGetPriorityMax = 125
	lxSchedGetPriorityMin = 126
	lxSchedRrGetInterval  = 127
	lxSetpriority         = 140
	lxGetpriority         = 141
	lxTimes               = 153
	lxGetrlimit           = 163
	lxSetrlimit           = 164
	lxGetrusage           = 165

	rlimCount   = 16
	rlimInf     = ^uint64(0)
	rlimitStack = 3
	rlimitNofil = 7
	nrOpen      = 1 << 20 // fs.nr_open: the ceiling for RLIMIT_NOFILE
)

type rlimit struct{ cur, max uint64 }

func defaultRlimits() [rlimCount]rlimit {
	var r [rlimCount]rlimit
	for i := range r {
		r[i] = rlimit{rlimInf, rlimInf}
	}
	r[rlimitStack] = rlimit{8 << 20, rlimInf}
	r[4] = rlimit{0, rlimInf}                 // CORE
	r[6] = rlimit{maxSlots - 1, maxSlots - 1} // NPROC: the channel slot pool
	r[rlimitNofil] = rlimit{1024, 524288}     // NOFILE
	r[8] = rlimit{8 << 20, 8 << 20}           // MEMLOCK
	r[11] = rlimit{127516, 127516}            // SIGPENDING
	r[12] = rlimit{819200, 819200}            // MSGQUEUE
	r[13], r[14] = rlimit{0, 0}, rlimit{0, 0} // NICE, RTPRIO
	return r
}

// prlimit gets and/or sets one resource limit of process pid (0 = self).
// struct rlimit64 (and arm64's struct rlimit) is {u64 cur; u64 max}.
func (g *dguest) prlimit(pid int, res uint64, newAddr, oldAddr uint64) int64 {
	if res >= rlimCount {
		return sErr(lxEINVAL)
	}
	var nl rlimit
	if newAddr != 0 {
		b, err := g.argRead(newAddr, 16)
		if err != nil {
			return sErr(lxEFAULT)
		}
		nl = rlimit{le64(b), le64(b[8:])}
		if nl.cur > nl.max {
			return sErr(lxEINVAL)
		}
	}
	fs := g.dfs
	fs.mu.Lock()
	p, e := g.procOf(pid)
	if e != 0 || p.zombie {
		fs.mu.Unlock()
		return sErr(lxESRCH)
	}
	old := p.rlim[res]
	if newAddr != 0 {
		switch {
		case nl.max > old.max && !g.ps.cred.capable(24): // CAP_SYS_RESOURCE
			fs.mu.Unlock()
			return sErr(lxEPERM)
		case res == rlimitNofil && nl.max > nrOpen:
			fs.mu.Unlock()
			return sErr(lxEPERM)
		}
		p.rlim[res] = nl
		if res == rlimitNofil && p.ft != nil {
			p.ft.setMax(nl.cur)
		}
	}
	fs.mu.Unlock()
	if oldAddr != 0 {
		var b [16]byte
		put64(b[0:], old.cur)
		put64(b[8:], old.max)
		if g.writeMem(oldAddr, b[:]) != nil {
			return sErr(lxEFAULT)
		}
	}
	return 0
}

func (t *ftable) setMax(cur uint64) {
	t.mu.Lock()
	if cur >= nrOpen {
		t.max = nrOpen
	} else {
		t.max = int(cur)
	}
	t.mu.Unlock()
}

// ---- usage ------------------------------------------------------------------------

// rusage is the part of struct rusage the host can tell us: CPU times in ns,
// peak memory in KiB, and page-ins as major faults.
type rusage struct {
	utime, stime int64
	maxrss       int64
	majflt       int64
}

func (r rusage) plus(o rusage) rusage {
	return rusage{r.utime + o.utime, r.stime + o.stime, max(r.maxrss, o.maxrss), r.majflt + o.majflt}
}

// linux encodes the 144-byte arm64 struct rusage.
func (r rusage) linux() []byte {
	b := make([]byte, 144)
	put64(b[0:], uint64(r.utime/1e9))
	put64(b[8:], uint64(r.utime%1e9/1e3))
	put64(b[16:], uint64(r.stime/1e9))
	put64(b[24:], uint64(r.stime%1e9/1e3))
	put64(b[32:], uint64(r.maxrss))
	put64(b[72:], uint64(r.majflt))
	return b
}

// selfUsage is the calling process's usage now (RUSAGE_SELF).
func (g *dguest) selfUsage() rusage {
	g.dfs.mu.Lock()
	ospid, prev := g.ps.ospid, g.ps.ruPrev
	g.dfs.mu.Unlock()
	return hostRusage(ospid).plus(prev)
}

func (g *dguest) getrusage(who int64, addr uint64) int64 {
	var r rusage
	switch who {
	case 0, 1: // RUSAGE_SELF; RUSAGE_THREAD is the stub's (proc.zig) and lands here only as a fallback
		r = g.selfUsage()
	case -1: // RUSAGE_CHILDREN
		g.dfs.mu.Lock()
		r = g.ps.cru
		g.dfs.mu.Unlock()
	default:
		return sErr(lxEINVAL)
	}
	if g.writeMem(addr, r.linux()) != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

// times fills struct tms in USER_HZ (100) ticks and returns the elapsed ticks.
func (g *dguest) times(addr uint64) int64 {
	if addr != 0 {
		self := g.selfUsage()
		g.dfs.mu.Lock()
		ch := g.ps.cru
		g.dfs.mu.Unlock()
		const tick = 1e7
		var b [32]byte
		put64(b[0:], uint64(self.utime/tick))
		put64(b[8:], uint64(self.stime/tick))
		put64(b[16:], uint64(ch.utime/tick))
		put64(b[24:], uint64(ch.stime/tick))
		if g.writeMem(addr, b[:]) != nil {
			return sErr(lxEFAULT)
		}
	}
	return int64(time.Since(bootTime()) / (10 * time.Millisecond))
}

// ---- scheduling ---------------------------------------------------------------------

const (
	schedOther      = 0
	schedFifo       = 1
	schedRR         = 2
	schedBatch      = 3
	schedIdle       = 5
	schedResetFork  = 0x40000000
	prioProcess     = 0
	prioPgrp        = 1
	prioUser        = 2
	capSysNice      = 23
	affinityMaskLen = 8 // bytes: one long covers the host's CPUs
)

type schedState struct {
	nice      int
	policy    int
	prio      int
	resetFork bool
	ioprio    int
}

func hostCPUMask() uint64 {
	n := runtime.NumCPU()
	if n >= 64 {
		return ^uint64(0)
	}
	return uint64(1)<<n - 1
}

func defaultSched() schedState { return schedState{} }

// forked is the child's copy; SCHED_RESET_ON_FORK drops a real-time policy
// and a negative nice.
func (s schedState) forked() schedState {
	if s.resetFork {
		if s.policy == schedFifo || s.policy == schedRR {
			s.policy, s.prio = schedOther, 0
		}
		if s.nice < 0 {
			s.nice = 0
		}
		s.resetFork = false
	}
	return s
}

func prioRange(policy int) (lo, hi int, ok bool) {
	switch policy {
	case schedFifo, schedRR:
		return 1, 99, true
	case schedOther, schedBatch, schedIdle:
		return 0, 0, true
	}
	return 0, 0, false
}

func (g *dguest) readParam(addr uint64) (int, lxErrno) {
	if addr == 0 {
		return 0, lxEINVAL
	}
	b, err := g.readMem(addr, 4)
	if err != nil {
		return 0, lxEFAULT
	}
	return int(int32(le32(b))), 0
}

func (g *dguest) schedSetscheduler(pid int, policy int64, paramAddr uint64, keepPolicy bool) int64 {
	if pid < 0 {
		return sErr(lxEINVAL)
	}
	prio, e := g.readParam(paramAddr)
	if e != 0 {
		return sErr(e)
	}
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	p, e := g.procOf(pid)
	if e != 0 {
		return sErr(e)
	}
	reset := p.sched.resetFork
	if keepPolicy {
		policy = int64(p.sched.policy)
	} else {
		if policy < 0 {
			return sErr(lxEINVAL)
		}
		reset = policy&schedResetFork != 0
		policy &^= schedResetFork
	}
	lo, hi, ok := prioRange(int(policy))
	if !ok || prio < lo || prio > hi {
		return sErr(lxEINVAL)
	}
	if hi > 0 && !g.ps.cred.capable(capSysNice) {
		return sErr(lxEPERM)
	}
	p.sched.policy, p.sched.prio, p.sched.resetFork = int(policy), prio, reset
	return 0
}

func (g *dguest) schedGet(pid int, f func(s schedState) int64) int64 {
	if pid < 0 {
		return sErr(lxEINVAL)
	}
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	p, e := g.procOf(pid)
	if e != 0 {
		return sErr(e)
	}
	return f(p.sched)
}

func (g *dguest) schedGetparam(pid int, addr uint64) int64 {
	if addr == 0 {
		return sErr(lxEINVAL)
	}
	prio := g.schedGet(pid, func(s schedState) int64 { return int64(s.prio) })
	if prio < 0 {
		return prio
	}
	var b [4]byte
	put32(b[:], uint32(prio))
	if g.writeMem(addr, b[:]) != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

// schedGetaffinity follows the kernel's size rules: the buffer must hold the
// host's CPUs and be a whole number of longs; it returns the bytes written.
func (g *dguest) schedGetaffinity(pid int, size uint64, addr uint64) int64 {
	if r, ok := g.hostGetaffinity(pid, size, addr); ok {
		return r
	}
	if size*8 < uint64(runtime.NumCPU()) || size&7 != 0 {
		return sErr(lxEINVAL)
	}
	if pid < 0 {
		return sErr(lxESRCH) // no such process, where sched_getparam says EINVAL
	}
	fs := g.dfs
	fs.mu.Lock()
	p, e := g.procOf(pid)
	fs.mu.Unlock()
	if e != 0 {
		return sErr(e)
	}
	var b [affinityMaskLen]byte
	put64(b[:], p.cpus.Load())
	if g.writeMem(addr, b[:]) != nil {
		return sErr(lxEFAULT)
	}
	return affinityMaskLen
}

func (g *dguest) schedSetaffinity(pid int, size uint64, addr uint64) int64 {
	if r, ok := g.hostSetaffinity(pid, size, addr); ok {
		return r
	}
	n := min(size, affinityMaskLen)
	b, err := g.readMem(addr, int(n))
	if err != nil {
		return sErr(lxEFAULT)
	}
	var mask uint64
	for i := range b {
		mask |= uint64(b[i]) << (8 * i)
	}
	mask &= hostCPUMask()
	if mask == 0 {
		return sErr(lxEINVAL)
	}
	fs := g.dfs
	fs.mu.Lock()
	p, e := g.procOf(pid)
	fs.mu.Unlock()
	if e != 0 {
		return sErr(e)
	}
	p.cpus.Store(mask)
	syncStdio()
	return 0
}

// prioTargets returns the processes a get/setpriority (which, who) names. The
// caller holds mu.
func (g *dguest) prioTargets(which, who int) ([]*pstate, lxErrno) {
	var out []*pstate
	switch which {
	case prioProcess:
		p, e := g.procOf(who)
		if e != 0 || p.zombie {
			return nil, lxESRCH
		}
		return []*pstate{p}, 0
	case prioPgrp:
		if who == 0 {
			who = g.ps.pgid
		}
		for _, p := range g.dfs.pt {
			if p.pgid == who && !p.zombie {
				out = append(out, p)
			}
		}
	case prioUser:
		uid := uint32(who)
		if who == 0 {
			uid = g.ps.cred.euid
		}
		for _, p := range g.dfs.pt {
			if p.cred.ruid == uid && !p.zombie {
				out = append(out, p)
			}
		}
	default:
		return nil, lxEINVAL
	}
	if len(out) == 0 {
		return nil, lxESRCH
	}
	return out, 0
}

// getpriority returns 20 - nice of the most favored target, the raw syscall's
// biased form (libc turns it back into a nice value).
func (g *dguest) getpriority(which, who int) int64 {
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	ps, e := g.prioTargets(which, who)
	if e != 0 {
		return sErr(e)
	}
	best := 20
	for _, p := range ps {
		best = min(best, p.sched.nice)
	}
	return int64(20 - best)
}

func (g *dguest) setpriority(which, who, nice int) int64 {
	nice = max(-20, min(19, nice))
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	ps, e := g.prioTargets(which, who)
	if e != 0 {
		return sErr(e)
	}
	me := &g.ps.cred
	for _, p := range ps {
		if me.euid != 0 && me.euid != p.cred.ruid && me.euid != p.cred.euid && !me.capable(capSysNice) {
			return sErr(lxEPERM)
		}
		if nice < p.sched.nice && !me.capable(capSysNice) {
			return sErr(lxEACCES)
		}
	}
	for _, p := range ps {
		p.sched.nice = nice
	}
	return 0
}

func init() {
	syscalls[lxPrlimit64] = func(g *dguest, a [6]uint64) int64 {
		return g.prlimit(int(int32(a[0])), uint64(uint32(a[1])), a[2], a[3])
	}
	syscalls[lxGetrlimit] = func(g *dguest, a [6]uint64) int64 { return g.prlimit(0, uint64(uint32(a[0])), 0, a[1]) }
	syscalls[lxSetrlimit] = func(g *dguest, a [6]uint64) int64 { return g.prlimit(0, uint64(uint32(a[0])), a[1], 0) }
	syscalls[lxGetrusage] = func(g *dguest, a [6]uint64) int64 { return g.getrusage(int64(int32(a[0])), a[1]) }
	syscalls[lxTimes] = func(g *dguest, a [6]uint64) int64 { return g.times(a[0]) }
	syscalls[lxGetpriority] = func(g *dguest, a [6]uint64) int64 { return g.getpriority(int(int32(a[0])), int(int32(a[1]))) }
	syscalls[lxSetpriority] = func(g *dguest, a [6]uint64) int64 {
		return g.setpriority(int(int32(a[0])), int(int32(a[1])), int(int32(a[2])))
	}
	syscalls[lxSchedSetscheduler] = func(g *dguest, a [6]uint64) int64 {
		return g.schedSetscheduler(int(int32(a[0])), int64(int32(a[1])), a[2], false)
	}
	syscalls[lxSchedSetparam] = func(g *dguest, a [6]uint64) int64 {
		return g.schedSetscheduler(int(int32(a[0])), 0, a[1], true)
	}
	syscalls[lxSchedGetscheduler] = func(g *dguest, a [6]uint64) int64 {
		return g.schedGet(int(int32(a[0])), func(s schedState) int64 {
			if s.resetFork {
				return int64(s.policy | schedResetFork)
			}
			return int64(s.policy)
		})
	}
	syscalls[lxSchedGetparam] = func(g *dguest, a [6]uint64) int64 { return g.schedGetparam(int(int32(a[0])), a[1]) }
	syscalls[lxSchedGetaffinity] = func(g *dguest, a [6]uint64) int64 {
		return g.schedGetaffinity(int(int32(a[0])), a[1], a[2])
	}
	syscalls[lxSchedSetaffinity] = func(g *dguest, a [6]uint64) int64 {
		return g.schedSetaffinity(int(int32(a[0])), a[1], a[2])
	}
	syscalls[lxSchedGetPriorityMax] = func(g *dguest, a [6]uint64) int64 {
		_, hi, ok := prioRange(int(int32(a[0])))
		if !ok {
			return sErr(lxEINVAL)
		}
		return int64(hi)
	}
	syscalls[lxSchedGetPriorityMin] = func(g *dguest, a [6]uint64) int64 {
		lo, _, ok := prioRange(int(int32(a[0])))
		if !ok {
			return sErr(lxEINVAL)
		}
		return int64(lo)
	}
	syscalls[lxSchedRrGetInterval] = func(g *dguest, a [6]uint64) int64 {
		if r := g.schedGet(int(int32(a[0])), func(schedState) int64 { return 0 }); r < 0 {
			return r
		}
		var b [16]byte
		put64(b[8:], 100_000_000) // 100 ms, the SCHED_RR default timeslice
		if g.writeMem(a[1], b[:]) != nil {
			return sErr(lxEFAULT)
		}
		return 0
	}
}
