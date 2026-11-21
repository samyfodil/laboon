package sandbox

import (
	"bufio"
	"bytes"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The host's own figures, from its /proc. Times there are in USER_HZ, which
// is 100 on every Linux the guest could tell apart.
const hostUserHZ = 100

var hostCPUInfo = sync.OnceValue(func() *hostCPU {
	h := &hostCPU{n: runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for line := range strings.Lines(string(b)) {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "model name":
				if h.brand == "" {
					h.brand = v
				}
			case "flags", "Features":
				if h.features == "" {
					h.features = v
				}
			case "bogomips", "BogoMIPS":
				if h.bogomips == 0 {
					h.bogomips, _ = strconv.ParseFloat(v, 64)
				}
			case "cpu MHz":
				if h.mhzP == 0 {
					f, _ := strconv.ParseFloat(v, 64)
					h.mhzP, h.mhzE = int(f), int(f)
				}
			case "CPU part":
				if h.partP == 0 {
					p, _ := strconv.ParseInt(v, 0, 32)
					h.partP, h.partE = int(p), int(p)
				}
			}
		}
	}
	h.memTotal = memStats().total
	return h
})

// cpuTicks returns per-CPU {user, nice, system, idle} in USER_HZ ticks.
func cpuTicks() [][4]uint64 {
	var out [][4]uint64
	f, err := os.Open("/proc/stat")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 5 || !strings.HasPrefix(fl[0], "cpu") || fl[0] == "cpu" {
			continue
		}
		var t [4]uint64
		for i := range t {
			t[i], _ = strconv.ParseUint(fl[i+1], 10, 64)
		}
		out = append(out, t)
	}
	return out
}

func memStats() hostMem {
	var m hostMem
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return m
	}
	for line := range strings.Lines(string(b)) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fl := strings.Fields(v)
		if len(fl) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(fl[0], 10, 64)
		n <<= 10 // kB
		switch k {
		case "MemTotal":
			m.total = n
		case "MemFree":
			m.free = n
		case "MemAvailable":
			m.avail = n
		case "Active":
			m.active = n
		case "Inactive":
			m.inactive = n
		case "Cached":
			m.cached = n
		case "AnonPages":
			m.anon = n
		case "Unevictable":
			m.wired = n
		case "SwapTotal":
			m.swapTotal = n
		case "SwapFree":
			m.swapFree = n
		}
	}
	return m
}

// loadAvg returns the host's 1/5/15 minute load averages.
func loadAvg() [3]float64 {
	var l [3]float64
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return l
	}
	fl := strings.Fields(string(b))
	for i := 0; i < 3 && i < len(fl); i++ {
		l[i], _ = strconv.ParseFloat(fl[i], 64)
	}
	return l
}

// bootTime is the host's boot time.
var bootTime = sync.OnceValue(func() time.Time {
	b, err := os.ReadFile("/proc/stat")
	if err == nil {
		for line := range strings.Lines(string(b)) {
			if v, ok := strings.CutPrefix(line, "btime "); ok {
				if s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
					return time.Unix(s, 0)
				}
			}
		}
	}
	return time.Now()
})

// procStat is a host process's /proc/<pid>/stat fields from after the
// command name, numbered as proc(5) numbers them minus 3.
func procStat(pid int) ([]string, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return nil, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return nil, false
	}
	return strings.Fields(string(b[i+1:])), true
}

func procStatU(fl []string, field int) uint64 {
	if field-3 >= len(fl) {
		return 0
	}
	n, _ := strconv.ParseUint(fl[field-3], 10, 64)
	return n
}

func ticksDur(t uint64) time.Duration { return time.Duration(t) * time.Second / hostUserHZ }

func pidTaskInfo(pid int) (taskInfo, bool) {
	var t taskInfo
	fl, ok := procStat(pid)
	if pid <= 0 || !ok {
		return t, false
	}
	t.faults = procStatU(fl, 10) + procStatU(fl, 12)
	t.pageins = procStatU(fl, 12)
	t.utime, t.stime = ticksDur(procStatU(fl, 14)), ticksDur(procStatU(fl, 15))
	t.threads = int(procStatU(fl, 20))
	t.virt = procStatU(fl, 23)
	t.rss = procStatU(fl, 24) * uint64(os.Getpagesize())
	return t, true
}

// hostRusage reads a host process's CPU time, peak resident size and major
// faults.
// exitRusage is the usage of g's process, about to exit: the stub's own
// getrusage, far cheaper than reading it from /proc.
func (g *dguest) exitRusage() rusage {
	sc := g.scratch()
	if r := g.host(unix.SYS_GETRUSAGE, unix.RUSAGE_SELF, g.scratchAddr()); r < 0 {
		return hostRusage(g.ps.ospid)
	}
	tv := func(b []byte) int64 { return int64(le64(b))*1e9 + int64(le64(b[8:]))*1e3 }
	return rusage{utime: tv(sc), stime: tv(sc[16:]), maxrss: int64(le64(sc[32:])), majflt: int64(le64(sc[72:]))}
}

func hostRusage(pid int) rusage {
	fl, ok := procStat(pid)
	if pid <= 0 || !ok {
		return rusage{}
	}
	r := rusage{
		utime:  int64(ticksDur(procStatU(fl, 14))),
		stime:  int64(ticksDur(procStatU(fl, 15))),
		majflt: int64(procStatU(fl, 12)),
	}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status"); err == nil {
		for line := range strings.Lines(string(b)) {
			if v, ok := strings.CutPrefix(line, "VmHWM:"); ok {
				if f := strings.Fields(v); len(f) > 0 {
					r.maxrss, _ = strconv.ParseInt(f[0], 10, 64)
				}
			}
		}
	}
	return r
}

// hostProcCPU is host process pid's CPU time, user and total; the total is
// its scheduler clock, to the nanosecond.
func hostProcCPU(pid int) (user, total time.Duration) {
	fl, ok := procStat(pid)
	if !ok {
		return 0, 0
	}
	user = ticksDur(procStatU(fl, 14))
	var ts unix.Timespec
	if unix.ClockGettime(int32(^pid<<3|cpuclockSched), &ts) != nil {
		return user, user + ticksDur(procStatU(fl, 15))
	}
	return user, time.Duration(ts.Nano())
}

// threadCPU is the CPU time of g's host thread, user and total, the total from
// its schedstat to the nanosecond.
func (g *dguest) threadCPU() (user, total time.Duration, ok bool) {
	tid, ok := g.hostTid(0)
	if !ok {
		return 0, 0, false
	}
	fl, ok := procStat(tid)
	if !ok {
		return 0, 0, false
	}
	user = ticksDur(procStatU(fl, 14))
	total = user + ticksDur(procStatU(fl, 15))
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(tid) + "/schedstat"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if ns, err := strconv.ParseInt(f[0], 10, 64); err == nil {
				total = time.Duration(ns)
			}
		}
	}
	return user, total, true
}
