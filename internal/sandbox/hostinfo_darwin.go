//go:build darwin

package sandbox

import (
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Host facts the synthetic /proc and /sys (and sysinfo) report: CPUs, memory,
// load, uptime, and per-process usage of a guest's stub. Static facts are read
// once; counters are read per call.

var (
	hostOnce sync.Once
	host     hostCPU

	machOnce    sync.Once
	mcHostSelf  *ffiCall  // mach_host_self
	mcProcInfo  *ffiCall  // host_processor_info
	mcStats64   *ffiCall  // host_statistics64
	mcVmDealloc *ffiCall  // vm_deallocate
	mcPidinfo   *ffiCall  // proc_pidinfo
	mcTimebase  *ffiCall  // mach_timebase_info
	mcTaskSelf  *ffiCall  // mach_task_self
	timebase    [2]uint32 // numer, denom: Mach absolute time units -> ns
)

func loadMach() bool {
	machOnce.Do(func() {
		lib, err := ffiOpenLibSystem()
		if err != nil {
			return
		}
		mcHostSelf, _ = ffiPrep(lib, "mach_host_self", ffiU32)
		mcProcInfo, _ = ffiPrep(lib, "host_processor_info", ffiS32, ffiU32, ffiS32, ffiPtr, ffiPtr, ffiPtr)
		mcStats64, _ = ffiPrep(lib, "host_statistics64", ffiS32, ffiU32, ffiS32, ffiPtr, ffiPtr)
		mcVmDealloc, _ = ffiPrep(lib, "vm_deallocate", ffiS32, ffiU32, ffiU64, ffiU64)
		mcPidinfo, _ = ffiPrep(lib, "proc_pidinfo", ffiS32, ffiS32, ffiS32, ffiU64, ffiPtr, ffiS32)
		mcTimebase, _ = ffiPrep(lib, "mach_timebase_info", ffiS32, ffiPtr)
		mcTaskSelf, _ = ffiPrep(lib, "mach_task_self", ffiU32)
		if mcTimebase == nil || machTimebase(&timebase) != 0 || timebase[1] == 0 {
			timebase = [2]uint32{1, 1}
		}
	})
	return mcTaskSelf != nil
}

func machHostSelf() uint32 { var r uint32; mcHostSelf.call(unsafe.Pointer(&r)); return r }
func machTaskSelf() uint32 { var r uint32; mcTaskSelf.call(unsafe.Pointer(&r)); return r }

func hostProcessorInfo(h uint32, flavor int32, cpus *uint32, info *unsafe.Pointer, cnt *uint32) int32 {
	var r int32
	mcProcInfo.call(unsafe.Pointer(&r), unsafe.Pointer(&h), unsafe.Pointer(&flavor),
		unsafe.Pointer(&cpus), unsafe.Pointer(&info), unsafe.Pointer(&cnt))
	return r
}

func hostStatistics64(h uint32, flavor int32, info unsafe.Pointer, cnt *uint32) int32 {
	var r int32
	mcStats64.call(unsafe.Pointer(&r), unsafe.Pointer(&h), unsafe.Pointer(&flavor),
		unsafe.Pointer(&info), unsafe.Pointer(&cnt))
	return r
}

func vmDeallocate(task uint32, addr, size uintptr) int32 {
	var r int32
	a, s := uint64(addr), uint64(size)
	mcVmDealloc.call(unsafe.Pointer(&r), unsafe.Pointer(&task), unsafe.Pointer(&a), unsafe.Pointer(&s))
	return r
}

func procPidinfo(pid int32, flavor int32, arg uint64, buf unsafe.Pointer, size int32) int32 {
	var r int32
	mcPidinfo.call(unsafe.Pointer(&r), unsafe.Pointer(&pid), unsafe.Pointer(&flavor),
		unsafe.Pointer(&arg), unsafe.Pointer(&buf), unsafe.Pointer(&size))
	return r
}

func machTimebase(info *[2]uint32) int32 {
	var r int32
	mcTimebase.call(unsafe.Pointer(&r), unsafe.Pointer(&info))
	return r
}

// hwcapFeat maps a host hw.optional sysctl to a Linux hwcap bit, mirroring
// stub/macos/hwcap.zig (which sets AT_HWCAP/AT_HWCAP2 from the same table) so
// /proc/cpuinfo agrees with what the guest's auxv says.
type hwcapFeat struct {
	sysctl string
	bit    int // 0-63 HWCAP, 64+ HWCAP2
	name   string
}

var hwcapFeats = []hwcapFeat{
	{"hw.optional.floatingpoint", 0, "fp"},
	{"hw.optional.arm.AdvSIMD", 1, "asimd"},
	{"hw.optional.arm.FEAT_AES", 3, "aes"},
	{"hw.optional.arm.FEAT_PMULL", 4, "pmull"},
	{"hw.optional.arm.FEAT_SHA1", 5, "sha1"},
	{"hw.optional.arm.FEAT_SHA256", 6, "sha2"},
	{"hw.optional.arm.FEAT_CRC32", 7, "crc32"},
	{"hw.optional.arm.FEAT_LSE", 8, "atomics"},
	{"hw.optional.arm.FEAT_FP16", 9, "fphp"},
	{"hw.optional.arm.FEAT_FP16", 10, "asimdhp"},
	{"hw.optional.arm.FEAT_RDM", 12, "asimdrdm"},
	{"hw.optional.arm.FEAT_JSCVT", 13, "jscvt"},
	{"hw.optional.arm.FEAT_FCMA", 14, "fcma"},
	{"hw.optional.arm.FEAT_LRCPC", 15, "lrcpc"},
	{"hw.optional.arm.FEAT_DPB", 16, "dcpop"},
	{"hw.optional.arm.FEAT_SHA3", 17, "sha3"},
	{"hw.optional.arm.FEAT_DotProd", 20, "asimddp"},
	{"hw.optional.arm.FEAT_SHA512", 21, "sha512"},
	{"hw.optional.arm.FEAT_FHM", 23, "asimdfhm"},
	{"hw.optional.arm.FEAT_DIT", 24, "dit"},
	{"hw.optional.arm.FEAT_LSE2", 25, "uscat"},
	{"hw.optional.arm.FEAT_LRCPC2", 26, "ilrcpc"},
	{"hw.optional.arm.FEAT_FlagM", 27, "flagm"},
	{"hw.optional.arm.FEAT_SSBS", 28, "ssbs"},
	{"hw.optional.arm.FEAT_SB", 29, "sb"},
	{"hw.optional.arm.FEAT_DPB2", 64 + 0, "dcpodp"},
	{"hw.optional.arm.FEAT_FlagM2", 64 + 7, "flagm2"},
	{"hw.optional.arm.FEAT_FRINTTS", 64 + 8, "frint"},
	{"hw.optional.arm.FEAT_I8MM", 64 + 13, "i8mm"},
	{"hw.optional.arm.FEAT_BF16", 64 + 14, "bf16"},
	{"hw.optional.arm.FEAT_AFP", 64 + 20, "afp"},
	{"hw.optional.arm.FEAT_RPRES", 64 + 21, "rpres"},
	{"hw.optional.arm.FEAT_CSSC", 64 + 34, "cssc"},
}

// appleChips gives the MIDR part numbers (E, P) and nominal max MHz (E, P) by
// chip generation. Darwin exposes neither (no MIDR read, no cpufrequency
// sysctl on Apple Silicon); M1/M2 parts are the ones Linux's cputype.h names.
var appleChips = []struct {
	prefix       string
	partE, partP int
	mhzE, mhzP   int
}{
	{"Apple M1", 0x022, 0x023, 2064, 3204},
	{"Apple M2", 0x032, 0x033, 2424, 3504},
	{"Apple M3", 0x048, 0x049, 2748, 4056},
	{"Apple M4", 0x058, 0x059, 2892, 4400},
}

func hostCPUInfo() *hostCPU {
	hostOnce.Do(func() {
		h := &host
		h.n = 1
		if v, err := unix.SysctlUint32("hw.logicalcpu"); err == nil && v > 0 {
			h.n = int(v)
		}
		if v, err := unix.SysctlUint32("hw.perflevel1.logicalcpu"); err == nil && int(v) < h.n {
			h.eCores = int(v)
		}
		h.brand, _ = unix.Sysctl("machdep.cpu.brand_string")
		if v, err := unix.SysctlUint64("hw.memsize"); err == nil {
			h.memTotal = v
		}
		h.bogomips = 48
		if v, err := unix.SysctlUint64("hw.tbfrequency"); err == nil && v > 0 {
			h.bogomips = float64(v) * 2 / 1e6
		}
		var names []string
		for _, f := range hwcapFeats { // already in bit order
			if v, err := unix.SysctlUint32(f.sysctl); err == nil && v != 0 {
				names = append(names, f.name)
			}
		}
		h.features = strings.Join(names, " ")
		h.partE, h.partP = 0x022, 0x023
		for _, c := range appleChips {
			if strings.HasPrefix(h.brand, c.prefix) {
				h.partE, h.partP, h.mhzE, h.mhzP = c.partE, c.partP, c.mhzE, c.mhzP
			}
		}
	})
	return &host
}

// cpuTicks returns per-CPU {user, nice, system, idle} in USER_HZ ticks.
func cpuTicks() [][4]uint64 {
	if !loadMach() {
		return nil
	}
	var ncpu, cnt uint32
	var info unsafe.Pointer
	const processorCPULoadInfo = 2
	if hostProcessorInfo(machHostSelf(), processorCPULoadInfo, &ncpu, &info, &cnt) != 0 || info == nil {
		return nil
	}
	raw := unsafe.Slice((*uint32)(info), cnt)
	out := make([][4]uint64, ncpu)
	for i := range out {
		// CPU_STATE_USER, SYSTEM, IDLE, NICE; Mach counts at 100 Hz.
		t := raw[i*4 : i*4+4]
		out[i] = [4]uint64{uint64(t[0]), uint64(t[3]), uint64(t[1]), uint64(t[2])}
	}
	vmDeallocate(machTaskSelf(), uintptr(info), uintptr(cnt)*4)
	return out
}

func memStats() hostMem {
	h := hostCPUInfo()
	m := hostMem{total: h.memTotal}
	page := uint64(16384)
	if v, err := unix.SysctlUint32("hw.pagesize"); err == nil && v > 0 {
		page = uint64(v)
	}
	if loadMach() {
		var vs [38]uint32
		cnt := uint32(len(vs))
		const hostVMInfo64 = 4
		if hostStatistics64(machHostSelf(), hostVMInfo64, unsafe.Pointer(&vs[0]), &cnt) == 0 {
			b := unsafe.Slice((*byte)(unsafe.Pointer(&vs[0])), len(vs)*4)
			u32 := func(off int) uint64 { return uint64(binary.LittleEndian.Uint32(b[off:])) * page }
			m.free = u32(0)
			m.active = u32(4)
			m.inactive = u32(8)
			m.wired = u32(12)
			purgeable, speculative := u32(88), u32(92)
			m.compressed = u32(128)
			m.cached = u32(136) // external (file-backed) pages
			m.anon = u32(140)   // internal (anonymous) pages
			m.free += speculative
			m.avail = m.free + m.cached + purgeable
			if m.avail > m.total {
				m.avail = m.total
			}
		}
	}
	if b, err := unix.SysctlRaw("vm.swapusage"); err == nil && len(b) >= 24 {
		m.swapTotal = binary.LittleEndian.Uint64(b[0:])
		m.swapFree = binary.LittleEndian.Uint64(b[8:])
	}
	return m
}

// loadAvg returns the host's 1/5/15 minute load averages.
func loadAvg() [3]float64 {
	var l [3]float64
	b, err := unix.SysctlRaw("vm.loadavg")
	if err != nil || len(b) < 24 {
		return l
	}
	scale := float64(binary.LittleEndian.Uint64(b[16:]))
	if scale == 0 {
		return l
	}
	for i := range l {
		l[i] = float64(binary.LittleEndian.Uint32(b[4*i:])) / scale
	}
	return l
}

// bootTime is the host's boot time.
func bootTime() time.Time {
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		return time.Unix(tv.Sec, int64(tv.Usec)*1000)
	}
	return time.Now()
}

func pidTaskInfo(pid int) (taskInfo, bool) {
	var t taskInfo
	if pid <= 0 || !loadMach() {
		return t, false
	}
	var b [96]byte
	const procPidTaskInfo = 4
	if procPidinfo(int32(pid), procPidTaskInfo, 0, unsafe.Pointer(&b[0]), int32(len(b))) != int32(len(b)) {
		return t, false
	}
	le := binary.LittleEndian
	t.virt = le.Uint64(b[0:])
	t.rss = le.Uint64(b[8:])
	// CPU times are in Mach absolute time units (ns only on Intel).
	t.utime = time.Duration(le.Uint64(b[16:]) * uint64(timebase[0]) / uint64(timebase[1]))
	t.stime = time.Duration(le.Uint64(b[24:]) * uint64(timebase[0]) / uint64(timebase[1]))
	t.faults = uint64(le.Uint32(b[52:]))
	t.pageins = uint64(le.Uint32(b[56:]))
	t.csw = uint64(le.Uint32(b[80:]))
	t.threads = int(int32(le.Uint32(b[84:])))
	return t, true
}

var hostRU struct {
	once     sync.Once
	pidRU    *ffiCall // proc_pid_rusage
	timebase *ffiCall // mach_timebase_info
	numer    uint64
	denom    uint64
}

// hostRusage reads a host process's CPU time and peak footprint with
// proc_pid_rusage (rusage_info_v4). Its times are mach absolute units,
// converted with the timebase.
// exitRusage is the usage of g's process, about to exit.
func (g *dguest) exitRusage() rusage { return hostRusage(g.ps.ospid) }

func hostRusage(pid int) rusage {
	if pid <= 0 {
		return rusage{}
	}
	hostRU.once.Do(func() {
		lib, err := ffiOpenLibSystem()
		if err != nil {
			return
		}
		hostRU.pidRU, _ = ffiPrep(lib, "proc_pid_rusage", ffiS32, ffiS32, ffiS32, ffiPtr)
		hostRU.timebase, _ = ffiPrep(lib, "mach_timebase_info", ffiS32, ffiPtr)
		var tb [2]uint32
		var tr int32
		if hostRU.timebase != nil {
			tp := unsafe.Pointer(&tb)
			hostRU.timebase.call(unsafe.Pointer(&tr), unsafe.Pointer(&tp))
		}
		if tr == 0 && tb[1] != 0 {
			hostRU.numer, hostRU.denom = uint64(tb[0]), uint64(tb[1])
		}
	})
	if hostRU.pidRU == nil || hostRU.denom == 0 {
		return rusage{}
	}
	const flavorV4 = 4
	var buf [37]uint64 // rusage_info_v4 is 296 bytes
	var pr int32
	pidv, fv := int32(pid), int32(flavorV4)
	bp := unsafe.Pointer(&buf)
	hostRU.pidRU.call(unsafe.Pointer(&pr), unsafe.Pointer(&pidv), unsafe.Pointer(&fv), unsafe.Pointer(&bp))
	if pr != 0 {
		return rusage{}
	}
	ns := func(t uint64) int64 { return int64(t * hostRU.numer / hostRU.denom) }
	return rusage{
		utime:  ns(buf[2]),
		stime:  ns(buf[3]),
		maxrss: int64(buf[30] / 1024), // ri_lifetime_max_phys_footprint
		majflt: int64(buf[6]),         // ri_pageins
	}
}

// hostProcCPU is host process pid's CPU time, user and total.
func hostProcCPU(pid int) (user, total time.Duration) {
	t, ok := pidTaskInfo(pid)
	if !ok {
		return 0, 0
	}
	return t.utime, t.utime + t.stime
}

// stHostTid is the offset in a thread's signal record of its host thread id
// (pthread_threadid_np), which stub/macos/sig.zig publishes; 0 while no
// thread runs on the slot.
const stHostTid = 80

// threadCPU is the CPU time of g's host thread, user and total, by the id
// its stub publishes in the thread's signal record.
func (g *dguest) threadCPU() (user, total time.Duration, ok bool) {
	sr := g.dfs.sigs()
	if sr == nil || !loadMach() {
		return 0, 0, false
	}
	tid := atomic.LoadUint64(sr.p64(tOff(g.slot) + stHostTid))
	if tid == 0 {
		return 0, 0, false
	}
	g.dfs.mu.Lock()
	ospid := g.ps.ospid
	g.dfs.mu.Unlock()
	var b [112]byte // struct proc_threadinfo; its times are in ns
	const procPidThreadID64Info = 15
	if procPidinfo(int32(ospid), procPidThreadID64Info, tid, unsafe.Pointer(&b[0]), int32(len(b))) != int32(len(b)) {
		return 0, 0, false
	}
	user = time.Duration(binary.LittleEndian.Uint64(b[0:]))
	return user, user + time.Duration(binary.LittleEndian.Uint64(b[8:])), true
}
