//go:build windows

package sandbox

import (
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Host facts the synthetic /proc and /sys report. Per-CPU ticks and load
// averages read as idle.

var (
	winHostOnce sync.Once
	winHost     hostCPU
)

type memoryStatusEx struct {
	length                                         uint32
	memoryLoad                                     uint32
	totalPhys, availPhys, totalPageFile, availPage uint64
	totalVirtual, availVirtual, availExtended      uint64
}

var procGlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

func memStatus() memoryStatusEx {
	m := memoryStatusEx{length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	return m
}

func hostCPUInfo() *hostCPU {
	winHostOnce.Do(func() {
		winHost = hostCPU{n: runtime.NumCPU(), brand: "x86_64", bogomips: 4000, memTotal: memStatus().totalPhys}
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
			if mhz, _, err := k.GetIntegerValue("~MHz"); err == nil {
				winHost.mhzE, winHost.mhzP = int(mhz), int(mhz)
			}
			if name, _, err := k.GetStringValue("ProcessorNameString"); err == nil && strings.TrimSpace(name) != "" {
				winHost.brand = strings.TrimSpace(name)
			}
			k.Close()
		}
		if guestArch == "aarch64" {
			var names []string
			for _, f := range winHwcaps { // already in bit order
				if windows.IsProcessorFeaturePresent(f.pf) {
					names = append(names, f.name)
				}
			}
			winHost.features = strings.Join(names, " ")
		}
	})
	return &winHost
}

// winHwcaps maps a Windows processor feature to the Linux arm64 hwcap bit it
// stands for (0-63 AT_HWCAP, 64+ AT_HWCAP2), so the guest's auxv and
// /proc/cpuinfo say what the host has. FP and Advanced SIMD come with every
// ARMv8 Windows runs on. SVE and SME are left out: a signal frame carries no
// SVE or ZA state.
var winHwcaps = []struct {
	pf   uint32
	bit  int
	name string
}{
	{windows.PF_ARM_V8_INSTRUCTIONS_AVAILABLE, 0, "fp"},
	{windows.PF_ARM_V8_INSTRUCTIONS_AVAILABLE, 1, "asimd"},
	{windows.PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE, 3, "aes"},
	{windows.PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE, 4, "pmull"},
	{windows.PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE, 5, "sha1"},
	{windows.PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE, 6, "sha2"},
	{windows.PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE, 7, "crc32"},
	{windows.PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE, 8, "atomics"},
	{windows.PF_ARM_V82_FP16_INSTRUCTIONS_AVAILABLE, 9, "fphp"},
	{windows.PF_ARM_V82_FP16_INSTRUCTIONS_AVAILABLE, 10, "asimdhp"},
	{windows.PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE, 13, "jscvt"},
	{windows.PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE, 15, "lrcpc"},
	{windows.PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE, 17, "sha3"},
	{windows.PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE, 20, "asimddp"},
	{windows.PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE, 21, "sha512"},
	{windows.PF_ARM_LSE2_AVAILABLE, 25, "uscat"},
	{windows.PF_ARM_V82_I8MM_INSTRUCTIONS_AVAILABLE, 64 + 13, "i8mm"},
	{windows.PF_ARM_V86_BF16_INSTRUCTIONS_AVAILABLE, 64 + 14, "bf16"},
	{windows.PF_ARM_V86_EBF16_INSTRUCTIONS_AVAILABLE, 64 + 32, "ebf16"},
}

// hostHwcap is the guest's AT_HWCAP and AT_HWCAP2 on an arm64 host.
func hostHwcap() (hwcap, hwcap2 uint64) {
	for _, f := range winHwcaps {
		if !windows.IsProcessorFeaturePresent(f.pf) {
			continue
		}
		if f.bit < 64 {
			hwcap |= 1 << f.bit
		} else {
			hwcap2 |= 1 << (f.bit - 64)
		}
	}
	return hwcap, hwcap2
}

func cpuTicks() [][4]uint64 { return make([][4]uint64, hostCPUInfo().n) }

func memStats() hostMem {
	m := memStatus()
	return hostMem{total: m.totalPhys, free: m.availPhys, avail: m.availPhys,
		swapTotal: m.totalPageFile - m.totalPhys, swapFree: m.availPage}
}

func loadAvg() [3]float64 { return [3]float64{} }

var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

func bootTime() time.Time {
	ms, _, _ := procGetTickCount64.Call()
	return time.Now().Add(-time.Duration(ms) * time.Millisecond)
}

var (
	procGetProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")
	procGetThreadTimes       = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetThreadTimes")
	procQueryThreadCycleTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryThreadCycleTime")
	procQueryProcessCycle    = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryProcessCycleTime")
)

// preciseCPU refines a CPU time Windows charges by scheduler tick (some 15 ms)
// with the cycles the thread or process ran, at the CPU's nominal frequency:
// the later of the two, so the time never goes back.
func preciseCPU(ticked time.Duration, cycleTime *windows.LazyProc, h windows.Handle) time.Duration {
	mhz := hostCPUInfo().mhzP
	var cycles uint64
	if r, _, _ := cycleTime.Call(uintptr(h), uintptr(unsafe.Pointer(&cycles))); r == 0 || mhz <= 0 {
		return ticked
	}
	return max(ticked, time.Duration(float64(cycles)*1000/float64(mhz)))
}

// processMemoryCounters is PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	cb, pageFaultCount                    uint32
	peakWorkingSetSize, workingSetSize    uintptr
	quotaPeakPagedPoolUsage, quotaPaged   uintptr
	quotaPeakNonPagedPoolUsage, quotaNonP uintptr
	pagefileUsage, peakPagefileUsage      uintptr
}

// hostProcUsage reads host process pid's CPU times, user and total, and its
// memory counters.
func hostProcUsage(pid int) (user, total time.Duration, mc processMemoryCounters, ok bool) {
	if pid <= 0 {
		return 0, 0, mc, false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, 0, mc, false
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return 0, 0, mc, false
	}
	mc.cb = uint32(unsafe.Sizeof(mc))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mc)), uintptr(mc.cb)); r == 0 {
		mc = processMemoryCounters{}
	}
	user = filetimeDur(u)
	return user, preciseCPU(user+filetimeDur(k), procQueryProcessCycle, h), mc, true
}

// filetimeDur is a FILETIME span, in 100 ns units.
func filetimeDur(f windows.Filetime) time.Duration {
	return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100
}

func pidTaskInfo(pid int) (taskInfo, bool) {
	u, t, mc, ok := hostProcUsage(pid)
	if !ok {
		return taskInfo{threads: 1}, pid > 0
	}
	return taskInfo{virt: uint64(mc.pagefileUsage), rss: uint64(mc.workingSetSize), utime: u, stime: t - u,
		faults: uint64(mc.pageFaultCount), threads: 1}, true
}

func hostRusage(pid int) rusage {
	u, t, mc, _ := hostProcUsage(pid)
	return rusage{utime: int64(u), stime: int64(t - u), maxrss: int64(mc.peakWorkingSetSize / 1024)}
}

// hostProcCPU is host process pid's CPU time, user and total.
func hostProcCPU(pid int) (user, total time.Duration) {
	u, t, _, _ := hostProcUsage(pid)
	return u, t
}

// threadCPU is the CPU time of g's OS thread, user and total.
func (g *dguest) threadCPU() (user, total time.Duration, ok bool) {
	sr := g.dfs.sigs()
	if sr == nil {
		return 0, 0, false
	}
	inj := sr.injector()
	if inj == nil {
		return 0, 0, false
	}
	inj.mu.Lock()
	defer inj.mu.Unlock()
	r, ok := inj.threads[g.pid]
	if !ok {
		return 0, 0, false
	}
	var c, e, k, u windows.Filetime
	if got, _, _ := procGetThreadTimes.Call(uintptr(r.handle), uintptr(unsafe.Pointer(&c)), uintptr(unsafe.Pointer(&e)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); got == 0 {
		return 0, 0, false
	}
	user = filetimeDur(u)
	return user, preciseCPU(user+filetimeDur(k), procQueryThreadCycleTime, r.handle), true
}
