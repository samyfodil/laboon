//go:build darwin || linux || windows

package sandbox

import (
	"bytes"
	"debug/elf"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The content of /proc and /sys, in Linux's exact text formats.

// What uname and /proc/sys/kernel report.
const (
	utsSysname  = "Linux"
	utsNodename = "laboon"
	utsRelease  = "6.8.0"
	utsVersion  = "#1 SMP PREEMPT laboon"
	utsDomain   = "(none)"
)

const (
	lxSysinfo = 179
	lxPidMax  = 4194304
)

func init() {
	syscalls[lxSysinfo] = func(g *dguest, a [6]uint64) int64 { return g.sysinfo(a[0]) }
}

func cpuList(n int) string {
	if n <= 1 {
		return "0"
	}
	return "0-" + strconv.Itoa(n-1)
}

func ticks(d time.Duration) uint64 { return uint64(d / (time.Second / lxUserHZ)) }

// ---- /proc -------------------------------------------------------------------

func (g *dguest) procRoot() *pnode {
	n := pdir(func() []pchild {
		kids := g.procGlobals()
		for _, t := range g.guests() {
			if t.pid != t.tgid {
				continue
			}
			// A process is listed by the pid the reader's namespace sees, and
			// only when it is visible there at all.
			local := g.nsPid(t.tgid)
			if local == 0 {
				continue
			}
			kids = append(kids, pchild{strconv.Itoa(local), g.pidDir(t, false)})
		}
		return kids
	})
	n.find = func(name string) *pnode {
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 || strconv.Itoa(pid) != name {
			return nil
		}
		gp, ok := g.nsToGlobal(pid) // the name is a pid in the reader's namespace
		if !ok {
			return nil
		}
		if t := g.guest(gp); t != nil {
			return g.pidDir(t, false)
		}
		return nil
	}
	return n
}

func (g *dguest) procGlobals() []pchild {
	return []pchild{
		{"self", plink(strconv.Itoa(g.nsPid(g.tgid)))},
		{"thread-self", plink(strconv.Itoa(g.nsPid(g.tgid)) + "/task/" + strconv.Itoa(g.nsPid(g.pid)))},
		{"cpuinfo", pfile(procCpuinfo)},
		{"meminfo", pfile(procMeminfo)},
		{"stat", pfile(g.procStat)},
		{"loadavg", pfile(g.procLoadavg)},
		{"uptime", pfile(procUptime)},
		{"version", pstr(fmt.Sprintf("Linux version %s (root@%s) (gcc (GCC) 13.2.0, GNU ld (GNU Binutils) 2.42) %s\n", utsRelease, utsNodename, utsVersion))},
		{"cmdline", pstr("console=hvc0 root=/dev/vda rw\n")},
		{"filesystems", pstr("nodev\tsysfs\nnodev\ttmpfs\nnodev\tbdev\nnodev\tproc\nnodev\tcgroup2\nnodev\tdevtmpfs\nnodev\tdevpts\nnodev\toverlay\n\text4\n")},
		{"mounts", plink("self/mounts")},
		{"swaps", pstr("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n")},
		{"partitions", pstr("major minor  #blocks  name\n\n")},
		{"diskstats", pstr("")},
		{"modules", pstr("")},
		{"cgroups", pstr("#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpuset\t0\t1\t1\ncpu\t0\t1\t1\nio\t0\t1\t1\nmemory\t0\t1\t1\npids\t0\t1\t1\n")},
		{"vmstat", pfile(procVmstat)},
		{"sys", pdir(g.procSysKids)},
		{"net", procNet()},
	}
}

func procCpuinfo() []byte {
	h := hostCPUInfo()
	var b bytes.Buffer
	for i := 0; i < h.n; i++ {
		fmt.Fprintf(&b, "processor\t: %d\n", i)
		fmt.Fprintf(&b, "BogoMIPS\t: %.2f\n", h.bogomips)
		fmt.Fprintf(&b, "Features\t: %s\n", h.features)
		fmt.Fprintf(&b, "CPU implementer\t: 0x61\n")
		fmt.Fprintf(&b, "CPU architecture: 8\n")
		fmt.Fprintf(&b, "CPU variant\t: 0x0\n")
		fmt.Fprintf(&b, "CPU part\t: 0x%03x\n", h.cpuPart(i))
		fmt.Fprintf(&b, "CPU revision\t: 0\n\n")
	}
	return b.Bytes()
}

func procMeminfo() []byte {
	m := memStats()
	kb := func(v uint64) uint64 { return v / 1024 }
	actAnon := min(m.active, m.anon)
	inactAnon := m.anon - min(m.anon, actAnon)
	inactAnon = min(inactAnon, m.inactive)
	var b bytes.Buffer
	row := func(k string, v uint64) { fmt.Fprintf(&b, "%-16s%8d kB\n", k+":", kb(v)) }
	row("MemTotal", m.total)
	row("MemFree", m.free)
	row("MemAvailable", m.avail)
	row("Buffers", 0)
	row("Cached", m.cached)
	row("SwapCached", 0)
	row("Active", m.active)
	row("Inactive", m.inactive)
	row("Active(anon)", actAnon)
	row("Inactive(anon)", inactAnon)
	row("Active(file)", m.active-actAnon)
	row("Inactive(file)", m.inactive-inactAnon)
	row("Unevictable", 0)
	row("Mlocked", 0)
	row("SwapTotal", m.swapTotal)
	row("SwapFree", m.swapFree)
	row("Zswap", m.compressed)
	row("Zswapped", 0)
	row("Dirty", 0)
	row("Writeback", 0)
	row("AnonPages", m.anon)
	row("Mapped", m.cached)
	row("Shmem", 0)
	row("KReclaimable", 0)
	row("Slab", m.wired/4)
	row("SReclaimable", 0)
	row("SUnreclaim", m.wired/4)
	row("KernelStack", 0)
	row("PageTables", 0)
	row("SecPageTables", 0)
	row("NFS_Unstable", 0)
	row("Bounce", 0)
	row("WritebackTmp", 0)
	row("CommitLimit", m.total/2+m.swapTotal)
	row("Committed_AS", m.anon)
	row("VmallocTotal", 133141626880)
	row("VmallocUsed", 0)
	row("VmallocChunk", 0)
	row("Percpu", 0)
	row("AnonHugePages", 0)
	row("ShmemHugePages", 0)
	row("ShmemPmdMapped", 0)
	row("FileHugePages", 0)
	row("FilePmdMapped", 0)
	fmt.Fprintf(&b, "HugePages_Total:   %5d\nHugePages_Free:    %5d\nHugePages_Rsvd:    %5d\nHugePages_Surp:    %5d\n", 0, 0, 0, 0)
	row("Hugepagesize", 2048*1024)
	row("Hugetlb", 0)
	return b.Bytes()
}

func procVmstat() []byte {
	m := memStats()
	const pg = 4096
	return []byte(fmt.Sprintf("nr_free_pages %d\nnr_inactive_anon 0\nnr_active_anon %d\nnr_inactive_file %d\nnr_active_file 0\nnr_mapped %d\npgpgin 0\npgpgout 0\npswpin 0\npswpout 0\npgfault 0\npgmajfault 0\n",
		m.free/pg, m.anon/pg, m.cached/pg, m.cached/pg))
}

func (g *dguest) procStat() []byte {
	cpus := cpuTicks()
	var tot [4]uint64
	for _, c := range cpus {
		for i := range tot {
			tot[i] += c[i]
		}
	}
	var b bytes.Buffer
	line := func(name string, t [4]uint64) {
		fmt.Fprintf(&b, "%s %d %d %d %d 0 0 0 0 0 0\n", name, t[0], t[1], t[2], t[3])
	}
	line("cpu ", tot)
	for i, c := range cpus {
		line("cpu"+strconv.Itoa(i), c)
	}
	g.mu.Lock()
	forks := g.nextPid - 1
	g.mu.Unlock()
	running := 0
	for range g.guests() {
		running++
	}
	fmt.Fprintf(&b, "intr 0\nctxt 0\nbtime %d\nprocesses %d\nprocs_running %d\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n",
		bootTime().Unix(), forks, min(running, hostCPUInfo().n))
	return b.Bytes()
}

func (g *dguest) procLoadavg() []byte {
	l := loadAvg()
	g.mu.Lock()
	last := g.nextPid - 1
	g.mu.Unlock()
	return []byte(fmt.Sprintf("%.2f %.2f %.2f 1/%d %d\n", l[0], l[1], l[2], len(g.guests()), last))
}

func procUptime() []byte {
	up := time.Since(bootTime()).Seconds()
	var idle uint64
	for _, c := range cpuTicks() {
		idle += c[3]
	}
	return []byte(fmt.Sprintf("%.2f %.2f\n", up, float64(idle)/lxUserHZ))
}

func (g *dguest) procSysKids() []pchild {
	sysFile := func(s string) *pnode { return pwfile(s + "\n") }
	ipc := g.ipcLimits()
	dir := func(kids ...pchild) *pnode { return pdir(func() []pchild { return kids }) }
	// net/ipv{4,6}/conf: a directory per interface (plus all/default), each a set
	// of writable per-interface sysctls. A created interface (a runtime's bridge
	// or veth) resolves here so e.g. conf/podman0/rp_filter exists. laboon's
	// socket-level network does not act on these, so writes are accepted and
	// dropped. find serves any interface or key name, as the kernel presents one
	// for every interface.
	confDefault := func(key string) string {
		switch key {
		case "rp_filter", "accept_ra", "accept_dad", "arp_notify":
			return "1"
		}
		return "0"
	}
	confIface := func() *pnode {
		keys := []string{"forwarding", "rp_filter", "accept_dad", "accept_ra", "route_localnet", "disable_ipv6", "arp_notify", "arp_ignore"}
		return &pnode{kind: pDir, perm: 0o555,
			kids: func() []pchild {
				ks := make([]pchild, 0, len(keys))
				for _, k := range keys {
					ks = append(ks, pchild{k, sysFile(confDefault(k))})
				}
				return ks
			},
			find: func(key string) *pnode { return sysFile(confDefault(key)) },
		}
	}
	confDir := func() *pnode {
		return &pnode{kind: pDir, perm: 0o555,
			kids: func() []pchild { return []pchild{{"all", confIface()}, {"default", confIface()}} },
			find: func(string) *pnode { return confIface() },
		}
	}
	return []pchild{
		pchild{"kernel", dir(
			pchild{"ostype", sysFile(utsSysname)},
			pchild{"osrelease", sysFile(utsRelease)},
			pchild{"version", sysFile(utsVersion)},
			pchild{"hostname", utsFile(false)},
			pchild{"domainname", utsFile(true)},
			pchild{"pid_max", sysFile(strconv.Itoa(lxPidMax))},
			pchild{"threads-max", sysFile("127368")},
			pchild{"ngroups_max", sysFile("65536")},
			pchild{"cap_last_cap", sysFile("40")},
			pchild{"overflowuid", sysFile("65534")},
			pchild{"overflowgid", sysFile("65534")},
			pchild{"randomize_va_space", sysFile("2")},
			pchild{"shmmax", sysFile(strconv.FormatUint(ipc.shmMax, 10))},
			pchild{"shmall", sysFile(strconv.FormatUint(ipc.shmAll, 10))},
			pchild{"shmmni", sysFile(strconv.Itoa(shmMni))},
			pchild{"sem", sysFile(fmt.Sprintf("%d\t%d\t%d\t%d", semMsl, semMns, semOpm, semMni))},
			pchild{"msgmax", sysFile(strconv.Itoa(msgMax))},
			pchild{"msgmnb", sysFile(strconv.Itoa(msgMnb))},
			pchild{"msgmni", sysFile(strconv.Itoa(msgMni))},
			pchild{"perf_event_paranoid", sysFile("2")},
			pchild{"core_pattern", sysFile("core")},
			pchild{"tainted", sysFile("0")},
			pchild{"printk", sysFile("4\t4\t1\t7")},
			pchild{"random", dir(
				pchild{"uuid", pfile(func() []byte { return []byte(randomUUID() + "\n") })},
				pchild{"boot_id", pstr(g.pst.bootID + "\n")},
				pchild{"entropy_avail", pstr("256\n")},
				pchild{"poolsize", pstr("256\n")},
			)},
		)},
		pchild{"vm", dir(
			pchild{"overcommit_memory", sysFile("0")},
			pchild{"overcommit_ratio", sysFile("50")},
			pchild{"max_map_count", sysFile("65530")},
			pchild{"swappiness", sysFile("60")},
			pchild{"min_free_kbytes", sysFile("67584")},
			pchild{"mmap_min_addr", sysFile("32768")},
			pchild{"mmap_rnd_bits", sysFile(strconv.Itoa(int(g.vmRndBits())))},
		)},
		pchild{"fs", dir(
			pchild{"file-max", sysFile("9223372036854775807")},
			pchild{"file-nr", pfile(func() []byte { return []byte(fmt.Sprintf("%d\t0\t9223372036854775807\n", 64*len(g.guests()))) })},
			pchild{"nr_open", sysFile("1048576")},
			pchild{"pipe-max-size", sysFile("1048576")},
			pchild{"aio-max-nr", sysFile("65536")},
			pchild{"inotify", dir(
				pchild{"max_user_watches", sysFile("524288")},
				pchild{"max_user_instances", sysFile("128")},
				pchild{"max_queued_events", sysFile("16384")},
			)},
		)},
		pchild{"net", dir(
			pchild{"core", dir(
				pchild{"somaxconn", sysFile("4096")},
			)},
			pchild{"ipv4", dir(
				pchild{"ip_local_port_range", sysFile("32768\t60999")},
				pchild{"tcp_fin_timeout", sysFile("60")},
				pchild{"ping_group_range", sysFile("1\t0")},
				pchild{"ip_forward", sysFile("0")},
				pchild{"conf", confDir()},
			)},
			pchild{"ipv6", dir(
				pchild{"conf", confDir()},
			)},
		)},
		pchild{"debug", dir()},
		pchild{"dev", dir()},
		pchild{"user", dir(
			pchild{"max_user_namespaces", sysFile("63448")},
		)},
	}
}

func procNet() *pnode {
	return pdir(func() []pchild {
		return []pchild{
			{"if_inet6", pstr("")},
			{"route", pstr("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT                                                       \n")},
			{"dev", pstr("Inter-|   Receive                                                |  Transmit\n" +
				" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
				"    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n")},
			{"tcp", pstr("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")},
			{"tcp6", pstr("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")},
			{"udp", pstr("   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n")},
			{"udp6", pstr("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n")},
			{"unix", pstr("Num       RefCount Protocol Flags    Type St Inode Path\n")},
		}
	})
}

// ---- /proc/<pid> -------------------------------------------------------------

// procUsage gathers what stat/statm/status report about process p.
type procUsage struct {
	ti      taskInfo
	vsz     uint64
	threads int
	img     *imgInfo
	data    uint64 // anonymous private mappings
	stack   uint64
}

func (g *dguest) usage(p *dguest) procUsage {
	var u procUsage
	u.ti, _ = pidTaskInfo(g.hostPidOf(p.tgid))
	u.threads = len(g.threadsOf(p.tgid))
	u.img = g.imgInfoOf(p)
	p.pi.mu.Lock()
	for _, v := range p.pi.vmas {
		u.vsz += v.hi - v.lo
		if v.path == "" && !v.shared {
			u.data += v.hi - v.lo
		}
	}
	p.pi.mu.Unlock()
	if u.img != nil {
		u.vsz += (u.img.mainHi - u.img.mainLo) + (u.img.interpHi - u.img.interpLo) + (u.img.stackHi - u.img.stackLo)
		u.stack = u.img.stackHi - u.img.stackLo
	}
	if u.vsz < u.ti.rss {
		u.vsz = u.ti.rss
	}
	return u
}

func (g *dguest) pidDir(t *dguest, task bool) *pnode {
	p := t
	if t.tgid != t.pid {
		if l := g.guest(t.tgid); l != nil {
			p = l
		}
	}
	pi := p.pi
	ints := func(s string) *pnode { return pwfile(s + "\n") }
	return pdir(func() []pchild {
		pi.mu.Lock()
		exe, exePin, argv, env := pi.exe, pi.exePin, pi.argv, pi.env
		pi.mu.Unlock()
		cwd := p.getCwd()
		kids := []pchild{
			{"exe", p.exeNode(exe, exePin)},
			{"cwd", plink(cwd)},
			{"root", plink("/")},
			{"cmdline", pstr(nulJoin(argv))},
			{"environ", pstr(nulJoin(env))},
			{"comm", pwfile(g.commOf(p) + "\n")},
			{"stat", pfileR(func(r *dguest) []byte { return r.pidStat(t, p) })},
			{"statm", pfileR(func(r *dguest) []byte { return r.pidStatm(p) })},
			{"status", pfileR(func(r *dguest) []byte { return r.pidStatus(t, p) })},
			{"maps", pfileR(func(r *dguest) []byte { return r.pidMaps(p) })},
			{"smaps", pfileR(func(r *dguest) []byte { return r.pidSmaps(p, false) })},
			{"smaps_rollup", pfileR(func(r *dguest) []byte { return r.pidSmaps(p, true) })},
			{"auxv", pfileR(func(r *dguest) []byte { return r.auxvOf(p) })},
			{"limits", pfileR(func(r *dguest) []byte { return r.pidLimits(p) })},
			{"mountinfo", pstr(mountinfo)},
			{"mounts", pstr(mounts)},
			{"fd", g.fdDir(p)},
			{"fdinfo", g.fdinfoDir(p)},
			{"oom_score_adj", ints("0")},
			{"oom_adj", ints("0")},
			{"oom_score", pstr("666\n")},
			{"cgroup", pstr("0::/\n")},
			{"loginuid", ints("4294967295")},
			{"sessionid", pstr("4294967295")},
			{"uid_map", pmap("         0          0 4294967295\n", idMapPut(false))},
			{"gid_map", pmap("         0          0 4294967295\n", idMapPut(true))},
			{"setgroups", pmap("allow\n", func(w *dguest, b []byte) lxErrno { return 0 })},
			{"ns", g.nsDir(p)},
			{"personality", pstr("00000000\n")},
			{"wchan", pstr("0")},
			{"io", pstr("rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n")},
			{"coredump_filter", ints("00000033")},
			{"timerslack_ns", ints("50000")},
			{"schedstat", pstr("0 0 0\n")},
		}
		if openProcMem != nil {
			kids = append(kids, pchild{"mem", &pnode{kind: pFile, perm: 0o600, write: true, mem: t}})
		}
		if !task {
			kids = append(kids, pchild{"task", g.taskDir(p)})
		}
		return kids
	})
}

// nsDir is /proc/<pid>/ns: the magic links naming the process's namespaces.
// Chromium's sandbox checks these exist (access F_OK) before entering the
// unprivileged user-namespace sandbox. A process that unshared CLONE_NEWUSER
// gets a distinct user-namespace inode so a before/after comparison sees the
// change.
func (g *dguest) nsDir(p *dguest) *pnode {
	const initNs = 4026531835
	return pdir(func() []pchild {
		user := uint64(initNs + 2) // 4026531837, the init user namespace
		if g.view(p).Userns {
			user = 4026540000 + uint64(p.tgid)
		}
		g.dfs.mu.Lock()
		pidns := uint64(initNs+1) + uint64(p.ps.ns.id)*0x10000
		childns := pidns
		if p.ps.childPidNs != nil {
			childns = uint64(initNs+1) + uint64(p.ps.childPidNs.id)*0x10000
		}
		g.dfs.mu.Unlock()
		link := func(name string, ino uint64) pchild {
			return pchild{name, plink(fmt.Sprintf("%s:[%d]", name, ino))}
		}
		return []pchild{
			link("cgroup", initNs+0),
			link("ipc", initNs+4),
			link("mnt", initNs+6),
			link("net", initNs+5),
			link("pid", pidns),
			{"pid_for_children", plink(fmt.Sprintf("pid:[%d]", childns))},
			link("time", initNs-1),
			{"time_for_children", plink(fmt.Sprintf("time:[%d]", initNs-1))},
			link("user", user),
			link("uts", initNs+3),
		}
	})
}

func (g *dguest) taskDir(p *dguest) *pnode {
	n := pdir(func() []pchild {
		var kids []pchild
		for _, t := range g.threadsOf(p.tgid) {
			// Threads are listed by their tid in the reading process's namespace.
			kids = append(kids, pchild{strconv.Itoa(g.nsPid(t.pid)), g.pidDir(t, true)})
		}
		return kids
	})
	// nlink without building a node per thread: 2 (. and ..) plus one per
	// thread subdirectory, the count Chromium's sandbox reads to confirm the
	// process is single-threaded.
	n.nlink = func() uint32 { return uint32(2 + len(g.threadsOf(p.tgid))) }
	return n
}

func nulJoin(v []string) string {
	var b strings.Builder
	for _, s := range v {
		b.WriteString(s)
		b.WriteByte(0)
	}
	return b.String()
}

// commOf is the task name (prctl PR_SET_NAME's, else the program's file
// name), at most 15 bytes.
func (g *dguest) commOf(p *dguest) string {
	if c, ok := g.dfs.commOf(p.pid); ok && c != "" {
		return c
	}
	p.pi.mu.Lock()
	c := p.pi.comm
	if c == "" {
		c = path.Base(p.pi.exe)
	}
	p.pi.mu.Unlock()
	if len(c) > 15 {
		c = c[:15]
	}
	return c
}

func (g *dguest) state(t *dguest) (byte, string) {
	switch {
	case t.pid == g.pid:
		return 'R', "R (running)"
	case g.dfs.traceStopped(t.pid):
		return 't', "t (tracing stop)"
	}
	if _, stopped := g.sigs().jobStop(t.tgid); stopped {
		return 'T', "T (stopped)"
	}
	return 'S', "S (sleeping)"
}

func (g *dguest) ttyNr() uint64 {
	if f := g.pst.stdio[0]; f != nil {
		if hostIsTTY(f) {
			return lxMakedev(136, 0)
		}
	}
	return 0
}

// view is p's process-registry snapshot (ids, credentials, limits).
func (g *dguest) view(p *dguest) procView {
	v, ok := g.procView(p.tgid)
	if !ok {
		v = procView{Pid: p.tgid, PPid: p.ppid, Pgid: 1, Sid: 1, Rlim: defaultRlimits()}
	}
	return v
}

func (g *dguest) pidStat(t, p *dguest) []byte {
	u := g.usage(p)
	v := g.view(p)
	st, _ := g.state(t)
	utime, stime := ticks(u.ti.utime), ticks(u.ti.stime)
	if t != p {
		utime, stime = 0, 0
	}
	p.pi.mu.Lock()
	start := p.pi.start
	p.pi.mu.Unlock()
	startTicks := ticks(start.Sub(bootTime()))
	var code0, code1, stk uint64
	if u.img != nil {
		code0, code1, stk = u.img.mainLo, u.img.mainHi, u.img.sp
	}
	// The ids are shown in the reading process's namespace.
	pid, ppid := g.nsPid(t.pid), g.nsPid(v.PPid)
	pgid, sid := g.nsPid(v.Pgid), g.nsPid(v.Sid)
	return []byte(fmt.Sprintf("%d (%s) %c %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
		pid, g.commOf(t), st, ppid, pgid, sid, g.ttyNr(), -1, 4194560,
		u.ti.faults, 0, u.ti.pageins, 0, utime, stime, 0, 0, 20+v.Nice, v.Nice, u.threads, 0, startTicks,
		u.vsz, u.ti.rss/darwinPage, lxRlimInfinity, code0, code1, stk, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0))
}

func (g *dguest) pidStatm(p *dguest) []byte {
	u := g.usage(p)
	var text uint64
	if u.img != nil {
		text = u.img.mainHi - u.img.mainLo
	}
	const pg = darwinPage
	return []byte(fmt.Sprintf("%d %d %d %d 0 %d 0\n", u.vsz/pg, u.ti.rss/pg, 0, text/pg, (u.data+u.stack)/pg))
}

func (g *dguest) pidStatus(t, p *dguest) []byte {
	u := g.usage(p)
	_, st := g.state(t)
	n := hostCPUInfo().n
	var text, lib uint64
	if u.img != nil {
		text = u.img.mainHi - u.img.mainLo
		lib = u.img.interpHi - u.img.interpLo
	}
	t.ft.mu.Lock()
	fdsize := 64
	for fd := range t.ft.fds {
		for fd >= fdsize {
			fdsize *= 2
		}
	}
	t.ft.mu.Unlock()
	kb := func(v uint64) string { return fmt.Sprintf("%8d kB", v/1024) }
	mask := fmt.Sprintf("%x", uint64(1)<<n-1)
	var b bytes.Buffer
	v := g.view(p)
	// The ids are shown in the reading process's namespace.
	tgid, pid, ppid := g.nsPid(p.tgid), g.nsPid(t.pid), g.nsPid(v.PPid)
	pgid, sid := g.nsPid(v.Pgid), g.nsPid(v.Sid)
	fmt.Fprintf(&b, "Name:\t%s\nUmask:\t0022\nState:\t%s\nTgid:\t%d\nNgid:\t0\nPid:\t%d\nPPid:\t%d\nTracerPid:\t%d\n",
		g.commOf(t), st, tgid, pid, ppid, g.tracerPid(t.pid))
	var groups strings.Builder
	for _, gid := range v.Groups {
		fmt.Fprintf(&groups, "%d ", gid)
	}
	fmt.Fprintf(&b, "Uid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nFDSize:\t%d\nGroups:\t%s\nNStgid:\t%d\nNSpid:\t%d\nNSpgid:\t%d\nNSsid:\t%d\n",
		v.Uid, v.Euid, v.Suid, v.Euid, v.Gid, v.Egid, v.Sgid, v.Egid, fdsize, groups.String(), tgid, pid, pgid, sid)
	fmt.Fprintf(&b, "Kthread:\t0\nVmPeak:\t%s\nVmSize:\t%s\nVmLck:\t%s\nVmPin:\t%s\nVmHWM:\t%s\nVmRSS:\t%s\n",
		kb(u.vsz), kb(u.vsz), kb(0), kb(0), kb(u.ti.rss), kb(u.ti.rss))
	fmt.Fprintf(&b, "RssAnon:\t%s\nRssFile:\t%s\nRssShmem:\t%s\nVmData:\t%s\nVmStk:\t%s\nVmExe:\t%s\nVmLib:\t%s\nVmPTE:\t%s\nVmSwap:\t%s\nHugetlbPages:\t%s\n",
		kb(u.ti.rss), kb(0), kb(0), kb(u.data), kb(u.stack), kb(text), kb(lib), kb(0), kb(0), kb(0))
	fmt.Fprintf(&b, "CoreDumping:\t0\nTHP_enabled:\t1\nuntag_mask:\t0xffffffffffffff\nThreads:\t%d\nSigQ:\t0/63448\n", u.threads)
	ss := g.sigs().status(t.pid, p.tgid)
	fmt.Fprintf(&b, "SigPnd:\t%016x\nShdPnd:\t%016x\nSigBlk:\t%016x\nSigIgn:\t%016x\nSigCgt:\t%016x\n", ss[0], ss[1], ss[2], ss[3], ss[4])
	fmt.Fprintf(&b, "CapInh:\t%016x\nCapPrm:\t%016x\nCapEff:\t%016x\nCapBnd:\t%016x\nCapAmb:\t0000000000000000\n", v.CapInh, v.CapPrm, v.CapEff, v.CapBnd)
	fmt.Fprintf(&b, "NoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\nSpeculation_Store_Bypass:\tthread safe\nSpeculationIndirectBranch:\tunknown\n")
	fmt.Fprintf(&b, "Cpus_allowed:\t%s\nCpus_allowed_list:\t%s\nMems_allowed:\t1\nMems_allowed_list:\t0\n", mask, cpuList(n))
	fmt.Fprintf(&b, "voluntary_ctxt_switches:\t%d\nnonvoluntary_ctxt_switches:\t0\n", u.ti.csw)
	return b.Bytes()
}

// pidMaps renders /proc/<pid>/maps. A process reading its own asks its stub,
// which serves every guest mapping (mapsOfStub). Another process's shows only
// its program and interpreter images and the initial stack, as its stub
// recorded them, plus the mappings the supervisor made for it: the stub
// answers only the thread whose syscall it is serving.
func (g *dguest) pidMaps(p *dguest) []byte {
	if p.tgid == g.tgid {
		if es, ok := g.hostMaps(); ok {
			return g.renderMaps(p, es)
		}
	} else if es, ok := g.otherMaps(p); ok {
		return g.renderMaps(p, es)
	}
	type ent struct {
		lo, hi uint64
		perm   string
		off    uint64
		ino    uint64
		name   string
	}
	var es []ent
	pi := p.pi
	pi.mu.Lock()
	exe := pi.exe
	for _, v := range pi.vmas {
		perm := []byte("---p")
		if v.prot&lxProtRead != 0 {
			perm[0] = 'r'
		}
		if v.prot&lxProtWrite != 0 {
			perm[1] = 'w'
		}
		if v.prot&lxProtExec != 0 {
			perm[2] = 'x'
		}
		if v.shared {
			perm[3] = 's'
		}
		es = append(es, ent{v.lo, v.hi, string(perm), v.off, v.ino, v.path})
	}
	pi.mu.Unlock()
	if img := g.imgInfoOf(p); img != nil {
		es = append(es, ent{img.mainLo, img.mainHi, "r-xp", 0, 0, exe})
		if img.interpHi > img.interpLo {
			es = append(es, ent{img.interpLo, img.interpHi, "r-xp", 0, 0, g.interpOf(p)})
		}
		es = append(es, ent{img.stackLo, img.stackHi, "rw-p", 0, 0, "[stack]"})
	}
	sort.Slice(es, func(i, j int) bool { return es[i].lo < es[j].lo })
	var b bytes.Buffer
	for _, e := range es {
		line := fmt.Sprintf("%08x-%08x %s %08x %02x:%02x %d ", e.lo, e.hi, e.perm, e.off, 0, 0, e.ino)
		if e.name != "" {
			line += strings.Repeat(" ", max(0, 73-len(line))) + e.name
		}
		b.WriteString(line + "\n")
	}
	return b.Bytes()
}

// interpOf is the guest path of the program's dynamic linker (PT_INTERP).
func (g *dguest) interpOf(p *dguest) string {
	pi := p.pi
	pi.mu.Lock()
	exe, ip := pi.exe, pi.interp
	pi.mu.Unlock()
	if ip != "" {
		return ip
	}
	rp, e := g.resolve(exe, true)
	if e != 0 {
		return ""
	}
	src, e := g.openFile(rp)
	if e != 0 {
		return ""
	}
	defer src.Close()
	f, err := elf.NewFile(src) // read the ELF through the routed overlay node, not a host path
	if err != nil {
		return ""
	}
	for _, ph := range f.Progs {
		if ph.Type == elf.PT_INTERP {
			b := make([]byte, ph.Filesz)
			if _, err := ph.ReadAt(b, 0); err == nil {
				ip = string(bytes.TrimRight(b, "\x00"))
			}
		}
	}
	pi.mu.Lock()
	pi.interp = ip
	pi.mu.Unlock()
	return ip
}

func (g *dguest) pidLimits(p *dguest) []byte {
	rl := g.view(p).Rlim
	var b bytes.Buffer
	fmt.Fprintf(&b, "%-25s %-20s %-20s %-10s\n", "Limit", "Soft Limit", "Hard Limit", "Units")
	names := []struct{ name, unit string }{
		{"Max cpu time", "seconds"}, {"Max file size", "bytes"}, {"Max data size", "bytes"},
		{"Max stack size", "bytes"}, {"Max core file size", "bytes"}, {"Max resident set", "bytes"},
		{"Max processes", "processes"}, {"Max open files", "files"}, {"Max locked memory", "bytes"},
		{"Max address space", "bytes"}, {"Max file locks", "locks"}, {"Max pending signals", "signals"},
		{"Max msgqueue size", "bytes"}, {"Max nice priority", ""}, {"Max realtime priority", ""},
		{"Max realtime timeout", "us"},
	}
	str := func(v uint64) string {
		if v == lxRlimInfinity {
			return "unlimited"
		}
		return strconv.FormatUint(v, 10)
	}
	for i, n := range names {
		cur, max := rl[i].cur, rl[i].max
		fmt.Fprintf(&b, "%-25s %-20s %-20s %-10s\n", n.name, str(cur), str(max), n.unit)
	}
	return b.Bytes()
}

const lxRlimInfinity = ^uint64(0)

const mountinfo = `21 0 0:32 / / rw,relatime - overlay overlay rw
22 21 0:22 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
23 21 0:21 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
24 23 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate
25 21 0:5 / /dev rw,nosuid,relatime - devtmpfs devtmpfs rw,mode=755
26 25 0:23 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=000
27 25 0:24 / /dev/shm rw,nosuid,nodev - tmpfs shm rw
`

const mounts = `overlay / overlay rw,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup cgroup2 ro,nosuid,nodev,noexec,relatime,nsdelegate 0 0
devtmpfs /dev devtmpfs rw,nosuid,relatime,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
shm /dev/shm tmpfs rw,nosuid,nodev 0 0
`

func (g *dguest) fdinfoDir(p *dguest) *pnode {
	return pdir(func() []pchild {
		p.ft.mu.Lock()
		fds := make([]int, 0, len(p.ft.fds))
		for fd := range p.ft.fds {
			fds = append(fds, fd)
		}
		p.ft.mu.Unlock()
		sort.Ints(fds)
		out := make([]pchild, 0, len(fds))
		for _, fd := range fds {
			out = append(out, pchild{strconv.Itoa(fd), pfile(func() []byte { return fdinfo(p, fd) })})
		}
		return out
	})
}

func fdinfo(p *dguest, fd int) []byte {
	d, ok := p.ft.get(fd)
	if !ok {
		return nil
	}
	var pos int64
	flags := uint64(lxORdwr)
	var ino uint64
	if m := d.mem; m != nil {
		m.mu.Lock()
		pos = m.pos
		m.mu.Unlock()
		flags = m.accmode()
		ino = pino(d.gp)
	}
	if d.f != nil || d.vf != nil {
		if off, err := d.tell(); err == nil {
			pos = off
		}
	}
	if d.f != nil {
		if acc, app, err := hostAccMode(d.f); err == nil {
			flags = uint64(acc)
			if app {
				flags |= lxOAppend
			}
		}
		_, ino = d.hostDevIno()
	} else if d.vf != nil {
		flags = uint64(d.fx.oflags & (lxOAccmod | lxOAppend))
		_, ino = d.hostDevIno()
	}
	if d.nonblock.Load() {
		flags |= lxONonblock
	}
	if p.ft.isCloexec(fd) {
		flags |= lxOCloexec
	}
	flags |= lxOLargefile
	return []byte(fmt.Sprintf("pos:\t%d\nflags:\t0%o\nmnt_id:\t21\nino:\t%d\n", pos, flags, ino))
}

// ---- /sys --------------------------------------------------------------------

func sysRoot(cg *cgStore) *pnode {
	h := hostCPUInfo()
	dir := func(kids ...pchild) *pnode { return pdir(func() []pchild { return kids }) }
	s := func(v string) *pnode { return pstr(v + "\n") }
	all := cpuList(h.n)
	cpu := func(i int) *pnode {
		cluster, clusterCPUs := 0, cpuList(h.eCores)
		if i >= h.eCores {
			cluster = 1
			clusterCPUs = fmt.Sprintf("%d-%d", h.eCores, h.n-1)
		}
		id := strconv.Itoa(i)
		kids := []pchild{
			{"online", s("1")},
			{"topology", dir(
				pchild{"core_id", s(id)},
				pchild{"cluster_id", s(strconv.Itoa(cluster))},
				pchild{"physical_package_id", s("0")},
				pchild{"die_id", s("0")},
				pchild{"core_cpus_list", s(id)},
				pchild{"thread_siblings_list", s(id)},
				pchild{"core_siblings_list", s(all)},
				pchild{"package_cpus_list", s(all)},
				pchild{"cluster_cpus_list", s(clusterCPUs)},
			)},
		}
		if mhz := h.cpuMHz(i); mhz > 0 {
			khz := strconv.Itoa(mhz * 1000)
			kids = append(kids, pchild{"cpufreq", dir(
				pchild{"cpuinfo_max_freq", s(khz)},
				pchild{"cpuinfo_min_freq", s("600000")},
				pchild{"scaling_cur_freq", s(khz)},
				pchild{"scaling_max_freq", s(khz)},
				pchild{"scaling_min_freq", s("600000")},
				pchild{"scaling_governor", s("schedutil")},
				pchild{"cpuinfo_transition_latency", s("0")},
				pchild{"related_cpus", s(id)},
				pchild{"affected_cpus", s(id)},
			)})
		}
		return dir(kids...)
	}
	cpus := pdir(func() []pchild {
		kids := []pchild{
			{"online", s(all)}, {"possible", s(all)}, {"present", s(all)},
			{"offline", s("")}, {"isolated", s("")}, {"kernel_max", s("511")},
		}
		for i := 0; i < h.n; i++ {
			kids = append(kids, pchild{"cpu" + strconv.Itoa(i), cpu(i)})
		}
		return kids
	})
	return dir(
		pchild{"devices", dir(
			pchild{"system", dir(
				pchild{"cpu", cpus},
				pchild{"node", dir(
					pchild{"online", s("0")},
					pchild{"possible", s("0")},
					pchild{"has_cpu", s("0")},
					pchild{"node0", dir(pchild{"cpulist", s(all)})},
				)},
			)},
		)},
		pchild{"fs", dir(pchild{"cgroup", cgroupDir(cg)})},
		pchild{"kernel", dir(
			pchild{"mm", dir(
				pchild{"transparent_hugepage", dir(
					pchild{"enabled", s("always [madvise] never")},
					pchild{"defrag", s("always defer defer+madvise [madvise] never")},
					pchild{"hpage_pmd_size", s("2097152")},
				)},
			)},
		)},
		pchild{"class", dir()},
		pchild{"bus", dir()},
		pchild{"block", dir()},
		pchild{"module", dir()},
		pchild{"firmware", dir()},
	)
}

// ---- sysinfo / uname ---------------------------------------------------------

// sysinfo fills a Linux arm64 struct sysinfo (112 bytes).
func (g *dguest) sysinfo(addr uint64) int64 {
	m := memStats()
	l := loadAvg()
	var b [112]byte
	put64(b[0:], uint64(time.Since(bootTime()).Seconds()))
	for i := range l {
		put64(b[8+8*i:], uint64(l[i]*65536))
	}
	put64(b[32:], m.total)
	put64(b[40:], m.free)
	put64(b[64:], m.swapTotal)
	put64(b[72:], m.swapFree)
	procs := len(g.guests())
	b[80], b[81] = byte(procs), byte(procs>>8)
	put32(b[104:], 1) // mem_unit
	if err := g.writeMem(addr, b[:]); err != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

// mapEnt is one guest mapping as stub/macos/mem.zig's MapEnt reports it: aux is
// the open-file id of a file mapping or the SysV attachment cookie, attr packs
// the host protection (bits 0-2), MAP_SHARED (bit 3) and the kind (bits 8+).
type mapEnt struct{ lo, hi, off, aux, attr uint64 }

const (
	mapAnon = 1 + iota
	mapFile
	mapShm
	mapHeap
	mapMain
	mapInterp
	mapStack
	mapVdso // the kernel's special mappings, by their names in /proc/<pid>/maps
	mapVvar
	mapVvarVclock
	mapVsyscall
)

// specialMaps names the special mappings by kind.
var specialMaps = map[uint64]string{mapVdso: "[vdso]", mapVvar: "[vvar]", mapVvarVclock: "[vvar_vclock]", mapVsyscall: "[vsyscall]"}

// fileName is what /proc/<pid>/maps shows for a mapped file.
type fileName struct {
	path     string
	dev, ino uint64
}

// mapsOfStub has g's stub list the process's mappings, a scratch-full at a time.
func (g *dguest) mapsOfStub() ([]mapEnt, bool) {
	var out []mapEnt
	from := uint64(0)
	for len(out) < 1<<20 {
		g.ch.page.args = [6]uint64{from}
		g.ch.reply(repMaps)
		if err := g.ch.wait(); err != nil || g.ch.page.kind != msgHostRet {
			return nil, false
		}
		n := int(g.ch.page.ret)
		sc := g.scratch()
		if n*40 > len(sc) {
			return nil, false
		}
		for i := 0; i < n; i++ {
			b := sc[i*40:]
			out = append(out, mapEnt{le64(b), le64(b[8:]), le64(b[16:]), le64(b[24:]), le64(b[32:])})
		}
		if from = g.ch.page.args[1]; from == 0 {
			break
		}
	}
	return out, true
}

// renderMaps formats es as Linux's /proc/<pid>/maps for process p.
func (g *dguest) renderMaps(p *dguest, es []mapEnt) []byte {
	var b bytes.Buffer
	for _, l := range g.mapsLines(p, es) {
		b.WriteString(l + "\n")
	}
	return b.Bytes()
}

// mapsLines is es as the lines of Linux's /proc/<pid>/maps for process p.
func (g *dguest) mapsLines(p *dguest, es []mapEnt) []string {
	pi := p.pi
	pi.mu.Lock()
	exe := pi.exe
	pi.mu.Unlock()
	imgName := func(gp string) fileName {
		fn := fileName{path: gp}
		if fi, e := g.lstatGuest(gp); e == 0 { // dev/ino through the routed overlay node
			fn.dev, fn.ino = HostDevIno(fi)
		}
		return fn
	}
	var mainName, interpName *fileName
	out := make([]string, 0, len(es))
	for _, e := range es {
		perm := []byte("---p")
		if e.attr&1 != 0 {
			perm[0] = 'r'
		}
		if e.attr&2 != 0 {
			perm[1] = 'w'
		}
		if e.attr&4 != 0 {
			perm[2] = 'x'
		}
		if e.attr&8 != 0 {
			perm[3] = 's'
		}
		var fn fileName
		switch e.attr >> 8 {
		case mapAnon:
			if e.attr&8 != 0 {
				fn.path = "/dev/zero (deleted)"
			}
		case mapFile:
			p.mp.mu.Lock()
			fn = p.mp.names[e.aux]
			p.mp.mu.Unlock()
		case mapShm:
			p.mp.mu.Lock()
			if at := p.mp.shm[e.aux]; at != nil {
				fn = fileName{path: fmt.Sprintf("/SYSV%08x (deleted)", uint32(at.seg.perm.key)), ino: uint64(at.id)}
			}
			p.mp.mu.Unlock()
		case mapHeap:
			fn.path = "[heap]"
		case mapMain:
			if mainName == nil {
				n := imgName(exe)
				mainName = &n
			}
			fn = *mainName
		case mapInterp:
			if interpName == nil {
				n := imgName(g.interpOf(p))
				interpName = &n
			}
			fn = *interpName
		case mapStack:
			fn.path = "[stack]"
		case mapVdso, mapVvar, mapVvarVclock, mapVsyscall:
			fn.path = specialMaps[e.attr>>8]
		}
		major := fn.dev>>8&0xfff | fn.dev>>32&^0xfff
		minor := fn.dev&0xff | fn.dev>>12&^0xff
		line := fmt.Sprintf("%08x-%08x %s %08x %02x:%02x %d ", e.lo, e.hi, perm, e.off, major, minor, fn.ino)
		if fn.path != "" {
			line += strings.Repeat(" ", max(0, 73-len(line))) + fn.path
		}
		out = append(out, line)
	}
	return out
}

// idMapPut applies a write to /proc/<pid>/uid_map or gid_map: the caller
// becomes the first (inside) id, root in its user namespace, completing the
// mapping a Chromium-style unprivileged sandbox sets up after unshare.
func idMapPut(gid bool) func(w *dguest, b []byte) lxErrno {
	return func(w *dguest, b []byte) lxErrno {
		f := strings.Fields(string(b))
		if len(f) == 0 {
			return lxEINVAL
		}
		id, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil {
			return lxEINVAL
		}
		w.withCreds(func(c *creds) int64 {
			if !c.userns {
				return 0 // only a user-namespace member maps ids
			}
			u := uint32(id)
			if gid {
				c.rgid, c.egid, c.sgid, c.fsgid = u, u, u, u
			} else {
				c.ruid, c.euid, c.suid, c.fsuid = u, u, u, u
			}
			return 0
		})
		return 0
	}
}
