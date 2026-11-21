//go:build darwin || linux || windows

package sandbox

const stdioTraced = uint64(1) << 63

// stdioSinglestep asks the HVF stub to single-step one instruction (arm64
// software step via MDSCR_EL1.SS); the native backends single-step via TF in the
// trace frame instead, so it is set only for an HVF tracee on PTRACE_SINGLESTEP.
const stdioSinglestep = uint64(1) << 62

// stdioSeccomp marks a slot whose process has a seccomp filter: the Linux stub
// runs rt_sigreturn past the supervisor for the filter instead of completing it
// locally, and the darwin stubs post each call for the filters' verdict
// (msgSeccomp) before serving it. Mirrors STDIO_SECCOMP in stub/zig/stub.zig,
// stub/macos/stub.zig and stub/macos/vmm.zig.
const stdioSeccomp = uint64(1) << 61

// stdioAffinity marks a slot whose thread holds an rseq CPU (lx_rseq.go), or
// whose process's affinity mask leaves out a CPU:
// the darwin stub, which otherwise reports the host CPU it runs on, asks the
// supervisor for getcpu, as that CPU may be outside the mask. Mirrors
// STDIO_AFFINITY in stub/macos/stub.zig.
const stdioAffinity = uint64(1) << 60

// Methods run with dfs.mu held, except notifyExit. Only Linux installs tracing.
type ptraceBackend interface {
	traced(int) bool
	traceStopped(int) bool
	tracer(int) int
	wait(*dguest, waitSel, bool) (waitEvent, bool, bool)
	owns(*pstate) bool
	processExit(*pstate) (kill, release []int)
	holdsExit(*pstate) bool
	notifyExit(*pstate)
	forget(*pstate)
	takeOver(*dguest, int)
	signal(*dguest, int, sigInfo) (int, sigInfo)
	groupStop(*dguest, int) bool
}

func (fs *dfs) isTraced(tid int) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.tracing != nil && fs.tracing.traced(tid)
}

// traceStopped reports whether thread tid is in a ptrace stop.
func (fs *dfs) traceStopped(tid int) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.tracing != nil && fs.tracing.traceStopped(tid)
}

func (g *dguest) traceSignal(sig int, si sigInfo) (int, sigInfo) {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	if g.tracing == nil || sig == sigKILL {
		return sig, si
	}
	return g.tracing.signal(g, sig, si)
}

var ptraceReturn = func(g *dguest, ret int64) {}

func (g *dguest) traceGroupStop(sig int) bool {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	return g.tracing != nil && g.tracing.groupStop(g, sig)
}

func (fs *dfs) processTraced(pid int) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.tracing != nil && fs.tracing.owns(fs.pt[pid])
}

func (g *dguest) tracerPid(tid int) int {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	if g.tracing == nil {
		return 0
	}
	return g.ps.ns.localOf(g.tracing.tracer(tid))
}
