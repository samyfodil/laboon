//go:build windows

package sandbox

import (
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procPeekNamedPipe    = modKernel32.NewProc("PeekNamedPipe")
	procSuspendThread    = modKernel32.NewProc("SuspendThread")
	procGetThreadContext = modKernel32.NewProc("GetThreadContext")
	procSetThreadContext = modKernel32.NewProc("SetThreadContext")
	procQueueUserAPC     = modKernel32.NewProc("QueueUserAPC")
)

// hostInterruptibleRead and hostInterruptibleWrite see only files whose I/O
// does not wait for a peer: the host's pipes are pipeend_windows.go's, the
// guest's the supervisor's own, and the pipes behind /dev/zero and the random
// devices are kept full.
func (g *dguest) hostInterruptibleRead(f *os.File, buf []byte, k readKind) (int, error) {
	return f.Read(buf)
}

func (g *dguest) hostInterruptibleWrite(f *os.File, buf []byte) (int, error) {
	return f.Write(buf)
}

// Signal injection, the supervisor's half of Windows delivery. The shared
// layer (lx_signal.go) decides which thread a signal goes to and marks it
// pending; wakeThread reaches that thread in the stub. A thread running guest
// code is redirected by stealing its context (SuspendThread +
// Get/SetThreadContext), a thread parked in an alertable stub wait is broken by
// a cross-process APC (probes §6). Frame building itself is the stub's
// (stub/windows/sig.zig); the supervisor only stashes the stolen context and
// points the thread at lc_sig_redirect.
//
// The CONTEXT layout and the redirect's registers are per architecture
// (signal_windows_amd64.go, signal_windows_arm64.go).

const threadAccess = 0x2 | 0x8 | 0x10 | 0x800 // SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | QUERY_LIMITED_INFORMATION

// stStubSp is the offset in a thread's signal record of its stub stack top
// (stub/windows/sig.zig Thread.stub_sp).
const stStubSp = 80

const (
	stReturnLo      = 88
	stReturnHi      = 96
	stReturnRetry   = 104
	stReturnTail    = 112
	stReturnTailEnd = 120
)

// winStub is one stub process as the injector reaches it: its handle, its
// view of the channel section, its signal entry points and the guest code
// ranges a thread may be redirected from.
type winStub struct {
	proc     windows.Handle
	chanBase uint64
	redirect uintptr
	apc      uintptr
	mu       sync.Mutex
	code     [][2]uint64
}

// forked returns the record of a fork child of this stub: the same entry
// points and view, a copy of the code ranges.
func (st *winStub) forked(proc windows.Handle) *winStub {
	st.mu.Lock()
	defer st.mu.Unlock()
	return &winStub{proc: proc, chanBase: st.chanBase, redirect: st.redirect, apc: st.apc, code: append([][2]uint64(nil), st.code...)}
}

// addCode records code mapped at run time (a shared library and its
// trampolines). A range is never dropped: a later mapping there that a
// thread executes is guest code too.
func (st *winStub) addCode(lo, hi uint64) {
	st.mu.Lock()
	st.code = append(st.code, [2]uint64{lo, hi})
	st.mu.Unlock()
}

func (st *winStub) inCode(pc uint64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.code {
		if pc >= r[0] && pc < r[1] {
			return true
		}
	}
	return false
}

type threadReg struct {
	handle windows.Handle
	owns   bool // true when we OpenThread'd it (a clone child), closed on exit
	st     *winStub
}

// winInjector maps every guest thread of a run to its OS thread and stub.
type winInjector struct {
	mu      sync.Mutex
	threads map[int]threadReg // guest tid -> OS thread
	parked  map[int][]int     // a stopped process's tgid -> the tids it suspended
}

var winInjectors sync.Map // *sigRun -> *winInjector

func winInstallInjector(sr *sigRun) {
	winInjectors.Store(sr, &winInjector{threads: map[int]threadReg{}})
}

func (sr *sigRun) injector() *winInjector {
	if v, ok := winInjectors.Load(sr); ok {
		return v.(*winInjector)
	}
	return nil
}

// winSetThread records guest thread tid as OS thread h of stub st, replacing
// (and closing, if owned) what tid had.
func winSetThread(sr *sigRun, tid int, h windows.Handle, owns bool, st *winStub) {
	inj := sr.injector()
	if inj == nil {
		return
	}
	inj.mu.Lock()
	if r, ok := inj.threads[tid]; ok && r.owns {
		windows.CloseHandle(r.handle)
	}
	inj.threads[tid] = threadReg{handle: h, owns: owns, st: st}
	inj.mu.Unlock()
}

// winRegisterThread opens a clone or fork child's OS thread by the id it
// reported, so a signal can reach it. One whose process a job-control stop
// already holds is held too before it runs guest code: the stop was reported
// as in effect.
func winRegisterThread(sr *sigRun, tid int, osTid uint32, st *winStub) {
	h, err := windows.OpenThread(threadAccess, false, osTid)
	if err != nil {
		return
	}
	winSetThread(sr, tid, h, true, st)
	if t := sr.thread(tid); t != nil {
		if _, stopped := sr.jobStop(t.tgid); stopped {
			if p := sr.proc(t.tgid); p != nil {
				sr.hostStopThread(p, t)
			}
		}
	}
}

func winUnregisterThread(sr *sigRun, tid int) {
	inj := sr.injector()
	if inj == nil {
		return
	}
	inj.mu.Lock()
	if r, ok := inj.threads[tid]; ok {
		delete(inj.threads, tid)
		if r.owns {
			windows.CloseHandle(r.handle)
		}
	}
	inj.mu.Unlock()
}

func winDropInjector(sr *sigRun) {
	inj := sr.injector()
	if inj == nil {
		return
	}
	inj.mu.Lock()
	for _, r := range inj.threads {
		if r.owns {
			windows.CloseHandle(r.handle)
		}
	}
	inj.threads = nil
	inj.mu.Unlock()
	winInjectors.Delete(sr)
}

// winSigDebug gates verbose signal-injection tracing (LC_SIGDEBUG=1).
var winSigDebug = os.Getenv("LC_SIGDEBUG") == "1"

// wakeThread reaches thread t in the stub: a cross-process APC to break any
// alertable wait, and, when the thread is running guest code (not in stub code
// or a handler), a context steal that redirects it into lc_sig_redirect.
func (sr *sigRun) wakeThread(t *sigThread) {
	// sr.wake has already queued the Go kick. Set the host wait event before
	// any injection/APC work (which can fail or find the stub busy).
	t.mu.Lock()
	if t.wr >= 0 {
		windows.SetEvent(windows.Handle(t.wr))
	}
	t.mu.Unlock()
	inj := sr.injector()
	if inj == nil {
		return
	}
	inj.mu.Lock()
	reg, ok := inj.threads[t.tid]
	inj.mu.Unlock()
	if !ok {
		return
	}
	h, st := reg.handle, reg.st

	// Break an alertable wait (a futex, a sleep, sigsuspend/sigtimedwait, or
	// the channel exchange); the pending signal is taken on the way out.
	procQueueUserAPC.Call(st.apc, uintptr(h), 0)

	if r, _, _ := procSuspendThread.Call(uintptr(h)); r == ^uintptr(0) {
		return
	}
	defer windows.ResumeThread(h)

	// SuspendThread returns before the thread has stopped; GetThreadContext
	// waits for it. Only then do its flags say what it is doing.
	buf := make([]byte, unsafe.Sizeof(winContext{})+16)
	ctx := (*winContext)(unsafe.Pointer((uintptr(unsafe.Pointer(&buf[0])) + 15) &^ 15))
	ctx.ContextFlags = contextFull
	if r, _, _ := procGetThreadContext.Call(uintptr(h), uintptr(unsafe.Pointer(ctx))); r == 0 {
		return
	}
	o := tOff(t.slot)
	busy := atomic.LoadUint32((*uint32)(unsafe.Pointer(&sr.area[o+stBusy])))
	inh := atomic.LoadUint32((*uint32)(unsafe.Pointer(&sr.area[o+stInHandler])))
	if winSigDebug {
		println("[wake] tid", t.tid, "busy", int64(busy), "inh", int64(inh))
	}
	if busy != 0 || inh != 0 {
		return // in stub code; it delivers on the way out
	}
	// These ranges take precedence over broad image/trampoline ranges.
	// The canonical context is stable while busy is clear. Rewind the gate;
	// never save or deliver from its partially restored live registers.
	load := func(off int) uint64 {
		return atomic.LoadUint64((*uint64)(unsafe.Pointer(&sr.area[o+off])))
	}
	pc := ctx.pc()
	inReturn := pc >= load(stReturnLo) && pc < load(stReturnHi)
	inTail := pc >= load(stReturnTail) && pc < load(stReturnTailEnd)
	if inReturn || inTail {
		ctx.setPC(load(stReturnRetry))
		procSetThreadContext.Call(uintptr(h), uintptr(unsafe.Pointer(ctx)))
		return
	}
	// Elsewhere in the stub, a return-gate check still lies ahead.
	if !st.inCode(ctx.pc()) {
		if winSigDebug {
			println("[skip] tid", t.tid, "pc", int64(ctx.pc()), "not in guest code")
		}
		return
	}
	// Stash the stolen context in the thread's slot scratch; lc_sig_redirect
	// reads it from there and delivers.
	off := t.slot*slotSize + scratchOff
	*(*winContext)(unsafe.Pointer(&sr.fs.mem[off])) = *ctx
	if winSigDebug {
		println("[redirect] tid", t.tid, "pc", int64(ctx.pc()), "flags", int64(ctx.ContextFlags))
	}
	// The redirect runs on the thread's stub stack: below the guest's stack
	// pointer may be someone else's memory (a Go goroutine stack is 2 KiB,
	// its neighbour's lies under it). The stub records it before it first
	// enters the guest.
	top := atomic.LoadUint64((*uint64)(unsafe.Pointer(&sr.area[o+stStubSp])))
	if top == 0 {
		return
	}
	ctx.redirect(uint64(st.redirect), st.chanBase+uint64(off), top)
	procSetThreadContext.Call(uintptr(h), uintptr(unsafe.Pointer(ctx)))
}
