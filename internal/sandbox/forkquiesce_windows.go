package sandbox

import (
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lcForkQuiesce is a parent stub's request just before RtlCloneUserProcess,
// its region locks held: the supervisor quiesces the stub's other threads
// (quiesceFork) and resumes them once lcForked reports.
const lcForkQuiesce = 0x4c430028

// ntdll's exception dispatch takes a lock around the vectored handler list,
// and a fork child, which has only the cloning thread, waits forever on its
// first exception if another thread held it at the clone (windows/probes
// p9_vehlock.zig: 2-13 children in 1000 with threads raising exceptions). The
// lock is held only while a thread walks the list inside ntdll, not across
// the handler call, so a clone made while every other thread is suspended
// outside ntdll, or parked in a syscall, finds it free.

// ntdllImage is ntdll's image range in this process; a system DLL sits at the
// same address in every process of a boot, the stubs' included.
var ntdllImage = sync.OnceValues(func() (uint64, uint64) {
	h, err := windows.LoadLibrary("ntdll.dll")
	if err != nil {
		return 0, 0
	}
	var mi windows.ModuleInfo
	if windows.GetModuleInformation(windows.CurrentProcess(), h, &mi, uint32(unsafe.Sizeof(mi))) != nil {
		return 0, 0
	}
	return uint64(mi.BaseOfDll), uint64(mi.BaseOfDll) + uint64(mi.SizeOfImage)
})

// quiesceFork suspends every thread of stub st but self at a moment when none
// may hold the handler-list lock, and returns what resumes them. After many
// tries it gives up and leaves them suspended anyway: the child's own release
// of the lock (stub.zig vehUnlock) is the backstop.
func quiesceFork(sr *sigRun, st *winStub, self int) func() {
	inj := sr.injector()
	lo, hi := ntdllImage()
	if inj == nil || lo == 0 {
		return func() {}
	}
	inj.mu.Lock()
	var hs []windows.Handle
	for tid, r := range inj.threads {
		if r.st == st && tid != self {
			if h := dupThread(r.handle); h != 0 {
				hs = append(hs, h)
			}
		}
	}
	inj.mu.Unlock()
	for try := 0; ; try++ {
		var held []windows.Handle
		for _, h := range hs {
			if suspendThread(h) {
				held = append(held, h)
			}
		}
		resume := func() {
			for _, h := range held {
				windows.ResumeThread(h)
			}
		}
		busy := false
		for _, h := range held {
			if inDispatch(st.proc, h, lo, hi) {
				busy = true
				break
			}
		}
		if !busy || try == 1000 {
			return func() {
				resume()
				for _, h := range hs {
					windows.CloseHandle(h)
				}
			}
		}
		resume()
		runtime.Gosched()
	}
}

// inDispatch reports whether suspended thread h of process proc may hold the
// lock: its pc is in ntdll and not just past a syscall instruction.
func inDispatch(proc, h windows.Handle, lo, hi uint64) bool {
	buf := make([]byte, unsafe.Sizeof(winContext{})+16)
	ctx := (*winContext)(unsafe.Pointer((uintptr(unsafe.Pointer(&buf[0])) + 15) &^ 15))
	ctx.ContextFlags = contextFull
	if r, _, _ := procGetThreadContext.Call(uintptr(h), uintptr(unsafe.Pointer(ctx))); r == 0 {
		return false // gone
	}
	pc := ctx.pc()
	if pc < lo || pc >= hi {
		return false
	}
	var insn [4]byte
	if windows.ReadProcessMemory(proc, uintptr(pc-4), &insn[0], 4, nil) != nil {
		return true
	}
	return !afterSyscall(insn)
}
