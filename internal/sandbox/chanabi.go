package sandbox

import (
	"errors"
	"sync/atomic"
	"unsafe"
)

// Channel ABI shared by the Go supervisor and the native stub — stub/zig/stub.zig
// on Linux, stub/macos/chan.zig on macOS. The slot page is a memory ABI between
// two processes, like a syscall frame: both sides must agree on this layout and
// these constants. The ONLY per-OS difference is the primitive used to block on
// and wake page.state (a Linux shared futex vs. macOS os_sync_wait_on_address);
// the message protocol and page layout are identical. See chan.go (linux) and
// chan_darwin.go (macOS) for the two handshakes.
//
// The field names lean x86-64 (rip, and args map rdi/rsi/rdx/r10/r8/r9). On
// arm64 the same slots hold the arm64 state unchanged: rip is the trapping pc,
// guestRip the resume pc, and args[0..5] are x0..x5. The layout does not change.

// Message kinds (stub -> supervisor) and reply kinds (supervisor -> stub).
const (
	msgReady   = 1
	msgSyscall = 2
	msgHostRet = 3
	msgForked  = 4 // child -> sup: forked, real pid in args[0]
	// A syscall the stub served in-guest (futex, clock_gettime, mmap, ...),
	// posted only so a traced thread's entry and exit stops still fire. nr and
	// args hold the call, ret the result it already produced; the supervisor
	// runs both ptrace stops and replies repResult with the (possibly edited)
	// result. Never posted when the thread is untraced.
	msgTraceLocal = 5
	// Windows: a clone child's first message, its OS thread id in args[0],
	// which the supervisor opens so a signal can reach it.
	msgThreadId = 6
	// Darwin and Windows: a guest syscall of a process with a seccomp filter,
	// posted before the stub serves it in-guest or forwards it. nr, args and
	// guestRip are the call; the supervisor runs the filters and replies
	// repResult with args[0] = 1 and ret the result when they decided it, or
	// args[0] = 0 to let it run.
	msgSeccomp = 7

	repResult = 1 // final syscall result in ret
	repHost   = 2 // perform syscall nr(args) on the host, reply msgHostRet
	repStart  = 3 // jump to args[0] (entry) with stack args[1], stdio args[2]
	repClone  = 4 // spawn a guest thread
	repExec   = 5 // execve: jump to args[0] with stack args[1]
	repFork   = 6 // fork the stub process (Linux: save the forking thread's context, see forkProc)
	// Linux only: before an execve clears the old address space, move the
	// stub onto a dedicated exec stack so the teardown cannot pull out the
	// stack it runs on; the stub acks with msgHostRet, then serves the unmaps
	// and the new image's maps there until repExec.
	repExecPrepare = 13
	// Linux only: a raw rt_sigreturn the stub ran through the guest seccomp
	// filter and this layer owns, so the stub may complete it on its frame. Any
	// other reply to a raw rt_sigreturn means an outer guest's filter trapped it
	// (it belongs to an inner layer) and the frame is left for the SIGSYS.
	repSigreturn = 14
	// Linux only: the trap was no syscall site the rewriter made; the stub
	// raises SIGILL in the guest.
	repFault = 12
	// macOS only: the supervisor has no mach_vm view of the guest, so it
	// reads and writes guest memory by having the stub (which shares the
	// guest address space) copy to/from the slot's window (chan_darwin.go).
	// args[0] = guest address, args[1] = length (<= winSize); reply
	// msgHostRet. Windows: args[2] = offset in the window, and ret = 1 when
	// the stub could not vouch for the guest range and copied nothing.
	repPeek = 7 // copy args[1] bytes at guest args[0] -> slot window
	repPoke = 8 // copy args[1] bytes slot window -> guest args[0]
	// macOS only: rewrite the svc/tpidr/ctr sites of a runtime-loaded shared
	// library's executable segment (copied in by mem.zig, so mapElf never saw it).
	// args[0] = count of site guest-addresses packed as u64s in the slot scratch;
	// the stub patches each to a branch into a freshly built island. Reply
	// msgHostRet. Done while the segment is still writable, before mprotect R+X.
	repRewrite = 10
	// macOS only: end the stub thread a CLONE_VM child process runs on (its
	// exit_group, a fatal signal, or an exec into a stub of its own). The
	// thread posts nrThreadGone as its last use of the slot.
	repThreadEnd = 11
	// macOS only: list the guest's mappings from address args[0] into the
	// scratch (stub/macos/mem.zig MapEnt); ret = count, args[1] = where the
	// next request resumes (0: done). Reply msgHostRet.
	repMaps = 12
	// macOS only: repMaps with each mapping's counts for /proc/<pid>/smaps
	// (stub/macos/smaps.zig SmapEnt).
	repSmaps = 22
	// macOS only: repPoke into pages the guest may not write too, as
	// ptrace's writes (FOLL_FORCE).
	repForcePoke = 24
	// Windows only: a stub started ahead on a spare slot moves to the slot
	// at offset args[0], whose events it finds in that slot's stdio and
	// pinfo fields, and reports msgReady there (stubpool_windows.go).
	repAdopt = 13
	// Windows only: make guest memory [args[0], +args[1]) writable for the
	// supervisor's write, turning the pages of code made executable at run
	// time that are executable writable again (stub/windows/mem.zig). Reply
	// msgHostRet, ret 1 when the guest may not write all of it.
	repWritable = 15
)

// scratch is the per-slot byte buffer after the chanPage header, for the
// macOS ops that pass small data. Offset is aligned clear of the header.
const (
	scratchOff = 128
	scratchLen = slotSize - scratchOff
)

// The header must end before the scratch; a field added past it fails here.
var _ [scratchOff - unsafe.Sizeof(chanPage{})]struct{}

// state word values: who owns the slot right now.
const (
	stReq = 1 // request posted, supervisor to act
	stRep = 2 // reply posted, stub to act
	// stDead: the supervisor is done with the slot's thread (its process is
	// ending). A waiting stub thread exits on it, and a supervisor wait on
	// the slot returns errExited: being a value, it cannot be missed the way
	// a wake can.
	stDead = 3
)

// markDead sets the state word to stDead, unless it holds a thread's posted
// gone notice the supervisor has not read: nothing replies to that notice, so
// the thread, and with it the last of its process, may be gone before it is
// read, and ending the slot then must not lose how the thread ended.
func markDead(pg *chanPage) {
	for {
		cur := atomic.LoadUint32(&pg.state)
		if cur == stReq && pg.kind == msgSyscall && pg.nr == nrThreadGone {
			return
		}
		if atomic.CompareAndSwapUint32(&pg.state, cur, stDead) {
			return
		}
	}
}

const (
	slotSize = 4096
	slotsLen = slotSize * maxSlots
)

// spin is how many times a waiter polls page.state before it sleeps.
const spin = 20000

var errExited = errors.New("stub exited")

// chanPage is one channel slot: the per-thread message frame. The layout is
// shared verbatim with the native stub (struct chan). guestRip must stay at
// offset 104 (OFF_GUEST_RIP in the stub).
type chanPage struct {
	self  uint64 // slot address; the stub reads it to find its own slot
	state uint32
	// Linux: set while a cloned stub thread runs on this slot; the kernel
	// zeroes it (CLONE_CHILD_CLEARTID) when that thread is gone. Windows:
	// bit i set while guest fd i is the null device the stub serves itself.
	// macOS: how the next exec places the program (layoutNorand).
	alive uint32
	kind  uint64
	nr    uint64
	args  [6]uint64
	rip   uint64 // trapping syscall site (x86 rip / arm64 pc); validates a trap
	ret   uint64 // syscall result
	// Sleep flags: each side sets its own before sleeping so the other knows
	// to issue a wake. See the exchange in the stub and wait/reply here.
	stubSleep uint32
	supSleep  uint32
	guestRip  uint64 // where the guest resumes after this syscall
	stdio     uint64 // bit i set: serve read/write on fd i in-process
	pinfo     uint64 // macOS, slot 0: guest address of the stub's procinfo record
}

// newChannel wraps slot idx within the shared region mem. It records the slot's
// guest-visible address so the stub thread can find it. done is closed when the
// main stub dies; stop when this (possibly forked) process exits, so a serve
// goroutine wakes even if its stub thread is gone.
func newChannel(mem []byte, idx int, slotsBase uint64, done, stop <-chan struct{}) *channel {
	page := (*chanPage)(unsafe.Pointer(&mem[idx*slotSize]))
	page.self = slotsBase + uint64(idx*slotSize)
	return &channel{page: page, done: done, stop: stop}
}

// channel is the supervisor's handle on one slot. The blocking/waking methods
// (wait, reply, host, clone) are per-OS; the fields are shared.
type channel struct {
	page *chanPage
	done <-chan struct{} // main stub died
	stop <-chan struct{} // this process exited
	sp   spinner         // adaptive spin estimator for this slot (see adaptspin.go)
}
