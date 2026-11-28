//go:build linux

package sandbox

import (
	"errors"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The message kinds, state values, slot sizing and chanPage layout are shared
// with the native stub and defined in chanabi.go. This file holds the Linux
// handshake (a shared futex on page.state) and the Linux stub's fixed address
// layout.

const (
	// Shared (not FUTEX_PRIVATE) futex ops: the word lives in two processes.
	futexWait = 0
	futexWake = 1
)

// Stub layout; see stub/zig/stub.zig and stub/build.sh. Guest mappings may not
// touch this window. It defaults to the primary window; a nested laboon's stub
// is a PIE the outer places at a free high window, and adoptWindow sets these
// to that base once the stub reports it at ready (stubwin_linux.go). A process
// uses one stub, so one window.
var (
	stubLo    uint64 = 0x6c0000000000
	stubHi    uint64 = 0x700000000000
	slotsAddr uint64 = 0x6c1000000000 // slotsAddr() in stub.zig
)

// stubWinSize is the window's extent (stub.WIN_SIZE): code + the channel,
// signal/exec stacks and tid table that sit at fixed offsets above the base.
const stubWinSize = 0x40000000000

// wait blocks until the stub posts a request. It spins first (catching a
// request without the cost of a park) and then parks on the futex. How long it
// spins is adaptive -- learned from how fast this slot's stub keeps answering.
// See adaptspin.go.
func (c *channel) wait() error {
	ensureCalibrated()
	start := cputicks()
	if budget := c.sp.budget(); budget > 0 {
		switch c.spinFor(start + budget) {
		case stReq:
			c.sp.hit(cputicks() - start)
			return nil
		case stDead:
			return errExited
		}
	}
	return c.park(start, true)
}

// spinFor waits for the stub to post a request (state stReq) or the slot to die
// (stDead), until the deadline (cputicks) passes; it returns the state it saw.
// With UMWAIT it parks the core low-power and wakes on the store; otherwise it
// busy-polls. Either way catching the request costs no park.
func (c *channel) spinFor(deadline uint64) uint32 {
	if hasUmwait {
		return waitStore(&c.page.state, stReq, stDead, deadline)
	}
	for {
		// Poll the state word a batch of times, PAUSE between reads (yields the
		// SMT sibling and lowers power), before touching the clock. The batch is
		// sized so PAUSE dominates and the rdtsc cost does not inflate the
		// measured arrival, while the deadline is still checked ~every µs.
		for i := 0; i < 32; i++ {
			st := atomic.LoadUint32(&c.page.state)
			if st == stReq || st == stDead {
				return st
			}
			spinHint()
		}
		if cputicks() >= deadline {
			return atomic.LoadUint32(&c.page.state)
		}
	}
}

// park sleeps on the state futex until the stub posts a request or the slot
// dies. When learn is set it folds the total wait (from start) into the slot's
// spin estimator on return.
func (c *channel) park(start uint64, learn bool) error {
	for {
		atomic.StoreUint32(&c.page.supSleep, 1)
		cur := atomic.LoadUint32(&c.page.state)
		if cur == stReq || cur == stDead {
			atomic.StoreUint32(&c.page.supSleep, 0)
			if cur == stDead {
				return errExited
			}
			if learn {
				c.sp.miss(cputicks() - start)
			}
			return nil
		}
		_, _, en := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&c.page.state)),
			futexWait, uintptr(cur), 0, 0, 0)
		if en == 0 && atomic.LoadUint32(&c.page.state) == stReq {
			parkSeen(atomic.LoadUint64(c.wakeAt()))
		}
		atomic.StoreUint32(&c.page.supSleep, 0)
	}
}

// wakeAt is where the side that wakes the other stamps when (the stub's
// Thread.wake_at), for the woken side's measure of the park cost.
func (c *channel) wakeAt() *uint64 {
	return (*uint64)(unsafe.Add(unsafe.Pointer(c.page), stubWakeAt))
}

// end marks the slot dead and wakes both sides: the supervisor's wait
// returns errExited, and a stub thread still waiting for a reply exits.
func (c *channel) end() {
	markDead(c.page)
	unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&c.page.state)), futexWake, 1<<31-1, 0, 0, 0)
}

// reply posts kind unless the slot went dead meanwhile (end), which it must
// not undo.
func (c *channel) reply(kind uint64) {
	c.page.kind = kind
	for {
		cur := atomic.LoadUint32(&c.page.state)
		if cur == stDead {
			return
		}
		if atomic.CompareAndSwapUint32(&c.page.state, cur, stRep) {
			break
		}
	}
	if atomic.LoadUint32(&c.page.stubSleep) == 0 {
		return
	}
	atomic.StoreUint64(c.wakeAt(), cputicks())
	unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&c.page.state)),
		futexWake, 1, 0, 0, 0)
	c.sp.wokePeer()
}

// host has the stub perform a syscall on the host and returns its raw
// result (negative errno on failure). The stub's seccomp filter only admits
// memory-management syscalls.
func (c *channel) host(nr uintptr, args ...uint64) (int64, error) {
	c.page.nr = uint64(nr)
	c.page.args = [6]uint64{}
	copy(c.page.args[:], args)
	c.reply(repHost)
	if err := c.wait(); err != nil {
		return 0, err
	}
	if c.page.kind != msgHostRet {
		return 0, errors.New("stub protocol: expected host result")
	}
	return int64(c.page.ret), nil
}

// gone marks the slot's stub thread gone with its whole process: the kernel
// clears a thread's alive word (CLONE_CHILD_CLEARTID) only while another
// thread of the process remains, so the last one leaves it set.
func (c *channel) gone() {
	atomic.StoreUint32(&c.page.alive, 0)
	unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&c.page.alive)), futexWake, 1<<31-1, 0, 0, 0)
}

// awaitGone waits until the kernel has zeroed the slot's alive word, i.e.
// the stub thread that ran on it has exited and no longer touches its stack.
// The kernel clears and wakes the word as the thread exits, however it ends,
// unless it is the last thread of its process (gone covers that).
func (c *channel) awaitGone() {
	for atomic.LoadUint32(&c.page.alive) != 0 {
		unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&c.page.alive)),
			futexWait, 1, 0, 0, 0)
	}
}

// clone asks the stub to spawn a thread (see clone in stub/zig). The stub
// replies with the real tid, which the supervisor ignores.
func (c *channel) clone(childStack, tls, slotAddr, bootTop uint64) {
	c.page.args = [6]uint64{childStack, tls, slotAddr, bootTop}
	c.reply(repClone)
	c.wait()
}
