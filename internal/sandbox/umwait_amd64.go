package sandbox

import (
	"sync/atomic"
	"unsafe"
)

// UMONITOR/UMWAIT (x86 WAITPKG) give an event-driven, low-power wait: the core
// parks on the channel's state word and wakes on the store that changes it --
// the same promptness as a busy spin (tens of nanoseconds) but without burning
// the core, so under load the cores stay free for the work that has to answer.
// It replaces the busy spin where the CPU has it; elsewhere the spin remains.

func cpuidWaitpkg() bool
func umonitor(addr unsafe.Pointer)
func umwait(ctrl uint32, deadline uint64)

var hasUmwait = cpuidWaitpkg()

// umwaitCtrl selects C0.1 (bit 0 = 1): the lighter sleep, quicker to wake.
const umwaitCtrl = 1

// waitStore parks until *addr becomes want1 or want2, or the deadline (cputicks)
// passes, and returns the value it observed. UMWAIT can return early -- on the
// store, on a spurious event, or at the OS-capped maximum -- so it loops,
// re-arming and re-checking, until a wanted value or the deadline. The re-check
// after UMONITOR closes the lost-wake window (a store between the first load and
// the arm is caught; a store after the arm makes UMWAIT fall through at once).
func waitStore(addr *uint32, want1, want2 uint32, deadline uint64) uint32 {
	for {
		v := atomic.LoadUint32(addr)
		if v == want1 || v == want2 || cputicks() >= deadline {
			return v
		}
		umonitor(unsafe.Pointer(addr))
		if v = atomic.LoadUint32(addr); v == want1 || v == want2 {
			return v
		}
		umwait(umwaitCtrl, deadline)
	}
}
