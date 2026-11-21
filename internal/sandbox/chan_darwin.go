//go:build darwin

package sandbox

import (
	"errors"
	"sync"
	"sync/atomic"
	"unsafe"
)

// The message kinds, state values, slot sizing and chanPage layout are shared
// with the native stub and defined in chanabi.go. This file holds the macOS
// handshake: os_sync_wait_on_address(_with_timeout) / os_sync_wake_by_address_any (macOS
// 14.4+), the cross-process analog of the Linux shared futex. Both calls are
// SHARED (the state word lives in a MAP_SHARED region spanning two processes).
// The stub side is stub/macos/chan.zig.
//
// Unlike Linux's fixed high stub mapping, the Darwin stub maps the shared
// region at a kernel-picked base and is handed its slot pointer directly, so
// page.self is unused across the boundary and the stub layout has no fixed
// addresses here.

const osSyncShared = 1

var (
	syncOnce  sync.Once
	syncErr   error
	scWait    *ffiCall // os_sync_wait_on_address
	scWake    *ffiCall // os_sync_wake_by_address_any
	scWakeAll *ffiCall // os_sync_wake_by_address_all
)

// initSync resolves the os_sync primitives from libSystem once. They are macOS
// 14.4+ and absent from older SDK stubs, so they are looked up at runtime.
func initSync() error {
	syncOnce.Do(func() {
		lib, err := ffiOpenLibSystem()
		if err != nil {
			syncErr = err
			return
		}
		if scWait, syncErr = ffiPrep(lib, "os_sync_wait_on_address", ffiS32, ffiPtr, ffiU64, ffiU64, ffiU32); syncErr != nil {
			return
		}
		if scWake, syncErr = ffiPrep(lib, "os_sync_wake_by_address_any", ffiS32, ffiPtr, ffiU64, ffiU32); syncErr != nil {
			return
		}
		scWakeAll, syncErr = ffiPrep(lib, "os_sync_wake_by_address_all", ffiS32, ffiPtr, ffiU64, ffiU32)
	})
	return syncErr
}

// os_sync_wait_on_address(void *addr, uint64 value, size_t size, uint32 flags) -> int
func syncWait(addr uintptr, value uint64, size uintptr, flags uint32) int32 {
	var ret int32
	sz := uint64(size)
	scWait.call(unsafe.Pointer(&ret), unsafe.Pointer(&addr), unsafe.Pointer(&value), unsafe.Pointer(&sz), unsafe.Pointer(&flags))
	return ret
}

// os_sync_wake_by_address_any(void *addr, size_t size, uint32 flags) -> int
func syncWake(addr uintptr, size uintptr, flags uint32) int32 {
	var ret int32
	sz := uint64(size)
	scWake.call(unsafe.Pointer(&ret), unsafe.Pointer(&addr), unsafe.Pointer(&sz), unsafe.Pointer(&flags))
	return ret
}

// os_sync_wake_by_address_all(void *addr, size_t size, uint32 flags) -> int
func syncWakeAll(addr uintptr, size uintptr, flags uint32) int32 {
	var ret int32
	sz := uint64(size)
	scWakeAll.call(unsafe.Pointer(&ret), unsafe.Pointer(&addr), unsafe.Pointer(&sz), unsafe.Pointer(&flags))
	return ret
}

func (c *channel) stateAddr() uintptr { return uintptr(unsafe.Pointer(&c.page.state)) }

// wait blocks until the stub posts a request.
func (c *channel) wait() error {
	for range spin {
		if atomic.LoadUint32(&c.page.state) == stReq {
			return nil
		}
	}
	for {
		atomic.StoreUint32(&c.page.supSleep, 1)
		cur := atomic.LoadUint32(&c.page.state)
		if cur == stReq || cur == stDead {
			atomic.StoreUint32(&c.page.supSleep, 0)
			if cur == stDead {
				return errExited
			}
			return nil
		}
		syncWait(c.stateAddr(), uint64(cur), 4, osSyncShared)
		atomic.StoreUint32(&c.page.supSleep, 0)
	}
}

// wake unblocks the supervisor's own wait.
func (c *channel) wake() { syncWake(c.stateAddr(), 4, osSyncShared) }

// gone is Linux's (chan.go): only there does a slot carry its stub thread's
// alive word.
func (c *channel) gone() {}

// end marks the slot dead and wakes both sides: the supervisor's wait
// returns errExited, and a stub thread still waiting for a reply ends.
func (c *channel) end() {
	atomic.StoreUint32(&c.page.state, stDead)
	syncWakeAll(c.stateAddr(), 4, osSyncShared)
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
	syncWake(c.stateAddr(), 4, osSyncShared)
}

// copyOp runs one peek/poke memory op: the stub copies args[1] bytes between
// guest address args[0] and the slot window, so the supervisor can read and
// write guest memory without a mach_vm view. The syscall the slot holds keeps
// its arguments: a tracer reads a stopped tracee's memory through its channel,
// and the call goes on with them after the stop.
func (c *channel) copyOp(kind uint64, addr, n uint64) error {
	held := [2]uint64{c.page.args[0], c.page.args[1]}
	defer func() { c.page.args[0], c.page.args[1] = held[0], held[1] }()
	c.page.args[0] = addr
	c.page.args[1] = n
	c.reply(kind)
	if err := c.wait(); err != nil {
		return err
	}
	if c.page.kind != msgHostRet {
		return errors.New("stub protocol: expected copy ack")
	}
	if c.page.ret == 1 {
		return errGuestFault
	}
	return nil
}

// errGuestFault is a peek or poke of a guest range that faults.
var errGuestFault = errors.New("guest range faults")

// host has the stub perform a (translated, Darwin) syscall in the guest's
// address space and returns its raw result. Only the numbers the Seatbelt
// allowlist admits are reachable.
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

// hostChan is the channel as the shared code holds it; darwin's needs nothing
// beyond the slot.
type hostChan = channel

func (g *dguest) scratch() []byte {
	o := g.slot*slotSize + scratchOff
	return g.mem[o : o+scratchLen]
}

// readMem copies n bytes of guest memory at addr by having the stub peek them
// into the slot window, a window at a time.
func (g *dguest) readMem(addr uint64, n int) ([]byte, error) {
	out := make([]byte, n)
	for off := 0; off < n; {
		chunk := min(n-off, winSize)
		if err := g.ch.copyOp(repPeek, addr+uint64(off), uint64(chunk)); err != nil {
			return nil, err
		}
		copy(out[off:off+chunk], g.window()[:chunk])
		off += chunk
	}
	return out, nil
}

// forceWriteMem writes data into guest memory at addr as ptrace does, into a
// page the guest may not write too (FOLL_FORCE).
func (g *dguest) forceWriteMem(addr uint64, data []byte) error {
	return g.pokeMem(repForcePoke, addr, data)
}

// writeMem copies data into guest memory at addr via the stub's poke.
func (g *dguest) writeMem(addr uint64, data []byte) error { return g.pokeMem(repPoke, addr, data) }

func (g *dguest) pokeMem(kind, addr uint64, data []byte) error {
	for off := 0; off < len(data); {
		chunk := min(len(data)-off, winSize)
		copy(g.window()[:chunk], data[off:off+chunk])
		if err := g.ch.copyOp(kind, addr+uint64(off), uint64(chunk)); err != nil {
			return err
		}
		off += chunk
	}
	return nil
}

// strPage bounds each read of a guest C string: the guest's smallest page, a
// guest under HVF mapping 4 KiB pages.
const strPage = 0x1000

// ioBuf returns a buffer for up to n bytes on their way to or from guest
// memory: the slot window itself, so putBuf and getBuf move the data with one
// stub copy and none here.
func (g *dguest) ioBuf(n int) []byte { return g.window()[:min(n, winSize)] }

// putBuf copies b into guest memory at addr: with one stub copy when b is
// ioBuf's, through the window otherwise.
func (g *dguest) putBuf(addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if g.atWindow(b) {
		return g.ch.copyOp(repPoke, addr, uint64(len(b)))
	}
	return g.writeMem(addr, b)
}

// getBuf fills b from guest memory at addr: with one stub copy when b is
// ioBuf's, through the window otherwise.
func (g *dguest) getBuf(addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if g.atWindow(b) {
		return g.ch.copyOp(repPeek, addr, uint64(len(b)))
	}
	for off := 0; off < len(b); {
		chunk := min(len(b)-off, winSize)
		if err := g.ch.copyOp(repPeek, addr+uint64(off), uint64(chunk)); err != nil {
			return err
		}
		copy(b[off:off+chunk], g.window()[:chunk])
		off += chunk
	}
	return nil
}

// atWindow reports whether b starts the slot window, where the stub's peek and
// poke copy.
func (g *dguest) atWindow(b []byte) bool {
	w := g.window()
	return unsafe.SliceData(b) == unsafe.SliceData(w) && len(b) <= len(w)
}

// ended is false: a macOS stub's end closes the channel's stop (dead).
func (c *channel) ended() bool { return false }
