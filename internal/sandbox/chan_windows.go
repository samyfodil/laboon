//go:build windows

package sandbox

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows handshake on a channel slot. WaitOnAddress is process-local, so
// each side spins on page.state and then sleeps on its own auto-reset event,
// which the other side sets only when the sleep flag says it is needed. The
// supervisor's wait also watches the stub process, so a dead stub ends it.
type hostChan struct {
	*channel
	evStub, evSup windows.Handle // the stub waits on evStub, the supervisor on evSup
	proc          windows.Handle
	ownProc       bool          // proc is this channel's own handle (newStubChan)
	woke          time.Duration // when reply last had to wake the stub, 0 if it did not
	ioMu          sync.Mutex
	ioDead        bool
	ioGone        chan struct{}  // channel equivalent of ioDeath, for the readiness bus
	ioDeath       windows.Handle // manual-reset; never share evSup with I/O waits
	stopW         chan struct{}  // the channel's stop, closed once it ends
}

// newHostChan is the supervisor's handle on slot ch, whose stop closes when
// the slot ends (end), so a supervisor-side wait selecting on it gives up.
func newHostChan(ch *channel) *hostChan {
	c := &hostChan{channel: ch, stopW: make(chan struct{})}
	c.stop = c.stopW
	return c
}

// After reply wakes the stub, its next request is at least that wakeup away,
// so wait keeps spinning for about as long as wakeups take (wakeNs, a
// running estimate: down at once to a faster sample, up slowly) rather than
// sleep and need a wakeup of its own. Where waking a thread is slow (a VM
// without Hyper-V enlightenments: hundreds of microseconds), that halves the
// wakeups of a guest whose calls each outlast the stub's spin.
var wakeNs atomic.Int64

const maxWakeSpin = 2 * time.Millisecond

func noteWake(d time.Duration) {
	for {
		old := wakeNs.Load()
		n := int64(d)
		if old != 0 && n > old {
			n = old + (n-old)/16
		}
		if wakeNs.CompareAndSwap(old, n) {
			return
		}
	}
}

func (c *hostChan) requested() bool { return atomic.LoadUint32(&c.page.state) == stReq }

func (c *hostChan) wait() error {
	for range spin {
		if c.requested() {
			c.wokeSeen()
			return nil
		}
	}
	if c.woke != 0 {
		end := c.woke + min(2*time.Duration(wakeNs.Load()), maxWakeSpin)
		for monoNow() < end {
			for range spin {
				if c.requested() {
					c.wokeSeen()
					return nil
				}
			}
		}
	}
	defer c.wokeSeen()
	for {
		atomic.StoreUint32(&c.page.supSleep, 1)
		switch atomic.LoadUint32(&c.page.state) {
		case stReq:
			atomic.StoreUint32(&c.page.supSleep, 0)
			return nil
		case stDead:
			atomic.StoreUint32(&c.page.supSleep, 0)
			return errExited
		}
		ev, err := windows.WaitForMultipleObjects([]windows.Handle{c.evSup, c.proc}, false, windows.INFINITE)
		atomic.StoreUint32(&c.page.supSleep, 0)
		if err != nil {
			return err
		}
		if ev == windows.WAIT_OBJECT_0+1 {
			if atomic.LoadUint32(&c.page.state) == stReq {
				return nil
			}
			return errExited
		}
	}
}

// reply posts kind unless the slot went dead meanwhile (end), which it must
// not undo.
func (c *hostChan) reply(kind uint64) {
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
	if atomic.LoadUint32(&c.page.stubSleep) != 0 {
		windows.SetEvent(c.evStub)
		c.woke = monoNow()
	}
}

// wokeSeen records, when the request now posted answers a wakeup of the
// stub, how long that took.
func (c *hostChan) wokeSeen() {
	if c.woke != 0 {
		noteWake(monoNow() - c.woke)
		c.woke = 0
	}
}

// ended reports whether the stub process has ended, which ends every wait a
// thread of it has in the supervisor.
func (c *hostChan) ended() bool {
	if c.proc == 0 {
		return false
	}
	ev, err := windows.WaitForSingleObject(c.proc, 0)
	return err == nil && ev == windows.WAIT_OBJECT_0
}

// wake ends a supervisor wait on this slot, for teardown.
func (c *hostChan) wake() { windows.SetEvent(c.evSup) }

// gone is Linux's (chan.go): only there does a slot carry its stub thread's
// alive word.
func (c *hostChan) gone() {}

// end marks the slot dead and wakes the supervisor's wait on it, which
// returns errExited. The stub thread, if it is still waiting, waits on: its
// process is ending.
func (c *hostChan) end() {
	markDead(c.page)
	c.endIO()
	c.wake()
}

// copyOp has the stub copy n bytes between guest memory at addr and the slot
// window at off. It reports false when the stub could not vouch for the guest
// range, which the caller then copies itself.
func (c *hostChan) copyOp(kind, addr, n, off uint64) (bool, error) {
	c.page.args[0] = addr
	c.page.args[1] = n
	c.page.args[2] = off
	c.reply(kind)
	if err := c.wait(); err != nil {
		return false, err
	}
	if c.page.kind != msgHostRet {
		return false, errProtocol
	}
	return c.page.ret == 0, nil
}

// writable has the stub make guest memory [addr, addr+n) writable for the
// supervisor's write (repWritable) and reports whether the guest may write
// all of it. A page frozen for memory another process runs (the stub answers
// 2, with the page of memory and its freezes served) is first cooled there
// through cool (codereg.go), and the stub asked again, to thaw it.
func (c *hostChan) writable(addr, n uint64, cool func(x objPage)) bool {
	kind, nr, args, ret := c.page.kind, c.page.nr, c.page.args, c.page.ret
	defer func() { c.page.kind, c.page.nr, c.page.args, c.page.ret = kind, nr, args, ret }()
	var cooled [3]uint64
	for {
		c.page.args = [6]uint64{addr, n, 0, cooled[0], cooled[1], cooled[2]}
		c.reply(repWritable)
		if err := c.wait(); err != nil || c.page.kind != msgHostRet {
			return false
		}
		if c.page.ret != 2 {
			return c.page.ret == 0
		}
		x := objPage{c.page.args[0], c.page.args[1]}
		cool(x)
		cooled = [3]uint64{x.obj, x.off, c.page.args[2]}
	}
}

var errProtocol = errors.New("stub protocol error")

// strPage bounds each read of a guest C string: the guest's page size.
const strPage = 0x1000

func (g *dguest) scratch() []byte {
	o := g.slot*slotSize + scratchOff
	return g.mem[o : o+scratchLen]
}

// readMem copies n bytes of guest memory at addr straight out of the stub
// process.
func (g *dguest) readMem(addr uint64, n int) ([]byte, error) {
	out := make([]byte, n)
	if n == 0 {
		return out, nil
	}
	var got uintptr
	if err := windows.ReadProcessMemory(g.ch.proc, uintptr(addr), &out[0], uintptr(n), &got); err != nil || int(got) != n {
		return nil, errFault
	}
	return out, nil
}

// writeMem copies data into guest memory at addr as the guest's own write
// would land: a page it may not write is a fault. A page of code made
// executable at run time that is executable now is made writable first (the
// stub does it, repWritable), so what is written there runs only once
// rewritten. It is for the thread's own syscalls, while its stub awaits the
// reply; a write into a process another thread serves is writeMemCross.
func (g *dguest) writeMem(addr uint64, data []byte) error {
	if len(data) == 0 || ntWrite(g.ch.proc, addr, data) {
		return nil
	}
	cool := func(x objPage) {
		if w := g.mp.w; w != nil {
			w.run.code.cool(g.ps.ospid, x)
		}
	}
	if !g.ch.writable(addr, uint64(len(data)), cool) || !ntWrite(g.ch.proc, addr, data) {
		return errFault
	}
	return nil
}

// writeMemCross is writeMem into a process whose stub another thread may be
// talking to: an executable page of code made at run time stays so, and the
// write into it fails.
func (g *dguest) writeMemCross(addr uint64, data []byte) error {
	if len(data) == 0 || ntWrite(g.ch.proc, addr, data) {
		return nil
	}
	return errFault
}

// forceWriteMem writes data into guest memory at addr as ptrace does, into a
// page the guest may not write too (FOLL_FORCE).
func (g *dguest) forceWriteMem(addr uint64, data []byte) error {
	if g.writeMem(addr, data) == nil {
		return nil
	}
	var put uintptr
	if err := windows.WriteProcessMemory(g.ch.proc, uintptr(addr), &data[0], uintptr(len(data)), &put); err == nil && int(put) == len(data) {
		return nil
	}
	return writeCopy(g.ch.proc, addr, data)
}

// writeCopy writes data into pages of a copy-on-write view, a saved image's
// code: WriteProcessMemory asks for a writable page, which such a view never
// is, so each page is made copy-on-write for the write, which takes its
// private copy, and given back its protection.
func writeCopy(proc windows.Handle, addr uint64, data []byte) error {
	for len(data) > 0 {
		page := addr &^ (pageSize - 1)
		n := min(uint64(len(data)), page+pageSize-addr)
		var mbi windows.MemoryBasicInformation
		if windows.VirtualQueryEx(proc, uintptr(page), &mbi, unsafe.Sizeof(mbi)) != nil || mbi.Type != memMapped {
			return errFault
		}
		cow := uint32(windows.PAGE_WRITECOPY)
		if mbi.Protect&(windows.PAGE_EXECUTE|windows.PAGE_EXECUTE_READ|windows.PAGE_EXECUTE_WRITECOPY) != 0 {
			cow = windows.PAGE_EXECUTE_WRITECOPY
		}
		var old uint32
		if windows.VirtualProtectEx(proc, uintptr(page), pageSize, cow, &old) != nil {
			return errFault
		}
		ok := ntWrite(proc, addr, data[:n])
		windows.VirtualProtectEx(proc, uintptr(page), pageSize, old, &old)
		procFlushInstructionCache.Call(uintptr(proc), uintptr(page), pageSize)
		if !ok {
			return errFault
		}
		addr, data = addr+n, data[n:]
	}
	return nil
}

var procNtWriteVirtualMemory = modNtdll.NewProc("NtWriteVirtualMemory")

// ntWrite writes data into proc at addr as the page protection allows, unlike
// WriteProcessMemory, which makes a read-only page writable for the write.
func ntWrite(proc windows.Handle, addr uint64, data []byte) bool {
	var put uintptr
	r, _, _ := procNtWriteVirtualMemory.Call(uintptr(proc), uintptr(addr), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&put)))
	return r == 0 && int(put) == len(data)
}

var errFault = errors.New("bad guest address")

// ioBuf returns a buffer for up to n bytes on their way to or from guest
// memory: the slot window, which the stub copies to and from the guest itself.
func (g *dguest) ioBuf(n int) []byte { return g.window()[:min(n, winSize)] }

// putBuf copies b into guest memory at addr: by the stub when b lies in the
// window, else, or when the stub cannot vouch for the range, by
// WriteProcessMemory, which reports a bad address.
func (g *dguest) putBuf(addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if off, ok := g.winOffset(b); ok {
		if done, err := g.ch.copyOp(repPoke, addr, uint64(len(b)), off); done || err != nil {
			return err
		}
	}
	return g.writeMem(addr, b)
}

// getBuf fills b from guest memory at addr, as putBuf does the other way.
func (g *dguest) getBuf(addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if off, ok := g.winOffset(b); ok {
		if done, err := g.ch.copyOp(repPeek, addr, uint64(len(b)), off); done || err != nil {
			return err
		}
	}
	var got uintptr
	if err := windows.ReadProcessMemory(g.ch.proc, uintptr(addr), &b[0], uintptr(len(b)), &got); err != nil || int(got) != len(b) {
		return errFault
	}
	return nil
}

// winOffset reports where b starts in the slot window, if it lies within it.
func (g *dguest) winOffset(b []byte) (uint64, bool) {
	w := g.window()
	p := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	lo := uintptr(unsafe.Pointer(unsafe.SliceData(w)))
	if p < lo || p+uintptr(len(b)) > lo+uintptr(len(w)) {
		return 0, false
	}
	return uint64(p - lo), true
}
