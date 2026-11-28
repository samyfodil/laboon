package sandbox

import (
	"bytes"
	"fmt"
	"unsafe"
)

// The syscall inputs the stub copied into the slot's argument area as the call
// entered (stub/zig/args.zig), as Linux copies a syscall's input structures
// from user memory when it starts. A handler reads its inputs through argRead
// and argGet, which take them from there and go to guest memory for anything
// not copied. The area is the guest's to write, so loadArgs bounds-checks each
// record and the bytes are copied out once. argValidate, set by a test, checks
// every copy against guest memory.
//
// A handler's results go the other way through putOut: left in the slot's
// window with a record in the area, which the stub copies to guest memory as
// the call returns, the call's result becoming EFAULT if one faults -- what a
// failed write gives a handler. Results stay in order: one that cannot be left
// so flushes those before it, as does any reuse of the window (ioBuf).

const (
	argOff     = hopEnd // the areas follow the hop pages in the memfd
	argSize    = 32 << 10
	argMaxRecs = 24
	argMaxOuts = 16
	argOutsOff = 8 + 16*argMaxRecs // nout, pad, then the result records
	argDataOff = 1024
	argApply   = 1 // the header's flags: the call returns through the stub's once
	shmLen     = argOff + maxSlots*argSize
)

type argRec struct {
	addr     uint64
	len, off uint32
}

// argSet is the records of the syscall being served, and the results left for
// the stub to copy out.
type argSet struct {
	n    int
	recs [argMaxRecs]argRec

	defer_ bool // results may be left for the stub
	nout   int
	outs   [argMaxOuts]argRec
	outEnd int  // window bytes the results hold
	fault  bool // a flushed result faulted: the call fails with EFAULT
}

var argValidate bool

func (g *dguest) argArea() []byte {
	o := argOff + g.slot*argSize
	return g.mem[o : o+argSize : o+argSize]
}

// loadArgs takes the records of the syscall the thread posted. A traced
// thread's are not used: its tracer may change the memory at the entry stop.
func (g *dguest) loadArgs() {
	g.args = argSet{}
	if g.traced.Load() {
		return
	}
	a := g.argArea()
	g.args.defer_ = le32(a[4:])&argApply != 0
	n := min(int(le32(a)), argMaxRecs)
	for i := range n {
		r := a[8+16*i:]
		rec := argRec{addr: le64(r), len: le32(r[8:]), off: le32(r[12:])}
		if rec.off < argDataOff || uint64(rec.off)+uint64(rec.len) > argSize {
			continue
		}
		g.args.recs[g.args.n] = rec
		g.args.n++
	}
}

// argCopy fills b with the guest bytes at addr from the syscall's copied
// inputs, when one copy holds them all.
func (g *dguest) argCopy(addr uint64, b []byte) bool {
	for _, r := range g.args.recs[:g.args.n] {
		if addr < r.addr || addr-r.addr+uint64(len(b)) > uint64(r.len) {
			continue
		}
		o := uint64(r.off) + addr - r.addr
		copy(b, g.argArea()[o:o+uint64(len(b))])
		if argValidate {
			g.argCheck(addr, b)
		}
		return true
	}
	return false
}

// argCStr is the NUL-terminated string at addr from the syscall's copied
// inputs, when one copy starts there and holds its NUL.
func (g *dguest) argCStr(addr uint64) (string, bool) {
	for _, r := range g.args.recs[:g.args.n] {
		if r.addr != addr {
			continue
		}
		d := g.argArea()[r.off : r.off+r.len]
		i := bytes.IndexByte(d, 0)
		if i < 0 {
			return "", false
		}
		s := string(d[:i])
		if argValidate {
			g.argCheck(addr, []byte(s+"\x00"))
		}
		return s, true
	}
	return "", false
}

// argCheck compares a copied input with guest memory. A read that fails (the
// thread gone, or the range unmapped since by another) leaves nothing to
// compare.
func (g *dguest) argCheck(addr uint64, b []byte) {
	m := make([]byte, len(b))
	if g.mp.read(addr, m) == nil && !bytes.Equal(m, b) {
		panic(fmt.Sprintf("laboon: syscall input at %#x copied as %x, memory holds %x", addr, b, m))
	}
}

// deferOut leaves b, the guest bytes at addr, for the stub to copy out as the
// call returns, if it can: copied into the window, unless b is already there.
// When it cannot it flushes the results before, for the caller to write b
// after them.
func (g *dguest) deferOut(addr uint64, b []byte) bool {
	a := &g.args
	if len(b) == 0 || !a.defer_ || g.traced.Load() || a.nout == argMaxOuts {
		g.flushOuts()
		return false
	}
	w := g.window()
	off := -1
	if p, w0 := uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&w[0])); p >= w0 && p+uintptr(len(b)) <= w0+uintptr(len(w)) {
		off = int(p - w0)
	} else {
		off = (a.outEnd + 7) &^ 7
		if off+len(b) > len(w) {
			g.flushOuts()
			return false
		}
		copy(w[off:], b)
	}
	a.outEnd = max(a.outEnd, off+len(b))
	r := argRec{addr: addr, len: uint32(len(b)), off: uint32(off)}
	a.outs[a.nout] = r
	h := g.argArea()[argOutsOff+8+16*a.nout:]
	put64(h, r.addr)
	put32(h[8:], r.len)
	put32(h[12:], r.off)
	a.nout++
	put32(g.argArea()[argOutsOff:], uint32(a.nout))
	return true
}

// flushOuts writes the results left so far to guest memory now, in order.
func (g *dguest) flushOuts() {
	a := &g.args
	if a.nout == 0 {
		return
	}
	w := g.window()
	for _, r := range a.outs[:a.nout] {
		if g.writeMem(r.addr, w[r.off:r.off+r.len]) != nil {
			a.fault = true
		}
	}
	a.nout, a.outEnd = 0, 0
	put32(g.argArea()[argOutsOff:], 0)
}

// outResult is the call's result r, or EFAULT when a result it flushed
// faulted.
func (g *dguest) outResult(r int64) int64 {
	if g.args.fault {
		return sErr(lxEFAULT)
	}
	return r
}
