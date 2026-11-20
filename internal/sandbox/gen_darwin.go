package sandbox

import (
	"time"
)

// An x86-64 guest issues x86-64 syscall numbers; the shared table is keyed by
// the asm-generic (arm64) numbers, so toGeneric translates the number and the
// legacy arguments before dispatch and fromGeneric adjusts the result. The
// translation itself (x64Generic/x64Result) is shared with the linux and
// windows x86-64 backends in lx_x64nr_amd64.go.
//
// The memory calls (mmap, mprotect, munmap, brk, mremap) and arch_prctl are
// served in the stub for a darwin guest and never forwarded, so toGeneric does
// not special-case them: a forwarded one has no handler and ENOSYSes loudly,
// which is the intended "the stub missed it" failure.

// Keys for x86-64 calls whose generic form needs a custom handler. The values
// are laboon-private, distinct from any Linux number.
const (
	lxPoll   = 0x4c431000 + 7
	lxSelect = 0x4c431000 + 23
	lxTime   = 0x4c431000 + 201
)

func init() {
	syscalls[lxPoll] = func(g *dguest, a [6]uint64) int64 {
		timeout := time.Duration(-1)
		if ms := int64(int32(a[2])); ms >= 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
		r := g.pollFor(a[0], a[1], timeout, 0)
		if r == sErr(errRestart) {
			r = sErr(errRestartNoHand)
		}
		return r
	}
	syscalls[lxSelect] = func(g *dguest, a [6]uint64) int64 {
		timeout := time.Duration(-1)
		if a[4] != 0 {
			b, err := g.readMem(a[4], 16)
			if err != nil {
				return sErr(lxEFAULT)
			}
			sec, usec := int64(le64(b)), int64(le64(b[8:]))
			if sec < 0 || usec < 0 {
				return sErr(lxEINVAL)
			}
			timeout = time.Duration(sec)*time.Second + time.Duration(min(usec, 999999))*time.Microsecond
		}
		start := time.Now()
		r := g.selectFor(int64(int32(a[0])), a[1], a[2], a[3], timeout, 0)
		if a[4] != 0 && r >= 0 {
			left := max(timeout-time.Since(start), 0)
			var b [16]byte
			put64(b[:], uint64(left/time.Second))
			put64(b[8:], uint64(left%time.Second/time.Microsecond))
			g.writeMem(a[4], b[:])
		}
		return r
	}
	syscalls[lxTime] = func(g *dguest, a [6]uint64) int64 {
		now := time.Now().Unix()
		if a[0] != 0 {
			var b [8]byte
			put64(b[:], uint64(now))
			if g.writeMem(a[0], b[:]) != nil {
				return sErr(lxEFAULT)
			}
		}
		return now
	}
}

// x64ToGeneric maps an x86-64 syscall to the shared table's key; the result
// goes back through x64FromGeneric.
func x64ToGeneric(nr uint64, a [6]uint64) (uint64, [6]uint64, bool) {
	switch nr {
	case 34: // pause: a ppoll on nothing
		return lxPpoll, [6]uint64{}, true
	case 7:
		return lxPoll, a, true
	case 23:
		return lxSelect, a, true
	case 201:
		return lxTime, a, true
	}
	return x64Generic(nr, a)
}

func x64FromGeneric(nr uint64, a [6]uint64, r int64) int64 { return x64Result(nr, a, r) }

// toGeneric/fromGeneric dispatch on the guest's architecture, not the
// supervisor's build arch: a native supervisor can host an x86-64 guest (under
// Rosetta, in the x86-64 stub) alongside arm64 guests. An arm64 guest already
// posts the asm-generic numbers, so its translation is the identity.
func (g *dguest) toGeneric(nr uint64, a [6]uint64) (uint64, [6]uint64, bool) {
	if g.run.x64 {
		return x64ToGeneric(nr, a)
	}
	return nr, a, true
}

func (g *dguest) fromGeneric(nr uint64, a [6]uint64, r int64) int64 {
	if g.run.x64 {
		return x64FromGeneric(nr, a, r)
	}
	return r
}
