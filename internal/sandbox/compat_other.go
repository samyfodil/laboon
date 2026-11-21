//go:build darwin || windows

package sandbox

import (
	"io"
	"math/bits"
	"os"
)

// getcpu reports a CPU of the thread's affinity mask, NUMA node 0: the one
// its rseq area names, else one by its tid. The stub's threads are not
// pinned, so which host CPU one is on says nothing; the tid spreads threads
// over the mask as a scheduler would.
func (g *dguest) getcpu(cpu, node uint64) int64 {
	mask := g.ps.cpus.Load()
	var c, z [4]byte
	n := nthCPU(mask, g.pid%max(bits.OnesCount64(mask), 1))
	if v, ok := g.rseqCPU(); ok {
		n = v
	}
	put32(c[:], uint32(n))
	if cpu != 0 && g.writeMem(cpu, c[:]) != nil || node != 0 && g.writeMem(node, z[:]) != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

// nthCPU is the n-th CPU (from 0) of mask, or 0 when it has fewer.
func nthCPU(mask uint64, n int) int {
	for ; mask != 0; mask &= mask - 1 {
		if n == 0 {
			return bits.TrailingZeros64(mask)
		}
		n--
	}
	return 0
}

func (g *dguest) rseq(a [6]uint64) int64 { return g.rseqEmulated(a) }

// The affinity calls keep the mask in the process's sched state: the stub's
// threads are not pinned to it.
func (g *dguest) hostGetaffinity(pid int, size, addr uint64) (int64, bool) { return 0, false }
func (g *dguest) hostSetaffinity(pid int, size, addr uint64) (int64, bool) { return 0, false }

// readPrefix has the whole of b or none of it: the stub's copy does not say
// where it stopped.
func (g *dguest) readPrefix(addr uint64, b []byte) int {
	if g.getBuf(addr, b) == nil {
		return len(b)
	}
	return 0
}

// writeFaulting writes what Linux would of a buffer that runs into memory
// the guest cannot read: a regular file keeps the bytes before the fault;
// anything else, which the host cannot fault at that point, gets nothing.
func (g *dguest) writeFaulting(f *os.File, buf []byte, tail int, nonblock bool) (int, error) {
	if fi, err := f.Stat(); len(buf) == 0 || err != nil || !fi.Mode().IsRegular() {
		return 0, errFaultWrite
	}
	return f.Write(buf)
}

// The supervisor cannot see the guest's memory, so the stub measures, at the
// entry of a read it leaves to the supervisor, how much of the call's output
// vector the guest can write from its start, and tags it into the request's
// ret (outPrefix in the stubs' mem.zig). Untagged, as from a stub that did
// not measure, it is all of it.
const outTag = 2 << 62

// noteOut takes the stub's measure from a request's ret.
func (g *dguest) noteOut(ret uint64) {
	g.outW = ^uint64(0)
	if ret>>62 == outTag>>62 {
		g.outW = ret &^ (3 << 62)
	}
}

// writablePrefix is how much of the call's output buffer at addr, n bytes
// long, the guest can write from its start, as the stub measured it.
func (g *dguest) writablePrefix(addr, n uint64) uint64 { return min(n, g.outW) }

// writableVecPrefix is how many of the first n bytes of the call's output
// vector v the guest can write from its start.
func (g *dguest) writableVecPrefix(v [][2]uint64, n int) int { return int(min(uint64(n), g.outW)) }

// readFaulting reads what Linux would into buf, past which tail more bytes of
// the guest's buffer cannot be written. A regular file gives what fits and
// moves its offset that far; with no room at all it fails, except at its end,
// where a read gives nothing. Anything else is a stream (readStreamFaulting).
func (g *dguest) readFaulting(f *os.File, buf []byte, tail int, nonblock bool) (int, error) {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return g.readStreamFaulting(f, buf, nonblock)
	}
	if len(buf) > 0 {
		return f.Read(buf)
	}
	if off, err := f.Seek(0, io.SeekCurrent); err == nil && off >= fi.Size() {
		return 0, io.EOF
	}
	return 0, errFaultRead
}

// rndBits is the kernel's default mmap_rnd_bits for the architecture, which
// /proc/sys/vm reports.
func rndBits() uint64 { return mmapRndBits }

// The clocks a stub does not serve itself reach the supervisor: those that
// are not the host's alike, and the CPU-time clocks.
func (g *dguest) hostClockGettime(id int32, addr uint64) (int64, bool) { return 0, false }
func (g *dguest) hostClockGetres(id int32, addr uint64) (int64, bool)  { return 0, false }
