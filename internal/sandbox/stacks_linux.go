package sandbox

import "golang.org/x/sys/unix"

// Each slot has three private stacks in the stub window (stub/zig/stub.zig):
// its alternate signal stack, its exec stack and its service stack. They are
// mapped stackChunk slots at a time, in a stub process only once a thread of
// it is to run on a slot of that chunk, so their memory -- and, under strict
// overcommit, their commit charge -- follows the threads the process has.
const stackChunk = 64 // STACK_CHUNK in stub.zig

var slotStacks = [...]struct{ off, size uint64 }{
	{0x1b000000000, 128 << 10}, // altsAddr, ALT_SIZE
	{0x17000000000, 64 << 10},  // execsAddr, EXEC_SIZE
	{0x23000000000, 64 << 10},  // scratchAddr, SCRATCH_SIZE
}

// mapSlotStacks maps slot idx's stack chunk in g's stub process, unless it
// already is: a fork child inherits its parent's chunks, and the stub maps
// chunk 0 itself. The caller holds g.mp.mu.
func (g *dguest) mapSlotStacks(idx int) bool {
	c := idx / stackChunk
	if g.mp.stackChunks[c] {
		return true
	}
	for _, s := range slotStacks {
		at := stubLo + s.off + uint64(c)*stackChunk*s.size
		r := g.host(unix.SYS_MMAP, at, stackChunk*s.size, unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE|unix.MAP_NORESERVE, ^uint64(0), 0)
		if r != int64(at) && r != -int64(unix.EEXIST) {
			if r >= 0 {
				g.host(unix.SYS_MUNMAP, uint64(r), stackChunk*s.size)
			}
			return false
		}
	}
	if g.mp.stackChunks == nil {
		g.mp.stackChunks = map[int]bool{}
	}
	g.mp.stackChunks[c] = true
	return true
}
