//go:build (linux || windows) && amd64

package sandbox

const guestArch = x64Machine

// Linux's x86-64 layout constants: ELF_ET_DYN_BASE, where a position-
// independent program with an interpreter loads, and vm.mmap_rnd_bits, the
// default page-count entropy of its randomized bases.
const (
	etDynBase    = 0x555555554000
	mmapRndBits  = x64MmapRndBits
	stackRndBits = 22 // STACK_RND_MASK

	vmTaskSize  = 0x7ffffffff000 // the top of a 47-bit user address space
	unmappedDiv = 3              // TASK_UNMAPPED_BASE is TASK_SIZE / 3
	map32bit    = 0x40           // MAP_32BIT

	// unlimitedStackLegacy: an unlimited stack does not make the mmap layout
	// legacy (bottom-up) here, x86's mmap_is_legacy having no such case.
	unlimitedStackLegacy = false
)

// hostABI is the guest's ABI, the supervisor's own architecture's.
var hostABI = &abiX64

const epollEventSize = x64EpollEventSize
