//go:build (linux || windows) && arm64

package sandbox

// On Linux and Windows the guest runs the host's architecture: this file and
// lx_arch_amd64.go hold its layout constants (lx_abi.go has the rest of what
// the shared layer does differently per guest ABI).

const guestArch = a64Machine

// Linux's arm64 layout constants (48-bit VA): ELF_ET_DYN_BASE, where a
// position-independent program with an interpreter loads, and
// vm.mmap_rnd_bits, the default page-count entropy of its randomized bases.
const (
	etDynBase    = 0xaaaaaaaaa000
	mmapRndBits  = a64MmapRndBits
	stackRndBits = 18 // STACK_RND_MASK

	vmTaskSize  = 1 << 48 // the top of a 48-bit user address space
	unmappedDiv = 4       // TASK_UNMAPPED_BASE is TASK_SIZE / 4
	map32bit    = 0       // no MAP_32BIT

	// unlimitedStackLegacy: an unlimited stack makes the mmap layout legacy
	// (bottom-up), as the generic mmap_is_legacy has it.
	unlimitedStackLegacy = true
)

// hostABI is the guest's ABI, the supervisor's own architecture's.
var hostABI = &abiA64

const epollEventSize = a64EpollEventSize
