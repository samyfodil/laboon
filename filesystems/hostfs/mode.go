//go:build darwin || linux || windows

package hostfs

// Linux S_IFMT type bits, which HostStat.mode carries so the overlay never sees
// a host mode's own type encoding.
const (
	lxSIFMT  = 0xf000
	lxSIFIFO = 0x1000
	lxSIFCHR = 0x2000
	lxSIFDIR = 0x4000
	lxSIFBLK = 0x6000
	lxSIFREG = 0x8000
	lxSIFLNK = 0xa000
	lxSIFSCK = 0xc000
)
