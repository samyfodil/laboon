package sandbox

// a64Next is where the arm64 instruction w at pc can go next: its target for
// a branch (reg reads a register, 31 being the zero register), and pc+4
// unless it always branches.
func a64Next(w uint32, pc uint64, reg func(int) uint64) []uint64 {
	sext := func(v uint32, bits uint) uint64 {
		return uint64(int64(uint64(v)<<(64-bits)) >> (64 - bits))
	}
	switch {
	case w&0x7c000000 == 0x14000000: // B, BL
		return []uint64{pc + sext(w&0x3ffffff, 26)<<2}
	case w&0xff000010 == 0x54000000: // B.cond
		return []uint64{pc + 4, pc + sext(w>>5&0x7ffff, 19)<<2}
	case w&0x7e000000 == 0x34000000: // CBZ, CBNZ
		return []uint64{pc + 4, pc + sext(w>>5&0x7ffff, 19)<<2}
	case w&0x7e000000 == 0x36000000: // TBZ, TBNZ
		return []uint64{pc + 4, pc + sext(w>>5&0x3fff, 14)<<2}
	case w&0xff9ffc1f == 0xd61f0000: // BR, BLR, RET
		return []uint64{reg(int(w >> 5 & 31))}
	}
	return []uint64{pc + 4}
}
