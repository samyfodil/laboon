package rewrite

// A minimal x86-64 length decoder. The recursive descent needs only each
// instruction's length, its control-flow class (to follow branches and stop at
// terminators), whether it is a direct relative branch (and to where), whether
// it touches %fs memory, and whether it can be relocated -- far less than a full
// disassembler, which boxes every operand and so dominates time and allocation.
// This computes it straight from the encoding.
//
// golang.org/x/arch/x86/x86asm is kept only as a test oracle: x86dec_test.go
// checks this decoder against it, for length and control flow, on real amd64
// code and by fuzzing.

// x86inst is one decoded instruction. ok is false when the length cannot be
// determined (truncated or an unknown encoding), which stops the descent as a
// disassembler error would.
type x86inst struct {
	len        int
	ok         bool
	syscall    bool // SYSCALL (0f 05)
	terminates bool // JMP / RET / IRET / UD2 / HLT: no fall-through
	relOK      bool // a direct relative branch (JMP/CALL/Jcc/JrCXZ/LOOP rel8|rel32)
	rel        int  // its displacement (target = off + len + rel)
	movable    bool // can be relocated into a trampoline (matches rewrite.movable)
	fsMem      bool // a %fs-segment memory operand
	ripMem     bool // a RIP-relative memory operand (not relocatable)
	dispAt     int  // where its 32-bit displacement starts, ripMem
	relocRip   bool // not movable only for its RIP-relative operand, in a legacy encoding
	destAX     bool // destination is the AX/EAX/RAX accumulator (scavenge heuristic)
}

// immediate-size codes in the opcode tables.
const (
	imNone = iota
	im8    // 1 byte
	im16   // 2 bytes
	im32   // 4 bytes (fixed; used for branch rel32, unaffected by the 66 prefix)
	imZ    // 2 bytes with a 66 prefix, else 4
	imV    // 8 with REX.W, 2 with 66, else 4 (mov r,imm)
	imMoffs
	imGrp3b // F6: imm8 only when ModRM.reg is 0 or 1 (TEST rm8,imm8)
	imGrp3z // F7: immZ only when ModRM.reg is 0 or 1 (TEST rm,immZ)
	imEnter
)

// x86op1 and x86op0F describe the 1-byte and 0f-escape opcode maps: low 4 bits
// the immediate code, bit 4 (hasModRM) whether a ModRM byte follows.
var x86op1, x86op0F [256]uint8

const (
	hasModRM = 0x10
	known    = 0x20 // a tabled opcode; an untabled one (entry 0) makes the decoder give up
)

func opEntry(modrm bool, imm uint8) uint8 {
	e := known | imm
	if modrm {
		e |= hasModRM
	}
	return e
}

func init() {
	set := func(t *[256]uint8, lo, hi int, modrm bool, imm uint8) {
		for o := lo; o <= hi; o++ {
			t[o] = opEntry(modrm, imm)
		}
	}
	// --- one-byte opcode map ---
	t := &x86op1
	// ALU groups 00-3D: xx0-xx3 have ModRM, xx4 imm8, xx5 immZ.
	for _, base := range []int{0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38} {
		set(t, base, base+3, true, imNone)
		t[base+4] = opEntry(false, im8)
		t[base+5] = opEntry(false, imZ)
	}
	set(t, 0x50, 0x5f, false, imNone)  // PUSH/POP r
	t[0x63] = opEntry(true, imNone)    // MOVSXD
	t[0x68] = opEntry(false, imZ)      // PUSH immZ
	t[0x69] = opEntry(true, imZ)       // IMUL r,rm,immZ
	t[0x6a] = opEntry(false, im8)      // PUSH imm8
	t[0x6b] = opEntry(true, im8)       // IMUL r,rm,imm8
	set(t, 0x6c, 0x6f, false, imNone)  // INS/OUTS
	set(t, 0x70, 0x7f, false, im8)     // Jcc rel8
	t[0x80] = opEntry(true, im8)       // grp1 rm,imm8
	t[0x81] = opEntry(true, imZ)       // grp1 rm,immZ
	t[0x83] = opEntry(true, im8)       // grp1 rm,imm8
	set(t, 0x84, 0x8f, true, imNone)   // TEST/XCHG/MOV/LEA/MOV seg/POP rm
	set(t, 0x90, 0x97, false, imNone)  // XCHG r (90 = NOP)
	set(t, 0x98, 0x9f, false, imNone)  // CBW..LAHF
	set(t, 0xa0, 0xa3, false, imMoffs) // MOV AL/eAX, moffs
	set(t, 0xa4, 0xa7, false, imNone)  // MOVS/CMPS
	t[0xa8] = opEntry(false, im8)      // TEST AL,imm8
	t[0xa9] = opEntry(false, imZ)      // TEST eAX,immZ
	set(t, 0xaa, 0xaf, false, imNone)  // STOS/LODS/SCAS
	set(t, 0xb0, 0xb7, false, im8)     // MOV r8,imm8
	set(t, 0xb8, 0xbf, false, imV)     // MOV r,imm16/32/64
	set(t, 0xc0, 0xc1, true, im8)      // grp2 rm,imm8
	t[0xc2] = opEntry(false, im16)     // RET imm16
	t[0xc3] = opEntry(false, imNone)   // RET
	t[0xc6] = opEntry(true, im8)       // grp11 MOV rm,imm8
	t[0xc7] = opEntry(true, imZ)       // grp11 MOV rm,immZ
	t[0xc8] = opEntry(false, imEnter)  // ENTER imm16,imm8
	t[0xc9] = opEntry(false, imNone)   // LEAVE
	t[0xca] = opEntry(false, im16)     // far RET imm16
	t[0xcb] = opEntry(false, imNone)   // far RET
	t[0xcc] = opEntry(false, imNone)   // INT3
	t[0xcd] = opEntry(false, im8)      // INT imm8
	t[0xce] = opEntry(false, imNone)   // INTO
	t[0xcf] = opEntry(false, imNone)   // IRET
	set(t, 0xd0, 0xd3, true, imNone)   // grp2 rm,1|CL
	t[0xd7] = opEntry(false, imNone)   // XLAT
	set(t, 0xd8, 0xdf, true, imNone)   // x87
	set(t, 0xe0, 0xe3, false, im8)     // LOOP/JrCXZ rel8
	set(t, 0xe4, 0xe5, false, im8)     // IN imm8
	set(t, 0xe6, 0xe7, false, im8)     // OUT imm8
	t[0xe8] = opEntry(false, im32)     // CALL rel32
	t[0xe9] = opEntry(false, im32)     // JMP rel32
	t[0xeb] = opEntry(false, im8)      // JMP rel8
	set(t, 0xec, 0xef, false, imNone)  // IN/OUT DX
	t[0xf1] = opEntry(false, imNone)   // INT1
	t[0xf4] = opEntry(false, imNone)   // HLT
	t[0xf5] = opEntry(false, imNone)   // CMC
	t[0xf6] = opEntry(true, imGrp3b)   // grp3 rm (TEST has imm8)
	t[0xf7] = opEntry(true, imGrp3z)   // grp3 rm (TEST has immZ)
	set(t, 0xf8, 0xfd, false, imNone)  // CLC..STD
	t[0xfe] = opEntry(true, imNone)    // grp4 INC/DEC rm
	t[0xff] = opEntry(true, imNone)    // grp5 INC/DEC/CALL/JMP/PUSH rm

	// --- 0f escape map ---
	f := &x86op0F
	set(f, 0x00, 0x01, true, imNone) // grp6/grp7
	// 0f 05 SYSCALL, 0f 0b UD2, 0f 34 SYSENTER: no ModRM (left zero = imNone).
	t0f := []struct{ lo, hi int }{{0x02, 0x04}, {0x0d, 0x0f}, {0x10, 0x17}, {0x18, 0x1f},
		{0x28, 0x2f}, {0x40, 0x4f}, {0x50, 0x6f}, {0x74, 0x76}, {0x77, 0x7f}, {0x90, 0x9f},
		{0xa3, 0xa3}, {0xab, 0xab}, {0xaf, 0xb1}, {0xb3, 0xb3}, {0xb6, 0xb8}, {0xbb, 0xc1},
		{0xc3, 0xc3}, {0xc7, 0xc7}, {0xd0, 0xff}}
	for _, r := range t0f {
		set(f, r.lo, r.hi, true, imNone)
	}
	set(f, 0x20, 0x23, true, imNone)  // MOV cr/dr
	set(f, 0x80, 0x8f, false, im32)   // Jcc rel32
	f[0x70] = opEntry(true, im8)      // PSHUF imm8
	set(f, 0x71, 0x73, true, im8)     // grp12-14 imm8
	f[0xa4] = opEntry(true, im8)      // SHLD imm8
	f[0xa5] = opEntry(true, imNone)   // SHLD CL
	f[0xac] = opEntry(true, im8)      // SHRD imm8
	f[0xad] = opEntry(true, imNone)   // SHRD CL
	f[0xae] = opEntry(true, imNone)   // grp15
	f[0xa2] = opEntry(false, imNone)  // CPUID
	set(f, 0xa0, 0xa1, false, imNone) // PUSH/POP FS
	f[0xba] = opEntry(true, im8)      // grp8 BT imm8
	f[0xb2] = opEntry(true, imNone)   // LSS
	f[0xb4] = opEntry(true, imNone)   // LFS
	f[0xb5] = opEntry(true, imNone)   // LGS
	f[0xb9] = opEntry(true, imNone)   // UD1
	f[0xc2] = opEntry(true, im8)      // CMPPS imm8
	f[0xc4] = opEntry(true, im8)      // PINSRW imm8
	f[0xc5] = opEntry(true, im8)      // PEXTRW imm8
	f[0xc6] = opEntry(true, im8)      // SHUFPS imm8
	set(f, 0x30, 0x37, false, imNone) // WRMSR/RDTSC/...
	set(f, 0xc8, 0xcf, false, imNone) // BSWAP
	f[0x05] = opEntry(false, imNone)  // SYSCALL
	set(f, 0x06, 0x09, false, imNone) // CLTS/SYSRET/INVD/WBINVD
	f[0x0b] = opEntry(false, imNone)  // UD2
	f[0x34] = opEntry(false, imNone)  // SYSENTER
	f[0x35] = opEntry(false, imNone)  // SYSEXIT
	f[0x77] = opEntry(false, imNone)  // EMMS (no ModRM) -- overrides the range above
	f[0xa6] = opEntry(false, imNone)
	f[0xa7] = opEntry(false, imNone)
}

func x86s8(b byte) int { return int(int8(b)) }
func x86s32(b []byte) int {
	return int(int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24))
}

// InsnLen is the length of the x86-64 instruction at the start of code, or 0
// when it decodes as none.
func InsnLen(code []byte) int {
	if in := x86decode(code); in.ok {
		return in.len
	}
	return 0
}

// RipDisp is InsnLen, and where in the instruction its RIP-relative
// operand's 32-bit displacement starts (0 when it has none): what moving it
// must adjust.
func RipDisp(code []byte) (n, at int) {
	in := x86decode(code)
	if !in.ok {
		return 0, 0
	}
	if in.ripMem {
		return in.len, in.dispAt
	}
	return in.len, 0
}

// x86decode decodes one instruction at code[0], in 64-bit mode.

func x86decode(code []byte) x86inst {
	var in x86inst
	n := len(code)
	i := 0
	opsize16, fs, rexW, rep, addr32 := false, false, false, false, false
prefixes:
	for i < n {
		switch code[i] {
		case 0x66:
			opsize16 = true
		case 0x67:
			addr32 = true
		case 0x64:
			fs = true // %fs segment
		case 0x65, 0x2e, 0x36, 0x3e, 0x26:
			fs = false // another segment prefix overrides %fs (last one wins)
		case 0xf3:
			rep = true
		case 0xf0, 0xf2:
		default:
			break prefixes
		}
		i++
	}
	if i >= n {
		return in
	}
	if c := code[i]; c == 0xc5 || c == 0xc4 || c == 0x62 {
		return x86decodeVex(code, i)
	}
	rexB, rexR := false, false
	if code[i] >= 0x40 && code[i] <= 0x4f {
		rexW = code[i]&0x08 != 0
		rexR = code[i]&0x04 != 0
		rexB = code[i]&0x01 != 0
		i++
	}
	if i >= n {
		return in
	}

	op := code[i]
	i++
	var entry uint8
	is0F, is3A := false, false
	switch {
	case op == 0x0f:
		if i >= n {
			return in
		}
		op2 := code[i]
		i++
		if op2 == 0x38 || op2 == 0x3a {
			if i >= n {
				return in
			}
			is3A = op2 == 0x3a
			i++ // the third opcode byte
			entry = known | hasModRM
			if is3A {
				entry = known | hasModRM | im8
			}
			op = 0 // 3-byte ops carry no control flow
		} else {
			is0F = true
			op = op2
			entry = x86op0F[op2]
		}
	default:
		entry = x86op1[op]
	}
	if entry&known == 0 {
		return in // an untabled opcode: give up (the descent stops here, as on a decode error)
	}

	// ModRM / SIB / displacement.
	modReg, modRM, modIsReg := -1, -1, false
	if entry&hasModRM != 0 {
		m, reg, rm, rip, mem, ok := x86modrm(code[i:])
		if !ok {
			return in
		}
		modReg, modRM, modIsReg = reg, rm, !mem
		in.ripMem = rip
		in.dispAt = i + 1 // a RIP-relative operand has no SIB: disp32 follows the ModRM
		in.fsMem = fs && mem
		i += m
	}
	in.destAX = x86destAX(op, is0F, is3A, modReg, modRM, modIsReg, opsize16, rexR, rexB)

	// Immediate.
	imc := entry & 0x0f
	if imc == imMoffs {
		in.fsMem = fs // moffs is a memory operand with no ModRM
	}
	imsz, ok := x86immSize(imc, opsize16, rexW, addr32, modReg)
	if !ok {
		return in
	}
	if i+imsz > n {
		return in
	}
	immAt := i
	i += imsz
	in.len = i
	in.ok = true

	x86classify(&in, op, is0F, is3A, modReg, code, immAt, opsize16, rexW, rexB, rep)
	return in
}

// x86immSize resolves an immediate-size code to a byte count.
func x86immSize(code uint8, opsize16, rexW, addr32 bool, modReg int) (int, bool) {
	switch code {
	case imNone:
		return 0, true
	case im8:
		return 1, true
	case im16:
		return 2, true
	case im32:
		return 4, true
	case imZ:
		if opsize16 && !rexW { // REX.W (64-bit operand) overrides the 66 prefix
			return 2, true
		}
		return 4, true
	case imV:
		if rexW {
			return 8, true
		}
		if opsize16 {
			return 2, true
		}
		return 4, true
	case imMoffs:
		if addr32 {
			return 4, true // 32-bit address-size override
		}
		return 8, true
	case imGrp3b: // F6: imm8 only for TEST (ModRM.reg 0 or 1)
		if modReg == 0 || modReg == 1 {
			return 1, true
		}
		return 0, true
	case imGrp3z: // F7: immZ only for TEST (ModRM.reg 0 or 1)
		if modReg == 0 || modReg == 1 {
			if opsize16 && !rexW {
				return 2, true
			}
			return 4, true
		}
		return 0, true
	case imEnter:
		return 3, true // imm16 + imm8
	}
	return 0, false
}

// x86modrm parses ModRM (+ SIB + displacement), returning the byte count, the
// reg and rm fields, whether it is RIP-relative memory, and whether it is a
// memory (not register-direct) form.
func x86modrm(b []byte) (n, reg, rm int, rip, mem, ok bool) {
	if len(b) < 1 {
		return 0, 0, 0, false, false, false
	}
	m := b[0]
	mod := m >> 6
	reg = int(m>>3) & 7
	rm = int(m) & 7
	n = 1
	if mod == 3 {
		return n, reg, rm, false, false, true // register direct
	}
	mem = true
	if rm == 4 { // SIB
		if len(b) < n+1 {
			return 0, 0, 0, false, false, false
		}
		sib := b[n]
		n++
		if mod == 0 && sib&7 == 5 { // disp32 (no base)
			n += 4
		}
	} else if mod == 0 && rm == 5 { // RIP-relative disp32
		rip = true
		n += 4
	}
	switch mod {
	case 1:
		n++ // disp8
	case 2:
		n += 4 // disp32
	}
	if len(b) < n {
		return 0, 0, 0, false, false, false
	}
	return n, reg, rm, rip, mem, true
}

// x86destAX reports whether the instruction's destination is the AX/EAX/RAX
// accumulator (not AL), matching the disassembler's Args[0] for the scavenge
// heuristic. It covers the common accumulator-setting forms; anything else is
// reported false, which only makes the scavenge more conservative (a missed
// indirect syscall is caught by the stub's seccomp backstop, not a leak).
func x86destAX(op byte, is0F, is3A bool, reg, rm int, modIsReg, opsize16, rexR, rexB bool) bool {
	if is0F || is3A {
		switch op { // reg-destination two-byte ops writing a GPR (movzx/movsx/imul/...)
		case 0xaf, 0xb6, 0xb7, 0xbe, 0xbf, 0xb8, 0xbd, 0xbc:
			return reg == 0 && !rexR
		}
		return false
	}
	regDst := reg == 0 && !rexR           // ModRM.reg is (r)ax
	rmDst := modIsReg && rm == 0 && !rexB // ModRM.rm is a register and (r)ax
	switch {
	case op&0xc7 == 0x03: // odd ALU r,rm (03,0b,13,1b,23,2b,33,3b): reg dest
		return regDst
	case op&0xc7 == 0x01: // even ALU rm,r (01,09,...,39): rm dest
		return rmDst
	case op&0xc7 == 0x05: // ALU (e)ax,immz (05,0d,...,3d): implicit accumulator
		return true
	}
	switch op {
	case 0x8b, 0x8d, 0x63: // MOV r,rm / LEA / MOVSXD: reg dest
		return regDst
	case 0x89, 0x87, 0xc7, 0xf7, 0xff, 0xd1, 0xd3, 0xc1, 0x8f: // rm dest
		return rmDst
	case 0xb8: // MOV (e)ax,imm (B8+rd, rd=0)
		return !rexB
	case 0xa9, 0xa1, 0x05: // TEST (e)ax,imm / MOV (e)ax,moffs / (already covered)
		return true
	case 0x98, 0x99: // CWDE/CDQE writes (r)ax; CQO/CDQ writes rdx:rax
		return true
	}
	_ = opsize16
	return false
}

// x86classify sets the control-flow fields from the opcode.
func x86classify(in *x86inst, op byte, is0F, is3A bool, modReg int, code []byte, immAt int, opsize16, rexW, rexB, rep bool) {
	rel8 := func() {
		in.relOK = true
		in.rel = x86s8(code[immAt])
	}
	rel32 := func() {
		in.relOK = true
		in.rel = x86s32(code[immAt:])
	}
	if is3A {
		in.movable = !in.ripMem
		in.relocRip = in.ripMem
		return
	}
	if is0F {
		switch {
		case op == 0x05: // SYSCALL
			in.syscall = true
		case op == 0x0b: // UD2
			in.terminates = true
		case op >= 0x80 && op <= 0x8f: // Jcc rel32
			rel32()
		}
		// Not movable: SYSCALL, UD2, UD1, SYSENTER, multi-byte NOP, Jcc.
		nm := op == 0x05 || op == 0x0b || op == 0xb9 || op == 0x34 || op == 0x1f || (op >= 0x80 && op <= 0x8f)
		in.movable = !nm && !in.ripMem
		in.relocRip = !nm && in.ripMem
		return
	}
	switch op {
	case 0xe8: // CALL rel32
		rel32()
	case 0xe9: // JMP rel32
		in.terminates = true
		rel32()
	case 0xeb: // JMP rel8
		in.terminates = true
		rel8()
	case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f: // Jcc rel8
		rel8()
	case 0xe0, 0xe1, 0xe2, 0xe3: // LOOP/LOOPE/LOOPNE/JrCXZ rel8
		rel8()
	case 0xc2, 0xc3: // near RET
		in.terminates = true
	case 0xcf: // IRET only when 66 (IRET) or REX.W (IRETQ); plain CF is IRETD
		in.terminates = opsize16 || rexW
	case 0xf4: // HLT
		in.terminates = true
	case 0xff: // grp5: /4 indirect JMP terminates
		if modReg == 4 {
			in.terminates = true
		}
	}
	// Not movable (matches the disassembler's set): NOP (90 without REX.B, and
	// the 0f1f form handled above), INT (cd), HLT (f4), near CALL/JMP rel, near
	// RET, LOOP/JrCXZ, Jcc, and indirect near CALL/JMP (ff /2, /4). Far ret
	// (ca/cb LRET), int3 (cc), into (ce) and icebp (f1) are not in that set.
	nm := false
	switch op {
	case 0xcc, 0xcd, 0xf4, 0xe8, 0xe9, 0xeb, 0xc2, 0xc3, 0xe0, 0xe1, 0xe2, 0xe3:
		nm = true
	case 0x90:
		nm = !rexB && !rep // 90 is NOP only without REX.B (else XCHG r8) and without F3 (else PAUSE)
	case 0xc7:
		nm = modReg == 7 // C7 /7 is XBEGIN (a branch), not MOV
	}
	if op >= 0x70 && op <= 0x7f {
		nm = true
	}
	if op == 0xff && (modReg == 2 || modReg == 4) {
		nm = true
	}
	in.movable = !nm && !in.ripMem
	in.relocRip = !nm && in.ripMem
}

// x86decodeVex decodes a VEX/EVEX instruction starting at code[p] (p past the
// legacy prefixes). These are SSE/AVX forms: no control flow, always a ModRM,
// movable unless RIP-relative.
func x86decodeVex(code []byte, p int) x86inst {
	var in x86inst
	n := len(code)
	var mapSel int // 1=0F, 2=0F38, 3=0F3A
	switch code[p] {
	case 0xc5: // 2-byte VEX
		if p+1 >= n {
			return in
		}
		mapSel = 1
		p += 2
	case 0xc4: // 3-byte VEX
		if p+2 >= n {
			return in
		}
		mapSel = int(code[p+1] & 0x1f)
		p += 3
	case 0x62: // EVEX
		if p+3 >= n {
			return in
		}
		mapSel = int(code[p+1] & 0x3)
		p += 4
	}
	if p >= n {
		return in
	}
	vop := code[p]
	p++ // opcode byte
	m, _, _, rip, _, ok := x86modrm(code[p:])
	if !ok {
		return in
	}
	in.dispAt = p + 1
	p += m
	imm := 0
	switch {
	case mapSel == 3: // 0F3A map: always imm8
		imm = 1
	case mapSel == 1: // 0F map: the imm8-bearing opcodes (shuffles, shifts, compares)
		switch vop {
		case 0x70, 0x71, 0x72, 0x73, 0xc2, 0xc4, 0xc5, 0xc6:
			imm = 1
		}
	}
	if p+imm > n {
		return in
	}
	in.len = p + imm
	in.ok = true
	// A RIP-relative operand cannot be stolen into a trampoline: its address is
	// relative to the instruction's own position, which the move changes. This
	// holds for VEX/EVEX too (AVX constant pools are RIP-relative loads); the
	// disassembler misses this for VEX/EVEX, so here the decoder is stricter
	// than the oracle, which is the safe direction.
	in.ripMem = rip
	in.movable = !rip
	return in
}
