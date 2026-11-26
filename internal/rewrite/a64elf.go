package rewrite

import (
	"debug/elf"
	"io"
	"slices"
	"sync"
)

// a64Mu serializes arm64 scans: they share reused scratch (the visited bitmap
// and work queue), so concurrent scans from several execing guests would race.
var a64Mu sync.Mutex

// A64ELFEntries returns the instruction boundaries recursive descent starts
// from: the program entry, every function symbol (.symtab and .dynsym),
// DT_INIT and DT_FINI, the init, fini and preinit arrays, and the addresses
// relocations make pointers to (R_AARCH64_RELATIVE), as ELF virtual
// addresses. Those outside the code a caller scans are ignored there.
func A64ELFEntries(f *elf.File) []uint64 {
	funcs := []uint64{f.Entry}
	add := func(syms []elf.Symbol) {
		for _, s := range syms {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Value != 0 {
				funcs = append(funcs, s.Value)
			}
		}
	}
	if syms, err := f.Symbols(); err == nil {
		add(syms)
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		add(syms)
	}
	return append(funcs, pointedCode(f)...)
}

// A64TextRange returns the [start,end) vaddr of the .text section if it lies
// in segment p, else the whole segment (so the heuristic in A64SegmentSites
// still has a bound when sections are stripped).
func A64TextRange(f *elf.File, p *elf.Prog) (uint64, uint64) {
	if s := f.Section(".text"); s != nil && s.Addr >= p.Vaddr && s.Addr < p.Vaddr+p.Filesz {
		return s.Addr, s.Addr + s.Size
	}
	return p.Vaddr, p.Vaddr + p.Filesz
}

// A64SegmentSites finds every `svc #0` to rewrite in code, an executable
// segment at vaddr, and returns their offsets in ascending order. A bare
// 0xd4000001 word in a literal pool or a GOT/reloc table is data, not a
// syscall, and must not be patched, so this is recursive descent from funcs
// (vaddrs; those outside the segment are ignored) and the code the segment
// takes the address of, never a linear scan.
//
// Descent alone misses syscalls reached only through an indirect branch from
// code with no entry of its own (a local asm helper: musl has dozens). Within
// [textLo, textHi), an svc word descent did not reach is code when what runs
// into it says so (a64CodeBefore): walking back through words that fall
// through, a write to x8, where the Linux ABI passes the syscall number, or
// code descent reached. A word decoded code loads as data never is. A second
// descent then starts from those sites, reaching syscalls that reuse an x8 set
// earlier in the same helper.
func A64SegmentSites(code []byte, vaddr uint64, funcs []uint64, textLo, textHi uint64) []int {
	a64Mu.Lock()
	defer a64Mu.Unlock()
	sites, _ := a64SegmentSites(code, vaddr, funcs, textLo, textHi)
	return sites
}

// A64WindowSites is A64SegmentSites over code at vaddr, a window of a larger
// range analyzed one window at a time, that also returns the targets of its
// direct branches past its end, for the windows after it.
func A64WindowSites(code []byte, vaddr uint64, funcs []uint64) (sites []int, next []uint64) {
	a64Mu.Lock()
	defer a64Mu.Unlock()
	sites, exits := a64SegmentSites(code, vaddr, funcs, vaddr, vaddr+uint64(len(code)))
	for _, e := range exits {
		if e >= len(code) {
			next = append(next, vaddr+uint64(e))
		}
	}
	return sites, next
}

// a64SegmentSites is A64SegmentSites, which also returns the direct branch
// targets out of code, as offsets. a64Mu held.
func a64SegmentSites(code []byte, vaddr uint64, funcs []uint64, textLo, textHi uint64) ([]int, []int) {
	var entries []int
	for _, fn := range funcs {
		if fn >= vaddr && fn < vaddr+uint64(len(code)) {
			entries = append(entries, int(fn-vaddr))
		}
	}
	entries = append(entries, addrTaken(code, vaddr, textLo, textHi)...)
	seen := map[int]bool{}
	for _, off := range a64scan(code, entries, isSVC0, a64flowFastOK) {
		seen[off] = true
	}
	visited := slices.Clone(a64SeenBuf[:len(code)/4+1])
	data := slices.Clone(a64DataBuf[:len(code)/4+1])
	lo := 0
	if textLo > vaddr {
		lo = int(textLo - vaddr)
	}
	var extra []int
	for off := 4; off+4 <= len(code); off += 4 {
		if seen[off] || data[off/4] || le32(code[off:]) != a64SVC0 {
			continue
		}
		if va := vaddr + uint64(off); va < textLo || va >= textHi {
			continue
		}
		if a64CodeBefore(code, off, lo, visited, data) {
			extra = append(extra, off)
		}
	}
	if len(extra) > 0 {
		for _, off := range a64scan(code, append(entries, extra...), isSVC0, a64flowFastOK) {
			if !data[off/4] {
				seen[off] = true
			}
		}
		for _, off := range extra {
			seen[off] = true
		}
	}
	sites := make([]int, 0, len(seen))
	for off := range seen {
		sites = append(sites, off)
	}
	slices.Sort(sites)
	return sites, slices.Clone(a64Exits)
}

// A64AnonSites finds the svc sites in code written at run time, one page of
// it, as AnonSites does: descent from roots, then A64SegmentSites' test for
// the svc words descent did not reach. exits are the targets of the direct
// branches out of it, as offsets from its start.
func A64AnonSites(code []byte, roots []int) (sites, exits []int) {
	funcs := make([]uint64, 0, len(roots))
	for _, r := range roots {
		if r >= 0 {
			funcs = append(funcs, uint64(r))
		}
	}
	a64Mu.Lock()
	defer a64Mu.Unlock()
	return a64SegmentSites(code, 0, funcs, 0, uint64(len(code)))
}

// a64CodeBefore reports whether the svc word at off is code by what runs
// into it: walking back from it while each word falls through to the next,
// it meets a write to x8 or code descent reached (visited) before a word that
// does not fall through, data, or lo.
func a64CodeBefore(code []byte, off, lo int, visited, data []bool) bool {
	for b := off - 4; b >= lo; b -= 4 {
		if visited[b/4] {
			return true
		}
		w := le32(code[b:])
		if data[b/4] || !a64FallsThrough(w) {
			return false
		}
		if a64WritesX8(w) {
			return true
		}
	}
	return false
}

// a64FallsThrough reports whether the instruction w, executed, can go on to
// the next word: anything but an unconditional branch (B, BR, RET, ERET and
// their authenticated forms; BL and BLR return), an exception-generating
// instruction (SVC, HVC, SMC, BRK, HLT) or a word no instruction encodes (the
// UDF space, bits 31:16 clear).
func a64FallsThrough(w uint32) bool {
	switch {
	case w>>16 == 0:
		return false
	case w&0xfc000000 == 0x14000000: // B
		return false
	case w&0xfe000000 == 0xd6000000: // unconditional branch (register)
		opc := w >> 21 & 0xf
		return opc == 1 || opc == 9 // BLR, BLRAA/BLRAB
	case w&0xff000000 == 0xd4000000: // exception generation
		return false
	}
	return true
}

// a64WritesX8 reports whether w writes x8 (or w8): a data-processing
// instruction (immediate or register) with Rd 8, a general-register load
// (literal, single, pair, exclusive) into it, or an MRS to it.
func a64WritesX8(w uint32) bool {
	switch {
	case w>>26&7 == 4: // data processing, immediate
		return w&31 == 8
	case w>>25&7 == 5: // data processing, register
		return w&31 == 8
	case w&0xfff00000 == 0xd5300000: // MRS
		return w&31 == 8
	case w&0x3f000000 == 0x18000000: // LDR (literal), general register
		return w&31 == 8 && w>>30 != 3
	case w&0x3e000000 == 0x38000000: // load/store register, general register
		opc := w >> 22 & 3
		load := opc != 0 && !(w>>30 == 3 && opc == 2) // not a store, not PRFM
		return load && w&31 == 8
	case w&0x3e000000 == 0x28000000: // load/store pair, general registers
		return w&(1<<22) != 0 && (w&31 == 8 || w>>10&31 == 8)
	case w&0x3f400000 == 0x08400000: // load exclusive
		return w&31 == 8
	}
	return false
}

// A64ELFSites returns the svc sites of every executable PT_LOAD segment of f,
// as ELF virtual addresses in ascending order.
func A64ELFSites(f *elf.File) ([]uint64, error) {
	funcs := A64ELFEntries(f)
	var sites []uint64
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		code := make([]byte, p.Filesz)
		if _, err := io.ReadFull(p.Open(), code); err != nil {
			return nil, err
		}
		tlo, thi := A64TextRange(f, p)
		for _, off := range A64SegmentSites(code, p.Vaddr, funcs, tlo, thi) {
			sites = append(sites, p.Vaddr+uint64(off))
		}
	}
	return sites, nil
}

func isSVC0(w uint32) bool { return w == a64SVC0 }

// addrTaken returns the offsets, within .text, of code whose address the
// segment materializes with adr or adrp+add: functions reached only through
// a pointer (musl's res_msend cleanup handler, callbacks), whose syscalls
// descent from the symbol table never visits.
func addrTaken(code []byte, vaddr, tlo, thi uint64) []int {
	imm21 := func(w uint32) int64 { return int64(((w>>5)&0x7ffff)<<2|(w>>29)&3) << 43 >> 43 }
	var out []int
	for off := 0; off+4 <= len(code); off += 4 {
		w := le32(code[off:])
		pc := vaddr + uint64(off)
		var t uint64
		switch w & 0x9f000000 {
		case 0x10000000: // adr
			t = pc + uint64(imm21(w))
		case 0x90000000: // adrp, then add xd, xd, #lo12 within a few words
			rd := w & 0x1f
			found := false
			for k := 1; k <= 4 && off+4*k+4 <= len(code); k++ {
				n := le32(code[off+4*k:])
				if n&0xffc00000 == 0x91000000 && n&0x1f == rd && (n>>5)&0x1f == rd {
					t = pc&^0xfff + uint64(imm21(w)<<12) + uint64((n>>10)&0xfff)
					found = true
					break
				}
			}
			if !found {
				continue
			}
		default:
			continue
		}
		if t >= tlo && t < thi && t%4 == 0 {
			out = append(out, int(t-vaddr))
		}
	}
	return out
}
