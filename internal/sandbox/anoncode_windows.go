//go:build windows

package sandbox

import "github.com/samyfodil/laboon/internal/rewrite"

// anonSites serves lcAnonSites (anoncode.go) for the page at page. A page
// the stub holds aside (from: a shadow of shared code it fills before putting
// it in place, stub/windows/mem.zig) is read there. Given a trampoline area,
// [area, area+room), its sites get trampolines there too (anonTramps).
func (g *wguest) anonSites(dg *dguest, page, pc, from, area, room uint64) int64 {
	read := g.sp.readMem
	if from != 0 {
		read = aside(read, page, pageSize, from)
	}
	n := g.anon.sites(dg, pageSize, page, pc, read, func(pc uint64) uint64 { return insnEnd(read, pc) })
	if n >= 0 && area != 0 {
		g.anonTramps(dg, page, int(n), area, room, read)
	}
	return n
}

// aside reads the ps bytes at page from from instead.
func aside(read func(addr uint64, b []byte) error, page, ps, from uint64) func(addr uint64, b []byte) error {
	return func(addr uint64, b []byte) error {
		for len(b) > 0 {
			n, src := uint64(len(b)), addr
			switch {
			case addr >= page && addr < page+ps:
				n, src = min(n, page+ps-addr), from+(addr-page)
			case addr < page && addr+n > page:
				n = page - addr
			}
			if err := read(src, b[:n]); err != nil {
				return err
			}
			addr += n
			b = b[n:]
		}
		return nil
	}
}

// insnEnd is where the instruction at pc ends (x86-64), or 0.
func (g *wguest) insnEnd(pc uint64) uint64 { return insnEnd(g.sp.readMem, pc) }

func insnEnd(read func(addr uint64, b []byte) error, pc uint64) uint64 {
	b := make([]byte, 16)
	if read(pc, b) != nil {
		return 0
	}
	if n := rewrite.InsnLen(b); n > 0 {
		return pc + uint64(n)
	}
	return 0
}

// lcInsn: (pc) -> the length of the x86-64 instruction there | where its
// RIP-relative displacement starts << 8 (0 when it has none); 0 when it
// decodes as none. The stub runs a store out of line with it
// (stub/windows/ool.zig).
const lcInsn = 0x4c43002c

func (g *wguest) insn(pc uint64) int64 {
	b := make([]byte, 16)
	for len(b) > 0 && g.sp.readMem(pc, b) != nil {
		b = b[:len(b)-1] // the instruction ends before an unreadable page
	}
	n, at := rewrite.RipDisp(b)
	return int64(n | at<<8)
}
