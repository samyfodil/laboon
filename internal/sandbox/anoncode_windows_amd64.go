//go:build windows

package sandbox

import (
	"encoding/binary"
	"slices"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// anonStolenMax bounds an instruction a trampoline takes the place of.
const anonStolenMax = 16

// anonTramps gives the n sites of the page at page, just analyzed, whose run
// before them a trampoline can take a trampoline in [area, area+room), as
// file code has: a trap dispatches an exception on the guest's stack, into
// the red zone below rsp that Linux leaves alone across a syscall. After the
// reply anonSites wrote it appends what the stub patches: a u32 count and
// the u32 bytes of the area used, then per patch a u16 offset in the page, a
// u16 length and anonStolenMax bytes, the length of them put there. read
// reads the page as analyzed.
func (g *wguest) anonTramps(dg *dguest, page uint64, n int, area, room uint64, read func(uint64, []byte) error) {
	sc := dg.scratch()
	at := 4*(n+1) + 8*int(binary.LittleEndian.Uint32(sc[4*n:]))
	if at+8 > len(sc) {
		return
	}
	clear(sc[at : at+8])
	sites, steal := g.anon.runs(page)
	var plan rewrite.Plan
	for i, off := range sites {
		if steal[i] != 0 {
			plan.Sites = append(plan.Sites, rewrite.Site{Off: uint32(off), Steal: steal[i]})
		}
	}
	code := make([]byte, pageSize)
	if len(plan.Sites) == 0 || read(page, code) != nil {
		return
	}
	w := rewrite.New(area, room, g.entry)
	w.NoStray = true
	w.SegmentSlot(tebSlotTP)
	if g.exitEntry != 0 {
		w.ExitStack(tebSlotStk, g.exitEntry)
	}
	patched := slices.Clone(code)
	w.Apply(plan, patched, page)
	tr := w.Trampolines()
	if w.Fast == 0 || g.sp.writeMem(area, tr) != nil {
		return
	}
	g.sp.flushCode(area, uint64(len(tr)))
	var stolen []anonStolen
	out := sc[at+8:]
	for _, s := range plan.Sites {
		ins := int(s.Off) - int(s.Steal)
		l := rewrite.InsnLen(code[ins:])
		if patched[ins] != 0xe9 || code[ins] == 0xe9 || l < 5 || l > anonStolenMax || len(out) < 4+anonStolenMax {
			continue
		}
		binary.LittleEndian.PutUint16(out, uint16(ins))
		binary.LittleEndian.PutUint16(out[2:], uint16(l))
		copy(out[4:4+anonStolenMax], patched[ins:ins+l])
		out = out[4+anonStolenMax:]
		stolen = append(stolen, anonStolen{off: ins, orig: slices.Clone(code[ins : ins+l]), new: slices.Clone(patched[ins : ins+l])})
	}
	binary.LittleEndian.PutUint32(sc[at:], uint32(len(stolen)))
	binary.LittleEndian.PutUint32(sc[at+4:], uint32(len(tr)))
	g.anon.stole(page, stolen)
}
