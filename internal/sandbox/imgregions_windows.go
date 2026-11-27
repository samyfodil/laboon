//go:build windows

package sandbox

import (
	"encoding/binary"
	"errors"
	"slices"
)

// imgRegion is a piece of a placed image as the stub's region table holds it
// (stub/windows/mem.zig adoptImages): attr packs the guest's protection
// (bits 0-2), what the piece is (imgCode, imgTramp, imgCow) and the kind
// /proc/<pid>/maps lists it as (bits 16+, 0 for none), off its file offset,
// and tramp, tramp2 the trampoline areas a code piece's sites branch to.
// With the image in the table, the guest changes its protection as it does
// any mapping's, and its code made writable runs again only once analyzed
// again, as code made executable at run time does.
type imgRegion struct{ lo, hi, attr, off, tramp, tramp2 uint64 }

const (
	imgCode  = 1 << 8 // rewritten code
	imgTramp = 2 << 8 // a trampoline area
	imgCow   = 4 << 8 // part of a saved image's copy-on-write view (mapImageView)
)

// regions is the placed image in pieces of one protection and one kind, as
// mapImage leaves it: kind is mapMain or mapInterp.
func (img *wimage) regions(kind uint64) []imgRegion {
	cuts := []uint64{img.lo, img.hi}
	for _, r := range img.prots {
		cuts = append(cuts, r.lo, r.hi)
	}
	for _, s := range img.segs {
		cuts = append(cuts, s.lo, s.hi)
	}
	for _, t := range img.tramps {
		cuts = append(cuts, t.base, t.base+t.size)
	}
	mid := img.lo
	if img.view != nil {
		mid = img.lo + img.view.size
		cuts = append(cuts, mid)
	}
	cuts = slices.DeleteFunc(cuts, func(c uint64) bool { return c < img.lo || c > img.hi })
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	var tramp [2]uint64
	for i, t := range img.tramps[:min(len(img.tramps), 2)] {
		tramp[i] = t.base
	}
	var out []imgRegion
	for i := 0; i+1 < len(cuts); i++ {
		a, b := cuts[i], cuts[i+1]
		var prot uint64
		for _, r := range img.prots { // later runs override, as mapImage applies them
			if a >= r.lo && a < r.hi {
				prot = linuxProt(r.prot)
			}
		}
		attr := prot
		isTramp := false
		for _, t := range img.tramps {
			if a >= t.base && a < t.base+t.size {
				isTramp = true
			}
		}
		switch {
		case isTramp:
			attr |= imgTramp
		case prot&lxProtExec != 0:
			attr |= imgCode
		}
		if a < mid {
			attr |= imgCow
		}
		var off uint64
		for _, s := range img.segs {
			if a >= s.lo && a < s.hi {
				k := kind
				if s.attr != mapFile {
					k = s.attr
				}
				attr |= k << 16
				off = s.off + a - s.lo
			}
		}
		r := imgRegion{lo: a, hi: b, attr: attr, off: off}
		if attr&imgCode != 0 {
			r.tramp, r.tramp2 = tramp[0], tramp[1]
		}
		out = append(out, r)
	}
	return out
}

// putImgRegions writes rs to the stub's scratch for REP_START: their count,
// then each one's six words.
func putImgRegions(sc []byte, rs []imgRegion) error {
	if 8+len(rs)*48 > len(sc) {
		return errors.New("image regions do not fit the stub's scratch")
	}
	binary.LittleEndian.PutUint64(sc, uint64(len(rs)))
	for i, r := range rs {
		b := sc[8+i*48:]
		for j, v := range []uint64{r.lo, r.hi, r.attr, r.off, r.tramp, r.tramp2} {
			binary.LittleEndian.PutUint64(b[j*8:], v)
		}
	}
	return nil
}
