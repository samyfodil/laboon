//go:build (windows || darwin) && arm64

package sandbox

import (
	"encoding/binary"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// anonAnalyze finds the svc sites of a page of code made at run time
// (anoncode.go) and the targets of its branches out of it.
func anonAnalyze(code []byte, entries []int) (sites []int, steal []uint8, exits []int) {
	sites, exits = rewrite.A64AnonSites(code, entries)
	return sites, nil, exits
}

// trapSiteIn and untrapSite turn the svc at off in code into the stub's trap
// (udf #0) and back. The windows stub branches to an island instead (its
// jitSiteWord), which untrapSite takes back too.
func trapSiteIn(code []byte, off int) {
	if off%4 == 0 && off+4 <= len(code) && binary.LittleEndian.Uint32(code[off:]) == 0xd4000001 {
		binary.LittleEndian.PutUint32(code[off:], 0)
	}
}

func untrapSite(code []byte, off int) {
	if off%4 != 0 || off+4 > len(code) {
		return
	}
	if w := binary.LittleEndian.Uint32(code[off:]); w == 0 || w&0xfc000000 == 0x14000000 {
		binary.LittleEndian.PutUint32(code[off:], 0xd4000001)
	}
}
