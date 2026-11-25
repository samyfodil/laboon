//go:build windows || darwin

package sandbox

import (
	"encoding/binary"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// a64AnonAnalyze finds the svc sites of a page of arm64 code made at run time
// (anoncode.go) and the targets of its branches out of it.
func a64AnonAnalyze(code []byte, entries []int) (sites []int, steal []uint8, exits []int) {
	sites, exits = rewrite.A64AnonSites(code, entries)
	return sites, nil, exits
}

// a64UntrapSite turns the stub's trap at off in code (udf #0; the windows
// stub branches to an island instead, its jitSiteWord) back into the svc it
// replaced.
func a64UntrapSite(code []byte, off int) {
	if off%4 != 0 || off+4 > len(code) {
		return
	}
	if w := binary.LittleEndian.Uint32(code[off:]); w == 0 || w&0xfc000000 == 0x14000000 {
		binary.LittleEndian.PutUint32(code[off:], 0xd4000001)
	}
}
