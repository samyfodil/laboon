//go:build (windows || darwin) && amd64

package sandbox

import "github.com/samyfodil/laboon/internal/rewrite"

// anonAnalyze finds the syscall sites of a page of code made at run time
// (anoncode.go) and the targets of its branches out of it, with each site's
// run a trampoline can take.
func anonAnalyze(code []byte, entries []int) (sites []int, steal []uint8, exits []int) {
	plan, exits := rewrite.AnonPlan(code, entries)
	for _, s := range plan {
		sites = append(sites, int(s.Off))
		steal = append(steal, s.Steal)
	}
	return sites, steal, exits
}

// trapSiteIn and untrapSite turn the syscall at off in code into the stub's
// trap (ud2) and back.
func trapSiteIn(code []byte, off int) {
	if off+2 <= len(code) && code[off] == 0x0f && code[off+1] == 0x05 {
		code[off+1] = 0x0b
	}
}

func untrapSite(code []byte, off int) {
	if off+2 <= len(code) && code[off] == 0x0f && code[off+1] == 0x0b {
		code[off+1] = 0x05
	}
}
