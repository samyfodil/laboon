//go:build windows || darwin

package sandbox

import "github.com/samyfodil/laboon/internal/rewrite"

// x64AnonAnalyze finds the syscall sites of a page of x86-64 code made at run
// time (anoncode.go) and the targets of its branches out of it, with each
// site's run a trampoline can take.
func x64AnonAnalyze(code []byte, entries []int) (sites []int, steal []uint8, exits []int) {
	plan, exits := rewrite.AnonPlan(code, entries)
	for _, s := range plan {
		sites = append(sites, int(s.Off))
		steal = append(steal, s.Steal)
	}
	return sites, steal, exits
}

// x64UntrapSite turns the stub's trap (ud2) at off in code back into the
// syscall it replaced.
func x64UntrapSite(code []byte, off int) {
	if off+2 <= len(code) && code[off] == 0x0f && code[off+1] == 0x0b {
		code[off+1] = 0x05
	}
}
