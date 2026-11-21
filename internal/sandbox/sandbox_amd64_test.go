package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestSyscallPreservesRegisters checks every way into the stub keeps every
// register but rax, rcx and r11, the flags, the SSE registers and the red
// zone below rsp intact, and that execve starts from it: a rewritten site in
// a loaded image, the trap fallback where the platform has one for it, and a
// syscall in code the guest made executable at run time.
func TestSyscallPreservesRegisters(t *testing.T) {
	root, regs := guestRoot(t, "regs_amd64")
	belowsp := addGuest(t, root, "belowsp_amd64")
	for _, trap := range trapModes {
		restore := useTraps(trap)
		for _, jit := range []string{"", "jit"} {
			args := func(a ...string) []string {
				if jit != "" {
					a = append(a, jit)
				}
				return a
			}
			var o bytes.Buffer
			code, err := Run(context.Background(), regs, Config{Args: args("regs"), Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
			if err != nil || code != 0 || !strings.Contains(o.String(), "regs preserved") {
				t.Fatalf("trap=%v %s: code=%d err=%v out=%q", trap, jit, code, err, o.String())
			}
			o.Reset()
			code, err = Run(context.Background(), belowsp, Config{Args: args(belowsp), Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
			if err != nil || code != 0 || o.String() != "first: below sp preserved\nsecond: below sp preserved\n" {
				t.Fatalf("trap=%v %s belowsp: code=%d err=%v out=%q", trap, jit, code, err, o.String())
			}
		}
		restore()
	}
}
