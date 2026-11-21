package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestSyscallPreservesRegisters checks every way into the stub keeps every
// register but x0, NZCV, the FP/SIMD registers and the memory below sp
// intact, and that threads and execve start from it: a rewritten site in a
// loaded image, the trap fallback where the platform has one for it, and a
// syscall in code the guest made executable at run time.
func TestSyscallPreservesRegisters(t *testing.T) {
	regs, threads, belowsp := guestPath(t, "regs_arm64"), guestPath(t, "threads"), guestPath(t, "belowsp_arm64")
	for _, trap := range trapModes {
		restore := useTraps(trap)
		for _, jit := range []string{"", "jit"} {
			args := func(a ...string) []string {
				if jit != "" {
					a = append(a, jit)
				}
				return a
			}
			var o, trace bytes.Buffer
			code, err := Run(context.Background(), regs, Config{Args: args("regs"), Stdout: &o, Stderr: &o, Trace: &trace})
			if err != nil || code != 0 || !strings.Contains(o.String(), "regs preserved") {
				t.Fatalf("trap=%v %s: code=%d err=%v out=%q", trap, jit, code, err, o.String())
			}
			if want := "(0 with trampolines)"; strings.Contains(trace.String(), want) != trap {
				t.Fatalf("trap=%v: trace %q", trap, strings.SplitN(trace.String(), "\n", 2)[0])
			}
			o.Reset()
			code, err = Run(context.Background(), belowsp, Config{Args: args(belowsp), Stdout: &o, Stderr: &o})
			if err != nil || code != 0 || o.String() != "first: below sp preserved\nsecond: below sp preserved\n" {
				t.Fatalf("trap=%v %s belowsp: code=%d err=%v out=%q", trap, jit, code, err, o.String())
			}
		}
		var o bytes.Buffer
		code, err := Run(context.Background(), threads, Config{Args: []string{"threads"}, Stdout: &o, Stderr: &o})
		if err != nil || code != 0 || !strings.Contains(o.String(), "counter=4000 joined_sum=60") {
			t.Fatalf("trap=%v threads: code=%d err=%v out=%q", trap, code, err, o.String())
		}
		restore()
	}
}
