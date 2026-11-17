//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSyscallPreservesRegisters checks both ways into the stub, an island
// and the udf/SIGILL fallback, keep every register but x0, NZCV, the
// FP/SIMD registers and the memory below sp intact, and that threads and
// execve start from either.
func TestSyscallPreservesRegisters(t *testing.T) {
	dir := t.TempDir()
	regs, threads := filepath.Join(dir, "regs"), filepath.Join(dir, "threads")
	belowsp := filepath.Join(dir, "belowsp")
	for _, c := range [][]string{
		{"-O2", "-static", "-o", belowsp, "../../testdata/belowsp_arm64.c"},
		{"-O2", "-static", "-o", regs, "../../testdata/regs_arm64.c"},
		{"-O2", "-static", "-pthread", "-o", threads, "../../testdata/threads.c"},
	} {
		if b, err := exec.Command("gcc", c...).CombinedOutput(); err != nil {
			t.Skipf("static gcc unavailable: %v\n%s", err, b)
		}
	}
	defer func(was bool) { fastTramp = was }(fastTramp)
	for _, trap := range []bool{false, true} {
		fastTramp = !trap
		var o, trace bytes.Buffer
		code, err := Run(context.Background(), regs, Config{Args: []string{"regs"}, Stdout: &o, Stderr: &o, Trace: &trace})
		if err != nil || code != 0 || !strings.Contains(o.String(), "regs preserved") {
			t.Fatalf("trap=%v: code=%d err=%v out=%q", trap, code, err, o.String())
		}
		if want := "(0 with trampolines)"; strings.Contains(trace.String(), want) != trap {
			t.Fatalf("trap=%v: trace %q", trap, strings.SplitN(trace.String(), "\n", 2)[0])
		}
		o.Reset()
		code, err = Run(context.Background(), threads, Config{Args: []string{"threads"}, Stdout: &o, Stderr: &o})
		if err != nil || code != 0 || !strings.Contains(o.String(), "counter=4000 joined_sum=60") {
			t.Fatalf("trap=%v threads: code=%d err=%v out=%q", trap, code, err, o.String())
		}
		o.Reset()
		code, err = Run(context.Background(), belowsp, Config{Args: []string{belowsp}, Stdout: &o, Stderr: &o})
		if err != nil || code != 0 || o.String() != "first: below sp preserved\nsecond: below sp preserved\n" {
			t.Fatalf("trap=%v belowsp: code=%d err=%v out=%q", trap, code, err, o.String())
		}
	}
}

// protBTI matches a traced mmap or mprotect (arm64 222, 226) whose prot is
// PROT_READ|PROT_EXEC|PROT_BTI; the trace prints all six argument registers.
var protBTI = regexp.MustCompile(`\] 22[26]\(0x[0-9a-f]+, 0x[0-9a-f]+, 0x15, `)

// glibc maps each BTI library's code a second time with PROT_BTI added. The
// code is already rewritten and unchanged, so it must not be rewritten again
// (each rewrite also takes a new trampoline chunk).
func TestBTIRemapKeepsRewrittenCode(t *testing.T) {
	dir := t.TempDir()
	rewrites := map[bool]int{}
	for _, bti := range []bool{false, true} {
		var flags []string
		if bti {
			flags = []string{"-mbranch-protection=standard", "-Wl,-z,force-bti"}
		}
		lib, exe := filepath.Join(dir, "libbti.so"), filepath.Join(dir, "btimain")
		for _, c := range [][]string{
			append([]string{"-O2", "-fPIC", "-shared", "-o", lib, "../../testdata/btilib.c"}, flags...),
			append([]string{"-O2", "-o", exe, "../../testdata/btimain.c", "-L" + dir, "-lbti", "-Wl,-rpath," + dir}, flags...),
		} {
			if b, err := exec.Command("gcc", c...).CombinedOutput(); err != nil {
				t.Skipf("gcc: %v\n%s", err, b)
			}
		}
		var o, trace bytes.Buffer
		code, err := Run(context.Background(), exe, Config{Args: []string{"btimain"}, Stdout: &o, Stderr: &o, Trace: &trace, Root: "/"})
		if err != nil || code != 0 || o.String() != "bti_add=5\n" {
			t.Fatalf("bti=%v: code=%d err=%v out=%q", bti, code, err, o.String())
		}
		if bti && !protBTI.MatchString(trace.String()) {
			t.Fatalf("no PROT_BTI mapping in the trace")
		}
		rewrites[bti] = strings.Count(trace.String(), "rewriting code at")
	}
	if rewrites[true] != rewrites[false] {
		t.Fatalf("code rewrites: %d with BTI, %d without", rewrites[true], rewrites[false])
	}
}
