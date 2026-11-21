package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// runGuest runs the program prog in root with args and returns its exit
// status, stdout and stderr.
func runGuest(t *testing.T, root, prog string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	cfg := Config{
		RootFS: HostRoot(root),
		Args:   append([]string{strings.TrimPrefix(prog, "/")}, args...),
		Env:    []string{"PATH=/bin"},
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
	}
	if testing.Verbose() && os.Getenv("LC_TRACE") != "" {
		cfg.Trace = os.Stderr
	}
	code, err := Run(context.Background(), prog, cfg)
	if err != nil {
		t.Fatalf("%s %v: Run: %v (stdout %q stderr %q)", prog, args, err, out.String(), errb.String())
	}
	return code, out.String(), errb.String()
}

// TestMuslThreads runs a musl pthread workload: worker threads contend on a
// mutex, are joined, and their return values summed -- clone(CLONE_VM), futex
// (mutex + join), TLS and the thread exit path (testdata/pthreadtest.c).
func TestMuslThreads(t *testing.T) {
	root, prog := guestRoot(t, "pthreadtest+musl")
	code, out, errs := runGuest(t, root, prog)
	if code != 0 || !strings.Contains(out, "OK") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestSignalBattery runs the in-process signal battery: SA_SIGINFO handlers,
// raise/kill/tgkill, nested handlers, ppoll's temporary mask, sigprocmask
// masking with pending delivery on unmask, sigaltstack, a SIGSEGV fault
// delivered to a handler, POSIX timers, sigtimedwait, FP preservation and
// cross-thread pthread_kill (testdata/m3sig.c).
func TestSignalBattery(t *testing.T) {
	root, prog := guestRoot(t, "m3sig")
	code, out, errs := runGuest(t, root, prog)
	if code != 0 || !strings.Contains(out, "m3sig fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestSignalIO covers delivery to a thread blocked in read with EINTR and
// SA_RESTART, and the default-action exit statuses (testdata/m3io.c).
func TestSignalIO(t *testing.T) {
	root, prog := guestRoot(t, "m3io")
	for _, c := range []struct {
		mode   string
		code   int
		stdout string
	}{
		{"pipe-read-intr", 0, "pipe-read-intr ok\n"},
		{"pipe-write-intr", 0, "pipe-write-intr ok\n"},
		{"pipe-read-kill", 128 + 9, ""},
		{"pipe-write-kill", 128 + 9, ""},
		{"pipe-state", 0, "pipe-state ok\n"},
		{"pipe-waits", 0, "pipe-waits ok\n"},
		{"eintr", 0, "eintr ok\n"},
		{"restart", 0, "restart ok\n"},
		{"kill9", 128 + 9, ""},
		{"term", 128 + 15, ""},
		{"segv", 128 + 11, ""},
		{"segvh", 0, "segvh ok\n"},
	} {
		t.Run(c.mode, func(t *testing.T) {
			code, out, errs := runGuest(t, root, prog, c.mode)
			if code != c.code || out != c.stdout {
				t.Fatalf("exit %d stdout %q stderr %q; want %d %q", code, out, errs, c.code, c.stdout)
			}
		})
	}
}

// TestIdregs: the AArch64 feature ID registers the guest reads with mrs are
// served and consistent with AT_HWCAP (testdata/idregs.c); on x86-64 the
// probe has nothing to check.
func TestIdregs(t *testing.T) {
	root, prog := guestRoot(t, "idregs")
	code, out, errs := runGuest(t, root, prog)
	if code != 0 || !strings.Contains(out, "idregs fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestMemtest drives the stub's memory (brk, anonymous and file mappings,
// partial munmap, mprotect, mremap) and the overlay's file calls
// (testdata/memtest.c).
func TestMemtest(t *testing.T) {
	root, prog := guestRoot(t, "memtest")
	code, out, errs := runGuest(t, root, prog, "/tmp", strconv.Itoa(os.Getpagesize()))
	if code != 0 || out != "memtest: 0 failures\n" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestFault: a guest fault ends the guest as killed by the signal, and on
// arm64 a junk x18 survives a syscall and a trapped mrs (testdata/fault.c).
func TestFault(t *testing.T) {
	root, prog := guestRoot(t, "fault")
	cases := []struct {
		mode   string
		code   int
		stdout string
	}{
		{"segv", 128 + 11, ""},
		{"ill", 128 + 4, ""},
	}
	if runtime.GOARCH == "arm64" {
		cases = append(cases, struct {
			mode   string
			code   int
			stdout string
		}{"x18", 0, ""})
	}
	// The CTR_EL0 the guest reads: the CPU's own on Linux; on macOS the stub's
	// 64-byte lines (ic ivau runs natively); on Windows a 128 KiB IminLine, so
	// a JIT's flush loop traps once per block (run_windows_arm64.go).
	ctr := map[string]uint64{"darwin": 0x8444c004, "windows": 0x8444c00f}[runtime.GOOS]
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			code, out, errs := runGuest(t, root, prog, c.mode)
			want := out == c.stdout
			if c.mode == "x18" {
				var got uint64
				n, err := fmt.Sscanf(out, "x18 ok %x\n", &got)
				want = err == nil && n == 1 && got != 0 && (ctr == 0 || got == ctr)
			}
			if code != c.code || !want {
				t.Fatalf("exit %d stdout %q stderr %q; want %d %q", code, out, errs, c.code, c.stdout)
			}
		})
	}
}
