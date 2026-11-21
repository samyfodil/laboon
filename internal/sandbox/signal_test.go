package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestSignals runs testdata/signals.c, built against glibc and musl, with
// syscalls taken through trampolines and through traps: each line is a check
// of Linux signal semantics.
func TestSignals(t *testing.T) {
	for _, name := range []string{"signals", "signals+musl"} {
		root, prog := guestRoot(t, name)
		for _, trap := range trapModes {
			restore := useTraps(trap)
			var o bytes.Buffer
			code, err := Run(context.Background(), prog, Config{Args: []string{"signals"}, RootFS: HostRoot(root), Stdout: &o, Stderr: &o})
			restore()
			if err != nil || code != 0 || strings.Contains(o.String(), "FAIL") || !strings.Contains(o.String(), "done fails=0") {
				t.Errorf("%s trap=%v: code=%d err=%v\n%s", name, trap, code, err, o.String())
			}
		}
	}
}

// A shell's background jobs: wait sleeps in sigsuspend until SIGCHLD. ash
// prints "Terminated" only if it reaps the killed job inside wait; a SIGCHLD
// that lands before kill returns has it reaped silently after the builtin,
// which native Linux does too now and then.
func TestShellJobs(t *testing.T) {
	code, out := runBusybox(t, `sleep 1 & wait; echo waited $?; sleep 5 & kill $!; wait $!; echo killed $?; trap "echo trapped" USR1; kill -USR1 $$; echo after`)
	out = strings.Replace(out, "waited 0\nTerminated\n", "waited 0\n", 1)
	if code != 0 || out != "waited 0\nkilled 143\ntrapped\nafter\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

// Go needs SIGURG for preemption and SIGSEGV for nil checks, and os/signal
// and os/exec rely on signals too.
func TestGoSignals(t *testing.T) {
	root := busyboxRoot(t)
	prog := putGuest(t, root, "gosignals", goGuest(t, "gosignals", "exe"))
	var o bytes.Buffer
	code, err := Run(context.Background(), prog, Config{Args: []string{"gosignals", "/bin/sh"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	want := "preempt ok\nnil-deref recovered true\nnotify user defined signal 1\nexec \"child-ok\\n\" <nil>\n"
	if err != nil || code != 0 || o.String() != want {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}
