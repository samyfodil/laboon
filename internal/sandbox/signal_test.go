//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// zigCC returns a zig binary for building musl guests, or "" if none.
func zigCC() string {
	for _, z := range []string{os.Getenv("ZIG"), "zig", "/tmp/zig-linux-x86_64-0.13.0/zig", os.ExpandEnv("$HOME/zig-0.13.0/zig")} {
		if p, err := exec.LookPath(z); z != "" && err == nil {
			return p
		}
	}
	return ""
}

// TestSignals runs testdata/signals.c, built against glibc and musl, with
// syscalls taken through trampolines and through traps: each line is a check
// of Linux signal semantics.
func TestSignals(t *testing.T) {
	dir := t.TempDir()
	builds := map[string][]string{
		"glibc": {"gcc", "-O2", "-static", "-pthread", "-o", filepath.Join(dir, "glibc"), "../../testdata/signals.c"},
	}
	if z := zigCC(); z != "" {
		target := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-linux-musl"
		builds["musl"] = []string{z, "cc", "-target", target, "-O2", "-static", "-o", filepath.Join(dir, "musl"), "../../testdata/signals.c"}
	}
	for libc, c := range builds {
		if b, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Skipf("build: %v\n%s", err, b)
		}
		for _, trap := range []bool{false, true} {
			was := fastTramp
			fastTramp = !trap
			var o bytes.Buffer
			code, err := Run(context.Background(), filepath.Join(dir, libc), Config{Args: []string{"signals"}, Stdout: &o, Stderr: &o})
			fastTramp = was
			if err != nil || code != 0 || strings.Contains(o.String(), "FAIL") || !strings.Contains(o.String(), "done fails=0") {
				t.Errorf("%s trap=%v: code=%d err=%v\n%s", libc, trap, code, err, o.String())
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
	exe := filepath.Join(t.TempDir(), "gosignals")
	cmd := exec.Command("go", "build", "-o", exe, "../../testdata/gosignals")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), exe, Config{Args: []string{"gosignals", "/bin/sh"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	want := "preempt ok\nnil-deref recovered true\nnotify user defined signal 1\nexec \"child-ok\\n\" <nil>\n"
	if err != nil || code != 0 || o.String() != want {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// Python handles signals in its main thread, which a process-directed signal
// must reach even when another thread sends it.
func TestPythonSignals(t *testing.T) {
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("no python3")
	}
	script := `import os, signal, subprocess, time, threading
got = []
signal.signal(signal.SIGALRM, lambda s, f: got.append(s))
signal.alarm(1)
time.sleep(1.2)
print("alarm", got == [signal.SIGALRM])
try:
    subprocess.run(["/bin/sleep", "5"], timeout=0.3)
except subprocess.TimeoutExpired:
    print("timeout")
p = subprocess.Popen(["/bin/sleep", "5"])
p.send_signal(signal.SIGTERM)
print("rc", p.wait())
threading.Thread(target=lambda: (time.sleep(0.2), os.kill(os.getpid(), signal.SIGINT))).start()
t0 = time.monotonic()
try:
    time.sleep(5)
except KeyboardInterrupt:
    print("sigint", time.monotonic() - t0 < 2)
`
	var o bytes.Buffer
	code, err := Run(context.Background(), "/usr/bin/python3", Config{Args: []string{"python3", "-c", script}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || o.String() != "alarm True\ntimeout\nrc -15\nsigint True\n" {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}
