package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These tests run the Linux host's own userland (python3, strace) over its own
// root, so they run only on a Linux host, and that host must have the tools:
// a missing one fails the test.

// hostTool returns the host program name resolves to, failing the test if the
// host has none.
func hostTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("this test runs the host's %s, which is not installed: %v", name, err)
	}
	return p
}

// Python handles signals in its main thread, which a process-directed signal
// must reach even when another thread sends it.
func TestPythonSignals(t *testing.T) {
	hostTool(t, "/usr/bin/python3")
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

func TestPythonSubprocess(t *testing.T) {
	hostTool(t, "/usr/bin/python3")
	script := `import os, subprocess
print(subprocess.run(["/bin/echo", "sub-ok"], capture_output=True).stdout.decode().strip())
try:
    subprocess.run(["/nonexistent"])
except FileNotFoundError:
    print("missing-ok")
pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 3"], os.environ)
print("spawn", os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
`
	var o bytes.Buffer
	code, err := Run(context.Background(), "/usr/bin/python3", Config{Args: []string{"python3", "-c", script}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || o.String() != "sub-ok\nmissing-ok\nspawn 3\n" {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

func TestPtraceStrace(t *testing.T) {
	strace := hostTool(t, "strace")
	for _, args := range [][]string{{strace, "/bin/echo", "hi"}, {strace, "-f", "-e", "trace=write", "/bin/sh", "-c", "echo hi; /bin/echo child"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		var out, trace bytes.Buffer
		code, err := Run(ctx, strace, Config{Args: args, RootFS: HostRoot("/"), Stdout: &out, Stderr: &trace})
		cancel()
		if err != nil || code != 0 || !strings.Contains(out.String(), "hi\n") || !strings.Contains(trace.String(), "write(1,") || !strings.Contains(trace.String(), "exited with 0") || badPtraceTrace(trace.String()) {
			t.Fatalf("args=%v code=%d err=%v out=%q trace=%s", args, code, err, out.String(), trace.String())
		}
	}
}

func TestPtraceThreadExec(t *testing.T) {
	strace := hostTool(t, "strace")
	// strace is the host's, so the guest's root is the host's.
	exe := guestPath(t, "execspawn")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out, trace bytes.Buffer
	code, err := Run(ctx, strace, Config{Args: []string{strace, "-f", "-e", "trace=process", exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &trace})
	if err != nil || code != 0 || !strings.HasSuffix(out.String(), "OK\n") || badPtraceTrace(trace.String()) {
		t.Fatalf("code=%d err=%v out=%q trace=%s", code, err, out.String(), trace.String())
	}
}
