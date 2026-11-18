//go:build linux

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func buildHello(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "hello")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/hello.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	return out
}

func TestRunHello(t *testing.T) {
	var stdout bytes.Buffer
	code, err := Run(context.Background(), buildHello(t), Config{
		Args:   []string{"hello", "world"},
		Stdout: &stdout,
		Stderr: &stdout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit = %d, want 7", code)
	}
	if !strings.Contains(stdout.String(), "hello from hello on Linux laboon, argv[1]=world") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

// TestNoRewriteRunsViaTrap runs a guest with rewriting disabled, so every one
// of its syscalls is a raw instruction. The stub's seccomp filter traps each
// (RET_TRAP) into the supervisor, which services it — the same mediation a
// rewritten site gets, just reached by a fault. The guest therefore runs
// correctly without a single rewritten site: static rewriting is an
// optimization, not a correctness requirement. (A raw syscall used to be
// fatal; it is now mediated, never executed raw, so the sandbox boundary is
// unchanged.)
func TestNoRewriteRunsViaTrap(t *testing.T) {
	var stdout bytes.Buffer
	code, err := Run(context.Background(), buildHello(t), Config{
		Args:      []string{"hello", "world"},
		Stdout:    &stdout,
		Stderr:    &stdout,
		NoRewrite: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil (serviced via the trap backstop)", err)
	}
	if code != 7 {
		t.Fatalf("exit = %d, want 7", code)
	}
	if !strings.Contains(stdout.String(), "hello from hello on Linux laboon, argv[1]=world") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunDynamic(t *testing.T) {
	out := filepath.Join(t.TempDir(), "hello-dyn")
	if b, err := exec.Command("gcc", "-O2", "-o", out, "../../testdata/hello.c").CombinedOutput(); err != nil {
		t.Skipf("gcc unavailable: %v\n%s", err, b)
	}
	var stdout bytes.Buffer
	// The host root supplies ld-linux and libc; the guest sees it read-only.
	code, err := Run(context.Background(), out, Config{
		Args:   []string{"hello", "dyn"},
		Stdout: &stdout,
		Stderr: &stdout,
		RootFS: HostRoot("/"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 || !strings.Contains(stdout.String(), "argv[1]=dyn") {
		t.Fatalf("exit = %d, stdout = %q", code, stdout.String())
	}
}

func TestRootIsReadOnly(t *testing.T) {
	const p = "/tmp/laboon-should-not-exist"
	os.Remove(p)
	var stderr bytes.Buffer
	if _, err := Run(context.Background(), "/usr/bin/touch", Config{
		Args:   []string{"touch", p},
		Stdout: &stderr,
		Stderr: &stderr,
		RootFS: HostRoot("/"),
	}); err != nil {
		t.Fatal(err)
	}
	// The guest's writes go to its overlay, never to the host's root.
	if _, err := os.Stat(p); err == nil {
		os.Remove(p)
		t.Fatalf("touch reached the host's root: %s", stderr.String())
	}
}

// A relative program path must still give the guest an absolute
// /proc/self/exe; static glibc asserts on it at startup.
func TestRelativeProgramPath(t *testing.T) {
	exe := buildHello(t)
	t.Chdir(filepath.Dir(exe))
	var stdout bytes.Buffer
	code, err := Run(context.Background(), filepath.Base(exe), Config{
		Args:   []string{"hello"},
		Stdout: &stdout,
		Stderr: &stdout,
	})
	if err != nil || code != 7 {
		t.Fatalf("code = %d, err = %v, output = %q", code, err, stdout.String())
	}
}

func TestAbortExitsWithSignalStatus(t *testing.T) {
	out := filepath.Join(t.TempDir(), "abort")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/abort.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	code, err := Run(context.Background(), out, Config{
		Args:   []string{"abort"},
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	})
	if err != nil || code != 128+6 {
		t.Fatalf("code = %d, err = %v, want 134 (SIGABRT)", code, err)
	}
}

// A pty's slave opens by the name ptsname gives, under any root.
func TestOpenpty(t *testing.T) {
	out := filepath.Join(t.TempDir(), "openpty")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/openpty.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"openpty"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "pty ok pts\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// A child process ends with its abort although another of its threads sleeps
// in the supervisor.
func TestChildAbortWithSleepingThread(t *testing.T) {
	out := filepath.Join(t.TempDir(), "abortsleep")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/abortsleep.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"abortsleep"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "eof=1 sigabrt=1 fast=1\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

func TestKillBlockedChild(t *testing.T) {
	out := filepath.Join(t.TempDir(), "killblocked")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/killblocked.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"killblocked"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "reader=1 writer=1\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

func TestPipeWriteEndError(t *testing.T) {
	out := filepath.Join(t.TempDir(), "pollerr")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/pollerr.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"pollerr"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "poll=1 err=1 select=2 r=1 w=1\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

func TestStopAndOrphanedStop(t *testing.T) {
	out := filepath.Join(t.TempDir(), "orphanstop")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/orphanstop.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"orphanstop"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "orphaned=1 stopped=1\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

func TestCloneOnStack(t *testing.T) {
	out := filepath.Join(t.TempDir(), "clonestack")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/clonestack.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"clonestack"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "clone child exit 42\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// System V shared memory, semaphores and message queues across fork: the
// macOS gate's ipctest, which the Linux stub now serves too.
func TestSysVIPC(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ipctest")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "testdata/ipctest.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"ipctest"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.HasSuffix(o.String(), "ALL OK\n") {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// Every stub shares the socket descriptors to map are passed over: one
// killed mid-transfer must not leave its descriptor for the next mapping.
func TestKillWhileMapping(t *testing.T) {
	out := filepath.Join(t.TempDir(), "killmmap")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/killmmap.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"killmmap"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || o.String() != "wrong files 0\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// TestKillWhileWaiting kills, or aborts with a sibling thread blocked, a
// child in each kind of wait the supervisor serves; the parent's waitpid must
// return at once.
func TestKillWhileWaiting(t *testing.T) {
	out := filepath.Join(t.TempDir(), "killwait")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/killwait.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"killwait"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "killwait: 0 failures") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestThreadExec runs testdata/threadexec.c: an exec from the main
// thread and from another thread of a multithreaded process; the other
// threads end, the new image runs alone with the process's pid, and the
// process ends when it does.
func TestThreadExec(t *testing.T) {
	out := filepath.Join(t.TempDir(), "threadexec")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-I", "testdata", "-o", out, "testdata/threadexec.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{out}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "ALL OK") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestKickRace signals a thread in a futex wait, then in a read of a pipe,
// many times, one signal after its handler has taken the last: a signal
// landing as the thread goes into the wait must still end it (Linux takes
// kicks without re-kicking).
func TestKickRace(t *testing.T) {
	out := filepath.Join(t.TempDir(), "kickrace")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/kickrace.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	for _, mode := range []string{"futex", "read"} {
		r, w, err := os.Pipe() // stdin nothing writes, for the reads
		if err != nil {
			t.Fatal(err)
		}
		var o bytes.Buffer
		code, err := Run(context.Background(), out, Config{Args: []string{"kickrace", "20000", mode}, Stdin: r, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
		r.Close()
		w.Close()
		if err != nil || code != 0 || !strings.Contains(o.String(), "kickrace: 20000 signals ok") {
			t.Fatalf("%s: code = %d, err = %v, out:\n%s", mode, code, err, o.String())
		}
	}
}

// TestSigSyscall: a syscall a signal lands on the way into returns to its own
// caller with its own result once the handler is done.
func TestSigSyscall(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sigsyscall")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/sigsyscall.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"sigsyscall", "20000"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "sigsyscall: 20000 signals ok") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestASLR: a program is placed as Linux's ASLR places it, anew at each
// execve, the same across a fork and fixed under ADDR_NO_RANDOMIZE, built
// position-independent and not.
func TestASLR(t *testing.T) {
	for _, mode := range [][]string{{"-static-pie"}, {"-static", "-no-pie", "-fno-pie"}} {
		out := filepath.Join(t.TempDir(), "aslr")
		args := append(append([]string{"-O2"}, mode...), "-o", out, "../../testdata/aslr.c")
		if b, err := exec.Command("gcc", args...).CombinedOutput(); err != nil {
			t.Skipf("static gcc unavailable: %v\n%s", err, b)
		}
		var o bytes.Buffer
		code, err := Run(context.Background(), out, Config{Args: []string{"aslr"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
		if err != nil || code != 0 || !strings.Contains(o.String(), "aslr fails=0") {
			t.Fatalf("%v: code = %d, err = %v, out:\n%s", mode, code, err, o.String())
		}
	}
}

// TestEpollClose: an epoll registration lasts as long as its open file, and
// the file's last close removes it and releases the file to its peer.
func TestEpollClose(t *testing.T) {
	out := filepath.Join(t.TempDir(), "epollclose")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/epollclose.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"epollclose"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "epollclose fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestRseq: restartable sequences are the host kernel's, registered on the
// guest's own thread, inherited by a fork and ended by an execve
// (testdata/rseq.c).
func TestRseq(t *testing.T) {
	out := filepath.Join(t.TempDir(), "rseq")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/rseq.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc with sys/rseq.h unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"rseq"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "rseq fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestVdso: the guest has the kernel's vDSO as a Linux process does
// (testdata/vdso.c).
func TestVdso(t *testing.T) {
	out := filepath.Join(t.TempDir(), "vdso")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/vdso.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"vdso"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "vdso fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestArgFault: syscalls given bad input pointers, or ones running into an
// unmapped page, fail with EFAULT as on Linux, and an input ending at a
// mapping's edge is read whole.
func TestArgFault(t *testing.T) {
	out := filepath.Join(t.TempDir(), "argfault")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/argfault.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"argfault"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "argfault fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestNetlinkDump: a netlink dump is handed out a datagram at a time as Linux
// does, sized by NLMSG_GOODSIZE and then by the reader's buffer, its
// NLMSG_DONE alone, with no ack and EBUSY for a second dump
// (testdata/nldump.c).
func TestNetlinkDump(t *testing.T) {
	out := filepath.Join(t.TempDir(), "nldump")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/nldump.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"nldump"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "nldump fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestVforkShare: a vfork child shares its parent's memory and stack, and the
// parent's state survives the child's use of that stack
// (testdata/vforkshare.c).
func TestVforkShare(t *testing.T) {
	out := filepath.Join(t.TempDir(), "vforkshare")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/vforkshare.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"vforkshare"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "vforkshare fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestOwnLoopback: a run with networking has its own loopback, as a network
// namespace has (testdata/vlo.c): a listener on a wildcard takes connections
// from it and from the host on one port, a datagram socket on a wildcard
// receives from it, and a service on the host's 127.0.0.1 is out of reach.
func TestOwnLoopback(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "vlo")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", bin, "../../testdata/vlo.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(free.Addr().(*net.TCPAddr).Port)
	free.Close()
	pr, pw := io.Pipe()
	done := make(chan struct{})
	var code int
	var runErr error
	go func() {
		defer close(done)
		args := []string{"vlo", port, strconv.Itoa(svc.Addr().(*net.TCPAddr).Port)}
		code, runErr = Run(context.Background(), bin, Config{Args: args, Stdout: pw, Stderr: pw, RootFS: HostRoot("/"), Net: true})
		pw.Close()
	}()
	var out strings.Builder
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		out.WriteString(sc.Text() + "\n")
		if sc.Text() == "ready" {
			c, err := net.Dial("tcp", "127.0.0.1:"+port)
			if err != nil {
				t.Errorf("the host's connect to the guest's listener: %v", err)
				continue
			}
			c.Write([]byte("host"))
			c.Close()
		}
	}
	<-done
	if runErr != nil || code != 0 || !strings.Contains(out.String(), "vlo fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, runErr, out.String())
	}
}

// TestProcSmaps: /proc/self/smaps lists /proc/self/maps' entries with the
// kernel's fields and counts, a fork child sees a page it shares with its
// parent shared and dirty (redis's check for an arm64 kernel bug), and
// smaps_rollup sums them (testdata/smaps.c).
func TestProcSmaps(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "smaps")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", bin, "../../testdata/smaps.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{Args: []string{"smaps"}, Stdout: &out, Stderr: &out, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(out.String(), "smaps fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, out.String())
	}
}

// TestVnetSockets: loopback sockets behave as Linux's, on vnet's loopback and
// on the run's own with networking. testdata/vaddr.c: the addresses they
// report (a wildcard-bound socket's source per destination, the address an
// accepted socket was reached at, IPv6's loopback apart from IPv4's) and a
// connected datagram socket taking only its peer's datagrams; vreuse.c:
// sharing a port by SO_REUSEADDR and SO_REUSEPORT; vmcast.c, without
// networking (a namespace whose only interface is lo): multicast.
func TestVnetSockets(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		prog string
		nets []bool
	}{{"vaddr", []bool{false, true}}, {"vreuse", []bool{false, true}}, {"vmcast", []bool{false}}} {
		bin := filepath.Join(dir, c.prog)
		if b, err := exec.Command("gcc", "-O2", "-static", "-o", bin, "../../testdata/"+c.prog+".c").CombinedOutput(); err != nil {
			t.Skipf("static gcc unavailable: %v\n%s", err, b)
		}
		for _, network := range c.nets {
			var out bytes.Buffer
			code, err := Run(context.Background(), bin, Config{Args: []string{c.prog}, Stdout: &out, Stderr: &out, RootFS: HostRoot("/"), Net: network})
			if err != nil || code != 0 || !strings.Contains(out.String(), c.prog+" fails=0") {
				t.Errorf("%s net=%v: code = %d, err = %v, out:\n%s", c.prog, network, code, err, out.String())
			}
		}
	}
}

// TestJitSys: code the guest writes and runs makes raw syscalls as code from
// a file does (testdata/jitsys.c).
func TestJitSys(t *testing.T) {
	out := filepath.Join(t.TempDir(), "jitsys")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/jitsys.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"jitsys"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "jitsys fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestSharedExec: code in shared memory makes syscalls as code from a file
// does, and what runs is what was last written to it, through any mapping
// and by any process sharing it (testdata/sharedexec.c).
func TestSharedExec(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sharedexec")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/sharedexec.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"sharedexec"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "sharedexec fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestSelfStore: code stores into the page it runs from, in private, shared
// and memfd memory, by every store form, an exclusive loop counting exactly
// from four threads, and an instruction it writes and runs
// (testdata/selfstore.c).
func TestSelfStore(t *testing.T) {
	out := filepath.Join(t.TempDir(), "selfstore")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/selfstore.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"selfstore"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "selfstore fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestCrossExec: code in shared memory is what was last written to it by
// any process, write(2) and a fork child's stores too, and a stopped child
// neither blocks its parent nor runs stale code once it goes on
// (testdata/crossexec.c).
func TestCrossExec(t *testing.T) {
	out := filepath.Join(t.TempDir(), "crossexec")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/crossexec.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"crossexec"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "crossexec fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestWritevAtomic: a writev to a pipe of at most PIPE_BUF bytes is one
// atomic write, whatever its iovecs (testdata/writevatomic.c).
func TestWritevAtomic(t *testing.T) {
	out := filepath.Join(t.TempDir(), "writevatomic")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/writevatomic.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"writevatomic"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "writevatomic fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestMmapPlace: mappings a program leaves unplaced go where Linux puts them
// (testdata/mmapplace.c), checked against the host mappings as they are made.
func TestMmapPlace(t *testing.T) {
	out := filepath.Join(t.TempDir(), "mmapplace")
	if b, err := exec.Command("gcc", "-O2", "-static-pie", "-o", out, "../../testdata/mmapplace.c").CombinedOutput(); err != nil {
		t.Skipf("static-pie gcc unavailable: %v\n%s", err, b)
	}
	vmaValidate = true
	defer func() { vmaValidate = false }()
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"mmapplace"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 || !strings.Contains(o.String(), "mmapplace fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

func TestThreads(t *testing.T) {
	out := filepath.Join(t.TempDir(), "threads")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/threads.c").CombinedOutput(); err != nil {
		t.Skipf("static pthread gcc unavailable: %v\n%s", err, b)
	}
	var stdout bytes.Buffer
	code, err := Run(context.Background(), out, Config{
		Args:   []string{"threads"},
		Stdout: &stdout,
		Stderr: &stdout,
	})
	if err != nil || code != 0 {
		t.Fatalf("code = %d, err = %v, output = %q", code, err, stdout.String())
	}
	// 4 threads * 1000 increments; join sum 0+10+20+30.
	if !strings.Contains(stdout.String(), "counter=4000 joined_sum=60") {
		t.Fatalf("output = %q", stdout.String())
	}
}

func TestRWXDefaultAndRejectRWX(t *testing.T) {
	out := filepath.Join(t.TempDir(), "rwx")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/rwx.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	for _, tc := range []struct {
		reject bool
		want   string
	}{{false, "allowed"}, {true, "denied"}} {
		var o bytes.Buffer
		_, err := Run(context.Background(), out, Config{
			Args: []string{"rwx"}, Stdout: &o, Stderr: &o, RejectRWX: tc.reject,
		})
		if err != nil {
			t.Fatalf("reject=%v: %v", tc.reject, err)
		}
		if !strings.Contains(o.String(), tc.want) {
			t.Fatalf("reject=%v: got %q, want %q", tc.reject, o.String(), tc.want)
		}
	}
}

func TestExecve(t *testing.T) {
	out := filepath.Join(t.TempDir(), "execer")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/execer.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	if _, err := os.Stat("/bin/busybox"); err != nil {
		t.Skip("/bin/busybox not present")
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{
		Args: []string{"execer"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/"),
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
	if !strings.Contains(o.String(), "before exec") || !strings.Contains(o.String(), "exec works") {
		t.Fatalf("out=%q", o.String())
	}
}

func TestForkWait(t *testing.T) {
	out := filepath.Join(t.TempDir(), "forker")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/forker.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"forker"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
	if !strings.Contains(o.String(), "child") || !strings.Contains(o.String(), "exit=7") {
		t.Fatalf("out=%q", o.String())
	}
}

func TestForkExec(t *testing.T) {
	out := filepath.Join(t.TempDir(), "forkexec")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/forkexec.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	if _, err := os.Stat("/bin/busybox"); err != nil {
		t.Skip("/bin/busybox not present")
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"fe"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
	if !strings.Contains(o.String(), "hello-from-exec") || !strings.Contains(o.String(), "child exit=0") {
		t.Fatalf("out=%q", o.String())
	}
}

func TestSlotReuse(t *testing.T) {
	out := filepath.Join(t.TempDir(), "churn")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/churn.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, out, Config{Args: []string{"churn"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "churn ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestStubsDieWithSupervisor kills a supervisor outright: its forked child
// stubs, which no parent-death signal covers, must still exit.
func TestStubsDieWithSupervisor(t *testing.T) {
	if prog := os.Getenv("LC_FORKBLOCK"); prog != "" {
		Run(context.Background(), prog, Config{Args: []string{"fb"}, Stdout: os.Stdout, Stderr: os.Stderr})
		return
	}
	out := filepath.Join(t.TempDir(), "forkblock")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/forkblock.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	sup := exec.Command(os.Args[0], "-test.run=^TestStubsDieWithSupervisor$")
	sup.Env = append(os.Environ(), "LC_FORKBLOCK="+out)
	stdout, err := sup.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	stubs := descendants(sup.Process.Pid)
	if len(stubs) < 2 {
		t.Fatalf("want a stub and its forked child, got %v", stubs)
	}
	sup.Process.Kill()
	sup.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for _, pid := range stubs {
		for unix.Kill(pid, 0) == nil {
			if time.Now().After(deadline) {
				unix.Kill(pid, unix.SIGKILL)
				t.Fatalf("stub %d outlived its supervisor", pid)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// TestComputingStubsDieWithSupervisor: stubs that never wait on their
// channel (a forked guest computing) die within a second of their
// supervisor, by the lifeline's SIGIO to their process group.
func TestComputingStubsDieWithSupervisor(t *testing.T) {
	if prog := os.Getenv("LC_FORKSPIN"); prog != "" {
		Run(context.Background(), prog, Config{Args: []string{"fs"}, Stdout: os.Stdout, Stderr: os.Stderr})
		return
	}
	out := filepath.Join(t.TempDir(), "forkspin")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/forkspin.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	sup := exec.Command(os.Args[0], "-test.run=^TestComputingStubsDieWithSupervisor$")
	sup.Env = append(os.Environ(), "LC_FORKSPIN="+out)
	stdout, err := sup.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	stubs := descendants(sup.Process.Pid)
	if len(stubs) < 2 {
		t.Fatalf("want a stub and its forked child, got %v", stubs)
	}
	sup.Process.Kill()
	sup.Wait()
	deadline := time.Now().Add(time.Second)
	for _, pid := range stubs {
		for unix.Kill(pid, 0) == nil {
			if time.Now().After(deadline) {
				unix.Kill(-stubs[0], unix.SIGKILL)
				t.Fatalf("stub %d outlived its supervisor by a second", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// descendants lists the processes below pid.
func descendants(pid int) []int {
	parent := map[int]int{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+2:]))
		parent[p], _ = strconv.Atoi(f[1])
	}
	var out []int
	for p := range parent {
		for q := parent[p]; q > 1; q = parent[q] {
			if q == pid {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func TestJoinThenUnmapStack(t *testing.T) {
	out := filepath.Join(t.TempDir(), "joinunmap")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/joinunmap.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"ju"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "joinunmap ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestDetachedThreadsExit: musl ends a detached thread by unmapping its own
// stack and then exiting.
func TestDetachedThreadsExit(t *testing.T) {
	z := zigCC()
	if z == "" {
		t.Skip("zig unavailable")
	}
	out := filepath.Join(t.TempDir(), "detach")
	target := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-linux-musl"
	if b, err := exec.Command(z, "cc", "-target", target, "-O2", "-static", "-o", out, "../../testdata/detach.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"detach"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "detach ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestLeaderExitsFirst: a process whose leader exits before its other
// thread ends with that thread, freeing what it held.
func TestLeaderExitsFirst(t *testing.T) {
	out := filepath.Join(t.TempDir(), "leaderexit")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/leaderexit.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"leaderexit"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "leaderexit ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestForkKeepsFP: a fork child has its parent's FP/SIMD registers and FP
// control word, also when the fork came in through a signal handler.
func TestForkKeepsFP(t *testing.T) {
	out := filepath.Join(t.TempDir(), "forkfp")
	args := []string{"-O2", "-static", "-o", out, "../../testdata/forkfp.c"}
	if runtime.GOARCH == "amd64" {
		if !cpuHasAVX() {
			t.Skip("no AVX")
		}
		args = append([]string{"-mavx"}, args...)
	}
	if b, err := exec.Command("gcc", args...).CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"forkfp"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "forkfp ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

func cpuHasAVX() bool {
	b, err := os.ReadFile("/proc/cpuinfo")
	return err == nil && bytes.Contains(b, []byte(" avx "))
}

// TestStubJumpKilled: a guest that branches into the stub's own syscall
// instructions to make a call the supervisor would mediate (here an mmap) is
// killed, not served.
func TestStubJumpKilled(t *testing.T) {
	out := filepath.Join(t.TempDir(), "stubjump")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/stubjump.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"stubjump"}, Stdout: &o, Stderr: &o})
	if !errors.Is(err, ErrKilled) || !strings.Contains(o.String(), "gadget at") || strings.Contains(o.String(), "ESCAPED") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestStubSignalScoped: the stub's kick signal, the one signal a guest can
// send by branching into the stub, does not reach a process outside the
// sandbox where Landlock scopes signals (ABI 6).
func TestStubSignalScoped(t *testing.T) {
	if abi, _, _ := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION); int(abi) < 6 {
		t.Skipf("Landlock ABI %d has no signal scope", int(abi))
	}
	out := filepath.Join(t.TempDir(), "stubjump")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/stubjump.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"stubjump", "signal", strconv.Itoa(os.Getpid())}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "tgkill -1\n") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestThreadExitRacesExitGroup: threads exiting one by one while their
// process ends do not leave the supervisor waiting on them.
func TestThreadExitRacesExitGroup(t *testing.T) {
	out := filepath.Join(t.TempDir(), "threadexitrace")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/threadexitrace.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, out, Config{Args: []string{"threadexitrace"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "threadexitrace ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestExitWhileMapping ends a process while its threads change mappings;
// under -race it checks the exit's memory accounting.
func TestExitWhileMapping(t *testing.T) {
	out := filepath.Join(t.TempDir(), "exitrace")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", out, "../../testdata/exitrace.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	code, err := Run(context.Background(), out, Config{Args: []string{"exitrace"}})
	if err != nil || code != 3 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestExitLeavesBlockedChildren(t *testing.T) {
	out := filepath.Join(t.TempDir(), "forkexit")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/forkexit.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	done := make(chan struct{})
	var code int
	var err error
	go func() {
		code, err = Run(context.Background(), out, Config{Args: []string{"forkexit"}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		t.Fatal("Run did not return after the main process exited")
	}
	if err != nil || code != 5 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestWaitReapsOnlyOwnChildren(t *testing.T) {
	out := filepath.Join(t.TempDir(), "waitown")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/waitown.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"waitown"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "waited child exit=4") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

func TestMemCap(t *testing.T) {
	out := filepath.Join(t.TempDir(), "eat")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", out, "../../testdata/eatmem.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{
		Args: []string{"eat"}, Stdout: &o, Stderr: &o, MaxBytes: 64 << 20,
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
	if !strings.Contains(o.String(), "malloc failed") {
		t.Fatalf("expected malloc to fail under the cap, got %q", o.String())
	}
}

func TestWritableOverlayAndDevices(t *testing.T) {
	if _, err := os.Stat("/bin/busybox"); err != nil {
		t.Skip("/bin/busybox not present")
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), "/bin/busybox", Config{
		Args: []string{"sh", "-c",
			"echo hi > /tmp/f && cat /tmp/f && echo x > /dev/null && echo devok && head -c 3 /dev/zero | wc -c"},
		Env: []string{"PATH=/bin:/usr/bin"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/"),
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
	out := o.String()
	if !strings.Contains(out, "hi") || !strings.Contains(out, "devok") || !strings.Contains(out, "3") {
		t.Fatalf("out=%q", out)
	}
}

// TestGoProgram runs a Go program whose runtime starts threads, linked both
// at the default address (0x10000 on arm64, too low for trampolines below
// it) and as a PIE, which has an interpreter.
func TestGoProgram(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []string{"exe", "pie"} {
		out := filepath.Join(dir, "go-"+mode)
		cmd := exec.Command("go", "build", "-buildmode="+mode, "-o", out, "../../testdata/gothreads.go")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("go build unavailable: %v\n%s", err, b)
		}
		var o bytes.Buffer
		code, err := Run(context.Background(), out, Config{Args: []string{"gothreads"}, Stdout: &o, Stderr: &o, RootFS: HostRoot("/")})
		if err != nil || code != 0 || !strings.Contains(o.String(), "go ok true") {
			t.Fatalf("%s: code=%d err=%v out=%q", mode, code, err, o.String())
		}
	}
}

// busybox ip reads the interfaces over netlink and checks each reply comes
// from the kernel (a sender address).
func TestIPAddr(t *testing.T) {
	code, out := runBusybox(t, "busybox ip addr")
	if code != 0 || !strings.Contains(out, "lo:") || !strings.Contains(out, "inet 127.0.0.1/8") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}
