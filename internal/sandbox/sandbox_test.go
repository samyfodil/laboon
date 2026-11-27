package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func buildHello(t *testing.T) string {
	t.Helper()
	out := guestPath(t, "hello")
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
//
// Windows has no trap to serve a raw syscall from: on amd64 its
// instrumentation-callback backstop kills the guest, and arm64, which has no
// backstop, refuses to run without rewriting.
func TestNoRewriteRunsViaTrap(t *testing.T) {
	var stdout bytes.Buffer
	code, err := Run(context.Background(), buildHello(t), Config{
		Args:      []string{"hello", "world"},
		Stdout:    &stdout,
		Stderr:    &stdout,
		NoRewrite: true,
	})
	switch {
	case runtime.GOOS == "windows" && runtime.GOARCH == "amd64":
		if !errors.Is(err, ErrKilled) {
			t.Fatalf("code=%d err=%v, want ErrKilled (the backstop kills a raw syscall)", code, err)
		}
		return
	case runtime.GOOS == "windows":
		if !errors.Is(err, errNoBackstop) {
			t.Fatalf("code=%d err=%v, want errNoBackstop", code, err)
		}
		return
	}
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
	root := dynRoot(t)
	var stdout bytes.Buffer
	code, err := Run(context.Background(), "/hello", Config{
		Args:   []string{"hello", "dyn"},
		Stdout: &stdout,
		Stderr: &stdout,
		RootFS: HostRoot(root),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 || !strings.Contains(stdout.String(), "argv[1]=dyn") {
		t.Fatalf("exit = %d, stdout = %q", code, stdout.String())
	}
}

func TestRootIsReadOnly(t *testing.T) {
	root := busyboxRoot(t)
	var stderr bytes.Buffer
	code, err := Run(context.Background(), "/bin/busybox", Config{
		Args:   []string{"touch", "/tmp/made", "/made"},
		Stdout: &stderr,
		Stderr: &stderr,
		RootFS: HostRoot(root),
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v %s", code, err, stderr.String())
	}
	// The guest's writes go to its overlay, never to the host directory.
	for _, p := range []string{"tmp/made", "made"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("touch reached the host's root: %s", p)
		}
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
	out := guestPath(t, "abort")
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
	root, out := guestRoot(t, "openpty")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"openpty"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "pty ok pts\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// A child process ends with its abort although another of its threads sleeps
// in the supervisor.
func TestChildAbortWithSleepingThread(t *testing.T) {
	root, out := guestRoot(t, "abortsleep")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"abortsleep"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "eof=1 sigabrt=1 fast=1\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

func TestKillBlockedChild(t *testing.T) {
	root, out := guestRoot(t, "killblocked")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"killblocked"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "reader=1 writer=1\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

func TestPipeWriteEndError(t *testing.T) {
	root, out := guestRoot(t, "pollerr")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"pollerr"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "poll=1 err=1 select=2 r=1 w=1\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

func TestStopAndOrphanedStop(t *testing.T) {
	root, out := guestRoot(t, "orphanstop")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"orphanstop"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "orphaned=1 stopped=1\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

func TestCloneOnStack(t *testing.T) {
	root, out := guestRoot(t, "clonestack")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"clonestack"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || o.String() != "clone child exit 42\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// System V shared memory, semaphores and message queues across fork: the
// macOS gate's ipctest, which the Linux stub now serves too.
func TestSysVIPC(t *testing.T) {
	root, out := guestRoot(t, "ipctest")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"ipctest"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.HasSuffix(o.String(), "ALL OK\n") {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// Each System V IPC limit IPC_INFO and /proc/sys/kernel report is enforced
// with Linux's errno, and removing an object makes room again. The memory cap
// bounds the segments' total, so SHMALL is reached at 64 MiB.
func TestSysVIPCLimits(t *testing.T) {
	root, out := guestRoot(t, "ipclimit")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"ipclimit"}, Stdout: &o, Stderr: &o, MaxBytes: 64 << 20})
	if err != nil || code != 0 || !strings.HasSuffix(o.String(), "ALL OK\n") {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// Every stub shares the socket descriptors to map are passed over: one
// killed mid-transfer must not leave its descriptor for the next mapping.
func TestKillWhileMapping(t *testing.T) {
	root, out := guestRoot(t, "killmmap")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"killmmap"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || o.String() != "wrong files 0\n" {
		t.Fatalf("code = %d, err = %v, out = %q", code, err, o.String())
	}
}

// TestKillWhileWaiting kills, or aborts with a sibling thread blocked, a
// child in each kind of wait the supervisor serves; the parent's waitpid must
// return at once.
func TestKillWhileWaiting(t *testing.T) {
	root, out := guestRoot(t, "killwait")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"killwait"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "killwait: 0 failures") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestThreadExec runs testdata/threadexec.c: an exec from the main
// thread and from another thread of a multithreaded process; the other
// threads end, the new image runs alone with the process's pid, and the
// process ends when it does.
func TestThreadExec(t *testing.T) {
	root, out := guestRoot(t, "threadexec")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{out}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "ALL OK") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestKickRace signals a thread in a futex wait, then in a read of a pipe,
// many times, one signal after its handler has taken the last: a signal
// landing as the thread goes into the wait must still end it (Linux takes
// kicks without re-kicking).
func TestKickRace(t *testing.T) {
	root, out := guestRoot(t, "kickrace")
	for _, mode := range []string{"futex", "read"} {
		r, w, err := os.Pipe() // stdin nothing writes, for the reads
		if err != nil {
			t.Fatal(err)
		}
		var o bytes.Buffer
		code, err := Run(context.Background(), out, Config{Args: []string{"kickrace", "20000", mode}, Stdin: r, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
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
	root, out := guestRoot(t, "sigsyscall")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"sigsyscall", "20000"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "sigsyscall: 20000 signals ok") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestASLR: a program is placed as Linux's ASLR places it, anew at each
// execve, the same across a fork and fixed under ADDR_NO_RANDOMIZE, built
// position-independent and not.
func TestASLR(t *testing.T) {
	for _, mode := range []string{"aslr", "aslr_nopie"} {
		root, out := guestRoot(t, mode)
		var o bytes.Buffer
		code, err := Run(context.Background(), out, Config{Args: []string{"aslr"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
		if err != nil || code != 0 || !strings.Contains(o.String(), "aslr fails=0") {
			t.Fatalf("%v: code = %d, err = %v, out:\n%s", mode, code, err, o.String())
		}
	}
}

// TestEpollClose: an epoll registration lasts as long as its open file, and
// the file's last close removes it and releases the file to its peer.
func TestEpollClose(t *testing.T) {
	root, out := guestRoot(t, "epollclose")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"epollclose"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "epollclose fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestRseq: restartable sequences are the host kernel's, registered on the
// guest's own thread, inherited by a fork and ended by an execve
// (testdata/rseq.c).
func TestRseq(t *testing.T) {
	root, out := guestRoot(t, "rseq")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"rseq"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "rseq fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestVdso: the guest has the kernel's vDSO as a Linux process does
// (testdata/vdso.c).
func TestVdso(t *testing.T) {
	root, out := guestRoot(t, "vdso")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"vdso"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "vdso fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestArgFault: syscalls given bad input pointers, or ones running into an
// unmapped page, fail with EFAULT as on Linux, and an input ending at a
// mapping's edge is read whole.
func TestArgFault(t *testing.T) {
	root, out := guestRoot(t, "argfault")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"argfault"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "argfault fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestNetlinkDump: a netlink dump is handed out a datagram at a time as Linux
// does, sized by NLMSG_GOODSIZE and then by the reader's buffer, its
// NLMSG_DONE alone, with no ack and EBUSY for a second dump
// (testdata/nldump.c).
func TestNetlinkDump(t *testing.T) {
	root, out := guestRoot(t, "nldump")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"nldump"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "nldump fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestVforkShare: a vfork child shares its parent's memory and stack, and the
// parent's state survives the child's use of that stack
// (testdata/vforkshare.c).
func TestVforkShare(t *testing.T) {
	root, out := guestRoot(t, "vforkshare")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"vforkshare"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "vforkshare fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestOwnLoopback: a run with networking has its own loopback, as a network
// namespace has (testdata/vlo.c): a listener on a wildcard takes connections
// from it and from the host on one port, a datagram socket on a wildcard
// receives from it, and a service on the host's 127.0.0.1 is out of reach.
func TestOwnLoopback(t *testing.T) {
	root, bin := guestRoot(t, "vlo")
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
		code, runErr = Run(context.Background(), bin, Config{Args: args, Stdout: pw, Stderr: pw, RootFS: HostRoot(root), Net: true})
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
	root, bin := guestRoot(t, "smaps")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{Args: []string{"smaps"}, Stdout: &out, Stderr: &out, RootFS: HostRoot(root)})
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
		bin := addGuest(t, dir, c.prog)
		for _, network := range c.nets {
			var out bytes.Buffer
			code, err := Run(context.Background(), bin, Config{Args: []string{c.prog}, Stdout: &out, Stderr: &out, RootFS: HostRoot(dir), Net: network})
			if err != nil || code != 0 || !strings.Contains(out.String(), c.prog+" fails=0") {
				t.Errorf("%s net=%v: code = %d, err = %v, out:\n%s", c.prog, network, code, err, out.String())
			}
		}
	}
}

// TestJitSys: code the guest writes and runs makes raw syscalls as code from
// a file does (testdata/jitsys.c).
func TestJitSys(t *testing.T) {
	root, out := guestRoot(t, "jitsys")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"jitsys"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "jitsys fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestSharedExec: code in shared memory makes syscalls as code from a file
// does, and what runs is what was last written to it, through any mapping
// and by any process sharing it (testdata/sharedexec.c).
func TestSharedExec(t *testing.T) {
	root, out := guestRoot(t, "sharedexec")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"sharedexec"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "sharedexec fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestSelfStore: code stores into the page it runs from, in private, shared
// and memfd memory, by every store form, an exclusive loop counting exactly
// from four threads, and an instruction it writes and runs
// (testdata/selfstore.c).
func TestSelfStore(t *testing.T) {
	root, out := guestRoot(t, "selfstore")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"selfstore"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "selfstore fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestCrossExec: code in shared memory is what was last written to it by
// any process, write(2) and a fork child's stores too, and a stopped child
// neither blocks its parent nor runs stale code once it goes on
// (testdata/crossexec.c).
func TestCrossExec(t *testing.T) {
	root, out := guestRoot(t, "crossexec")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"crossexec"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "crossexec fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestWritevAtomic: a writev to a pipe of at most PIPE_BUF bytes is one
// atomic write, whatever its iovecs (testdata/writevatomic.c).
func TestWritevAtomic(t *testing.T) {
	root, out := guestRoot(t, "writevatomic")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"writevatomic"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "writevatomic fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

// TestMmapPlace: mappings a program leaves unplaced go where Linux puts them
// (testdata/mmapplace.c), checked against the host mappings as they are made.
func TestMmapPlace(t *testing.T) {
	root, out := guestRoot(t, "mmapplace")
	defer validateVMAs()()
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"mmapplace"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "mmapplace fails=0") {
		t.Fatalf("code = %d, err = %v, out:\n%s", code, err, o.String())
	}
}

func TestThreads(t *testing.T) {
	root, out := guestRoot(t, "threads")
	var stdout bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root),
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
	root, out := guestRoot(t, "rwx")
	for _, tc := range []struct {
		reject bool
		want   string
	}{{false, "allowed"}, {true, "denied"}} {
		var o bytes.Buffer
		_, err := Run(context.Background(), out, Config{RootFS: HostRoot(root),
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
	root, out := guestRoot(t, "execer")
	withBusybox(t, root)
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{
		Args: []string{"execer"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root),
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
	if !strings.Contains(o.String(), "before exec") || !strings.Contains(o.String(), "exec works") {
		t.Fatalf("out=%q", o.String())
	}
}

func TestForkWait(t *testing.T) {
	root, out := guestRoot(t, "forker")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"forker"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
	if !strings.Contains(o.String(), "child") || !strings.Contains(o.String(), "exit=7") {
		t.Fatalf("out=%q", o.String())
	}
}

func TestForkExec(t *testing.T) {
	root, out := guestRoot(t, "forkexec")
	withBusybox(t, root)
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"fe"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
	if !strings.Contains(o.String(), "hello-from-exec") || !strings.Contains(o.String(), "child exit=0") {
		t.Fatalf("out=%q", o.String())
	}
}

func TestSlotReuse(t *testing.T) {
	root, out := guestRoot(t, "churn")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, out, Config{RootFS: HostRoot(root), Args: []string{"churn"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "churn ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

func TestJoinThenUnmapStack(t *testing.T) {
	root, out := guestRoot(t, "joinunmap")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"ju"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "joinunmap ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestDetachedThreadsExit: musl ends a detached thread by unmapping its own
// stack and then exiting.
func TestDetachedThreadsExit(t *testing.T) {
	root, out := guestRoot(t, "detach+musl")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: []string{"detach"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "detach ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestLeaderExitsFirst: a process whose leader exits before its other
// thread ends with that thread, freeing what it held.
func TestLeaderExitsFirst(t *testing.T) {
	root, out := guestRoot(t, "leaderexit")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"leaderexit"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "leaderexit ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestForkKeepsFP: a fork child has its parent's FP/SIMD registers and FP
// control word, also when the fork came in through a signal handler (a stray
// syscall Linux's seccomp trap serves; macOS and Windows kill a stray instead,
// the host backstop for a site the rewriter missed, so there only the
// rewritten site).
func TestForkKeepsFP(t *testing.T) {
	root, out := guestRoot(t, "forkfp")
	args := []string{"forkfp"}
	if runtime.GOOS != "linux" {
		args = append(args, "sites")
	}
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{Args: args, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
	if err != nil || code != 0 || !strings.Contains(o.String(), "forkfp ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestThreadExitRacesExitGroup: threads exiting one by one while their
// process ends do not leave the supervisor waiting on them.
func TestThreadExitRacesExitGroup(t *testing.T) {
	root, out := guestRoot(t, "threadexitrace")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, out, Config{RootFS: HostRoot(root), Args: []string{"threadexitrace"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "threadexitrace ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

// TestExitWhileMapping ends a process while its threads change mappings;
// under -race it checks the exit's memory accounting.
func TestExitWhileMapping(t *testing.T) {
	root, out := guestRoot(t, "exitrace")
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"exitrace"}})
	if err != nil || code != 3 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestExitLeavesBlockedChildren(t *testing.T) {
	root, out := guestRoot(t, "forkexit")
	done := make(chan struct{})
	var code int
	var err error
	go func() {
		code, err = Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"forkexit"}})
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
	root, out := guestRoot(t, "waitown")
	var o bytes.Buffer
	code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root), Args: []string{"waitown"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "waited child exit=4") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}

func TestMemCap(t *testing.T) {
	for _, name := range []string{"eatmem", "eatmem_nopie"} {
		t.Run(name, func(t *testing.T) {
			root, out := guestRoot(t, name)
			var o bytes.Buffer
			code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root),
				Args: []string{"eat"}, Stdout: &o, Stderr: &o, MaxBytes: 64 << 20,
			})
			if err != nil || code != 0 {
				t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
			}
			if !strings.Contains(o.String(), "malloc failed") {
				t.Fatalf("expected malloc to fail under the cap, got %q", o.String())
			}
		})
	}
}

// TestMemCapRunWide checks the cap holds for the run's processes together: a
// forked child holding its copy of 40 MiB cannot take 40 MiB more under a
// 64 MiB cap (where the host charges the copy at fork, the fork fails).
func TestMemCapRunWide(t *testing.T) {
	for _, name := range []string{"eatmem", "eatmem_nopie"} {
		t.Run(name, func(t *testing.T) {
			root, out := guestRoot(t, name)
			var o bytes.Buffer
			code, err := Run(context.Background(), out, Config{RootFS: HostRoot(root),
				Args: []string{name, "fork"}, Stdout: &o, Stderr: &o, MaxBytes: 64 << 20,
			})
			if err != nil || code != 0 {
				t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
			}
			if s := o.String(); !strings.Contains(s, "child malloc failed") && !strings.Contains(s, "fork failed") {
				t.Fatalf("expected the child to be held to the run's cap, got %q", s)
			}
		})
	}
}

func TestWritableOverlayAndDevices(t *testing.T) {
	var o bytes.Buffer
	code, err := Run(context.Background(), "/bin/busybox", Config{
		Args: []string{"sh", "-c", "/bin/busybox --install -s /bin; " +
			"echo hi > /tmp/f && cat /tmp/f && echo x > /dev/null && echo devok && head -c 3 /dev/zero | wc -c"},
		Env: []string{"PATH=/bin:/usr/bin"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(busyboxRoot(t)),
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
	for _, mode := range []string{"exe", "pie"} {
		root := dynRoot(t) // the PIE's interpreter
		out := putGuest(t, root, "gothreads", goGuest(t, "gothreads.go", mode))
		var o bytes.Buffer
		code, err := Run(context.Background(), out, Config{Args: []string{"gothreads"}, Stdout: &o, Stderr: &o, RootFS: HostRoot(root)})
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
