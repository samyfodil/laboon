//go:build windows

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/samyfodil/laboon/internal/oci"
)

// TestWindowsBusybox runs a static musl busybox from LC_WIN_ROOTFS, a rootfs
// holding /bin/busybox and /etc/hostname (windows/m1/run.sh builds one).
func TestWindowsBusybox(t *testing.T) {
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	host, err := os.ReadFile(root + `\etc\hostname`)
	if err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"dev"} // the sandbox's own /dev
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	top := strings.Join(slices.Compact(names), "\n") + "\n"
	cases := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{args: []string{"true"}},
		{args: []string{"false"}, code: 1},
		{args: []string{"echo", "hi"}, stdout: "hi\n"},
		{args: []string{"cat", "/etc/hostname"}, stdout: string(host)},
		{args: []string{"ls", "/etc"}, stdout: "hostname\n"},
		{args: []string{"ls", "/"}, stdout: top},
		{args: []string{"sh", "-c", "exit 7"}, code: 7},
		{args: []string{"cat", "/nope"}, code: 1, stderr: "cat: can't open '/nope': No such file or directory\n"},
		{args: []string{"cat", "/ETC/HOSTNAME"}, code: 1, stderr: "cat: can't open '/ETC/HOSTNAME': No such file or directory\n"},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			var out, errb bytes.Buffer
			cfg := Config{
				RootFS: HostRoot(root),
				Args:   append([]string{"busybox"}, c.args...),
				Env:    []string{"PATH=/bin"},
				Stdin:  strings.NewReader(""),
				Stdout: &out,
				Stderr: &errb,
			}
			if testing.Verbose() && os.Getenv("LC_TRACE") != "" {
				cfg.Trace = os.Stderr
			}
			code, err := Run(context.Background(), "/bin/busybox", cfg)
			if err != nil {
				t.Fatalf("Run: %v (stderr %q)", err, errb.String())
			}
			if code != c.code || out.String() != c.stdout || errb.String() != c.stderr {
				t.Fatalf("exit %d stdout %q stderr %q; want %d %q %q", code, out.String(), errb.String(), c.code, c.stdout, c.stderr)
			}
		})
	}
}

// TestWindowsNoRewriteKilled runs busybox with syscall rewriting disabled, so
// its first syscall is a raw stray. On x86-64 the stub's instrumentation-callback
// backstop (stub/windows/instrcb.zig) catches it — a syscall returning outside
// ntdll — and kills the guest: ErrKilled. (On Linux the trap backstop services
// such a stray instead; see TestNoRewriteRunsViaTrap.)
func TestWindowsNoRewriteKilled(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the instrumentation-callback backstop is x86-64 only")
	}
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	var out, errb bytes.Buffer
	_, err := Run(context.Background(), "/bin/busybox", Config{
		RootFS:    HostRoot(root),
		Args:      []string{"busybox", "true"},
		Env:       []string{"PATH=/bin"},
		Stdin:     strings.NewReader(""),
		Stdout:    &out,
		Stderr:    &errb,
		NoRewrite: true,
	})
	if !errors.Is(err, ErrKilled) {
		t.Fatalf("err = %v, want ErrKilled (stray syscall killed by the backstop)", err)
	}
}

// TestWindowsStubConfined checks that a stub that has reached its handshake
// runs in an AppContainer inside its job.
func TestWindowsStubConfined(t *testing.T) {
	sec, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, 0, slotsLen, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(sec)
	view, err := windows.MapViewOfFile(sec, windows.FILE_MAP_WRITE, 0, 0, slotsLen)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.UnmapViewOfFile(view)
	evStub, _ := windows.CreateEvent(nil, 0, 0, nil)
	evSup, _ := windows.CreateEvent(nil, 0, 0, nil)
	defer windows.CloseHandle(evStub)
	defer windows.CloseHandle(evSup)
	job, err := newJob(0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(job)
	sp, err := startStub(job, []windows.Handle{sec, evStub, evSup}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.close()
	mem := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&view))), slotsLen)
	ch := &hostChan{channel: newChannel(mem, 0, 0, nil, nil), evStub: evStub, evSup: evSup, proc: sp.proc}
	if err := ch.wait(); err != nil || ch.page.kind != msgReady {
		t.Fatalf("handshake: %v kind %d", err, ch.page.kind)
	}

	var tok windows.Token
	if err := windows.OpenProcessToken(sp.proc, windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	const tokenIsAppContainer = 29
	var isAC uint32
	var n uint32
	if err := windows.GetTokenInformation(tok, tokenIsAppContainer, (*byte)(unsafe.Pointer(&isAC)), 4, &n); err != nil || isAC == 0 {
		t.Fatalf("stub token is not an AppContainer (%v)", err)
	}
	var app []string
	if groups, err := tok.GetTokenGroups(); err == nil {
		for _, g := range groups.AllGroups() {
			if sid := g.Sid.String(); strings.HasPrefix(sid, "S-1-15-") {
				app = append(app, sid)
			}
		}
	}
	var in int32
	r, _, err := modKernel32.NewProc("IsProcessInJob").Call(uintptr(sp.proc), uintptr(job), uintptr(unsafe.Pointer(&in)))
	if r == 0 || in == 0 {
		t.Fatalf("stub not in its job (%v)", err)
	}
	t.Logf("stub: AppContainer token, in its job, package groups %v", app)

	// The mitigations it started with (stubMitigations), read back as the
	// PROCESS_MITIGATION_POLICY flags the kernel keeps.
	getPolicy := modKernel32.NewProc("GetProcessMitigationPolicy")
	for _, p := range []struct {
		name         string
		policy, want uint32
	}{
		{"strict handle checks", 3, 1},       // RaiseExceptionOnInvalidHandleReference
		{"system call disable", 4, 1 | 1<<2}, // DisallowWin32kSystemCalls, DisallowFsctlSystemCalls
		{"extension point disable", 6, 1},    // DisableExtensionPoints
		{"font disable", 9, 1},               // DisableNonSystemFonts
		{"image load", 10, 1 | 1<<1 | 1<<2},  // NoRemoteImages, NoLowMandatoryLabelImages, PreferSystem32Images
	} {
		var flags uint32
		if r, _, err := getPolicy.Call(uintptr(sp.proc), uintptr(p.policy), uintptr(unsafe.Pointer(&flags)), 4); r == 0 {
			t.Errorf("%s: %v", p.name, err)
		} else if flags&p.want != p.want {
			t.Errorf("%s: flags %#x, want %#x set", p.name, flags, p.want)
		}
	}
}

// winRun runs busybox with args over LC_WIN_ROOTFS and the kept upper layer.
func winRun(t *testing.T, root string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	cfg := Config{
		RootFS: HostRoot(root),
		Args:   append([]string{"busybox"}, args...),
		Env:    []string{"PATH=/bin"},
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
	}
	if testing.Verbose() && os.Getenv("LC_TRACE") != "" {
		cfg.Trace = os.Stderr
	}
	code, err := Run(context.Background(), "/bin/busybox", cfg)
	if err != nil {
		t.Fatalf("%v: Run: %v (stderr %q)", args, err, errb.String())
	}
	return code, out.String(), errb.String()
}

// TestWindowsFileApplets is M2's exit criterion: busybox file applets on the
// writable overlay. Each applet is its own run (fork comes with M4); the
// upper layer is kept between them.
func TestWindowsFileApplets(t *testing.T) {
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	host, err := os.ReadFile(root + `\etc\hostname`)
	if err != nil {
		t.Fatal(err)
	}
	testUpper = t.TempDir()
	defer func() { testUpper = "" }()
	sorted := func(s string) string {
		l := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
		slices.Sort(l)
		return strings.Join(l, "\n") + "\n"
	}
	steps := []struct {
		args   []string
		stdout string
		code   int
		sort   bool
	}{
		{args: []string{"mkdir", "-p", "/w/a/b"}},
		{args: []string{"cp", "/etc/hostname", "/w/a/b/h"}},
		{args: []string{"cat", "/w/a/b/h"}, stdout: string(host)},
		{args: []string{"mv", "/w/a/b/h", "/w/a/h2"}},
		{args: []string{"cat", "/w/a/b/h"}, code: 1},
		{args: []string{"ln", "-s", "h2", "/w/a/l"}},
		{args: []string{"readlink", "/w/a/l"}, stdout: "h2\n"},
		{args: []string{"cat", "/w/a/l"}, stdout: string(host)},
		{args: []string{"chmod", "640", "/w/a/h2"}},
		{args: []string{"stat", "-c", "%a %F", "/w/a/h2"}, stdout: "640 regular file\n"},
		{args: []string{"stat", "-c", "%F", "/w/a/l"}, stdout: "symbolic link\n"},
		{args: []string{"find", "/w"}, stdout: "/w\n/w/a\n/w/a/b\n/w/a/h2\n/w/a/l\n", sort: true},
		{args: []string{"sed", "-i", "s/laboon/LC/", "/w/a/h2"}},
		{args: []string{"cat", "/w/a/h2"}, stdout: strings.Replace(string(host), "laboon", "LC", 1)},
		{args: []string{"stat", "-c", "%a", "/w/a/h2"}, stdout: "640\n"},
		{args: []string{"tar", "-cf", "/w/t.tar", "-C", "/w", "a"}},
		{args: []string{"tar", "-tf", "/w/t.tar"}, stdout: "a/\na/b/\na/h2\na/l\n", sort: true},
		{args: []string{"mkdir", "/w/x"}},
		{args: []string{"tar", "-xf", "/w/t.tar", "-C", "/w/x"}},
		{args: []string{"readlink", "/w/x/a/l"}, stdout: "h2\n"},
		{args: []string{"cat", "/w/x/a/l"}, stdout: strings.Replace(string(host), "laboon", "LC", 1)},
		{args: []string{"rm", "-r", "/w/a"}},
		{args: []string{"ls", "/w"}, stdout: "t.tar\nx\n"},
		{args: []string{"touch", "/w/x/a:b*c?", "/w/x/CON", "/w/x/dot.", "/w/x/Foo", "/w/x/foo"}},
		{args: []string{"ls", "/w/x"}, stdout: "CON\nFoo\na\na:b*c?\ndot.\nfoo\n"},
		{args: []string{"rm", "/w/x/a:b*c?", "/w/x/CON", "/w/x/dot."}},
		{args: []string{"ls", "/w/x"}, stdout: "Foo\na\nfoo\n"},
		{args: []string{"sh", "-c", "echo x >> /w/x/foo; echo y >> /w/x/foo"}},
		{args: []string{"cat", "/w/x/foo"}, stdout: "x\ny\n"},
	}
	for _, s := range steps {
		code, out, errs := winRun(t, root, s.args...)
		if s.sort {
			out = sorted(out)
		}
		if code != s.code || s.code == 0 && out != s.stdout {
			t.Fatalf("%v: exit %d stdout %q stderr %q; want %d %q", s.args, code, out, errs, s.code, s.stdout)
		}
	}
}

// TestWindowsFSFault runs busybox with no %fs islands, so every thread-pointer
// access goes through the stub's fault handler.
func TestWindowsFSFault(t *testing.T) {
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("the fs-segment islands are x86-64 only")
	}
	testNoFSIslands = true
	defer func() { testNoFSIslands = false }()
	if code, out, errs := winRun(t, root, "sh", "-c", "echo a; echo b >&2; exit 3"); code != 3 || out != "a\n" || errs != "b\n" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsMemtest runs windows/m2/memtest.c, a static-PIE musl program
// that drives the stub's memory and the overlay's file calls.
// TestWindowsMemoryCap: WithMaxMemory holds the run's committed memory to its
// cap (the job's limit), and an allocation past it fails with ENOMEM.
func TestWindowsMemoryCap(t *testing.T) {
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	if _, err := os.Stat(root + `\bin\memcap`); err != nil {
		t.Skip("no /bin/memcap in the rootfs (windows/m2/run.sh builds it)")
	}
	for _, c := range []struct {
		max  uint64
		want func(n int) bool
	}{
		{0, func(n int) bool { return n == 256 }},
		{48 << 20, func(n int) bool { return n > 0 && n < 48 }},
	} {
		var out, errb bytes.Buffer
		cfg := Config{RootFS: HostRoot(root), Args: []string{"memcap"}, MaxBytes: c.max, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}
		code, err := Run(context.Background(), "/bin/memcap", cfg)
		var n int
		var why string
		fmt.Sscanf(out.String(), "memcap %d %s", &n, &why)
		if err != nil || code != 0 || !c.want(n) || (c.max > 0 && why != "ENOMEM") {
			t.Fatalf("max %d: exit %d err %v stdout %q stderr %q", c.max, code, err, out.String(), errb.String())
		}
		t.Logf("max %d MiB: %d MiB mapped (%s)", c.max>>20, n, why)
	}
}

func TestWindowsMemtest(t *testing.T) {
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	if _, err := os.Stat(root + `\bin\memtest`); err != nil {
		t.Skip("no /bin/memtest in the rootfs (windows/m2/run.sh builds it)")
	}
	var out, errb bytes.Buffer
	cfg := Config{RootFS: HostRoot(root), Args: []string{"memtest", "/tmp"}, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}
	if testing.Verbose() && os.Getenv("LC_TRACE") != "" {
		cfg.Trace = os.Stderr
	}
	code, err := Run(context.Background(), "/bin/memtest", cfg)
	if err != nil || code != 0 || out.String() != "memtest: 0 failures\n" {
		t.Fatalf("exit %d err %v stdout %q stderr %q", code, err, out.String(), errb.String())
	}
}

// TestWindowsLowerMeta reads the lower layer's POSIX metadata from
// <root>.lcmeta: modes and a symlink stored as a file holding its target.
func TestWindowsLowerMeta(t *testing.T) {
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	if _, err := os.Stat(root + ".lcmeta"); err != nil {
		t.Skip("no rootfs.lcmeta (windows/m2/run.sh writes one)")
	}
	for _, c := range []struct {
		args   []string
		stdout string
	}{
		{[]string{"readlink", "/bin/sh"}, "busybox\n"},
		{[]string{"stat", "-c", "%a %F", "/etc/hostname", "/bin/busybox", "/tmp", "/bin/sh"}, "644 regular file\n755 regular file\n1777 directory\n777 symbolic link\n"},
		{[]string{"sh", "-c", "echo via-symlink"}, "via-symlink\n"},
	} {
		if code, out, errs := winRun(t, root, c.args...); code != 0 || out != c.stdout {
			t.Fatalf("%v: exit %d stdout %q stderr %q; want %q", c.args, code, out, errs, c.stdout)
		}
	}
}

// TestWindowsFault runs windows/arm64/fault.c: a guest fault ends the guest
// as killed by the signal, and on arm64 a junk x18 survives a syscall and a
// trapped mrs.
func TestWindowsFault(t *testing.T) {
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	if _, err := os.Stat(root + `\bin\fault`); err != nil {
		t.Skip("no /bin/fault in the rootfs (windows/m2/run.sh and windows/arm64/run.sh build it)")
	}
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
		}{"x18", 0, "x18 ok 8444c00f\n"})
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			var out, errb bytes.Buffer
			cfg := Config{RootFS: HostRoot(root), Args: []string{"fault", c.mode}, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}
			if testing.Verbose() && os.Getenv("LC_TRACE") != "" {
				cfg.Trace = os.Stderr
			}
			code, err := Run(context.Background(), "/bin/fault", cfg)
			if err != nil || code != c.code || out.String() != c.stdout {
				t.Fatalf("exit %d err %v stdout %q stderr %q; want %d %q", code, err, out.String(), errb.String(), c.code, c.stdout)
			}
		})
	}
}

// winRunExe runs a non-busybox program /bin/<prog> and returns its result.
func winRunExe(t *testing.T, root, prog string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	cfg := Config{
		RootFS: HostRoot(root),
		Args:   append([]string{prog}, args...),
		Env:    []string{"PATH=/bin"},
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
	}
	if testing.Verbose() && os.Getenv("LC_TRACE") != "" {
		cfg.Trace = os.Stderr
	}
	code, err := Run(context.Background(), "/bin/"+prog, cfg)
	if err != nil {
		t.Fatalf("%s %v: Run: %v (stdout %q stderr %q)", prog, args, err, out.String(), errb.String())
	}
	return code, out.String(), errb.String()
}

func winSkipNoProg(t *testing.T, prog string) string {
	root := os.Getenv("LC_WIN_ROOTFS")
	if root == "" {
		t.Skip("LC_WIN_ROOTFS not set")
	}
	if _, err := os.Stat(root + `\bin\` + prog); err != nil {
		t.Skipf("no /bin/%s in the rootfs (windows/m3/run.sh builds it)", prog)
	}
	return root
}

// TestWindowsThreads runs a musl pthread workload: worker threads contend on a
// mutex, are joined, and their return values summed -- clone(CLONE_VM), futex
// (mutex + join), TLS and the thread exit path.
func TestWindowsThreads(t *testing.T) {
	root := winSkipNoProg(t, "pthreadtest")
	code, out, errs := winRunExe(t, root, "pthreadtest")
	if code != 0 || !strings.Contains(out, "OK") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsSignals runs the in-process signal battery: SA_SIGINFO handlers,
// raise/kill/tgkill, nested handlers, ppoll's temporary mask, sigprocmask
// masking with pending delivery on unmask, sigaltstack, a SIGSEGV fault
// delivered to a handler, POSIX timers, sigtimedwait, FP preservation and
// cross-thread pthread_kill.
func TestWindowsSignals(t *testing.T) {
	root := winSkipNoProg(t, "m3sig")
	code, out, errs := winRunExe(t, root, "m3sig")
	if code != 0 || !strings.Contains(out, "m3sig fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsKickRace signals a thread in futex waits, one signal after its
// handler took the last: one landing as the thread goes into a wait must
// still end it.
func TestWindowsKickRace(t *testing.T) {
	root := winSkipNoProg(t, "kickrace")
	code, out, errs := winRunExe(t, root, "kickrace", "5000")
	if code != 0 || !strings.Contains(out, "kickrace: 5000 signals ok") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsSigSyscall checks a syscall a signal lands on the way into
// returns to its own caller with its own result once the handler is done
// (testdata/sigsyscall.c).
func TestWindowsSigSyscall(t *testing.T) {
	root := winSkipNoProg(t, "sigsyscall")
	code, out, errs := winRunExe(t, root, "sigsyscall", "20000")
	if code != 0 || !strings.Contains(out, "sigsyscall: 20000 signals ok") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsASLR checks a program is placed as Linux's ASLR places it: anew
// at each execve, the same across a fork, fixed under ADDR_NO_RANDOMIZE
// (testdata/aslr.c).
func TestWindowsASLR(t *testing.T) {
	root := winSkipNoProg(t, "aslr")
	code, out, errs := winRunExe(t, root, "aslr")
	if code != 0 || !strings.Contains(out, "aslr fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsEpollClose checks an epoll registration lasts as long as its
// open file (testdata/epollclose.c).
func TestWindowsEpollClose(t *testing.T) {
	root := winSkipNoProg(t, "epollclose")
	code, out, errs := winRunExe(t, root, "epollclose")
	if code != 0 || !strings.Contains(out, "epollclose fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsArgFault checks syscalls given bad input pointers fail with
// EFAULT (testdata/argfault.c).
func TestWindowsArgFault(t *testing.T) {
	root := winSkipNoProg(t, "argfault")
	code, out, errs := winRunExe(t, root, "argfault")
	if code != 0 || !strings.Contains(out, "argfault fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsJitSys checks code the guest writes and runs makes raw syscalls
// as code from a file does: its pages are rewritten as they become executable
// (testdata/jitsys.c).
func TestWindowsJitSys(t *testing.T) {
	root := winSkipNoProg(t, "jitsys")
	code, out, errs := winRunExe(t, root, "jitsys")
	if code != 0 || !strings.Contains(out, "jitsys fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsWritevAtomic checks a writev to a pipe of at most PIPE_BUF bytes
// is one atomic write (testdata/writevatomic.c).
func TestWindowsWritevAtomic(t *testing.T) {
	root := winSkipNoProg(t, "writevatomic")
	code, out, errs := winRunExe(t, root, "writevatomic")
	if code != 0 || !strings.Contains(out, "writevatomic fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsLoopbackWithoutNet runs macos/m20-net/loopnet.c without
// networking, where the guest has loopback only; with NoNet, where it has no
// INET socket at all; and with networking under an egress allowlist, where
// its loopback is its own and the host's is out of reach.
func TestWindowsLoopbackWithoutNet(t *testing.T) {
	root := winSkipNoProg(t, "loopnet")
	// A service on the host's loopback, which a run under an egress allowlist
	// must not reach: its loopback is its own.
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostPort := strconv.Itoa(host.Addr().(*net.TCPAddr).Port)
	for _, c := range []struct {
		args  []string
		noNet bool
		allow []string
	}{{[]string{"loopback"}, false, nil}, {[]string{"none"}, true, nil}, {[]string{"local", hostPort}, false, []string{"example.com"}}} {
		var out bytes.Buffer
		code, err := Run(context.Background(), "/bin/loopnet", Config{
			RootFS: HostRoot(root), Args: append([]string{"loopnet"}, c.args...), Env: []string{"PATH=/bin"},
			Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out, NoNet: c.noNet,
			Net: c.allow != nil, AllowDomains: c.allow,
		})
		if err != nil || code != 0 || !strings.Contains(out.String(), "loopnet fails=0") {
			t.Errorf("%v: code %d err %v\n%s", c.args, code, err, out.String())
		}
	}
}

// TestWindowsSmaps: /proc/self/smaps lists /proc/self/maps' entries with
// Linux's fields and the host's counts, a fork child sees a page it shares
// with its parent shared and dirty, and smaps_rollup sums them
// (testdata/smaps.c).
func TestWindowsSmaps(t *testing.T) {
	root := winSkipNoProg(t, "smaps")
	code, out, errs := winRunExe(t, root, "smaps")
	if code != 0 || !strings.Contains(out, "smaps fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsIdregs: the AArch64 feature ID registers the guest reads with mrs
// are served (they trap at EL0 on Windows) and consistent with AT_HWCAP
// (testdata/idregs.c).
func TestWindowsIdregs(t *testing.T) {
	root := winSkipNoProg(t, "idregs")
	code, out, errs := winRunExe(t, root, "idregs")
	if code != 0 || !strings.Contains(out, "idregs fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsSharedCode: code in shared memory runs as Linux runs it: what was
// last written to it, through any view and by any process (sharedexec,
// crossexec), and a store into the page that runs it lands (selfstore).
func TestWindowsSharedCode(t *testing.T) {
	for _, prog := range []string{"sharedexec", "selfstore", "crossexec"} {
		t.Run(prog, func(t *testing.T) {
			root := winSkipNoProg(t, prog)
			code, out, errs := winRunExe(t, root, prog)
			if code != 0 || !strings.Contains(out, prog+" fails=0") {
				t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
			}
		})
	}
}

// TestWindowsLoopbackSockets: loopback sockets behave as Linux's, with
// networking and without (TestVnetSockets): the addresses they report
// (vaddr), sharing a port (vreuse), and multicast where lo is the only
// interface (vmcast).
func TestWindowsLoopbackSockets(t *testing.T) {
	for _, c := range []struct {
		prog string
		nets []bool
	}{{"vaddr", []bool{false, true}}, {"vreuse", []bool{false, true}}, {"vmcast", []bool{false}}} {
		root := winSkipNoProg(t, c.prog)
		for _, network := range c.nets {
			var out bytes.Buffer
			code, err := Run(context.Background(), "/bin/"+c.prog, Config{
				RootFS: HostRoot(root), Args: []string{c.prog}, Env: []string{"PATH=/bin"},
				Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out, Net: network,
			})
			if err != nil || code != 0 || !strings.Contains(out.String(), c.prog+" fails=0") {
				t.Errorf("%s net=%v: code %d err %v\n%s", c.prog, network, code, err, out.String())
			}
		}
	}
}

// TestWindowsSleepRestart checks a sleep a signal interrupts goes on or fails
// as on Linux: through a tracer's stop and a job-control stop it finishes,
// resumed by restart_syscall; a handler, even with SA_RESTART, ends it with
// EINTR (testdata/sleeprestart.c).
func TestWindowsSleepRestart(t *testing.T) {
	root := winSkipNoProg(t, "sleeprestart")
	code, out, errs := winRunExe(t, root, "sleeprestart")
	if code != 0 || !strings.Contains(out, "sleeprestart fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsPtraceFollow checks a tracer follows exec and fork, attaches and
// detaches, and holds a traced exit from the real parent until it lets the
// zombie go (testdata/ptracefollow.c).
func TestWindowsPtraceFollow(t *testing.T) {
	root := winSkipNoProg(t, "ptracefollow")
	code, out, errs := winRunExe(t, root, "ptracefollow")
	if code != 0 || !strings.Contains(out, "ptracefollow fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsPtraceSeize checks PTRACE_SEIZE, PTRACE_INTERRUPT and
// PTRACE_LISTEN, and attaching to a job-stopped task (testdata/ptraceseize.c).
func TestWindowsPtraceSeize(t *testing.T) {
	root := winSkipNoProg(t, "ptraceseize")
	for _, args := range [][]string{nil, {"stopped-mt"}} {
		code, out, errs := winRunExe(t, root, "ptraceseize", args...)
		if code != 0 || !strings.Contains(out, "ptraceseize fails=0") {
			t.Fatalf("%v: exit %d stdout %q stderr %q", args, code, out, errs)
		}
	}
}

// TestWindowsPtraceThreads checks a tracer follows a traced process's threads
// (testdata/ptracethreads.c).
func TestWindowsPtraceThreads(t *testing.T) {
	root := winSkipNoProg(t, "ptracethreads")
	code, out, errs := winRunExe(t, root, "ptracethreads")
	if code != 0 || !strings.Contains(out, "ptracethreads fails=0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestWindowsSignalIO covers delivery to a thread blocked in read with EINTR
// and SA_RESTART, and the default-action exit statuses.
func TestWindowsSignalIO(t *testing.T) {
	root := winSkipNoProg(t, "m3io")
	cases := []struct {
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
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			code, out, errs := winRunExe(t, root, "m3io", c.mode)
			if code != c.code || out != c.stdout {
				t.Fatalf("exit %d stdout %q stderr %q; want %d %q", code, out, errs, c.code, c.stdout)
			}
		})
	}
}

// TestWindowsHostPipes gives the guest host pipes of PIPE_BUF bytes as its
// stdio (testdata in windows/m3/m3io.c). A reader that keeps a read as large
// as the pipe pending (as PowerShell's pipeline does) leaves the pipe
// reporting no room, yet output goes through; a write blocked on a full pipe
// ends with EINTR on a signal, having written nothing; a non-blocking write is
// taken while the pipe is full, the next fails with EAGAIN, and POLLOUT
// returns once the reader reads. On stdin, a blocked read ends with EINTR on
// a signal, and a poll wakes when data comes, which FIONREAD counts, followed
// by end of file.
func TestWindowsHostPipes(t *testing.T) {
	root := winSkipNoProg(t, "m3io")
	run := func(stdin io.Reader, stdout, stderr io.Writer, prog string, args ...string) int {
		t.Helper()
		cfg := Config{RootFS: HostRoot(root), Args: append([]string{prog}, args...), Env: []string{"PATH=/bin"}, Stdin: stdin, Stdout: stdout, Stderr: stderr}
		code, err := Run(context.Background(), "/bin/"+prog, cfg)
		for _, v := range []io.Writer{stdout, stderr} {
			if f, ok := v.(*os.File); ok {
				f.Close()
			}
		}
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return code
	}
	pipe := func() (r, w *os.File) {
		t.Helper()
		r, w, err := hostPipe(4096)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close(); w.Close() })
		return r, w
	}
	readAll := func(r *os.File) <-chan string {
		c := make(chan string, 1)
		go func() {
			var b bytes.Buffer
			b.ReadFrom(r)
			c <- b.String()
		}()
		return c
	}
	// waitLine reads r until a line equal to want, and returns a channel of
	// the rest of r.
	waitLine := func(r *os.File, want string) <-chan string {
		t.Helper()
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if line == want+"\n" {
				break
			}
			if err != nil {
				t.Fatalf("no %q line before %v", want, err)
			}
		}
		c := make(chan string, 1)
		go func() {
			var b bytes.Buffer
			b.ReadFrom(br)
			c <- b.String()
		}()
		return c
	}
	t.Run("stdout-pending-read", func(t *testing.T) {
		r, w := pipe()
		got := make(chan string, 1)
		go func() {
			var all []byte
			buf := make([]byte, 64<<10)
			for {
				n, err := r.Read(buf)
				all = append(all, buf[:n]...)
				if err != nil {
					got <- string(all)
					return
				}
			}
		}()
		for pipeRoom(w) > 0 { // until the reader's read is pending
			runtime.Gosched()
		}
		var errb bytes.Buffer
		code := run(strings.NewReader(""), w, &errb, "busybox", "sh", "-c", "echo hello; busybox seq 3000")
		out := <-got
		if code != 0 || !strings.HasPrefix(out, "hello\n1\n2\n") || !strings.HasSuffix(out, "\n2999\n3000\n") {
			t.Fatalf("exit %d, %d bytes of output, stderr %q", code, len(out), errb.String())
		}
	})
	t.Run("stdout-write-intr", func(t *testing.T) {
		r, w := pipe()
		var errb bytes.Buffer
		code := run(strings.NewReader(""), w, &errb, "m3io", "stdout-write-intr")
		out := <-readAll(r)
		if code != 0 || errb.String() != "stdout-write-intr ok\n" || len(out) != 4096 {
			t.Fatalf("exit %d stderr %q, %d bytes written", code, errb.String(), len(out))
		}
	})
	t.Run("stdout-nonblock", func(t *testing.T) {
		r, w := pipe()
		er, ew := pipe()
		codec := make(chan int, 1)
		go func() { codec <- run(strings.NewReader(""), w, ew, "m3io", "stdout-nonblock") }()
		rest := waitLine(er, "drain")
		out := <-readAll(r)
		code, errs := <-codec, <-rest
		if code != 0 || errs != "stdout-nonblock ok\n" || len(out) != 8192 {
			t.Fatalf("exit %d stderr %q, %d bytes written", code, errs, len(out))
		}
	})
	t.Run("stdin-read-intr", func(t *testing.T) {
		r, _ := pipe()
		var out, errb bytes.Buffer
		code := run(r, &out, &errb, "m3io", "stdin-read-intr")
		if code != 0 || out.String() != "stdin-read-intr ok\n" {
			t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
		}
	})
	t.Run("stdin-poll", func(t *testing.T) {
		r, w := pipe()
		er, ew := pipe()
		var out bytes.Buffer
		codec := make(chan int, 1)
		go func() { codec <- run(r, &out, ew, "m3io", "stdin-poll") }()
		rest := waitLine(er, "polling")
		w.Write([]byte("x"))
		w.Close()
		code := <-codec
		<-rest
		if code != 0 || out.String() != "stdin-poll ok\n" {
			t.Fatalf("exit %d stdout %q", code, out.String())
		}
	})
}

// pipeRoom is the write quota the pipe end w reports.
func pipeRoom(w *os.File) int {
	var info pipeLocalInfo
	var iosb windows.IO_STATUS_BLOCK
	if windows.NtQueryInformationFile(windows.Handle(w.Fd()), &iosb, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), filePipeLocalInformation) != nil {
		return -1
	}
	return int(info.writeQuotaAvailable)
}

// TestWindowsGoRuntime runs a static Go linux/amd64 binary with goroutines
// across threads; the Go scheduler's SIGURG preemption stresses delivery to a
// running thread.
func TestWindowsGoRuntime(t *testing.T) {
	root := winSkipNoProg(t, "gothreads")
	code, out, errs := winRunExe(t, root, "gothreads")
	if code != 0 || !strings.Contains(out, "go ok true") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

// alpineRoot unpacks LC_WIN_ALPINE_TAR (an alpine:3.20 filesystem tar with
// the M5 test programs added; windows/m5/run.sh builds it) with the Windows
// image extractor, once per test binary.
var alpineRoot = sync.OnceValues(func() (string, error) { return unpackTar("LC_WIN_ALPINE_TAR") })

// unpackTar unpacks the filesystem tar the environment variable names into
// a fresh rootfs, or returns "" when it is unset.
func unpackTar(env string) (string, error) {
	tarPath := os.Getenv(env)
	if tarPath == "" {
		return "", nil
	}
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	dir, err := os.MkdirTemp("", "lc-rootfs-")
	if err != nil {
		return "", err
	}
	root := filepath.Join(dir, "rootfs")
	if err := os.Mkdir(root, 0o755); err != nil {
		return "", err
	}
	return root, oci.Unpack(f, root, 1<<30)
}

func winAlpine(t *testing.T) string {
	root, err := alpineRoot()
	if err != nil {
		t.Fatal(err)
	}
	if root == "" {
		t.Skip("LC_WIN_ALPINE_TAR not set")
	}
	return root
}

func winRunIn(t *testing.T, root, prog string, args ...string) (int, string, string) {
	t.Helper()
	return winRunCfg(t, root, nil, prog, args...)
}

// winRunCfg is winRunIn with the Config adjusted by mod (networking, egress).
func winRunCfg(t *testing.T, root string, mod func(*Config), prog string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	cfg := Config{
		RootFS: HostRoot(root),
		Args:   args,
		Env:    []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"},
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
	}
	if mod != nil {
		mod(&cfg)
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

// TestWindowsAlpine is M5's exit criterion over a real Alpine rootfs: dynamic
// programs start in ld-musl, which maps their libraries; each executable
// mapping is rewritten as it is mapped.
func TestWindowsAlpine(t *testing.T) {
	root := winAlpine(t)
	cases := []struct {
		prog string
		args []string
		code int
		want []string
	}{
		{"/sbin/apk", []string{"apk", "--version"}, 0, []string{"apk-tools 2.14", "compiled for " + guestArch}},
		{"/bin/busybox", []string{"sh", "-c", "echo hi; x=$((6*7)); echo $x; exit 3"}, 3, []string{"hi\n42\n"}},
		{"/bin/sh", []string{"sh", "-c", "read v; echo got:$v"}, 0, []string{"got:\n"}},
		{"/bin/busybox", []string{"ls", "-l", "/"}, 0, []string{"drwxr-xr-x", " root ", " etc\n", " usr\n", "drwxrwxrwt"}},
		{"/bin/ls", []string{"ls", "-l", "/bin/sh"}, 0, []string{"lrwxrwxrwx", "/bin/sh -> /bin/busybox"}},
		{"/bin/busybox", []string{"cat", "/etc/os-release"}, 0, []string{"Alpine Linux v3.20"}},
		{"/bin/m5dyn", []string{"m5dyn"}, 0, []string{"v=9 len=5", "m5dyn OK"}},
		{"/bin/m5dlopen", []string{"m5dlopen"}, 0, []string{"zlib 1.", "m5dlopen OK"}},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			code, out, errs := winRunIn(t, root, c.prog, c.args...)
			ok := code == c.code
			for _, w := range c.want {
				ok = ok && strings.Contains(out, w)
			}
			if !ok {
				t.Fatalf("exit %d stdout %q stderr %q; want %d and %q", code, out, errs, c.code, c.want)
			}
		})
	}
}

// TestWindowsImageLookPath finds programs the way -image does, through the
// extracted rootfs's stored modes and symlinks.
func TestWindowsImageLookPath(t *testing.T) {
	root := winAlpine(t)
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	for name, want := range map[string]string{"apk": "/sbin/apk", "sh": "/bin/sh", "cat": "/bin/cat", "m5dyn": "/bin/m5dyn"} {
		if p, err := oci.LookPath(root, name, env); err != nil || p != want {
			t.Errorf("LookPath(%s) = %q, %v; want %q", name, p, err, want)
		}
	}
	if p, err := oci.LookPath(root, "os-release", []string{"PATH=/etc"}); err == nil {
		t.Errorf("LookPath(os-release) = %q, want not executable", p)
	}
}

// TestWindowsShell is M4's exit criterion for the shell: busybox sh scripts
// with subshells, command substitution, background jobs, exit statuses and
// traps, and pipelines through xargs, over Alpine's dynamic busybox.
func TestWindowsShell(t *testing.T) {
	root := winAlpine(t)
	cases := []struct {
		name, script string
		code         int
		want         string
	}{
		{"subshell", "(exit 3); echo $?; (cd /etc && pwd); pwd", 0, "3\n/etc\n/\n"},
		{"substitution", "echo $(echo a $(echo b)) $(( $(echo 6) * 7 ))", 0, "a b 42\n"},
		{"background", "sleep 0.2 & p=$!; (exit 5) & q=$!; wait $q; echo q=$?; wait $p; echo p=$?", 0, "q=5\np=0\n"},
		{"status", "false; echo $?; ! true; echo $?; sh -c 'exit 9'; echo $?", 0, "1\n1\n9\n"},
		{"trap-term", "trap 'echo term; exit 4' TERM; kill -TERM $$; sleep 1; echo missed", 4, "term\n"},
		{"trap-chld", "trap 'echo chld' CHLD; sleep 0.1 & wait; echo end", 0, "chld\nend\n"},
		{"kill-bg", "sleep 5 & p=$!; kill $p; wait $p; echo $?", 0, "143\n"},
		{"pipe-grep", "ls / | grep b | wc -l", 0, "3\n"},
		{"xargs", "seq 1 1000 | xargs -n 10 echo | wc -l", 0, "100\n"},
		{"find-cat", "a=$(find /etc -type f | xargs cat | wc -c); b=$(cat $(find /etc -type f) | wc -c); [ $a -gt 1000 ] && [ $a = $b ] && echo same", 0, "same\n"},
		{"sigpipe", "yes | head -n 1000 | wc -l; yes | head -n 1", 0, "1000\ny\n"},
		{"sigpipe-status", "sh -c 'yes | (head -n 1 >/dev/null; sleep 0.2); echo done'", 0, "done\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := winRunIn(t, root, "/bin/sh", "sh", "-c", c.script)
			if code != c.code || out != c.want {
				t.Fatalf("exit %d stdout %q stderr %q; want %d and %q", code, out, errs, c.code, c.want)
			}
		})
	}
}

// TestWindowsProcesses runs m4proc: fork, execve of a dynamic program,
// posix_spawn, system, vfork, waitpid with WNOHANG and the status macros,
// kill of a process group, fork from a multithreaded parent (only the caller
// survives), MAP_SHARED memory and a futex shared across fork; then fork+exec
// timing.
func TestWindowsProcesses(t *testing.T) {
	root := winAlpine(t)
	for _, c := range []string{"fork", "exec", "spawn", "pgrp", "mt", "shm", "killread", "killwrite", "abortpipe", "abortsleep", "jit", "bench"} {
		t.Run(c, func(t *testing.T) {
			code, out, errs := winRunIn(t, root, "/bin/m4proc", "m4proc", c)
			if code != 0 || !strings.Contains(out, c+" OK") {
				t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
			}
			if c == "bench" || c == "jit" {
				t.Log(strings.TrimSpace(out))
			}
		})
	}
}

// TestWindowsNet is M6's exit criterion: sockets served by the supervisor.
// m6net (windows/m6) runs a local TCP server and client (nonblocking
// connect, poll, epoll edge- and level-triggered, shutdown, a bulk transfer),
// signals interrupting each kind of network wait, AF_UNIX stream sockets with
// SCM_RIGHTS, socketpairs across fork, UDP and eventfd; busybox nc and httpd
// serve a request; DNS resolves through the supervisor's proxy; busybox wget
// and curl fetch an HTTP page; and the egress allowlist refuses what darwin
// refuses.
func TestWindowsNet(t *testing.T) {
	root := winAlpine(t)
	netOn := func(c *Config) { c.Net = true }
	allow := func(c *Config) { c.Net, c.AllowDomains = true, []string{"example.com"} }
	type tc struct {
		name string
		mod  func(*Config)
		prog string
		args []string
		code int // -1: any non-zero
		want []string
	}
	page := os.Getenv("LC_NET_URL")
	if page == "" {
		page = "http://example.com/"
	}
	cases := []tc{
		{"tcp", netOn, "/bin/m6net", []string{"m6net", "tcp"}, 0, []string{"tcp OK"}},
		{"eintr", netOn, "/bin/m6net", []string{"m6net", "eintr"}, 0, []string{"eintr OK"}},
		{"unix", nil, "/bin/m6net", []string{"m6net", "unix"}, 0, []string{"unix OK"}},
		{"pair", nil, "/bin/m6net", []string{"m6net", "pair"}, 0, []string{"pair OK"}},
		{"udp", netOn, "/bin/m6net", []string{"m6net", "udp"}, 0, []string{"udp OK"}},
		{"eventfd", nil, "/bin/m6net", []string{"m6net", "eventfd"}, 0, []string{"eventfd OK"}},
		{"ifaddrs", nil, "/bin/m6net", []string{"m6net", "ifaddrs"}, 0, []string{"ifaddrs OK"}},
		{"ifaddrs-net", netOn, "/bin/m6net", []string{"m6net", "ifaddrs", "net"}, 0, []string{"ifaddrs OK"}},
		{"ip", nil, "/bin/busybox", []string{"ip", "addr"}, 0, []string{"lo", "127.0.0.1"}},
		{"nonet", nil, "/bin/sh", []string{"sh", "-c", "wget -q -O - http://127.0.0.1:1/ 2>&1; echo rc=$?"}, 0, []string{"rc=1"}},
		{"nc", netOn, "/bin/sh", []string{"sh", "-c", "nc -l -p 9000 > /tmp/nc.out & sleep 1; echo hi-nc | nc 127.0.0.1 9000; wait; cat /tmp/nc.out"}, 0, []string{"hi-nc"}},
		{"httpd", netOn, "/bin/sh", []string{"sh", "-c", "mkdir -p /www && echo served > /www/index.html && busybox-extras httpd -p 127.0.0.1:8080 -h /www && wget -q -O - http://127.0.0.1:8080/index.html"}, 0, []string{"served"}},
		{"dns", netOn, "/bin/m6net", []string{"m6net", "dns", "example.com"}, 0, []string{"example.com -> ", "dns OK"}},
		{"nslookup", netOn, "/bin/busybox", []string{"nslookup", "example.com"}, 0, []string{"Name:", "example.com", "Address"}},
		{"wget", netOn, "/bin/busybox", []string{"wget", "-q", "-O", "-", page}, 0, []string{"Example Domain"}},
		{"curl", netOn, "/usr/bin/curl", []string{"curl", "-sS", page}, 0, []string{"Example Domain"}},
		{"allowed", allow, "/bin/busybox", []string{"wget", "-q", "-O", "-", page}, 0, []string{"Example Domain"}},
		{"denied-dns", allow, "/bin/m6net", []string{"m6net", "dns", "example.org", "denied"}, 0, []string{"dns OK"}},
		{"denied-wget", allow, "/bin/busybox", []string{"wget", "-q", "-O", "-", "http://example.org/"}, -1, nil},
		{"denied-ip", allow, "/usr/bin/curl", []string{"curl", "-sS", "--max-time", "10", "http://1.1.1.1/"}, 7, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.prog == "/usr/bin/curl" {
				if _, err := os.Stat(filepath.Join(root, "usr", "bin", "curl")); err != nil {
					t.Skip("no curl in the image")
				}
			}
			code, out, errs := winRunCfg(t, root, c.mod, c.prog, c.args...)
			ok := code == c.code || c.code == -1 && code != 0
			for _, w := range c.want {
				ok = ok && strings.Contains(out, w)
			}
			if !ok {
				t.Fatalf("exit %d stdout %q stderr %q; want %d and %q", code, out, errs, c.code, c.want)
			}
			if c.name == "dns" || strings.HasPrefix(c.name, "denied") {
				t.Logf("exit %d: %s%s", code, strings.TrimSpace(out), strings.TrimSpace(errs))
			}
		})
	}
}
