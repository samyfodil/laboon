//go:build windows

package sandbox

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/samyfodil/laboon/oci"
)

// winBusyboxRoot is busyboxRoot with an /etc/hostname, and returns its
// contents too.
func winBusyboxRoot(t *testing.T) (string, []byte) {
	t.Helper()
	root := busyboxRoot(t)
	host := []byte("laboon-m1\n")
	if err := os.Mkdir(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "hostname"), host, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, host
}

// TestWindowsBusybox runs a static busybox over a host directory root.
func TestWindowsBusybox(t *testing.T) {
	root, host := winBusyboxRoot(t)
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

// winRun runs busybox with args over root and the kept upper layer.
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

// TestWindowsFileApplets runs busybox file applets on the writable overlay,
// names NTFS cannot hold among them. Each applet is its own run; the upper
// layer is kept between them.
func TestWindowsFileApplets(t *testing.T) {
	root, host := winBusyboxRoot(t)
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

// TestWindowsMemoryCap: WithMaxMemory holds the run's committed memory to its
// cap (the job's limit), and an allocation past it fails with ENOMEM.
func TestWindowsMemoryCap(t *testing.T) {
	root, prog := guestRoot(t, "memcap")
	for _, c := range []struct {
		max  uint64
		want func(n int) bool
	}{
		{0, func(n int) bool { return n == 256 }},
		{48 << 20, func(n int) bool { return n > 0 && n < 48 }},
	} {
		var out, errb bytes.Buffer
		cfg := Config{RootFS: HostRoot(root), Args: []string{"memcap"}, MaxBytes: c.max, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}
		code, err := Run(context.Background(), prog, cfg)
		var n int
		var why string
		fmt.Sscanf(out.String(), "memcap %d %s", &n, &why)
		if err != nil || code != 0 || !c.want(n) || (c.max > 0 && why != "ENOMEM") {
			t.Fatalf("max %d: exit %d err %v stdout %q stderr %q", c.max, code, err, out.String(), errb.String())
		}
		t.Logf("max %d MiB: %d MiB mapped (%s)", c.max>>20, n, why)
	}
}

// TestWindowsLowerMeta reads the lower layer's POSIX metadata from
// <root>.lcmeta, which the image extractor writes: modes and a symlink stored
// as a file holding its target.
func TestWindowsLowerMeta(t *testing.T) {
	bb, err := os.ReadFile(filepath.Join(busyboxRoot(t), "bin", "busybox"))
	if err != nil {
		t.Fatal(err)
	}
	var img bytes.Buffer
	tw := tar.NewWriter(&img)
	for _, h := range []*tar.Header{
		{Name: "bin/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "tmp/", Typeflag: tar.TypeDir, Mode: 0o1777},
		{Name: "bin/busybox", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(bb))},
		{Name: "bin/sh", Typeflag: tar.TypeSymlink, Linkname: "busybox", Mode: 0o777},
		{Name: "etc/hostname", Typeflag: tar.TypeReg, Mode: 0o644, Size: 10},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		switch h.Name {
		case "bin/busybox":
			tw.Write(bb)
		case "etc/hostname":
			tw.Write([]byte("laboon-m1\n"))
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := oci.Unpack(&img, root, 1<<30); err != nil {
		t.Fatal(err)
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

// TestWindowsHostPipes gives the guest host pipes of PIPE_BUF bytes as its
// stdio (testdata/m3io.c). A reader that keeps a read as large
// as the pipe pending (as PowerShell's pipeline does) leaves the pipe
// reporting no room, yet output goes through; a write blocked on a full pipe
// ends with EINTR on a signal, having written nothing; a non-blocking write is
// taken while the pipe is full, the next fails with EAGAIN, and POLLOUT
// returns once the reader reads. On stdin, a blocked read ends with EINTR on
// a signal, and a poll wakes when data comes, which FIONREAD counts, followed
// by end of file.
func TestWindowsHostPipes(t *testing.T) {
	root := busyboxRoot(t)
	copyGuest(t, filepath.Join(root, "bin", "m3io"), "m3io")
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
