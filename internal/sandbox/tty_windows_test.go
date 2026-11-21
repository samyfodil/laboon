//go:build windows

package sandbox

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestWindowsConsole runs an interactive busybox sh on a Windows console:
// the test makes a pseudo console (ConPTY), starts itself on it as the child
// below, and types at it. The child's stdio are the console's handles, so
// Run puts the console in raw VT mode and serves it as /dev/pts/0: the
// prompt, a command, ^C interrupting sleep, ^Z stopping it and fg, SIGWINCH to the foreground
// program and the new `stty size` after ResizePseudoConsole, the exit status
// and the console's modes restored.
func TestWindowsConsole(t *testing.T) {
	if os.Getenv("LC_CONSOLE_CHILD") != "" {
		consoleChild(t)
		return
	}
	root := alpineRoot(t)
	var inR, inW, outR, outW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := windows.CreatePipe(&outR, &outW, nil, 0); err != nil {
		t.Fatal(err)
	}
	var hpc windows.Handle
	if err := windows.CreatePseudoConsole(windows.Coord{X: 80, Y: 25}, inR, outW, 0, &hpc); err != nil {
		t.Fatalf("CreatePseudoConsole: %v", err)
	}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		t.Fatal(err)
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, *(*unsafe.Pointer)(unsafe.Pointer(&hpc)), unsafe.Sizeof(hpc)); err != nil {
		t.Fatal(err)
	}
	si := &windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(*si))
	// Null std handles: the child gets the pseudo console's rather than
	// inheriting this process's redirected ones.
	si.Flags = windows.STARTF_USESTDHANDLES
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := windows.EscapeArg(exe) + " -test.run=^TestWindowsConsole$ -test.v"
	env := append(os.Environ(), "LC_CONSOLE_CHILD=1", "LC_CONSOLE_ROOT="+root)
	block, err := envBlock(env)
	if err != nil {
		t.Fatal(err)
	}
	var pi windows.ProcessInformation
	err = windows.CreateProcess(nil, windows.StringToUTF16Ptr(cmd), nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, &block[0], nil, &si.StartupInfo, &pi)
	windows.CloseHandle(inR)
	windows.CloseHandle(outW)
	if err != nil {
		windows.ClosePseudoConsole(hpc)
		t.Fatalf("CreateProcess: %v", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	var mu sync.Mutex
	var screen []byte
	go func() {
		buf := make([]byte, 4096)
		for {
			var n uint32
			if windows.ReadFile(outR, buf, &n, nil) != nil || n == 0 {
				return
			}
			mu.Lock()
			screen = append(screen, buf[:n]...)
			mu.Unlock()
		}
	}()
	mark := 0
	expect := func(want string, d time.Duration) {
		t.Helper()
		end := time.Now().Add(d)
		for {
			mu.Lock()
			i := strings.Index(string(screen[mark:]), want)
			if i >= 0 {
				mark += i + len(want)
			}
			s := string(screen[mark:])
			mu.Unlock()
			if i >= 0 {
				return
			}
			if time.Now().After(end) {
				windows.TerminateProcess(pi.Process, 1)
				windows.ClosePseudoConsole(hpc)
				t.Fatalf("expected %q; console output since the last match:\n%q", want, s)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	typ := func(s string) {
		var n uint32
		if err := windows.WriteFile(inW, []byte(s), &n, nil); err != nil {
			t.Fatal(err)
		}
	}

	expect("C1> ", 60*time.Second)
	typ("stty size; tty; echo $((6*7))z\r")
	expect("25 80", 20*time.Second)
	expect("/dev/pts/0", 10*time.Second)
	expect("42z", 10*time.Second)
	expect("C1> ", 10*time.Second)
	typ("sleep 20\r")
	time.Sleep(1500 * time.Millisecond)
	typ("\x03")
	expect("C1> ", 10*time.Second)
	typ("echo rc=$?\r")
	expect("rc=130", 10*time.Second)
	expect("C1> ", 10*time.Second)
	typ("sleep 20\r")
	time.Sleep(1500 * time.Millisecond)
	typ("\x1a")
	expect("Stopped", 10*time.Second)
	expect("C1> ", 10*time.Second)
	typ("fg\r")
	expect("sleep 20", 10*time.Second)
	time.Sleep(500 * time.Millisecond)
	typ("\x03")
	expect("C1> ", 10*time.Second)
	typ("/bin/m7tty winch\r")
	expect("waiting-winch", 20*time.Second)
	if err := windows.ResizePseudoConsole(hpc, windows.Coord{X: 100, Y: 30}); err != nil {
		t.Fatal(err)
	}
	expect("got-winch 30 100", 20*time.Second)
	expect("C1> ", 20*time.Second)
	typ("stty size\r")
	expect("30 100", 20*time.Second)
	expect("C1> ", 20*time.Second)
	typ("exit 3\r")
	expect("console child: exit 3", 30*time.Second)
	ev, err := windows.WaitForSingleObject(pi.Process, 30000)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		windows.TerminateProcess(pi.Process, 1)
		t.Fatalf("child did not exit (%v)", err)
	}
	var code uint32
	windows.GetExitCodeProcess(pi.Process, &code)
	windows.ClosePseudoConsole(hpc)
	windows.CloseHandle(inW)
	if code != 0 {
		mu.Lock()
		t.Fatalf("child test failed (%d):\n%q", code, screen)
	}
}

// consoleChild is TestWindowsConsole's process on the pseudo console: an
// interactive sh with the console as its stdio.
func consoleChild(t *testing.T) {
	cfg := Config{
		RootFS: HostRoot(os.Getenv("LC_CONSOLE_ROOT")),
		Args:   []string{"sh", "-i"},
		Env:    []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=xterm", "PS1=C1> "},
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	code, err := Run(context.Background(), "/bin/sh", cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var m uint32
	if windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &m) != nil || m&windows.ENABLE_LINE_INPUT == 0 {
		t.Errorf("console mode not restored: %#x", m)
	}
	os.Stdout.WriteString("console child: exit " + strconv.Itoa(code) + "\r\n")
	if code != 3 {
		t.Fatalf("exit %d", code)
	}
}

// envBlock is env as a CreateProcess environment block.
func envBlock(env []string) ([]uint16, error) {
	var b []uint16
	for _, kv := range env {
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, err
		}
		b = append(b, u...)
	}
	return append(b, 0), nil
}
