//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPtrace(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "ptrace")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", exe, "../../testdata/ptrace.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		out := &ptraceCancelWriter{cancel: cancel}
		Run(ctx, exe, Config{Args: []string{exe, "cancel"}, RootFS: HostRoot("/"), Stdout: out, Stderr: out})
		if !strings.Contains(out.String(), "ready\n") {
			t.Fatalf("tracee never stopped: %s", out.String())
		}
	})
	for _, mode := range []string{"registers", "memaccess", "breakpoint", "procmem", "namespace", "syscall", "events", "signals", "detach", "kill", "killexit", "tracerexit", "exitkill"} {
		for _, traps := range []bool{false, true} {
			name := mode
			if traps {
				name += "/traps"
			}
			t.Run(name, func(t *testing.T) {
				fastTramp = !traps
				defer func() { fastTramp = false }()
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				var out bytes.Buffer
				code, err := Run(ctx, exe, Config{Args: []string{exe, mode}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
				if err != nil || code != 0 || !strings.HasSuffix(out.String(), "OK\n") {
					t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
				}
			})
		}
	}
}

func TestPtraceStrace(t *testing.T) {
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace unavailable")
	}
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
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace unavailable")
	}
	exe := filepath.Join(t.TempDir(), "execspawn")
	if b, err := exec.Command("gcc", "-O2", "-static", "-pthread", "-o", exe, "../../testdata/execspawn.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out, trace bytes.Buffer
	code, err := Run(ctx, strace, Config{Args: []string{strace, "-f", "-e", "trace=process", exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &trace})
	if err != nil || code != 0 || !strings.HasSuffix(out.String(), "OK\n") || badPtraceTrace(trace.String()) {
		t.Fatalf("code=%d err=%v out=%q trace=%s", code, err, out.String(), trace.String())
	}
}

func badPtraceTrace(s string) bool {
	for _, text := range []string{"No such process", "No child processes", "ptrace_syscall_info.op", "Stray PTRACE", "syscall_0x"} {
		if strings.Contains(s, text) {
			return true
		}
	}
	return false
}

type ptraceCancelWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	cancel context.CancelFunc
}

func (w *ptraceCancelWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(b)
	if strings.Contains(w.buf.String(), "ready\n") {
		w.cancel()
	}
	return n, err
}

func (w *ptraceCancelWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
