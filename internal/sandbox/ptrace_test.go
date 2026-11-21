package sandbox

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPtrace(t *testing.T) {
	root, exe := guestRoot(t, "ptrace")
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		out := &ptraceCancelWriter{cancel: cancel}
		Run(ctx, exe, Config{Args: []string{exe, "cancel"}, RootFS: HostRoot(root), Stdout: out, Stderr: out})
		if !strings.Contains(out.String(), "ready\n") {
			t.Fatalf("tracee never stopped: %s", out.String())
		}
	})
	for _, mode := range []string{"registers", "memaccess", "breakpoint", "procmem", "namespace", "syscall", "events", "signals", "detach", "kill", "killexit", "tracerexit", "exitkill"} {
		for _, traps := range trapModes {
			name := mode
			if traps {
				name += "/traps"
			}
			t.Run(name, func(t *testing.T) {
				defer useTraps(traps)()
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				var out bytes.Buffer
				code, err := Run(ctx, exe, Config{Args: []string{exe, mode}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
				if err != nil || code != 0 || !strings.HasSuffix(out.String(), "OK\n") {
					t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
				}
			})
		}
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
