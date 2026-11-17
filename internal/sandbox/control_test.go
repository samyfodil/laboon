package sandbox

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Control.Signal must reach the guest's init process as a real signal it can
// handle, and Control.Pid must name the running host leader.
func TestControlSignal(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "sigwait")
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/sigwait.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ctrl := &Control{}
	type res struct {
		code int
		err  error
	}
	done := make(chan res, 1)
	go func() {
		code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: pw, Control: ctrl})
		pw.Close()
		done <- res{code, err}
	}()

	// Wait until the guest has installed its handler and announced readiness.
	buf := make([]byte, len("READY"))
	if _, err := io.ReadFull(pr, buf); err != nil || string(buf) != "READY" {
		t.Fatalf("guest readiness = %q err=%v", buf, err)
	}
	if ctrl.Pid() <= 0 {
		t.Fatalf("Pid() = %d, want the running host leader", ctrl.Pid())
	}
	if err := ctrl.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal(SIGTERM): %v", err)
	}
	rest, _ := io.ReadAll(pr) // the guest writes GOTTERM then exits, closing the pipe
	r := <-done
	if r.err != nil || r.code != 0 || !strings.Contains(string(rest), "GOTTERM") {
		t.Fatalf("code=%d err=%v out=%q (handler did not run)", r.code, r.err, rest)
	}
	// After the run, a Signal is a safe no-op, not a panic or a use of freed state.
	if err := ctrl.Signal(syscall.SIGTERM); err != syscall.ESRCH {
		t.Fatalf("Signal after exit = %v, want ESRCH", err)
	}
}
