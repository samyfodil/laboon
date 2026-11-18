//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSeccompEnforced runs testdata/seccomp.c: a guest-installed seccomp-bpf
// filter that fails getuid with EPERM and allows the rest must actually take
// effect in the guest — the supervisor runs the filter on every syscall.
func TestSeccompEnforced(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "seccomp")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/seccomp.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"seccomp"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot("/"),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}

// TestSeccompTrap runs testdata/seccomp_trap.c: a SECCOMP_RET_TRAP raises SIGSYS
// with a siginfo (si_code SYS_SECCOMP, si_syscall, si_arch) that a handler reads.
func TestSeccompTrap(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "seccomp_trap")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/seccomp_trap.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"seccomp_trap"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot("/"),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}

// TestSeccompSigreturn runs testdata/seccomp_sigreturn.c: a guest filter that
// TRAPs its own rt_sigreturn must take effect, so returning from a handler
// raises SIGSYS and the guest exits 42, not 1. rt_sigreturn is completed by the
// stub, so the guest's filter is honored only if every rt_sigreturn is first
// run past the supervisor; this guards that it is.
func TestSeccompSigreturn(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "seccomp_sigreturn")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/seccomp_sigreturn.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"seccomp_sigreturn"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot("/"),
	})
	if err != nil || code != 42 {
		t.Fatalf("code %d err %v (want 42: rt_sigreturn trapped -> SIGSYS -> exit 42)\n%s", code, err, out.String())
	}
}
