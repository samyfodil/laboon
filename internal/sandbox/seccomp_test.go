package sandbox

import (
	"bytes"
	"context"
	"testing"
)

// TestSeccompEnforced runs testdata/seccomp.c: a guest-installed seccomp-bpf
// filter that fails getuid with EPERM and allows the rest must actually take
// effect in the guest — the supervisor runs the filter on every syscall.
func TestSeccompEnforced(t *testing.T) {
	root, bin := guestRoot(t, "seccomp")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"seccomp"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}

// TestSeccompTrap runs testdata/seccomp_trap.c: a SECCOMP_RET_TRAP raises SIGSYS
// with a siginfo (si_code SYS_SECCOMP, si_syscall, si_arch) that a handler reads.
func TestSeccompTrap(t *testing.T) {
	root, bin := guestRoot(t, "seccomp_trap")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"seccomp_trap"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root),
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
	root, bin := guestRoot(t, "seccomp_sigreturn")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"seccomp_sigreturn"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root),
	})
	if err != nil || code != 42 {
		t.Fatalf("code %d err %v (want 42: rt_sigreturn trapped -> SIGSYS -> exit 42)\n%s", code, err, out.String())
	}
}

// TestSeccompKill runs testdata/seccomp_kill.c: SECCOMP_RET_KILL_PROCESS must
// end the process with SIGSYS though the guest installed a SIGSYS handler and
// blocked SIGSYS.
func TestSeccompKill(t *testing.T) {
	root, bin := guestRoot(t, "seccomp_kill")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"seccomp_kill"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root),
	})
	if err != nil || code != 0 || !bytes.Contains(out.Bytes(), []byte("SECKILL-OK")) {
		t.Fatalf("code %d err %v\n%s", code, err, out.String())
	}
}
