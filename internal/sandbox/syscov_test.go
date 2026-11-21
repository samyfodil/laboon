package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestSyscallCoverage runs the syscall coverage probe (testdata/syscov.c) under
// laboon and fails if any audited syscall returns ENOSYS (errno 38). The probe
// reports the errno of each call; a served call (EINVAL/EFAULT/EPERM/ESRCH) is
// fine, only "not implemented" is a gap. This guards parity: a syscall served
// on one host OS must not silently become ENOSYS on another. The macOS and
// Windows gates run the same probe against their hosts.
func TestSyscallCoverage(t *testing.T) {
	root, exe := guestRoot(t, "syscov")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 {
		t.Fatalf("probe exited code=%d err=%v\n%s", code, err, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "SYSCOV-DONE") {
		t.Fatalf("probe did not finish:\n%s", s)
	}
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == "38" {
			t.Errorf("%s is ENOSYS -- coverage gap (served on other hosts)", f[0])
		}
	}
}
