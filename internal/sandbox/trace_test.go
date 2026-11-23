package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestTrace checks Config.Trace gets a line per call the supervisor serves,
// with paths, written and read data, errnos and the exit decoded
// (testdata/tracecalls.c).
func TestTrace(t *testing.T) {
	root, prog := guestRoot(t, "tracecalls")
	var trace, out bytes.Buffer
	code, err := Run(context.Background(), prog, Config{
		RootFS: HostRoot(root),
		Args:   []string{"tracecalls"},
		Env:    []string{},
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &out,
		Trace:  &trace,
	})
	if err != nil || code != 7 {
		t.Fatalf("exit %d, %v: %s", code, err, out.String())
	}
	for _, want := range []string{
		`openat(AT_FDCWD, "/no/such/file", `,
		`) = -1 ENOENT (no such file or directory)`,
		`openat(AT_FDCWD, "/tmp/traced", 0x`,
		`, 0644) = 3`,
		`write(3, "trace-data", 10) = 10`,
		`read(3, 0x`,
		`, 16) = 10 "trace-data"`,
		`close(3) = 0`,
		`exit_group(7) ...`,
	} {
		if !strings.Contains(trace.String(), want) {
			t.Errorf("trace lacks %q:\n%s", want, trace.String())
		}
	}
	if strings.Contains(trace.String(), "syscall_") {
		t.Errorf("trace names a call by number:\n%s", trace.String())
	}
}
