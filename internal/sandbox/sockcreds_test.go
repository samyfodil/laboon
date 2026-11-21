package sandbox

import (
	"bytes"
	"context"
	"testing"
)

// TestSockCreds runs testdata/sockcreds.c: the AF_UNIX credential-passing path
// (SO_PASSCRED / SCM_CREDENTIALS / SO_PEERCRED) that Chromium's zygote uses to
// learn a forked child's real pid.
func TestSockCreds(t *testing.T) {
	root, bin := guestRoot(t, "sockcreds")
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"sockcreds"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot(root),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d (testdata/sockcreds.c line) err %v\n%s", code, err, out.String())
	}
}
