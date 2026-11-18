//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSockCreds runs testdata/sockcreds.c: the AF_UNIX credential-passing path
// (SO_PASSCRED / SCM_CREDENTIALS / SO_PEERCRED) that Chromium's zygote uses to
// learn a forked child's real pid.
func TestSockCreds(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sockcreds")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/sockcreds.c").CombinedOutput(); err != nil {
		t.Skipf("build: %v\n%s", err, b)
	}
	var out bytes.Buffer
	code, err := Run(context.Background(), bin, Config{
		Args:   []string{"sockcreds"},
		Stdout: &out, Stderr: &out, RootFS: HostRoot("/"),
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d (testdata/sockcreds.c line) err %v\n%s", code, err, out.String())
	}
}
