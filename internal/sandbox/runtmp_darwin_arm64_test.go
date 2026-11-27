package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunTmpIsolated runs two guests in one supervisor and has the second
// open the first one's channel and path files with raw Darwin syscalls
// (testdata/sbescape_arm64.c): each run's stubs may read only their own temp
// directory.
func TestRunTmpIsolated(t *testing.T) {
	root := busyboxRoot(t)
	probe := addGuest(t, root, "sbescape_arm64")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, "/bin/busybox", Config{RootFS: HostRoot(root), Args: []string{"sleep", "30"}})
	}()
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(tmp, runTmpPrefix())
	var chanPath string
	for i := 0; i < 100 && chanPath == ""; i++ {
		time.Sleep(50 * time.Millisecond)
		out, err := exec.Command("ps", "-axo", "command=").Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) > 1 && f[0] == "lc-stub" && strings.HasPrefix(f[1], prefix) {
				chanPath = f[1]
			}
		}
	}
	if chanPath == "" {
		t.Fatal("first run's stub not found")
	}
	for _, target := range []string{chanPath, chanPath + ".paths"} {
		f, err := os.CreateTemp(t.TempDir(), "out")
		if err != nil {
			t.Fatal(err)
		}
		code, err := Run(context.Background(), probe, Config{
			RootFS: HostRoot(root), Args: []string{"sbescape", target}, Stdout: f, Stderr: f,
		})
		f.Close()
		out, _ := os.ReadFile(f.Name())
		if err != nil || code != 0 || !strings.Contains(string(out), "read-host-file: denied") {
			t.Errorf("reading %s from another run: code %d err %v\n%s", target, code, err, out)
		}
	}
	cancel()
	<-done
}

// TestSeatbeltContains: guest code issuing raw Darwin syscalls, which the
// rewriter leaves alone, meets the stub's Seatbelt profile and is denied
// everything a stub does not do (testdata/sbescape_arm64.c).
func TestSeatbeltContains(t *testing.T) {
	root, probe := guestRoot(t, "sbescape_arm64")
	var o bytes.Buffer
	code, err := Run(context.Background(), probe, Config{RootFS: HostRoot(root), Args: []string{"sbescape"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.HasSuffix(o.String(), "PASS\n") {
		t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
	}
}
