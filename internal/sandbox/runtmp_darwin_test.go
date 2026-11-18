//go:build darwin

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRunTmpIsolated runs two guests in one supervisor and has the second
// open the first one's channel and path files with raw Darwin syscalls
// (sbescape.elf): each run's stubs may read only their own temp directory.
// LC_TEST_ROOT names a rootfs with /bin/busybox and /sbescape.elf.
func TestRunTmpIsolated(t *testing.T) {
	root := os.Getenv("LC_TEST_ROOT")
	if root == "" {
		t.Skip("LC_TEST_ROOT unset")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, "/bin/busybox", Config{RootFS: HostRoot(root), Args: []string{"sleep", "30"}})
	}()
	var chanPath string
	for i := 0; i < 100 && chanPath == ""; i++ {
		time.Sleep(50 * time.Millisecond)
		out, err := exec.Command("ps", "-axo", "command=").Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) > 1 && f[0] == "lc-stub" && strings.HasPrefix(f[1], tmpDir()) {
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
		code, err := Run(context.Background(), "/sbescape.elf", Config{
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
