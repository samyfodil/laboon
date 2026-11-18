//go:build darwin

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stubsOf lists the stub processes attached to channel file chanPath.
func stubsOf(t *testing.T, chanPath string) []string {
	out, err := exec.Command("ps", "-axo", "pid=,command=").Output()
	if err != nil {
		t.Fatal(err)
	}
	var pids []string
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) > 2 && strings.HasPrefix(f[1], "lc-stub") && f[2] == chanPath {
			pids = append(pids, f[0])
		}
	}
	return pids
}

// orphanCheck runs the calling test again as a helper supervisor whose guest
// runs args, waits until at least want stubs share its channel file, SIGKILLs
// it and fails unless they all exit. LC_TEST_ROOT names the rootfs.
func orphanCheck(t *testing.T, want int, args ...string) {
	root := os.Getenv("LC_TEST_ROOT")
	if os.Getenv("LC_ORPHAN_HELPER") != "" {
		Run(context.Background(), "/bin/busybox", Config{RootFS: HostRoot(root), Args: args})
		return
	}
	if root == "" {
		t.Skip("LC_TEST_ROOT unset")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), "LC_ORPHAN_HELPER=1", "LC_TEST_ROOT="+root)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var chanPath string
	var live []string
	for i := 0; i < 200 && len(live) < want; i++ {
		time.Sleep(100 * time.Millisecond)
		out, _ := exec.Command("ps", "-axo", "ppid=,command=").Output()
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) > 2 && f[0] == strconv.Itoa(cmd.Process.Pid) && strings.HasPrefix(f[1], "lc-stub") {
				chanPath = f[2]
			}
		}
		if chanPath != "" {
			live = stubsOf(t, chanPath)
		}
	}
	if len(live) < want {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("want %d stubs alive, got %v", want, live)
	}
	cmd.Process.Signal(syscall.SIGKILL)
	cmd.Wait()
	for i := 0; i < 50; i++ {
		if live = stubsOf(t, chanPath); len(live) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, p := range live {
		exec.Command("kill", "-9", p).Run()
	}
	t.Fatalf("stubs outlived their supervisor: %v", live)
}

// TestStubsDieWithSupervisor SIGKILLs a supervisor whose guest has forked
// children and whose stub pool is full, and expects every one of its stubs to
// exit. LC_TEST_ROOT names a rootfs with /bin/busybox.
func TestStubsDieWithSupervisor(t *testing.T) {
	orphanCheck(t, 4, "sh", "-c", "/bin/true; /bin/true; sleep 60 & sleep 60 & wait")
}

// TestSweepDead removes the temp entries of exited supervisors only.
func TestSweepDead(t *testing.T) {
	dir := t.TempDir()
	c := exec.Command("true")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	dead := strconv.Itoa(c.Process.Pid)
	self := strconv.Itoa(os.Getpid())
	for _, n := range []string{"lc-run-" + dead, "lcn." + dead + "-x1", "lcn-" + dead, "lc-run-" + self, "lc-run-1", "lc-run-x", "other-" + dead} {
		if err := os.MkdirAll(filepath.Join(dir, n, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sweepDead(dir, "lc-run-")
	sweepDead(dir, "lcn.")
	ents, _ := os.ReadDir(dir)
	var left []string
	for _, e := range ents {
		left = append(left, e.Name())
	}
	if want := []string{"lc-run-1", "lc-run-" + self, "lc-run-x", "lcn-" + dead, "other-" + dead}; strings.Join(left, ",") != strings.Join(want, ",") {
		t.Fatalf("left %v, want %v", left, want)
	}
}
