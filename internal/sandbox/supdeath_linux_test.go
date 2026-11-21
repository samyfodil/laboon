package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestStubsDieWithSupervisor kills a supervisor outright: its forked child
// stubs, which no parent-death signal covers, must still exit.
func TestStubsDieWithSupervisor(t *testing.T) {
	if prog := os.Getenv("LC_FORKBLOCK"); prog != "" {
		Run(context.Background(), prog, Config{Args: []string{"fb"}, Stdout: os.Stdout, Stderr: os.Stderr})
		return
	}
	out := guestPath(t, "forkblock")
	sup := exec.Command(os.Args[0], "-test.run=^TestStubsDieWithSupervisor$")
	sup.Env = append(os.Environ(), "LC_FORKBLOCK="+out)
	stdout, err := sup.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	stubs := descendants(sup.Process.Pid)
	if len(stubs) < 2 {
		t.Fatalf("want a stub and its forked child, got %v", stubs)
	}
	sup.Process.Kill()
	sup.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for _, pid := range stubs {
		for unix.Kill(pid, 0) == nil {
			if time.Now().After(deadline) {
				unix.Kill(pid, unix.SIGKILL)
				t.Fatalf("stub %d outlived its supervisor", pid)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// TestComputingStubsDieWithSupervisor: stubs that never wait on their
// channel (a forked guest computing) die within a second of their
// supervisor, by the lifeline's SIGIO to their process group.
func TestComputingStubsDieWithSupervisor(t *testing.T) {
	if prog := os.Getenv("LC_FORKSPIN"); prog != "" {
		Run(context.Background(), prog, Config{Args: []string{"fs"}, Stdout: os.Stdout, Stderr: os.Stderr})
		return
	}
	out := guestPath(t, "forkspin")
	sup := exec.Command(os.Args[0], "-test.run=^TestComputingStubsDieWithSupervisor$")
	sup.Env = append(os.Environ(), "LC_FORKSPIN="+out)
	stdout, err := sup.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	stubs := descendants(sup.Process.Pid)
	if len(stubs) < 2 {
		t.Fatalf("want a stub and its forked child, got %v", stubs)
	}
	sup.Process.Kill()
	sup.Wait()
	deadline := time.Now().Add(time.Second)
	for _, pid := range stubs {
		for unix.Kill(pid, 0) == nil {
			if time.Now().After(deadline) {
				unix.Kill(-stubs[0], unix.SIGKILL)
				t.Fatalf("stub %d outlived its supervisor by a second", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// descendants lists the processes below pid.
func descendants(pid int) []int {
	parent := map[int]int{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+2:]))
		parent[p], _ = strconv.Atoi(f[1])
	}
	var out []int
	for p := range parent {
		for q := parent[p]; q > 1; q = parent[q] {
			if q == pid {
				out = append(out, p)
				break
			}
		}
	}
	return out
}
