package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestShm checks SysV shared memory end to end: shmget, shmat (a real mapping),
// write and read back, shmdt, re-attach and confirm the data persisted, then
// IPC_RMID. Each host maps the segment its own way -- the Linux and macOS stubs
// map a stub fd, the Windows stub a duplicated section.
func TestShm(t *testing.T) {
	root, exe := guestRoot(t, "shmtest")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "SHM-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
