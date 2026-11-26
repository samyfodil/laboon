package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// A guest that makes a huge, mostly untouched range executable has the code it
// wrote rewritten, far inside the range too, while the supervisor reads only
// a bounded window of it at a time.
func TestExecWide(t *testing.T) {
	root, exe := guestRoot(t, "execwide")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	before := peakRSS()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "EXECWIDE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
	if grew := peakRSS() - before; before > 0 && grew > 512<<20 {
		t.Errorf("supervisor peak memory grew %d MiB", grew>>20)
	}
}
