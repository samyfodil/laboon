//go:build darwin || linux

package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestManyThreads(t *testing.T) {
	root, out := guestRoot(t, "manythreads")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, out, Config{RootFS: HostRoot(root), Args: []string{"manythreads"}, Stdout: &o, Stderr: &o})
	if err != nil || code != 0 || !strings.Contains(o.String(), "manythreads ok") {
		t.Fatalf("code=%d err=%v out=%q", code, err, o.String())
	}
}
