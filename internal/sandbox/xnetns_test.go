package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// Two containers in separate network namespaces reach each other over the
// shared virtual network (cross-netns vnet routing).
func TestXNetns(t *testing.T) {
	root, exe := guestRoot(t, "xnetns")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Net: true, Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "XNETNS-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
