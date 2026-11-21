package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestTmpfsGaps: a guest-mounted tmpfs serves every fd operation a real tmpfs
// does (testdata/tmpfsgaps.c).
func TestTmpfsGaps(t *testing.T) {
	root, exe := guestRoot(t, "tmpfsgaps")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot(root), Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "TMPFSGAPS-DONE") || strings.Contains(out.String(), "FAIL") {
		t.Fatalf("code=%d err=%v:\n%s", code, err, out.String())
	}
}
