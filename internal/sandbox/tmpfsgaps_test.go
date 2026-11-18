package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestTmpfsGaps surfaces which fd operations the in-memory tmpfs serves and which
// fail — ground truth for the limitations, not a pass/fail gate.
func TestTmpfsGaps(t *testing.T) {
	exe := buildProbe(t, "tmpfsgaps")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, RootFS: HostRoot("/"), Stdout: &out, Stderr: &out})
	t.Logf("tmpfsgaps (code=%d err=%v):\n%s", code, err, out.String())
	if !strings.Contains(out.String(), "TMPFSGAPS-DONE") {
		t.Fatalf("probe did not finish")
	}
}
