package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/filesystems/memfs"
)

// Lengths a guest chooses (an execve's argv, an executable mapping, a virtual
// network datagram) are bounded before the supervisor allocates for them: each
// fails in the guest, and the supervisor's peak memory stays far below what
// the lengths asked for.
func TestGuestLengths(t *testing.T) {
	root, exe := guestRoot(t, "guestlen")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	before := peakRSS()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{
		Args:   []string{exe},
		RootFS: HostRoot(root),
		Mounts: []Mount{{Guest: "/m", FS: memfs.NewMemFS()}},
		Net:    true,
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), "GUESTLEN-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
	// The argv alone asks for 16384 copies of a 128 KiB string.
	if grew := peakRSS() - before; before > 0 && grew > 512<<20 {
		t.Errorf("supervisor peak memory grew %d MiB", grew>>20)
	}
}
