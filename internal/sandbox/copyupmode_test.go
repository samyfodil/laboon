package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// TestCopyUpModeCheckpoint guards the metadata checkpoint against the gap the old
// per-syscall mirror had: a lower file copied up by a content write (no chmod)
// keeps a mode the host file cannot hold (0400) only in the inode side table. The
// kept upper's captured layer must still report 0400, because close() projects
// that table onto the path-keyed override.
func TestCopyUpModeCheckpoint(t *testing.T) {
	prog, err := os.ReadFile(guestPath(t, "copyupmode"))
	if err != nil {
		t.Fatal(err)
	}
	lower := unpackRoot(t, tarEntry{"secret", 0o400, []byte("old")}, tarEntry{"copyupmode", 0o755, prog})
	upper := filepath.Join(t.TempDir(), "upper")
	if err := os.Mkdir(upper, 0o755); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	code, err := Run(context.Background(), "/copyupmode", Config{
		Args: []string{"/copyupmode"}, RootFS: HostRoot(lower), Upper: upper,
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 {
		t.Fatalf("copyupmode code %d err %v\n%s", code, err, out.String())
	}

	// The captured layer: 0400 preserved though no chmod ever ran, content rewritten.
	l, err := hostfs.LayerFromDir(upper)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := l.Stat("secret"); !ok || a.Mode&0o7777 != 0o400 {
		t.Fatalf("secret mode = %+v ok=%v, want 0400", a, ok)
	}
	if b, err := l.ReadFile("secret"); err != nil || string(b) != "changed" {
		t.Fatalf("secret body = %q, %v", b, err)
	}
}
