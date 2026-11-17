package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/internal/vfs"
)

func buildProbe(t *testing.T, name string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), name)
	if b, err := exec.Command("gcc", "-O2", "-static", "-o", exe, "../../testdata/"+name+".c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	return exe
}

// A memFS-backed tmpfs file supports a private mmap (its bytes read back through
// the mapping) and its directory fstats as a directory.
func TestTmpfsMmap(t *testing.T) {
	exe := buildProbe(t, "tmpfsmmap")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{Args: []string{exe}, Root: "/", Stdout: &out, Stderr: &out})
	if err != nil || code != 0 || !strings.Contains(out.String(), "TMPFSMMAP-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

// A FileSystem the host mounts (WithFS, here an in-memory one) serves the guest's
// open/write/read/stat under its mount point.
func TestWithFSMem(t *testing.T) {
	exe := buildProbe(t, "fsrw")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{
		Args:   []string{exe},
		Root:   "/",
		Mounts: []Mount{{Guest: "/data", FS: vfs.NewMemFS()}},
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), "FSRW-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
