package sandbox

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// The suite keeps its plans where cmd/laboon does, so a rerun starts warm.
func init() {
	if d, err := os.UserCacheDir(); err == nil {
		c := rewrite.NewCache(filepath.Join(d, "laboon", "plans"))
		defaultCache = func() *rewrite.Cache { return c }
	}
}

// TestJitFlipNoPlanFiles: a JIT flipping one page between writable and
// executable, with new code each time, leaves no plan files behind: only the
// guest's own image is kept on disk (testdata/jitflip.c).
func TestJitFlipNoPlanFiles(t *testing.T) {
	const flips = 300
	root, prog := guestRoot(t, "jitflip")
	dir := t.TempDir()
	cache := rewrite.NewCache(dir)
	var o bytes.Buffer
	for _, rejectRWX := range []bool{false, true} {
		code, err := Run(context.Background(), prog, Config{
			Args: []string{"jitflip", strconv.Itoa(flips)}, Stdout: &o, Stderr: &o,
			RootFS: HostRoot(root), Cache: cache, RejectRWX: rejectRWX,
		})
		if err != nil || code != 0 || !strings.Contains(o.String(), "jitflip fails=0") {
			t.Fatalf("rejectRWX=%v: code = %d, err = %v, out:\n%s", rejectRWX, code, err, o.String())
		}
	}
	cache.Sync()
	var files []string
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if len(files) > 8 {
		t.Fatalf("%d flips left %d plan files", flips, len(files))
	}
}
