//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

// A guest chown's owner must survive and read back identically through stat()
// and fstat(). This guards two bugs the stat-through-the-interface work exposed:
// an overlay lower file copies up on chown (the override lands under the upper
// inode, but path-stat resolves to the lower identity), and an in-memory mount
// keeps the owner on the node (which plain nodeStat used to drop). The guest
// asserts stat==fstat==1000 for both; the backend must carry the guest owner.
func TestChownOwnerReadback(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	for _, d := range []string{lower, upper} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "f"), []byte("lower"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(lower, "ownerck")
	if b, err := exec.Command("gcc", "-O2", "-static", "-w", "-o", bin, "../../testdata/ownerck.c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}

	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "mf", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, []byte("mem")); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, "/ownerck", Config{
		Args:   []string{"/ownerck"},
		RootFS: HostRoot(lower),
		Upper:  upper,
		Mounts: []Mount{{Guest: "/data", FS: mem}},
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), "OWNER-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}
