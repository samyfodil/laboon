//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/filesystems/memfs"
)

// A guest overlay mount unions layers in the guest's own tree and cannot name a
// host directory as a layer, whether the root is a host directory with an upper
// or an in-memory filesystem (testdata/ovlconf.c).
func TestOverlayMountConfined(t *testing.T) {
	bin := guestBin(t, "ovlconf")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ovlconf"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	mem := memfs.NewMemFS()
	mirrorToMem(t, mem, root)
	for name, cfg := range map[string]Config{
		"hostroot": {RootFS: HostRoot(root), Upper: t.TempDir()},
		"memfs":    {RootFS: mem},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			var o bytes.Buffer
			cfg.Args = []string{"/ovlconf"}
			cfg.Stdout, cfg.Stderr = &o, &o
			code, err := Run(ctx, "/ovlconf", cfg)
			t.Log(strings.TrimSpace(o.String()))
			if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
				t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
			}
		})
	}
}
