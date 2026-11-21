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

// chroot confines every later path walk to the new root, on a host-directory
// root and on an in-memory one (testdata/chrootconf.c).
func TestChrootConfined(t *testing.T) {
	bin := guestPath(t, "chrootconf")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "chrootconf"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	mem := memfs.NewMemFS()
	mirrorToMem(t, mem, root)
	for name, cfg := range map[string]Config{
		"hostroot": {RootFS: HostRoot(root)},
		"memfs":    {RootFS: mem},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			var o bytes.Buffer
			cfg.Args = []string{"/chrootconf"}
			cfg.Stdout, cfg.Stderr = &o, &o
			code, err := Run(ctx, "/chrootconf", cfg)
			t.Log(strings.TrimSpace(o.String()))
			if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
				t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
			}
		})
	}
}
