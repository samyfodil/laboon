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

// TestFileOffset runs testdata/fileoffset.c over a host root, an in-memory
// mount and an overlay whose lower holds /lowerfile: offsets of separate and
// shared descriptions, O_APPEND from two processes, files unlinked or replaced
// while open (which Windows allows only with POSIX share and delete semantics),
// vectored I/O, fdinfo, SEEK_CUR locks and stdio redirection, built against
// glibc and musl.
func TestFileOffset(t *testing.T) {
	bins := map[string]string{"glibc": guestPath(t, "fileoffset"), "musl": guestPath(t, "fileoffset+musl")}
	for name, bin := range bins {
		b, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		// root lays out a guest root holding the probe and its work dir /w.
		root := func(t *testing.T, extra map[string]string) string {
			r := t.TempDir()
			if err := os.MkdirAll(filepath.Join(r, "w"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(r, "fileoffset"), b, 0o755); err != nil {
				t.Fatal(err)
			}
			for n, body := range extra {
				if err := os.WriteFile(filepath.Join(r, n), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			return r
		}
		cfg := func(r string) Config { return Config{Args: []string{"/fileoffset", "/w"}, RootFS: HostRoot(r)} }
		t.Run(name+"/host", func(t *testing.T) {
			runFileOffset(t, cfg(root(t, nil)))
		})
		t.Run(name+"/memfs", func(t *testing.T) {
			c := cfg(root(t, nil))
			c.Mounts = []Mount{{Guest: "/w", FS: memfs.NewMemFS()}}
			runFileOffset(t, c)
		})
		t.Run(name+"/overlay", func(t *testing.T) {
			lower := root(t, map[string]string{"lowerfile": "lower"})
			c := cfg(lower)
			c.Upper = t.TempDir()
			runFileOffset(t, c)
			if got, err := os.ReadFile(filepath.Join(lower, "lowerfile")); err != nil || string(got) != "lower" {
				t.Fatalf("lower layer modified: %q %v", got, err)
			}
		})
	}
}

func runFileOffset(t *testing.T, cfg Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	cfg.Stdout, cfg.Stderr = &o, &o
	code, err := Run(ctx, "/fileoffset", cfg)
	t.Log(strings.TrimSpace(o.String()))
	if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
		t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
	}
}
