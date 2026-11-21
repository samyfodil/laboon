//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/filesystems/memfs"
)

// TestFileOffset runs testdata/fileoffset.c, built against glibc and musl, over
// the host root, an in-memory mount and an overlay whose lower holds /lowerfile: offsets of
// separate and shared descriptions, O_APPEND, files unlinked or replaced while
// open, vectored I/O, fdinfo, SEEK_CUR locks and stdio redirection.
func TestFileOffset(t *testing.T) {
	dir := t.TempDir()
	builds := map[string][]string{
		"glibc": {"gcc", "-O2", "-static", "-w", "-o", filepath.Join(dir, "glibc"), "../../testdata/fileoffset.c"},
	}
	if z := zigCC(); z != "" {
		target := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-linux-musl"
		builds["musl"] = []string{z, "cc", "-target", target, "-O2", "-static", "-o", filepath.Join(dir, "musl"), "../../testdata/fileoffset.c"}
	}
	for libc, c := range builds {
		if b, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			t.Skipf("build: %v\n%s", err, b)
		}
		bin := filepath.Join(dir, libc)
		t.Run(libc+"/host", func(t *testing.T) {
			work := t.TempDir()
			runFileOffset(t, bin, Config{Args: []string{"fileoffset", work}, RootFS: HostRoot("/")})
		})
		t.Run(libc+"/memfs", func(t *testing.T) {
			work := t.TempDir()
			runFileOffset(t, bin, Config{Args: []string{"fileoffset", work}, RootFS: HostRoot("/"), Mounts: []Mount{{Guest: work, FS: memfs.NewMemFS()}}})
		})
		t.Run(libc+"/overlay", func(t *testing.T) {
			lower, upper := t.TempDir(), t.TempDir()
			if err := os.MkdirAll(filepath.Join(lower, "w"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lower, "lowerfile"), []byte("lower"), 0o644); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(bin)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lower, "fileoffset"), b, 0o755); err != nil {
				t.Fatal(err)
			}
			runFileOffset(t, "/fileoffset", Config{Args: []string{"/fileoffset", "/w"}, RootFS: HostRoot(lower), Upper: upper})
			if got, err := os.ReadFile(filepath.Join(lower, "lowerfile")); err != nil || string(got) != "lower" {
				t.Fatalf("lower layer modified: %q %v", got, err)
			}
		})
	}
}

func runFileOffset(t *testing.T, exe string, cfg Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	cfg.Stdout, cfg.Stderr = &o, &o
	code, err := Run(ctx, exe, cfg)
	if err != nil || code != 0 || !strings.Contains(o.String(), "done fails=0") {
		t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
	}
}
