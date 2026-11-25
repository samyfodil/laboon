package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

// A run with no host-directory root gives the guest no host tree: its own
// Darwin open, which only the stub's Seatbelt profile sees, reads no host file.
func TestSeatbeltNoHostRoot(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("HOSTCANARY"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := guestPath(t, "darwinopen_arm64")
	for _, tc := range []struct {
		name string
		cfg  Config
		prog string
	}{
		{"rootless", Config{}, exe},
		{"memfs", Config{RootFS: memRootWith(t, "darwinopen", exe)}, "/darwinopen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			var out bytes.Buffer
			cfg := tc.cfg
			cfg.Args = []string{"darwinopen", "/etc/passwd", secret}
			cfg.Stdout, cfg.Stderr = &out, &out
			code, err := Run(ctx, tc.prog, cfg)
			if err != nil || code != 0 || !strings.Contains(out.String(), "DARWIN-OPEN-DENIED") {
				t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
			}
		})
	}
}

// memRootWith is an in-memory root holding the host file src at /name.
func memRootWith(t *testing.T, name, src string) core.FileSystem {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o755); err != nil {
		t.Fatal(err)
	}
	mem := memfs.NewMemFS()
	mirrorToMem(t, mem, dir)
	return mem
}
