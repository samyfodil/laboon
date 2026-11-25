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

// The stub's Seatbelt profile names no tree of the guest's: a guest's own
// Darwin open, which only that profile sees, reads no host file, neither one
// outside the run nor one in its host-directory root (which the vfs alone may
// serve, through its whiteouts and mounts).
func TestSeatbeltNoGuestTree(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("HOSTCANARY"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := guestPath(t, "darwinopen_arm64")
	hostRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostRoot, "darwinopen"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	lower := filepath.Join(hostRoot, "lower.txt")
	if err := os.WriteFile(lower, []byte("LOWERCANARY"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  Config
		prog string
	}{
		{"rootless", Config{}, exe},
		{"memfs", Config{RootFS: memRootWith(t, "darwinopen", exe)}, "/darwinopen"},
		{"hostroot", Config{RootFS: HostRoot(hostRoot)}, "/darwinopen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			var out bytes.Buffer
			cfg := tc.cfg
			cfg.Args = []string{"darwinopen", "/etc/passwd", secret, lower, filepath.Join(hostRoot, "darwinopen")}
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
