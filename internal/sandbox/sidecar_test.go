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

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// A host image's sidecar records the owners and mode bits its host files cannot
// hold; the guest sees them, and a kept upper records the ones the guest set.
func TestImageSidecar(t *testing.T) {
	bin := guestBin(t, "statls")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	lower, upper := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(lower, "statls"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lower, "suid"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := hostfs.SaveOverrides(lower, map[string]*core.Override{
		"suid": {Uid: 1234, Gid: 56, HasOwner: true, Mode: 0o4755, HasMode: true},
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var o bytes.Buffer
	code, err := Run(ctx, "/statls", Config{
		Args: []string{"/statls", "/suid"}, RootFS: HostRoot(lower), Upper: upper,
		Stdout: &o, Stderr: &o,
	})
	if err != nil || code != 0 || !strings.Contains(o.String(), "/suid 1234 56 104755") {
		t.Fatalf("code=%d err=%v\n%s", code, err, o.String())
	}
}
