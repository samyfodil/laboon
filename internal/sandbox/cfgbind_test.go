package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// A Config.Mounts host-directory bind must expose the host subtree at the guest
// path, read and write, confined to the subtree.
func TestMountFileBind(t *testing.T) {
	root, exe := guestRoot(t, "cfgbind")
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "hello"), []byte("laboon-bind"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{
		Args:   []string{exe},
		RootFS: HostRoot(root),
		Mounts: []Mount{{Guest: "/laboonbind", FS: hostfs.Dir(host)}},
		Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), "BIND-FILE-OK") {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
	// The guest's write through the bind landed on the host subtree.
	if b, err := os.ReadFile(filepath.Join(host, "out")); err != nil || string(b) != "laboon-bind" {
		t.Fatalf("host-side write-back = %q err=%v", b, err)
	}
}
