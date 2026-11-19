package laboon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// TestWithUserOverride checks that WithUser resolves against the rootfs and
// overrides, and that without it a non-image run stays root.
func TestWithUserOverride(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/passwd"),
		[]byte("root:x:0:0::/root:/bin/sh\nchrome:x:1000:1000::/home/chrome:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/group"), []byte("root:x:0:\nchrome:x:1000:\nbob:x:1001:\n"), 0o644)

	_, cfg, err := programConfig("/x", newOptions([]Option{WithMount("/", hostfs.Dir(root)), WithUser("bob")}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User == nil || cfg.User.Uid != 1001 || cfg.User.Gid != 1001 {
		t.Errorf("WithUser(bob): got %+v, want uid/gid 1001", cfg.User)
	}

	_, cfg, err = programConfig("/x", newOptions([]Option{WithMount("/", hostfs.Dir(root))}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != nil {
		t.Errorf("no WithUser: got %+v, want nil (root)", cfg.User)
	}
}
