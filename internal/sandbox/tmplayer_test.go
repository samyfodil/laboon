//go:build linux || darwin

package sandbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// A guest-writable tree's backend never follows a symlink the guest swapped in
// for a directory after resolving a path through it: a node resolved while
// race was a directory, used once race is a symlink to a host directory, must
// neither read the host's file nor create one there. This is the window a
// guest thread opens by renaming a directory away and symlinking its name.
func TestTmpLayerRefusesSwappedSymlink(t *testing.T) {
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "secret.txt"), []byte("HOSTCANARY"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The backend a rootless run sets: the layer must not depend on it.
	layer, err := (&dfs{tmpDir: t.TempDir(), hostFS: hostfs.NewHostFS("", "", "")}).tmpLayer()
	if err != nil {
		t.Fatal(err)
	}
	root := layer.RootDir()
	race := filepath.Join(root, "race")
	if err := os.Mkdir(race, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(race, "secret.txt"), []byte("GUEST"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, err := layer.Lookup(layer.Root(), "race")
	if err != nil {
		t.Fatal(err)
	}
	file, err := layer.Lookup(dir, "secret.txt")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(race, filepath.Join(root, "racetmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, race); err != nil {
		t.Fatal(err)
	}

	if f, err := file.Open(os.O_RDONLY); err == nil {
		b := make([]byte, 16)
		n, _ := f.ReadAt(b, 0)
		f.Close()
		t.Errorf("opened the file through the swapped symlink, read %q", b[:n])
	}
	if _, err := layer.Create(dir, "made", core.CreateSpec{Kind: core.Reg, Mode: 0o644}); err == nil {
		t.Error("created a file through the swapped symlink")
	}
	if _, err := os.Stat(filepath.Join(host, "made")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a file appeared in the host directory: %v", err)
	}
}
