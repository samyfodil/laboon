package sandbox

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/internal/namespace"
)

// TestHostDirFSMountedOnRoot proves the sandbox's platform host access, expressed
// as a core.FileSystem, mounts on / and resolves/reads uniformly through the vfs
// Namespace — the homogeneous model: the real host directory is just a backend
// in the tree, with its platform I/O internal to it.
func TestHostDirFSMountedOnRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "f"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The sandbox's platform fs, as a FileSystem mounted on /. The symlink is
	// made through it, as a guest's is: each host has its own way to hold one.
	fsys := hostfs.Dir(dir)
	if _, err := fsys.Create(fsys.Root(), "link", core.CreateSpec{Kind: core.Symlink, Target: "hello"}); err != nil {
		t.Fatal(err)
	}
	ns := namespace.NewNamespace(fsys)

	read := func(p string) string {
		t.Helper()
		loc, err := ns.Resolve(p, true)
		if err != nil {
			t.Fatalf("resolve %s: %v", p, err)
		}
		f, err := loc.Node.Open(os.O_RDONLY)
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}
		b, _ := io.ReadAll(io.NewSectionReader(f, 0, 64))
		f.Close()
		return string(b)
	}

	if read("/hello") != "hi" {
		t.Error("read /hello through the mounted host fs")
	}
	if read("/sub/f") != "nested" {
		t.Error("read /sub/f")
	}
	// Symlink: not followed, then followed — resolution is the Namespace's.
	if loc, err := ns.Resolve("/link", false); err != nil || loc.Node.Kind() != core.Symlink {
		t.Fatalf("/link nofollow: %+v %v", loc, err)
	}
	if loc, err := ns.Resolve("/link", true); err != nil || loc.Path != "/hello" {
		t.Fatalf("/link follow -> %+v %v", loc, err)
	}
}
