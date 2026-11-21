package sandbox

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

// A memFS is a complete guest root with no host path behind it. Executing a
// program from it exercises the exec resolver's non-host path: the program and
// its dynamic linker are read through the FileSystem and spilled for the stub to
// map, so a dynamically-linked program runs with the vfs never handing out a
// guest host path.
func TestMemFSRootExec(t *testing.T) {
	root := dynRoot(t)
	withBusybox(t, root)
	mem := memfs.NewMemFS()
	mirrorToMem(t, mem, root)

	var out bytes.Buffer
	code, err := Run(context.Background(), "/hello", Config{
		Args:   []string{"hello", "memfs-root"},
		RootFS: mem, // a non-host root: resolution + exec load go through the FS
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil || code != 7 || !strings.Contains(out.String(), "argv[1]=memfs-root") {
		t.Fatalf("memfs-root exec: code=%d err=%v out=%q", code, err, out.String())
	}

	// execve from a non-host root: sh execs the dynamic program, so the exec
	// path resolves and spills it and its dynamic linker through the FS, not a
	// guest host path.
	var out2 bytes.Buffer
	code, err = Run(context.Background(), "/bin/busybox", Config{
		Args:   []string{"sh", "-c", "exec /hello execve"},
		RootFS: mem,
		Stdout: &out2,
		Stderr: &out2,
	})
	if err != nil || code != 7 || !strings.Contains(out2.String(), "argv[1]=execve") {
		t.Fatalf("memfs-root execve: code=%d err=%v out=%q", code, err, out2.String())
	}
}

// mirrorToMem copies the host directory tree at root into the in-memory
// filesystem fsys (directories, regular files, symlinks), so the guest's root is
// a memFS holding the same content with no host path behind it. Its regular
// files are programs and libraries, mirrored executable whatever the host's
// filesystem records.
func mirrorToMem(t *testing.T, fsys core.FileSystem, root string) {
	t.Helper()
	wfs, _ := fsys.(core.WriteFileSystem)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		parent := fsys.Root()
		if dir := filepath.Dir(rel); dir != "." {
			for _, part := range strings.Split(dir, string(filepath.Separator)) {
				n, e := fsys.Lookup(parent, part)
				if e != nil {
					return e
				}
				parent = n
			}
		}
		name := d.Name()
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			_, err = fsys.Create(parent, name, core.CreateSpec{Kind: core.Dir, Mode: uint32(info.Mode().Perm())})
		case info.Mode()&os.ModeSymlink != 0:
			tgt, e := os.Readlink(p)
			if e != nil {
				return e
			}
			_, err = fsys.Create(parent, name, core.CreateSpec{Kind: core.Symlink, Target: tgt})
		case info.Mode().IsRegular():
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			if wfs != nil {
				_, err = wfs.WriteFile(parent, name, core.CreateSpec{Kind: core.Reg, Mode: 0o755}, b)
			}
		}
		return err
	})
	if err != nil {
		t.Fatalf("mirror %s: %v", root, err)
	}
}
