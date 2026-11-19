package namespace

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	. "github.com/samyfodil/laboon/core"
)

// mkDir builds a host directory with files and returns a plain dirFS over it
// plus the directory path (so a test can add symlinks/dirs with os).
func mkDir(t *testing.T, files map[string]string) (FileSystem, string) {
	t.Helper()
	dir := t.TempDir()
	for p, body := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return newTestDirFS(dir), dir
}

// TestNamespaceResolve exercises the shape end to end through one FileSystem:
// multi-component resolution, a symlink followed only when asked, confinement of
// an absolute symlink target to the namespace root, and "..".
func TestNamespaceResolve(t *testing.T) {
	root, dir := mkDir(t, map[string]string{"etc/hostname": "host", "bin/sh": "#!"})
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "link")); err != nil { // absolute target
		t.Fatal(err)
	}
	if err := os.Symlink("../../etc/hostname", filepath.Join(dir, "up")); err != nil { // tries to escape
		t.Fatal(err)
	}
	ns := NewNamespace(root)

	if loc, err := ns.Resolve("/etc/hostname", true); err != nil || loc.Node.Kind() != Reg {
		t.Fatalf("etc/hostname: %+v %v", loc, err)
	}
	// Follow vs not-follow on the final symlink.
	if loc, err := ns.Resolve("/link", false); err != nil || loc.Node.Kind() != Symlink {
		t.Fatalf("link nofollow: kind=%v %v", loc.Node.Kind(), err)
	}
	if loc, err := ns.Resolve("/link", true); err != nil || loc.Node.Kind() != Reg || loc.Path != "/etc/hostname" {
		t.Fatalf("link follow: %+v %v", loc, err)
	}
	// An absolute symlink resolves from the namespace root; "../.." cannot climb
	// above it, so /up still lands on /etc/hostname, not outside.
	if loc, err := ns.Resolve("/up", true); err != nil || loc.Path != "/etc/hostname" {
		t.Fatalf("up (confined): %+v %v", loc, err)
	}
	// Missing path is an fs.ErrNotExist.
	if _, err := ns.Resolve("/nope", true); err == nil {
		t.Fatal("expected error for /nope")
	}
}

// TestNamespaceDotDotThroughSymlink checks ".." resolves against a symlink's
// target, not lexically. For /a/link/.. where link -> /x/y, POSIX lands on /x
// (the target's parent), not /a (what path.Clean would give by collapsing the
// text before following the link).
func TestNamespaceDotDotThroughSymlink(t *testing.T) {
	root, dir := mkDir(t, map[string]string{"x/y/f": "deep", "a/keep": "k"})
	if err := os.Symlink("/x/y", filepath.Join(dir, "a", "link")); err != nil {
		t.Fatal(err)
	}
	ns := NewNamespace(root)
	// /a/link/.. must be /x (parent of the symlink target), reachable to /x/y/f.
	if loc, err := ns.Resolve("/a/link/..", true); err != nil || loc.Path != "/x" {
		t.Fatalf("/a/link/..: path=%q want /x (err %v)", loc.Path, err)
	}
	if loc, err := ns.Resolve("/a/link/../y/f", true); err != nil || loc.Path != "/x/y/f" {
		t.Fatalf("/a/link/../y/f: path=%q want /x/y/f (err %v)", loc.Path, err)
	}
}

// TestNamespacePolicy checks the policy hook gates operations at the resolve
// chokepoint: it denies per (op, resolved path), sees through a symlink to the
// real target (so an escape cannot bypass it), and lets a nil policy through.
func TestNamespacePolicy(t *testing.T) {
	root, dir := mkDir(t, map[string]string{"etc/secret": "s", "etc/ok": "o"})
	if err := os.Symlink("/etc/secret", filepath.Join(dir, "sneaky")); err != nil {
		t.Fatal(err)
	}
	ns := NewNamespace(root)

	// No policy: everything resolves.
	if _, err := ns.Resolve("/etc/secret", true); err != nil {
		t.Fatalf("no policy should allow: %v", err)
	}

	// Deny writes to /etc/secret; reads redirected to /etc/ok; else allow.
	denied := &fs.PathError{Op: "policy", Path: "/etc/secret", Err: fs.ErrPermission}
	ns.SetPolicy(func(op, p string) (string, error) {
		switch {
		case p == "/etc/secret" && op == "write":
			return "", denied
		case p == "/etc/secret" && op == "read":
			return "/etc/ok", nil // redirect
		}
		return "", nil
	})
	if _, err := ns.ResolveOp("write", "/etc/secret", true); err == nil {
		t.Fatal("policy should deny write to /etc/secret")
	}
	// Read of /etc/secret is redirected to /etc/ok.
	if loc, err := ns.ResolveOp("read", "/etc/secret", true); err != nil || loc.Path != "/etc/ok" {
		t.Fatalf("policy should redirect read to /etc/ok: path=%q err=%v", loc.Path, err)
	}
	// The symlink resolves to /etc/secret, so the write is denied there too — a
	// symlink cannot smuggle the access past the hook.
	if _, err := ns.ResolveOp("write", "/sneaky", true); err == nil {
		t.Fatal("policy should deny write through the symlink to /etc/secret")
	}
	// A different path is unaffected.
	if _, err := ns.ResolveOp("write", "/etc/ok", true); err != nil {
		t.Fatalf("policy should allow write to /etc/ok: %v", err)
	}

	// Clearing the policy re-allows.
	ns.SetPolicy(nil)
	if _, err := ns.ResolveOp("write", "/etc/secret", true); err != nil {
		t.Fatalf("cleared policy should allow: %v", err)
	}
}

// TestNamespaceMount checks a second filesystem mounted at /mnt is entered on
// resolution, and that creating and reading through a resolved node works.
func TestNamespaceMount(t *testing.T) {
	root, dir := mkDir(t, map[string]string{"etc/x": "root-fs"})
	if err := os.Mkdir(filepath.Join(dir, "mnt"), 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := mkDir(t, map[string]string{"file": "mounted-fs"})
	ns := NewNamespace(root)
	if err := ns.Mount("/mnt", data); err != nil {
		t.Fatalf("mount: %v", err)
	}

	loc, err := ns.Resolve("/mnt/file", true)
	if err != nil || loc.FS != data {
		t.Fatalf("resolve into mount: fs=%p want=%p %v", loc.FS, data, err)
	}
	f, err := loc.Node.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	n, _ := f.ReadAt(b, 0)
	f.Close()
	if string(b[:n]) != "mounted-fs" {
		t.Fatalf("read through mount = %q", b[:n])
	}

	// Create a file in the mounted fs through its resolved directory node.
	mntRoot, err := ns.Resolve("/mnt", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mntRoot.FS.(WriteFileSystem).WriteFile(mntRoot.Node, "new", CreateSpec{Kind: Reg, Mode: 0o644}, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	loc, err = ns.Resolve("/mnt/new", true)
	if err != nil {
		t.Fatal(err)
	}
	f, _ = loc.Node.Open(0)
	got, _ := io.ReadAll(io.NewSectionReader(f, 0, 2))
	f.Close()
	if string(got) != "hi" {
		t.Fatalf("created-in-mount read = %q", got)
	}
}
