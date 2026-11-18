package build

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/internal/vfs"
	"github.com/samyfodil/laboon/internal/vfs/hostfs"
)

// TestCopyConfinedAbsSymlink proves COPY resolves an absolute symlink in the
// build context against the context root, not the host root, so it cannot read
// host files. A context symlink "evil" -> "/etc" must reach the context's own
// etc, not the host's.
func TestCopyConfinedAbsSymlink(t *testing.T) {
	ctx := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ctx, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctx, "etc", "hostname"), []byte("CONFINED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(ctx, "evil")); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	srcNS := vfs.NewNamespace(hostfs.NewDirFS(ctx))
	dstNS := vfs.NewNamespace(hostfs.NewDirFS(dst))
	if err := copyThroughVFS(srcNS, "evil/hostname", dstNS, "/out", nil, nil); err != nil {
		t.Fatalf("copy through the context symlink: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "out"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "CONFINED" {
		t.Fatalf("escaped confinement: got %q, want the context's etc/hostname (the host's /etc/hostname was read instead)", got)
	}
}

// TestCopyRejectsParentEscape proves COPY cannot climb out of the context with
// "..": a path above the context resolves back to the context root and misses.
func TestCopyRejectsParentEscape(t *testing.T) {
	base := t.TempDir()
	ctx := filepath.Join(base, "ctx")
	if err := os.MkdirAll(ctx, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), []byte("SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	srcNS := vfs.NewNamespace(hostfs.NewDirFS(ctx))
	dstNS := vfs.NewNamespace(hostfs.NewDirFS(dst))
	if err := copyThroughVFS(srcNS, "../secret.txt", dstNS, "/out", nil, nil); err == nil {
		t.Fatal("COPY ../secret.txt escaped the context: want an error, got nil")
	}
	if _, err := os.Stat(filepath.Join(dst, "out")); err == nil {
		t.Fatal("COPY ../secret.txt wrote an output despite escaping the context")
	}
}

// TestCopyPreservesSymlink proves a symlink inside a copied tree is recreated as
// a link, not dereferenced, so the walk stays confined and docker's behavior is
// kept.
func TestCopyPreservesSymlink(t *testing.T) {
	ctx := t.TempDir()
	tree := filepath.Join(ctx, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "real"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(tree, "link")); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	srcNS := vfs.NewNamespace(hostfs.NewDirFS(ctx))
	dstNS := vfs.NewNamespace(hostfs.NewDirFS(dst))
	if err := copyThroughVFS(srcNS, "tree", dstNS, "/tree", nil, nil); err != nil {
		t.Fatalf("copy tree: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dst, "tree", "link"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink in a copied tree was dereferenced, not preserved")
	}
	tgt, err := os.Readlink(filepath.Join(dst, "tree", "link"))
	if err != nil || tgt != "/etc/passwd" {
		t.Fatalf("preserved symlink target = %q, %v; want /etc/passwd", tgt, err)
	}
}
