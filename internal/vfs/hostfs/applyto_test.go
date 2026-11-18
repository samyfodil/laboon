package hostfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyToHardlink checks ApplyTo recreates a layer's hardlink as a hardlink
// in the materialized root, not two independent copies — so a build step that
// folds the layer in, and the next step reading it, see one shared inode.
func TestApplyToHardlink(t *testing.T) {
	l, err := NewLayer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Put("a", 0o644, []byte("shared")); err != nil {
		t.Fatal(err)
	}
	if err := l.Hardlink("b", "a"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := l.ApplyTo(root); err != nil {
		t.Fatal(err)
	}
	fa, err := os.Stat(filepath.Join(root, "a"))
	if err != nil {
		t.Fatal(err)
	}
	fb, err := os.Stat(filepath.Join(root, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fa, fb) {
		t.Fatal("ApplyTo materialized the hardlink as two independent files")
	}
}
