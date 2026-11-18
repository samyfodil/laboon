package hostfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samyfodil/laboon/internal/vfs"
)

// TestAttrFullStat checks a Node's Stat carries the full stat (size, nlink,
// mtime) a guest stat reply needs, both from a plain dirFS and through the
// overlay union that composes it.
func TestAttrFullStat(t *testing.T) {
	lower := t.TempDir()
	if err := os.WriteFile(filepath.Join(lower, "f"), []byte("twelve bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := vfs.NewOverlayFS(NewDirFS(lower), NewDirFS(t.TempDir()))
	n, err := fs.Lookup(fs.Root(), "f")
	if err != nil {
		t.Fatal(err)
	}
	a, err := n.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if a.Size != 12 {
		t.Errorf("Size = %d, want 12", a.Size)
	}
	if a.Nlink < 1 {
		t.Errorf("Nlink = %d, want >= 1", a.Nlink)
	}
	if a.Mtime == 0 {
		t.Error("Mtime not populated")
	}
}
