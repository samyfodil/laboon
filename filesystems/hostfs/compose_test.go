package hostfs

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
	"github.com/samyfodil/laboon/filesystems/tarfs"
)

// TestImageComposeCopyUp composes an image the way oci will: a read-only TarFS
// layer (no extraction) as the lower, a faithful on-disk DiskFS as the writable
// top. It proves reads come from the tar layer, a guest-owned write lands in the
// disk upper with its metadata, and a copy-up moves a layer file into the upper
// while the layer stays untouched.
func TestImageComposeCopyUp(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range []struct {
		name, data string
		tf         byte
		mode       int64
	}{
		{"bin/", "", tar.TypeDir, 0o755},
		{"bin/tool", "TOOLBYTES", tar.TypeReg, 0o755},
		{"etc/", "", tar.TypeDir, 0o755},
		{"etc/conf", "cfg", tar.TypeReg, 0o644},
	} {
		tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: e.tf, Mode: e.mode, Size: int64(len(e.data)), ModTime: time.Unix(1700000000, 0)})
		if e.data != "" {
			tw.Write([]byte(e.data))
		}
	}
	tw.Close()
	lower, err := tarfs.TarFS(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	upperDir := t.TempDir()
	upper := NewDiskFS(upperDir)
	ov := overlayfs.OverlayFS(lower, upper)

	// A read is served from the tar layer.
	if got := readNode(t, lookup(t, ov, "bin/tool")); got != "TOOLBYTES" {
		t.Fatalf("read bin/tool = %q, want TOOLBYTES", got)
	}

	// A guest-owned write lands in the disk upper with its metadata intact, and
	// the file really is on the host under the upper dir.
	owned, err := ov.(core.WriteFileSystem).WriteFile(ov.Root(), "owned", core.CreateSpec{Kind: core.Reg, Mode: 0o600, Uid: 1000, Gid: 1000}, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := owned.Stat(); a.Uid != 1000 || a.Mode != 0o600 {
		t.Fatalf("owned stat = %+v, want uid 1000 mode 0600", a)
	}
	if _, err := os.Stat(filepath.Join(upperDir, "owned")); err != nil {
		t.Fatalf("owned did not land in the disk upper: %v", err)
	}

	// Writing a layer file copies it up to the disk upper; the layer is untouched.
	conf := lookup(t, ov, "etc/conf")
	fh, err := conf.Open(os.O_WRONLY | os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteAt([]byte("NEW"), 0); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	if b, _ := os.ReadFile(filepath.Join(upperDir, "etc/conf")); string(b) != "NEW" {
		t.Fatalf("copy-up did not land in the upper: %q", b)
	}
	if got := readNode(t, lookup(t, ov, "etc/conf")); got != "NEW" {
		t.Fatalf("overlay read after copy-up = %q, want NEW", got)
	}
}

func lookup(t *testing.T, f core.FileSystem, p string) core.Node {
	t.Helper()
	n := f.Root()
	for _, name := range strings.Split(p, "/") {
		if name == "" {
			continue
		}
		c, err := f.Lookup(n, name)
		if err != nil {
			t.Fatalf("lookup %q in %q: %v", name, p, err)
		}
		n = c
	}
	return n
}

func readNode(t *testing.T, n core.Node) string {
	t.Helper()
	a, _ := n.Stat()
	fh, err := n.Open(os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	b := make([]byte, a.Size)
	k, _ := fh.ReadAt(b, 0)
	return string(b[:k])
}
