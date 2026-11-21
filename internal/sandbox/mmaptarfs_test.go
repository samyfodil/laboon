package sandbox

import (
	"archive/tar"
	"bytes"
	"testing"

	"github.com/samyfodil/laboon/filesystems/tarfs"
)

// mmap of a read-only file served by a tarfs mount works through the vfs: the
// file's size comes from tarNode.Stat and its content from tarFile.ReadAt (no
// host descriptor), so the guest maps it PROT_READ and reads across a page
// boundary, and read() agrees. Guards the virtual-file mmap path after
// File.Stat() became core.Info.
func TestMmapTarFS(t *testing.T) {
	exe := guestPath(t, "mmaptarfs")

	content := make([]byte, 8192)
	copy(content[0:], "TARFS-PAGE0-CONTENT")
	copy(content[4096:], "TARFS-PAGE1-CONTENT")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "f", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tfs, err := tarfs.TarFS(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	runMmapGuest(t, exe, tfs, "TARFS-MMAP-OK")
}
