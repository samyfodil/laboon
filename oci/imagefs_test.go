package oci

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/samyfodil/laboon/core"
)

type ent struct {
	name, data string
	tf         byte
	mode       int64
}

func TestImageFS(t *testing.T) {
	mk := func(ents ...ent) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range ents {
			tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: e.tf, Mode: e.mode, Size: int64(len(e.data)), ModTime: time.Unix(1700000000, 0)})
			if e.data != "" {
				tw.Write([]byte(e.data))
			}
		}
		tw.Close()
		return buf.Bytes()
	}
	l1, err := tarball.LayerFromReader(bytes.NewReader(mk(
		ent{"bin/", "", tar.TypeDir, 0o755},
		ent{"bin/sh", "L1-sh", tar.TypeReg, 0o755},
		ent{"usr/x", "USR", tar.TypeReg, 0o644},
	)))
	if err != nil {
		t.Fatal(err)
	}
	l2, err := tarball.LayerFromReader(bytes.NewReader(mk(
		ent{"bin/sh", "L2-sh", tar.TypeReg, 0o755}, // shadows l1
		ent{"etc/", "", tar.TypeDir, 0o755},
		ent{"etc/motd", "hello", tar.TypeReg, 0o644},
	)))
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, l1, l2)
	if err != nil {
		t.Fatal(err)
	}

	upper := t.TempDir()
	fsys, closeFn, err := ImageFS(img, upper)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()

	if got := read(t, fsys, "bin/sh"); got != "L2-sh" { // top layer wins
		t.Fatalf("bin/sh = %q, want L2-sh", got)
	}
	if got := read(t, fsys, "usr/x"); got != "USR" { // lower-only file
		t.Fatalf("usr/x = %q, want USR", got)
	}
	if got := read(t, fsys, "etc/motd"); got != "hello" {
		t.Fatalf("etc/motd = %q, want hello", got)
	}

	// A write lands in the on-disk upper, never the layers.
	if _, err := fsys.(core.WriteFileSystem).WriteFile(fsys.Root(), "new", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, []byte("W")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(upper, "new")); err != nil {
		t.Fatalf("write did not land in the upper: %v", err)
	}
}

func lookupP(t *testing.T, f core.FileSystem, p string) core.Node {
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

func read(t *testing.T, f core.FileSystem, p string) string {
	t.Helper()
	n := lookupP(t, f, p)
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
