package oci

import (
	"archive/tar"
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
)

type ent struct {
	name, data string
	tf         byte
	mode       int64
}

func mkLayer(t *testing.T, ents ...ent) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: e.tf, Mode: e.mode, Size: int64(len(e.data)), ModTime: time.Unix(1700000000, 0)})
		if e.data != "" {
			tw.Write([]byte(e.data))
		}
	}
	tw.Close()
	l, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestImageFS composes a cached two-layer image as a read-only FileSystem and
// checks top-layer-wins union, lower-only files, and that it refuses writes (the
// writable top is the caller's to add).
func TestImageFS(t *testing.T) {
	img, err := mutate.AppendLayers(empty.Image,
		mkLayer(t,
			ent{"bin/", "", tar.TypeDir, 0o755},
			ent{"bin/sh", "L1-sh", tar.TypeReg, 0o755},
			ent{"usr/x", "USR", tar.TypeReg, 0o644},
		),
		mkLayer(t,
			ent{"bin/sh", "L2-sh", tar.TypeReg, 0o755}, // shadows l1
			ent{"etc/motd", "hello", tar.TypeReg, 0o644},
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := Store(img, "test/app:latest", Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	layers, closeFS, err := stored.Layers()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFS()
	if len(layers) != 2 {
		t.Fatalf("got %d layers, want 2", len(layers))
	}
	view := overlayfs.OverlayFS(layers...) // the caller composes the layers

	if got := read(t, view, "bin/sh"); got != "L2-sh" { // top layer wins
		t.Fatalf("bin/sh = %q, want L2-sh", got)
	}
	if got := read(t, view, "usr/x"); got != "USR" {
		t.Fatalf("usr/x = %q, want USR", got)
	}
	if got := read(t, view, "etc/motd"); got != "hello" {
		t.Fatalf("etc/motd = %q, want hello", got)
	}
	// Each layer is read-only on its own.
	if _, err := layers[0].Create(layers[0].Root(), "new", core.CreateSpec{Kind: core.Reg, Mode: 0o644}); err == nil {
		t.Fatal("image layer should be read-only")
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
