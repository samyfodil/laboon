package oci

import (
	"archive/tar"
	"bytes"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

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

// TestLayoutCacheRoundTrip exercises PullFS's offline path: an image's blobs are
// saved as an OCI layout, reloaded without a network, composed into a FileSystem
// and resolved -- the whole image side minus the registry fetch.
func TestLayoutCacheRoundTrip(t *testing.T) {
	img, err := mutate.AppendLayers(empty.Image, mkLayer(t,
		ent{"bin/", "", tar.TypeDir, 0o755},
		ent{"bin/sh", "SH", tar.TypeReg, 0o755},
		ent{"etc/motd", "hi", tar.TypeReg, 0o644},
	))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	r, err := name.ParseReference("example/app:latest")
	if err != nil {
		t.Fatal(err)
	}
	refFile := refFileFor(dir, r, "amd64")
	cfg := Config{Entrypoint: []string{"/bin/sh"}, Env: []string{"PATH=/bin"}}
	if err := saveLayout(dir, refFile, img, cfg); err != nil {
		t.Fatal(err)
	}

	img2, cfg2, err := loadLayout(dir, refFile)
	if err != nil {
		t.Fatalf("reload layout offline: %v", err)
	}
	if len(cfg2.Entrypoint) != 1 || cfg2.Entrypoint[0] != "/bin/sh" {
		t.Fatalf("reloaded config = %+v", cfg2)
	}

	upper := t.TempDir()
	fsys, closeFS, err := ImageFS(img2, upper)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFS()
	if got := read(t, fsys, "bin/sh"); got != "SH" {
		t.Fatalf("bin/sh = %q, want SH", got)
	}
	if p, err := LookPathFS(fsys, "sh", cfg2.Env); err != nil || p != "/bin/sh" {
		t.Fatalf("LookPathFS(sh) = %q, %v; want /bin/sh", p, err)
	}
}
