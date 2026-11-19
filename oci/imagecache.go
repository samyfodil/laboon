package oci

import (
	"fmt"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// The image's layer blobs are cached as an OCI layout beside the unpacked
// rootfs, keyed by the same config digest, so (*Image).FS() composes the image
// without a network and a built image runs the same offline path a pulled one
// does.

func layoutDir(dir, hex string) string { return filepath.Join(dir, hex, "image") }

// saveLayout writes img's blobs as an OCI layout under its digest, once.
func saveLayout(dir, hex string, img v1.Image) error {
	ld := layoutDir(dir, hex)
	if _, err := os.Stat(ld); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(dir, hex), 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(filepath.Join(dir, hex), ".layout-*")
	if err != nil {
		return err
	}
	p, err := layout.Write(tmp, empty.Index)
	if err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := p.AppendImage(img); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, ld); err != nil && !os.IsExist(err) {
		os.RemoveAll(tmp)
		return err
	}
	return nil
}

// loadLayoutImage reopens a cached image's blobs as a v1.Image, without network.
func loadLayoutImage(dir, hex string) (v1.Image, error) {
	p, err := layout.FromPath(layoutDir(dir, hex))
	if err != nil {
		return nil, err
	}
	ii, err := p.ImageIndex()
	if err != nil {
		return nil, err
	}
	mf, err := ii.IndexManifest()
	if err != nil {
		return nil, err
	}
	if len(mf.Manifests) == 0 {
		return nil, fmt.Errorf("empty image layout")
	}
	return ii.Image(mf.Manifests[0].Digest)
}
