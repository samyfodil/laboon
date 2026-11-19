package oci

import (
	"fmt"
	"io"
	"os"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/tarfs"
)

// Layers returns the image's layers as read-only FileSystems, lowest first.
// Each is read lazily from its tar -- indexed once and served on demand, never
// extracted to a directory tree and never held whole in memory. The image is its
// layers; to run it, compose them with a writable top outside oci:
//
//	layers, close, _ := img.Layers()
//	defer close()
//	root := laboon.Overlay(append(layers, laboon.NewDiskFS(upperDir))...)
//	laboon.Run(ctx, prog, laboon.WithFS("/", root))
//
// close removes the staged layer tars and must be called when the layers are no
// longer in use.
func (i *Image) Layers() ([]core.FileSystem, func() error, error) {
	if i.img == nil {
		return nil, nil, fmt.Errorf("oci: image %s has no layers loaded", i.Ref)
	}
	return layerFSes(i.img)
}

// layerFSes stages each layer's uncompressed tar in a temp file (one file, not
// an unpacked tree) and opens it as a lazy TarFS; close removes them.
func layerFSes(img v1.Image) (layers []core.FileSystem, close func() error, err error) {
	v1layers, err := img.Layers()
	if err != nil {
		return nil, nil, err
	}
	tmp, err := os.MkdirTemp("", "laboon-layers-")
	if err != nil {
		return nil, nil, err
	}
	var files []*os.File
	cleanup := func() error {
		for _, f := range files {
			f.Close()
		}
		return os.RemoveAll(tmp)
	}
	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	for n, l := range v1layers {
		rc, e := l.Uncompressed()
		if e != nil {
			return nil, nil, fmt.Errorf("layer %d: %w", n, e)
		}
		f, e := os.CreateTemp(tmp, fmt.Sprintf("layer-%d-*.tar", n))
		if e != nil {
			rc.Close()
			return nil, nil, e
		}
		size, e := io.Copy(f, rc)
		rc.Close()
		if e != nil {
			f.Close()
			return nil, nil, fmt.Errorf("stage layer %d: %w", n, e)
		}
		files = append(files, f) // kept open: TarFS serves content via ReadAt
		tfs, e := tarfs.TarFS(f, size)
		if e != nil {
			return nil, nil, fmt.Errorf("index layer %d: %w", n, e)
		}
		layers = append(layers, tfs)
	}
	return layers, cleanup, nil
}
