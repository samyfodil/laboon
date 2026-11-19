package oci

import (
	"fmt"
	"io"
	"os"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
	"github.com/samyfodil/laboon/filesystems/tarfs"
)

// ImageFS composes img as a copy-on-write FileSystem without extracting it to a
// directory tree. Each layer is read from its tar through a lazy TarFS -- the
// archive is indexed once and content is served on demand, never held whole in
// memory -- and the layers are unioned lowest-first under a faithful on-disk
// writable upper, so the result is a guest root that reads from the image and
// writes to disk. The layers' uncompressed tars are staged in a temp directory
// (one file each, not an unpacked tree); the returned close removes them and
// must be called when the filesystem is no longer in use.
func ImageFS(img v1.Image, upper string) (fsys core.FileSystem, close func() error, err error) {
	layers, err := img.Layers()
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

	fses := make([]core.FileSystem, 0, len(layers)+1)
	for i, l := range layers {
		rc, e := l.Uncompressed()
		if e != nil {
			return nil, nil, fmt.Errorf("layer %d: %w", i, e)
		}
		f, e := os.CreateTemp(tmp, fmt.Sprintf("layer-%d-*.tar", i))
		if e != nil {
			rc.Close()
			return nil, nil, e
		}
		n, e := io.Copy(f, rc)
		rc.Close()
		if e != nil {
			f.Close()
			return nil, nil, fmt.Errorf("stage layer %d: %w", i, e)
		}
		files = append(files, f) // kept open: TarFS serves content via ReadAt
		tfs, e := tarfs.TarFS(f, n)
		if e != nil {
			return nil, nil, fmt.Errorf("index layer %d: %w", i, e)
		}
		fses = append(fses, tfs)
	}
	fses = append(fses, hostfs.NewDiskFS(upper))
	return overlayfs.OverlayFS(fses...), cleanup, nil
}
