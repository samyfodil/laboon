package hostfs

import (
	"io"
	"os"
	"path"

	"github.com/samyfodil/laboon/core"
)

// A ChangeSet is a layer's contents as a stable, walkable set of path changes —
// the primitive an image format serializes, with no knowledge of the backing
// store. It is how OCI (or any exporter) reads a layer out: the layer yields
// abstract changes and content; the format maps them to its own on-disk shape.
// Deletions and opacity, which vanish from a merged filesystem view, are explicit.
type ChangeSet interface {
	// Walk visits every change under the layer in a stable, parent-before-child
	// order. For a regular file the reader is its content (and must be consumed
	// before the next call); for everything else it is nil.
	Walk(fn func(Change, io.Reader) error) error
}

// Change is one path's contribution to a layer: an added or modified object with
// its attributes, a hardlink to an earlier path in the same walk, or a deletion.
type Change struct {
	Path   string    // clean, layer-relative ("etc/hosts")
	Attr   core.Attr // Kind, Mode, Uid, Gid, Target, Rdev, and Opaque/Whiteout flags
	LinkTo string    // non-empty: a hardlink to this earlier path (same object)
}

// ChangeSet returns a walkable view of the layer's changes.
func (l *Layer) ChangeSet() ChangeSet { return layerChanges{l} }

type layerChanges struct{ l *Layer }

func (c layerChanges) Walk(fn func(Change, io.Reader) error) error {
	return walkChanges(c.l, "", map[uint64]string{}, fn)
}

func walkChanges(l *Layer, dir string, links map[uint64]string, fn func(Change, io.Reader) error) error {
	entries, _, ok := l.Entries(dir)
	if !ok {
		return nil
	}
	for _, e := range entries {
		p := path.Join(dir, e.Name)
		if e.Whiteout {
			if err := fn(Change{Path: p, Attr: core.Attr{Whiteout: true}}, nil); err != nil {
				return err
			}
			continue
		}
		a, ok := l.Stat(p)
		if !ok {
			continue
		}
		ch := Change{Path: p, Attr: a}
		var content io.Reader
		if a.Kind == core.Reg {
			// Names that share an inode become a hardlink after the first.
			if fi, err := os.Lstat(l.host(p)); err == nil {
				if id, nlink, ok := core.FileID(fi); ok && nlink > 1 {
					if first, seen := links[id]; seen {
						ch.LinkTo = first
					} else {
						links[id] = p
					}
				}
			}
			if ch.LinkTo == "" {
				f, err := os.Open(l.host(p))
				if err != nil {
					return err
				}
				defer f.Close()
				content = f
			}
		}
		if err := fn(ch, content); err != nil {
			return err
		}
		if a.Kind == core.Dir {
			if err := walkChanges(l, p, links, fn); err != nil {
				return err
			}
		}
	}
	return nil
}
