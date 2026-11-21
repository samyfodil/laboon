package hostfs

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/samyfodil/laboon/core"
)

// LayerFromDir opens an existing self-describing OCI layer directory as a
// dir-backed Layer. Its files back the layer in place and its whiteout markers
// are read where they lie; guest owner and mode default to the host's unless an
// override is set later. It is how a build captures a run's kept upper layer.
func LayerFromDir(dir string) (*Layer, error) {
	l, err := NewLayer(dir)
	if err != nil {
		return nil, err
	}
	l.loadMeta()
	// Index any on-disk whiteout markers so Stat/IsWhiteout see them.
	filepath.WalkDir(dir, func(hp string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := filepath.Base(hp)
		if !strings.HasPrefix(base, core.WhiteoutPrefix) || base == core.OpaqueMarker {
			return nil
		}
		rel, _ := filepath.Rel(dir, filepath.Dir(hp))
		l.wh[clean(filepath.ToSlash(filepath.Join(rel, base[len(core.WhiteoutPrefix):])))] = true
		return nil
	})
	return l, nil
}

// ApplyTo materializes the layer onto the host directory root: it writes the
// layer's files, directories and symlinks and removes the paths its whiteouts
// delete, so root accumulates the layers applied to it across build steps.
func (l *Layer) ApplyTo(root string) error {
	// root carries a sidecar of its own for the guest owners and modes the host
	// files cannot hold (an unprivileged supervisor cannot chown; NTFS has no
	// modes): a later build step reads it back and a non-OCI run hydrates it.
	dst, err := NewLayer(root)
	if err != nil {
		return err
	}
	dst.loadMeta()
	links := map[uint64]string{} // layer inode -> first target materialized, to relink
	err = filepath.WalkDir(l.dir, func(hp string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(l.dir, hp)
		if err != nil || rel == "." {
			return err
		}
		name := filepath.ToSlash(rel)
		base := path.Base(name)
		parent := path.Dir(name)
		switch {
		case base == core.MetaFileName:
			return nil // internal sidecar
		case base == core.OpaqueMarker:
			os.RemoveAll(filepath.Join(root, filepath.FromSlash(parent)))
			dst.removeOverride(parent)
			return nil
		case strings.HasPrefix(base, core.WhiteoutPrefix):
			gone := path.Join(parent, base[len(core.WhiteoutPrefix):])
			os.RemoveAll(filepath.Join(root, filepath.FromSlash(gone)))
			dst.removeOverride(gone)
			return nil
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		fi, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.MkdirAll(target, fi.Mode().Perm()|0o700); err != nil {
				return err
			}
			if err := l.applyOverrideMode(target, name, true); err != nil {
				return err
			}
		case fi.Mode()&os.ModeSymlink != 0:
			tgt, err := os.Readlink(hp)
			if err != nil {
				return err
			}
			os.Remove(target)
			if err := os.Symlink(tgt, target); err != nil {
				return err
			}
		default:
			// Names that shared an inode in the layer stay hardlinks in root, so a
			// later build step sees the same link group, not independent copies.
			linked := false
			if id, nlink, ok := fileIdent(hp, fi); ok && nlink > 1 {
				if first, seen := links[id]; seen {
					os.Remove(target)
					if os.Link(first, target) == nil {
						linked = true // mode follows the shared inode
					}
				} else {
					links[id] = target
				}
			}
			if !linked {
				if err := copyFile(hp, target, fi.Mode().Perm()|0o600); err != nil {
					return err
				}
				if err := l.applyOverrideMode(target, name, false); err != nil {
					return err
				}
			}
		}
		l.carryMeta(dst, name)
		return nil
	})
	if err != nil {
		return err
	}
	return dst.SaveMeta()
}

// carryMeta copies what l records for name into dst's metadata, so it survives
// materialization where the host file cannot hold it: an owner other than the
// supervisor's, a mode below the owner floor or on a host with no POSIX modes,
// and a special node's or placeholder symlink's kind.
func (l *Layer) carryMeta(dst *Layer, name string) {
	cp := clean(name)
	l.mu.Lock()
	var o core.Override
	if p := l.over[cp]; p != nil {
		o = *p
	}
	l.mu.Unlock()
	dst.mu.Lock()
	*dst.ov(cp) = o
	dst.gc(cp)
	dst.mu.Unlock()
}

// applyOverrideMode restores a guest mode the host file could not carry (one
// below the owner-rw floor, such as 0400) onto a materialized path, keeping the
// owner bits the supervisor needs to read and traverse the result.
func (l *Layer) applyOverrideMode(target, name string, dir bool) error {
	l.mu.Lock()
	o := l.over[clean(name)]
	l.mu.Unlock()
	if o == nil || !o.HasMode {
		return nil
	}
	perm := os.FileMode(o.Mode & 0o777)
	if dir {
		perm |= 0o700
	} else {
		perm |= 0o400
	}
	return os.Chmod(target, perm)
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	os.Remove(dst)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
