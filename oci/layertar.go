package oci

import (
	"archive/tar"
	"io"
	"os"
	"path"
	"strings"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// The OCI image-layer tar conventions: a deleted path is an empty .wh.<name>
// entry, and a directory that replaces its lower counterpart wholesale carries
// a .wh..wh..opq marker. These live here, in the OCI image-format layer, not in
// the vfs filesystem underneath it.
const (
	whPrefix = ".wh."
	whOpaque = ".wh..wh..opq"
)

// WriteTar serializes a layer's changes as an uncompressed OCI image layer tar:
// directories, regular files, symlinks and special nodes, with deletions as .wh.
// whiteout entries and a fully-replaced directory as an opaque marker. It reads
// the layer only through the abstract hostfs.ChangeSet — owner, mode (including
// bits an unprivileged host file cannot hold), hardlink relationships and
// content all come across that primitive, so the image format needs no concrete
// layer type. Modification times are zeroed, so a layer's bytes depend only on
// its contents and a rebuild is reproducible.
func WriteTar(cs hostfs.ChangeSet, w io.Writer) error {
	tw := tar.NewWriter(w)
	err := cs.Walk(func(c hostfs.Change, content io.Reader) error {
		return writeChange(tw, c, content)
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

func writeChange(tw *tar.Writer, c hostfs.Change, content io.Reader) error {
	a := c.Attr
	if a.Whiteout {
		return tw.WriteHeader(&tar.Header{Name: whName(c.Path), Typeflag: tar.TypeReg})
	}
	hdr := &tar.Header{Name: c.Path, Mode: int64(a.Mode & 0o7777), Uid: int(a.Uid), Gid: int(a.Gid)}
	switch {
	case c.LinkTo != "":
		hdr.Typeflag, hdr.Linkname = tar.TypeLink, c.LinkTo
	case a.Kind == core.Dir:
		hdr.Typeflag, hdr.Name = tar.TypeDir, c.Path+"/"
	case a.Kind == core.Symlink:
		hdr.Typeflag, hdr.Linkname = tar.TypeSymlink, a.Target
	case a.Kind == core.Fifo:
		hdr.Typeflag = tar.TypeFifo
	case a.Kind == core.Blockdev:
		hdr.Typeflag = tar.TypeBlock
	case a.Kind == core.Chardev || a.Kind == core.Socket:
		hdr.Typeflag = tar.TypeChar
	default:
		hdr.Typeflag = tar.TypeReg
	}
	if t := hdr.Typeflag; t == tar.TypeChar || t == tar.TypeBlock || t == tar.TypeFifo {
		hdr.Devmajor = int64(a.Rdev>>8&0xfff | (a.Rdev >> 32 &^ 0xfff))
		hdr.Devminor = int64(a.Rdev&0xff | (a.Rdev >> 12 &^ 0xff))
	}
	if hdr.Typeflag == tar.TypeReg && content != nil {
		data, err := io.ReadAll(content)
		if err != nil {
			return err
		}
		hdr.Size = int64(len(data))
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	} else if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if a.Opaque {
		return tw.WriteHeader(&tar.Header{Name: path.Join(c.Path, whOpaque), Typeflag: tar.TypeReg})
	}
	return nil
}

// whName is the OCI whiteout marker for a deleted path: .wh.<base> in its parent.
func whName(p string) string {
	return path.Join(path.Dir(p), whPrefix+path.Base(p))
}

// ReadTar extracts an OCI image layer tar into dir and opens it as a vfs layer.
// Extraction is confined to dir through an os.Root, so a symlink in the archive
// cannot redirect a later entry's write outside it; whiteout and opaque markers
// land on disk as the layer's own deletions, and each entry's guest owner, mode
// and special-node kind are recorded in the layer's metadata afterward.
func ReadTar(r io.Reader, dir string) (*hostfs.Layer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	type meta struct {
		name            string
		mode, uid, gid  uint32
		kind            core.Kind
		special, setmod bool
		rdev            uint64
		link            string // a symlink's target
	}
	var metas []meta
	links := map[string]string{} // symlinks made after extraction, by name
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			root.Close()
			return nil, err
		}
		name, ok := clean(hdr.Name)
		if !ok {
			continue
		}
		if parent := path.Dir(name); parent != "." {
			root.MkdirAll(parent, 0o755)
		}
		mode, uid, gid := uint32(hdr.Mode)&0o7777, uint32(hdr.Uid), uint32(hdr.Gid)
		m := meta{name: name, mode: mode, uid: uid, gid: gid}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, core.HostMode(mode, true)); err != nil {
				root.Close()
				return nil, err
			}
			m.setmod = true
		case tar.TypeSymlink:
			// Made through the layer below, as the host keeps symlinks.
			root.Remove(name)
			m.link = hdr.Linkname
			links[name] = hdr.Linkname
		case tar.TypeLink:
			root.Remove(name)
			ln, _ := clean(hdr.Linkname)
			if t, ok := links[ln]; ok {
				m.link = t // a hard link to a symlink is that symlink again
				links[name] = t
				break
			}
			if err := root.Link(ln, name); err != nil {
				root.Close()
				return nil, err
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			f, err := root.Create(name)
			if err != nil {
				root.Close()
				return nil, err
			}
			f.Close()
			m.special = true
			m.rdev = uint64(hdr.Devminor&0xff | hdr.Devmajor<<8)
			switch hdr.Typeflag {
			case tar.TypeFifo:
				m.kind = core.Fifo
			case tar.TypeBlock:
				m.kind = core.Blockdev
			default:
				m.kind = core.Chardev
			}
		default: // regular file, including whiteout and opaque markers
			f, err := root.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, core.HostMode(mode, false))
			if err != nil {
				root.Close()
				return nil, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				root.Close()
				return nil, err
			}
			if err := f.Close(); err != nil {
				root.Close()
				return nil, err
			}
			m.setmod = true
		}
		if !strings.HasPrefix(path.Base(name), whPrefix) {
			metas = append(metas, m)
		}
	}
	root.Close()

	// Open the extracted directory as a layer (this indexes the .wh. markers on
	// disk), then record the metadata the host files cannot carry.
	l, err := hostfs.LayerFromDir(dir)
	if err != nil {
		return nil, err
	}
	for _, m := range metas {
		switch {
		case m.link != "":
			if err := l.Symlink(m.name, m.link, 0o777); err != nil {
				return nil, err
			}
		case m.special:
			l.Special(m.name, m.kind, m.rdev, m.mode)
		case m.setmod:
			l.SetMode(m.name, m.mode)
		}
		if m.uid != 0 || m.gid != 0 {
			l.SetOwner(m.name, m.uid, m.gid)
		}
	}
	return l, nil
}
