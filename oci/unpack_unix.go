//go:build !windows

package oci

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// Unpack extracts a flattened image tar (whiteouts already applied) into
// dir, which must exist.
func Unpack(r io.Reader, dir string, maxSize int64) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	type link struct{ target, name string }
	var links []link
	dirModes := map[string]fs.FileMode{}
	// A non-root owner and the setuid/setgid/sticky bits cannot be set on the host
	// (laboon runs unprivileged, and the modes are masked off below), so record
	// them in the sidecar the run hydrates into the guest's inode table.
	overrides := map[string]*core.Override{}
	var total int64

	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name, ok := clean(h.Name)
		if !ok {
			continue
		}
		if special := h.Mode & 0o7000; h.Uid != 0 || h.Gid != 0 || special != 0 {
			o := &core.Override{}
			if h.Uid != 0 || h.Gid != 0 {
				o.HasOwner, o.Uid, o.Gid = true, uint32(h.Uid), uint32(h.Gid)
			}
			if special != 0 {
				o.HasMode, o.Mode = true, uint32(h.Mode&0o7777)
			}
			overrides[name] = o
		}
		// Parents may arrive after children; create them traversable
		// and give directories their real modes at the end.
		if dir := path.Dir(name); dir != "." {
			if err := root.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		mode := fs.FileMode(h.Mode) & fs.ModePerm // drops setuid, setgid, sticky
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			dirModes[name] = mode
		case tar.TypeReg:
			total += h.Size
			if total > maxSize {
				return errTooLarge
			}
			if err := writeFile(root, name, tr, mode); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		case tar.TypeSymlink:
			if err := root.Symlink(h.Linkname, name); err != nil && !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("%s: %w", name, err)
			}
		case tar.TypeLink:
			target, ok := clean(h.Linkname)
			if ok {
				// The target may come later in the stream.
				links = append(links, link{target, name})
			}
		default:
			// Devices, FIFOs and the like: a read-only sandbox has no use
			// for them, and creating devices is exactly what to refuse.
		}
	}
	for _, l := range links {
		if err := root.Link(l.target, l.name); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("link %s: %w", l.name, err)
		}
	}
	for name, mode := range dirModes {
		if err := root.Chmod(name, mode|0o100); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return hostfs.SaveOverrides(dir, overrides)
}

func writeFile(root *os.Root, name string, r io.Reader, mode fs.FileMode) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return root.Chmod(name, mode)
}

// LookPath finds a program in rootfs the way a shell would, using the PATH
// in env. A name with a slash is used as is.
func LookPath(rootfs, file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		return file, nil
	}
	dirs := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			dirs = v
		}
	}
	for _, d := range filepath.SplitList(dirs) {
		p := path.Join("/", d, file)
		if hp, ok := resolveIn(rootfs, p); ok {
			if st, err := os.Lstat(hp); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%s: not found in image PATH", file)
}

// resolveIn is the host path of guest path p in rootfs, its symlinks followed
// as the guest sees them: an absolute target is relative to rootfs, and ".."
// stops at its top. os.Root would refuse the absolute links busybox images
// are made of.
func resolveIn(rootfs, p string) (string, bool) {
	rest := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	cur := "/"
	for hops := 0; len(rest) > 0; {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, c)
		hp := filepath.Join(rootfs, filepath.FromSlash(next))
		st, err := os.Lstat(hp)
		if err != nil {
			return "", false
		}
		if st.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if hops++; hops > 40 {
			return "", false
		}
		t, err := os.Readlink(hp)
		if err != nil {
			return "", false
		}
		if path.IsAbs(t) {
			cur = "/"
		}
		rest = append(strings.Split(t, "/"), rest...)
	}
	return filepath.Join(rootfs, filepath.FromSlash(cur)), true
}
