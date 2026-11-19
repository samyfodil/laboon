package oci

import (
	"archive/tar"
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samyfodil/laboon/filesystems/winfs"
)

// On Windows a rootfs is laid out for the sandbox's NTFS host filesystem
// (internal/winfs): names NTFS forbids are escaped, directories are
// case-sensitive where the volume allows it, a symlink is a file holding its
// target, and modes, owners and file types go to <dir>.lcmeta.

const (
	sIFDIR = 0o040000
	sIFREG = 0o100000
	sIFLNK = 0o120000
)

// hostRel is the host path, relative to the rootfs, of guest path name.
func hostRel(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = winfs.EscapeName(p)
	}
	return filepath.Join(parts...)
}

// Unpack extracts a flattened image tar (whiteouts already applied) into
// dir, which must exist and be empty, and writes dir.lcmeta.
func Unpack(r io.Reader, dir string, maxSize int64) error {
	winfs.SetCaseSensitive(dir) // else lookups check exact names
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	type link struct{ target, name string }
	var links []link
	meta := map[string]winfs.Entry{}
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
		host := hostRel(name)
		if d := filepath.Dir(host); d != "." {
			if err := root.MkdirAll(d, 0o755); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		// setuid and setgid are dropped, as on Linux; the sticky bit stays.
		perm := uint32(h.Mode) & 0o1777
		e := winfs.Entry{Uid: uint32(h.Uid), Gid: uint32(h.Gid), Path: name}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(host, 0o755); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			e.Mode = sIFDIR | perm
		case tar.TypeReg:
			total += h.Size
			if total > maxSize {
				return errTooLarge
			}
			if err := writeFile(root, host, tr); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			e.Mode = sIFREG | perm
		case tar.TypeSymlink:
			if err := writeFile(root, host, strings.NewReader(h.Linkname)); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			e.Mode = sIFLNK | 0o777
		case tar.TypeLink:
			if target, ok := clean(h.Linkname); ok {
				links = append(links, link{target, name})
			}
			continue
		default:
			continue // devices and FIFOs, as on Linux
		}
		if e.Valid() {
			meta[name] = e
		}
	}
	for _, l := range links {
		err := root.Link(hostRel(l.target), hostRel(l.name))
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("link %s: %w", l.name, err)
		}
		if e, ok := meta[l.target]; ok && err == nil {
			e.Path = l.name
			if e.Valid() {
				meta[l.name] = e
			}
		}
	}
	return writeMeta(dir+winfs.MetaSuffix, meta)
}

func writeFile(root *os.Root, name string, r io.Reader) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeMeta(p string, meta map[string]winfs.Entry) error {
	names := make([]string, 0, len(meta))
	for n := range meta {
		names = append(names, n)
	}
	slices.Sort(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(meta[n].String())
		b.WriteByte('\n')
	}
	return os.WriteFile(p, []byte(b.String()), 0o600)
}

func readMeta(rootfs string) map[string]winfs.Entry {
	m := map[string]winfs.Entry{}
	f, err := os.Open(rootfs + winfs.MetaSuffix)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if e, ok := winfs.ParseEntry(sc.Text()); ok {
			m[e.Path] = e
		}
	}
	return m
}

// LookPath finds a program in rootfs the way a shell would, using the PATH
// in env. A name with a slash is used as is. Symlinks are resolved inside
// the rootfs, from their stored targets.
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
	meta := readMeta(rootfs)
	for _, d := range strings.Split(dirs, ":") {
		p := path.Join("/", d, file)
		if mode, ok := resolveMode(rootfs, meta, p); ok && mode&0o170000 == sIFREG && mode&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in image PATH", file)
}

// resolveMode follows guest path p through stored symlinks and returns the
// mode of what it names. A file without an entry is 0755, as the sandbox
// reads it.
func resolveMode(rootfs string, meta map[string]winfs.Entry, p string) (uint32, bool) {
	rest := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	cur := ""
	for hops := 0; len(rest) > 0; {
		c := rest[0]
		rest = rest[1:]
		next := path.Join(cur, c)
		if c == ".." {
			next = path.Dir(cur)
			if next == "." {
				next = ""
			}
		}
		if next == "" || c == "." {
			cur = next
			continue
		}
		st, err := os.Lstat(filepath.Join(rootfs, hostRel(next)))
		if err != nil {
			return 0, false
		}
		mode := uint32(sIFREG | 0o755)
		if st.IsDir() {
			mode = sIFDIR | 0o755
		}
		if e, ok := meta[next]; ok {
			mode = e.Mode
		}
		if mode&0o170000 == sIFLNK {
			if hops++; hops > 40 {
				return 0, false
			}
			t, err := os.ReadFile(filepath.Join(rootfs, hostRel(next)))
			if err != nil {
				return 0, false
			}
			target := string(t)
			if strings.HasPrefix(target, "/") {
				cur = ""
			}
			rest = append(strings.Split(strings.Trim(target, "/"), "/"), rest...)
			continue
		}
		if len(rest) == 0 {
			return mode, true
		}
		if mode&0o170000 != sIFDIR {
			return 0, false
		}
		cur = next
	}
	return sIFDIR | 0o755, true
}
