package oci

import (
	"fmt"
	"path"
	"strings"

	"github.com/samyfodil/laboon/core"
)

// LookPathFS resolves file to an absolute path inside fsys, as a shell would:
// a file with a slash is taken as given, otherwise each PATH directory from env
// is tried. A candidate matches when it is a regular file, following symlinks
// (an image's /bin/sh -> busybox), so the entrypoint resolved from an image's
// config and PATH is found without extracting the image. The sandbox re-resolves
// the path at exec; this is only the PATH probe.
func LookPathFS(fsys core.FileSystem, file string, env []string) (string, error) {
	if file == "" {
		return "", fmt.Errorf("oci: empty program name")
	}
	if strings.ContainsRune(file, '/') {
		if execReady(fsys, file) {
			return abs(file), nil
		}
		return "", fmt.Errorf("oci: %s: no such file in image", file)
	}
	for _, dir := range pathDirs(env) {
		cand := path.Join(dir, file)
		if execReady(fsys, cand) {
			return abs(cand), nil
		}
	}
	return "", fmt.Errorf("oci: %s: not found in image PATH", file)
}

func abs(p string) string { return "/" + strings.Trim(path.Clean("/"+p), "/") }

func pathDirs(env []string) []string {
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok && v != "" {
			return strings.Split(v, ":")
		}
	}
	return []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
}

func execReady(fsys core.FileSystem, p string) bool {
	n, ok := walkFS(fsys, p, 0)
	return ok && n.Kind() == core.Reg
}

// walkFS resolves p from fsys's root a component at a time, following symlinks
// (bounded), and returns the final node.
func walkFS(fsys core.FileSystem, p string, hops int) (core.Node, bool) {
	if hops > 40 {
		return nil, false
	}
	parts := strings.Split(strings.Trim(path.Clean("/"+p), "/"), "/")
	cur := fsys.Root()
	for i, name := range parts {
		if name == "" {
			continue
		}
		if cur.Kind() != core.Dir {
			return nil, false
		}
		c, err := fsys.Lookup(cur, name)
		if err != nil {
			return nil, false
		}
		if c.Kind() == core.Symlink {
			tgt, err := c.Readlink()
			if err != nil {
				return nil, false
			}
			base := "/" + strings.Join(parts[:i], "/")
			if path.IsAbs(tgt) {
				base = "/"
			}
			full := path.Join(base, tgt)
			if rest := parts[i+1:]; len(rest) > 0 {
				full = path.Join(full, strings.Join(rest, "/"))
			}
			return walkFS(fsys, full, hops+1)
		}
		cur = c
	}
	return cur, true
}
