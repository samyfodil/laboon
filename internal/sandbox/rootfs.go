//go:build darwin || linux || windows

package sandbox

import "github.com/samyfodil/laboon/internal/vfs"

// hostRoot presents a host directory as the guest root, as a vfs.FileSystem, so
// Config.RootFS is the one root input and the sandbox takes no host path for the
// root. The parts that are inherently host-path-native — the darwin exec
// resolver, the overlay's writable upper and the image owner/mode sidecar —
// recover the directory with HostRootPath; everything else treats the root as the
// opaque FileSystem it is. Its own FileSystem methods delegate to a confined
// host-dir backend, so it is a usable filesystem if ever resolved directly.
type hostRoot struct {
	path string
	fs   vfs.FileSystem
}

// HostRoot presents the host directory path as a guest-root FileSystem. WithRoot
// and an image root use it, so a host directory reaches the sandbox as a
// FileSystem like any other backend.
func HostRoot(path string) vfs.FileSystem { return &hostRoot{path: path} }

// HostRootPath returns the host directory a root FileSystem names, if it is a
// host-directory root; ok is false for any other backend (in-memory, custom).
func HostRootPath(fs vfs.FileSystem) (string, bool) {
	if hr, ok := fs.(*hostRoot); ok {
		return hr.path, true
	}
	return "", false
}

func (h *hostRoot) backend() vfs.FileSystem {
	if h.fs == nil {
		h.fs = newHostDirFS(h.path, newRawHostFS(h.path))
	}
	return h.fs
}

func (h *hostRoot) Root() vfs.Node { return h.backend().Root() }
func (h *hostRoot) Lookup(d vfs.Node, name string) (vfs.Node, error) {
	return h.backend().Lookup(d, name)
}
func (h *hostRoot) ReadDir(d vfs.Node) ([]vfs.Dirent, error) { return h.backend().ReadDir(d) }
func (h *hostRoot) Create(d vfs.Node, name string, s vfs.CreateSpec) (vfs.Node, error) {
	return h.backend().Create(d, name, s)
}
func (h *hostRoot) Link(d vfs.Node, name string, t vfs.Node) (vfs.Node, error) {
	return h.backend().Link(d, name, t)
}
func (h *hostRoot) Remove(d vfs.Node, name string, isDir bool) error {
	return h.backend().Remove(d, name, isDir)
}
func (h *hostRoot) Rename(fd vfs.Node, from string, td vfs.Node, to string) error {
	return h.backend().Rename(fd, from, td, to)
}
