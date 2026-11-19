//go:build darwin || linux || windows

package sandbox

import (
	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// hostRoot presents a host directory as the guest root, as a core.FileSystem, so
// Config.RootFS is the one root input and the sandbox takes no host path for the
// root. The parts that are inherently host-path-native — the darwin exec
// resolver, the overlay's writable upper and the image owner/mode sidecar —
// recover the directory with HostRootPath; everything else treats the root as the
// opaque FileSystem it is. Its own FileSystem methods delegate to a confined
// host-dir backend, so it is a usable filesystem if ever resolved directly.
type hostRoot struct {
	path string
	fs   core.FileSystem
}

// HostRoot presents the host directory path as a guest-root FileSystem. An image
// root uses it; a public hostfs.Dir mounted at "/" is the embedder equivalent.
func HostRoot(path string) core.FileSystem { return &hostRoot{path: path} }

// HostRootPath returns the host directory a root FileSystem names, if it is a
// host-directory root; ok is false for any other backend (in-memory, custom). A
// public hostfs.Dir mounted at "/" is recognized too, so WithMount("/",
// hostfs.Dir(dir)) gets the same host-directory root — read-only lower, ephemeral
// writable upper, metadata sidecar — the image root does.
func HostRootPath(fs core.FileSystem) (string, bool) {
	if hr, ok := fs.(*hostRoot); ok {
		return hr.path, true
	}
	if hd, ok := fs.(*hostfs.HostDirFS); ok {
		return hd.RootDir(), true
	}
	return "", false
}

func (h *hostRoot) backend() core.FileSystem {
	if h.fs == nil {
		h.fs = hostfs.NewHostDirFS(h.path, hostfs.NewRawHostFS(h.path))
	}
	return h.fs
}

func (h *hostRoot) Root() core.Node { return h.backend().Root() }
func (h *hostRoot) Lookup(d core.Node, name string) (core.Node, error) {
	return h.backend().Lookup(d, name)
}
func (h *hostRoot) ReadDir(d core.Node) ([]core.Dirent, error) { return h.backend().ReadDir(d) }
func (h *hostRoot) Create(d core.Node, name string, s core.CreateSpec) (core.Node, error) {
	return h.backend().Create(d, name, s)
}
func (h *hostRoot) Link(d core.Node, name string, t core.Node) (core.Node, error) {
	return h.backend().Link(d, name, t)
}
func (h *hostRoot) Remove(d core.Node, name string, isDir bool) error {
	return h.backend().Remove(d, name, isDir)
}
func (h *hostRoot) Rename(fd core.Node, from string, td core.Node, to string) error {
	return h.backend().Rename(fd, from, td, to)
}
