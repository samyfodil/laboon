//go:build windows

package sandbox

import "github.com/samyfodil/laboon/filesystems/hostfs"

// seedLowerOwners copies the lower layer's non-root owners from the host
// backend's shared sidecar into this run's metadata table; files without one
// are root's.
func seedLowerOwners(fs *dfs) {
	for k, o := range hostfs.LowerOwners() {
		fs.ov.update(ikey{k[0], k[1]}, func(m *imeta) { m.uid, m.gid, m.hasOwner = o[0], o[1], true })
	}
}
