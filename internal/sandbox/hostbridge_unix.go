//go:build darwin || linux

package sandbox

import "github.com/samyfodil/laboon/filesystems/hostfs"

// upperChanged tells the host-dir cache that something outside the FileSystem
// backend created a file in the upper layer (a unix socket's bind), so the
// lookup cache must not serve a stale miss for it.
func (fs *dfs) upperChanged() {
	if c, ok := fs.hostFS.(*hostfs.CachedFS); ok {
		c.Changed()
	}
}
