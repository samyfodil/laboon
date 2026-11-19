//go:build windows

package sandbox

// upperChanged is a no-op on Windows: WinFS caches only the read-only lower
// layer's metadata, not the upper, so a mutation of the upper (a whiteout, a
// socket bind) needs no cache invalidation.
func (fs *dfs) upperChanged() {}
