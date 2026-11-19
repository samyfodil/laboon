//go:build darwin || linux

package hostfs

import (
	"os"
	"path/filepath"
	"testing"
)

// cacheSetup returns the cached host access over a lower and an upper layer.
func cacheSetup(t *testing.T) (*CachedFS, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir()) // the host walk refuses symlinks, as macOS's /var
	if err != nil {
		t.Fatal(err)
	}
	lower, upper := filepath.Join(dir, "lower"), filepath.Join(dir, "upper")
	for _, d := range []string{lower, upper} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return NewHostFS(lower, upper, "").(*CachedFS), upper
}

// TestCacheSeesMknodSocket checks a socket made with mknod in the upper layer
// ends the cache's memory of its path as missing.
func TestCacheSeesMknodSocket(t *testing.T) {
	c, upper := cacheSetup(t)
	p := filepath.Join(upper, "s")
	if _, err := c.hLstat(p); err == nil {
		t.Fatal("the socket exists before it is made")
	}
	if err := c.hMksock(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.hLstat(p); err != nil {
		t.Fatalf("the socket is missing once made: %v", err)
	}
}

// TestCacheForgetsRenamedUpper checks a lookup's cached identity of an upper
// path is dropped when the name moves.
func TestCacheForgetsRenamedUpper(t *testing.T) {
	c, upper := cacheSetup(t)
	p, q := filepath.Join(upper, "a"), filepath.Join(upper, "b")
	if err := c.hMkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := c.hLstatID(p); err != nil {
		t.Fatal(err)
	}
	if err := c.hRename(p, q, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.hLstatID(p); err == nil {
		t.Fatal("the old name is still found after the rename")
	}
	if _, err := c.hLstatID(q); err != nil {
		t.Fatalf("the new name is not found: %v", err)
	}
}
