//go:build darwin || linux

package hostfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCachedFSLayers(t *testing.T) {
	tmp := filepath.Clean(os.TempDir())
	for _, c := range []struct {
		root, upper, p string
		lower, inUp    bool
	}{
		{"/", "", "/etc/passwd", true, false},
		{"/", "", tmp + "/lc-run-1/x", false, false},
		{"/", "", "/tmp/lcn.1/s", false, false},
		{tmp, "", tmp + "/lc-run-1/x", false, false},
		{tmp + "/t/root", "", tmp + "/t/root/etc", true, false},
		{tmp + "/t/root", "", tmp + "/t/root", true, false},
		{"/r", "/up", "/r", true, false},
		{"/r", "/up", "/r/a", true, false},
		{"/r", "/up", "/up", false, true},
		{"/r", "/up", "/up/a", false, true},
		{"/r", "/up", "/rx", false, false},
	} {
		fs := newCachedFS(NewRawHostFS(c.root), c.root, c.upper).(*CachedFS)
		if got := fs.inLower(c.p); got != c.lower {
			t.Errorf("root %s upper %s: inLower(%s) = %v", c.root, c.upper, c.p, got)
		}
		if got := fs.inUpper(c.p); got != c.inUp {
			t.Errorf("root %s upper %s: inUpper(%s) = %v", c.root, c.upper, c.p, got)
		}
	}
}
