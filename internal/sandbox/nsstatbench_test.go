//go:build linux

package sandbox

import (
	"os"
	"path"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/internal/namespace"
	"github.com/samyfodil/laboon/internal/vfs"
)

// countFS wraps a hostFS and counts hLstat calls, to measure how many host
// stats a path resolution costs.
type countFS struct {
	hostFS
	lstats atomic.Int64
}

func (c *countFS) hLstat(p string) (os.FileInfo, error) {
	c.lstats.Add(1)
	return c.hostFS.hLstat(p)
}

// benchStatSetup builds a realistic deep lower tree (no upper writes) and the
// shared-cache Namespace over it, the composition the live stat path would use.
func benchStatSetup(b *testing.B, depth int) (*countFS, *namespace.Namespace, string, string) {
	b.Helper()
	dir := b.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	// A deep path like a musl/node lib: /d0/d1/.../dN/leaf.
	gp := "/"
	hostdir := lower
	for i := 0; i < depth; i++ {
		gp = path.Join(gp, "d")
		hostdir = filepath.Join(hostdir, "d")
	}
	if err := os.MkdirAll(hostdir, 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.MkdirAll(upper, 0o755); err != nil {
		b.Fatal(err)
	}
	gp = path.Join(gp, "leaf")
	if err := os.WriteFile(filepath.Join(hostdir, "leaf"), []byte("x"), 0o644); err != nil {
		b.Fatal(err)
	}
	c := &countFS{hostFS: newHostFS(lower, upper, "")}
	ns := namespace.NewNamespace(vfs.NewOverlayFSWithMeta(core.NewMetaStore(),
		newHostDirFS(lower, c), newHostDirFS(upper, c)))
	return c, ns, gp, lower
}

// BenchmarkStatDirect is today's fast path: one whole-path host lstat.
func BenchmarkStatDirect(b *testing.B) {
	c, _, gp, lower := benchStatSetup(b, 6)
	hp := filepath.Join(lower, filepath.FromSlash(gp))
	c.lstats.Store(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.hLstat(hp); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(c.lstats.Load())/float64(b.N), "hlstat/op")
}

// BenchmarkStatResolve is the homogeneous path: component-walk resolve + Stat.
func BenchmarkStatResolve(b *testing.B) {
	c, ns, gp, _ := benchStatSetup(b, 6)
	c.lstats.Store(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loc, err := ns.Resolve(gp, false)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := loc.Node.Stat(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(c.lstats.Load())/float64(b.N), "hlstat/op")
}
