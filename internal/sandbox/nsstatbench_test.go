package sandbox

import (
	"os"
	"path"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
	"github.com/samyfodil/laboon/internal/namespace"
)

// countFS wraps a FileSystem and counts the Lookup calls a resolution makes
// through it, a proxy for how many host stats a component-walk resolve costs
// against the one whole-path host lstat of the direct fast path.
type countFS struct {
	core.FileSystem
	lookups atomic.Int64
}

func (c *countFS) Lookup(dir core.Node, name string) (core.Node, error) {
	c.lookups.Add(1)
	return c.FileSystem.Lookup(dir, name)
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
	c := &countFS{FileSystem: overlayfs.OverlayFS(
		hostfs.NewHostDirFS(lower, hostfs.NewHostFS(lower, upper, "")),
		hostfs.NewHostDirFS(upper, hostfs.NewHostFS(lower, upper, "")))}
	ns := namespace.NewNamespace(c)
	return c, ns, gp, lower
}

// BenchmarkStatDirect is the old fast path: one whole-path host lstat.
func BenchmarkStatDirect(b *testing.B) {
	_, _, gp, lower := benchStatSetup(b, 6)
	hp := filepath.Join(lower, filepath.FromSlash(gp))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := os.Lstat(hp); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStatResolve is the homogeneous path: component-walk resolve + Stat.
func BenchmarkStatResolve(b *testing.B) {
	c, ns, gp, _ := benchStatSetup(b, 6)
	c.lookups.Store(0)
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
	b.ReportMetric(float64(c.lookups.Load())/float64(b.N), "lookup/op")
}
