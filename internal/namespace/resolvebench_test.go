package namespace

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	. "github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
)

// BenchmarkResolveStat times a stat as the sandbox does one, a following
// Walk.Path and then an unfollowed Resolve of the path it returns, over
// overlay(dir, dir) at depth 7. lookups/op counts the filesystem lookups the
// cache did not save: 0 is a hit on both resolutions.
func BenchmarkResolveStat(b *testing.B) {
	const dir = "/d1/d2/d3/d4/d5/d6"
	lowerDir := b.TempDir()
	for _, d := range []string{dir, "/scratch"} {
		if err := os.MkdirAll(filepath.Join(lowerDir, d), 0o755); err != nil {
			b.Fatal(err)
		}
	}
	for i := 0; i < 64; i++ {
		if err := os.WriteFile(filepath.Join(lowerDir, dir, fmt.Sprint("f", i)), []byte("x"), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	ofs := overlayfs.OverlayFS(newTestDirFS(lowerDir), newTestDirFS(b.TempDir()))
	c := &countFS{FileSystem: ofs, g: ofs.(DirGenerational)}
	ns := NewNamespace(c)
	dloc, err := ns.Resolve(dir, true)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := ofs.Create(dloc.Node, "w", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		b.Fatal(err)
	}

	stat := func(b *testing.B, w Walk, p string) {
		gp, err := w.Path(ns, p)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ns.Resolve(gp, false); err != nil {
			b.Fatal(err)
		}
	}
	run := func(name string, w Walk, names func(i int) string, between func()) {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < 64; i++ {
				stat(b, w, names(i))
			}
			c.lookups.Store(0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if between != nil {
					between()
				}
				stat(b, w, names(i%64))
			}
			b.ReportMetric(float64(c.lookups.Load())/float64(b.N), "lookups/op")
		})
	}
	abs := func(i int) string { return fmt.Sprint(dir, "/f", i) }
	rel := func(i int) string { return fmt.Sprint("f", i) }
	follow := Walk{FollowLast: true}
	fromDir := Walk{Start: dir, FollowLast: true}

	run("absolute", follow, abs, nil)
	run("relative", fromDir, rel, nil)
	run("afterWrite", follow, abs, func() {
		loc, err := ns.Resolve(dir+"/w", false)
		if err != nil {
			b.Fatal(err)
		}
		f, err := loc.Node.Open(os.O_WRONLY | os.O_APPEND)
		if err != nil {
			b.Fatal(err)
		}
		f.Close()
	})
	createIn := func(d string) func() {
		return func() {
			dloc, err := ns.Resolve(d, true)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := ofs.Create(dloc.Node, "t", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
				b.Fatal(err)
			}
			if dloc, err = ns.Resolve(d, true); err != nil {
				b.Fatal(err)
			}
			if err := ofs.Remove(dloc.Node, "t", false); err != nil {
				b.Fatal(err)
			}
		}
	}
	run("afterCreate", follow, abs, createIn(dir))
	run("afterCreateElsewhere", follow, abs, createIn("/scratch"))
}
