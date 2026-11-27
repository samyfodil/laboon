package namespace

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	. "github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
)

// TestResolveCacheInvalidation checks that the path-resolution cache never
// serves a result the overlay has since changed: a removed file must stop
// resolving, a newly created one must appear, and a copy-up must be reflected
// (the cache must not hand back a stale lower-layer node).
func TestResolveCacheInvalidation(t *testing.T) {
	lowerDir := t.TempDir()
	upperDir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(lowerDir, "a"), 0o755))
	must(os.WriteFile(filepath.Join(lowerDir, "a/f"), []byte("lower"), 0o644))
	must(os.WriteFile(filepath.Join(lowerDir, "a/g"), []byte("lower-g"), 0o644))

	ofs := overlayfs.OverlayFS(newTestDirFS(lowerDir), newTestDirFS(upperDir))
	ns := NewNamespace(ofs)
	if ns.genOf == nil {
		t.Fatal("overlay is not generational; cache would be disabled")
	}

	adir, err := ns.Resolve("/a", true)
	must(err)

	// Prime the cache for all three paths.
	if _, err := ns.Resolve("/a/f", true); err != nil {
		t.Fatalf("prime /a/f: %v", err)
	}
	if _, err := ns.Resolve("/a/new", true); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("/a/new should be absent: %v", err)
	}

	// Create /a/new via the overlay: it must now resolve (the cached miss is
	// stale once Create bumps the generation).
	if _, err := ofs.Create(adir.Node, "new", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := ns.Resolve("/a/new", true); err != nil {
		t.Fatalf("created file not visible (stale negative/gen): %v", err)
	}

	// Remove the lower-only /a/f: a cached positive must not survive.
	if err := ofs.Remove(adir.Node, "f", false); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := ns.Resolve("/a/f", true); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("removed file still resolves — STALE POSITIVE CACHE: %v", err)
	}

	// Copy-up of /a/g: resolve it, copy it up (a metadata change does), then a
	// write through a freshly resolved node must land in the top layer and
	// leave the lower untouched — proving the cache did not hand back a stale
	// lower-layer node.
	loc, err := ns.Resolve("/a/g", false)
	must(err)
	mode := uint32(0o644)
	if err := loc.Node.SetAttr(AttrUpdate{Mode: &mode}); err != nil { // triggers copy-up + gen bump
		t.Fatalf("copy-up: %v", err)
	}
	loc2, err := ns.Resolve("/a/g", true)
	must(err)
	w, err := loc2.Node.Open(os.O_WRONLY | os.O_TRUNC)
	must(err)
	if _, err := w.WriteAt([]byte("TOP"), 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()
	if b, _ := os.ReadFile(filepath.Join(upperDir, "a/g")); string(b) != "TOP" {
		t.Fatalf("write did not land in the upper (stale node from cache): %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(lowerDir, "a/g")); string(b) != "lower-g" {
		t.Fatalf("lower mutated: %q", b)
	}
}

// TestResolveCacheConcurrent stresses the cache under concurrent resolves and
// mutations (copy-up, create, remove) of the same paths, to catch a data race
// on a shared cached node or the generation check. Run with -race.
func TestResolveCacheConcurrent(t *testing.T) {
	lowerDir := t.TempDir()
	upperDir := t.TempDir()
	for i := 0; i < 20; i++ {
		d := filepath.Join(lowerDir, "d")
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "f"+string(rune('a'+i))), []byte("x"), 0o644)
	}
	ofs := overlayfs.OverlayFS(newTestDirFS(lowerDir), newTestDirFS(upperDir))
	ns := NewNamespace(ofs)
	dloc, _ := ns.Resolve("/d", true)

	done := make(chan struct{})
	go func() { // mutator: copy-up / create / remove, bumping the generation
		for i := 0; i < 2000; i++ {
			n := string(rune('a' + i%20))
			if loc, err := ns.Resolve("/d/f"+n, false); err == nil {
				mode := uint32(0o644)
				loc.Node.SetAttr(AttrUpdate{Mode: &mode})
			}
			ofs.Create(dloc.Node, "new"+n, CreateSpec{Kind: Reg, Mode: 0o644})
			ofs.Remove(dloc.Node, "new"+n, false)
		}
		close(done)
	}()
	for r := 0; r < 4; r++ { // resolvers hammering the same paths
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				for i := 0; i < 20; i++ {
					loc, err := ns.Resolve("/d/f"+string(rune('a'+i)), true)
					if err == nil {
						loc.Node.Stat() // read node fields concurrently with copy-up
					}
				}
			}
		}()
	}
	<-done
}

// countFS counts its root's lookups and makes the lookup of the name doubt a
// miss that may not hold.
type countFS struct {
	FileSystem
	g       DirGenerational
	lookups atomic.Int64
	doubt   atomic.Pointer[string]
}

func (c *countFS) Gen() uint64              { return c.g.Gen() }
func (c *countFS) Touch()                   { c.g.Touch() }
func (c *countFS) Epoch() uint64            { return c.g.Epoch() }
func (c *countFS) DirGen(dir string) uint64 { return c.g.DirGen(dir) }

func (c *countFS) Lookup(dir Node, name string) (Node, error) {
	c.lookups.Add(1)
	if d := c.doubt.Load(); d != nil && *d == name {
		return nil, MaybeNotExist("lookup", name, errors.New("host refused"))
	}
	return c.FileSystem.Lookup(dir, name)
}

// TestResolveCacheMiss checks a definite miss is cached, for Resolve and for
// Walk.Path, until the overlay changes, and a doubtful one never is.
func TestResolveCacheMiss(t *testing.T) {
	lowerDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(lowerDir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	ofs := overlayfs.OverlayFS(newTestDirFS(lowerDir), newTestDirFS(t.TempDir()))
	c := &countFS{FileSystem: ofs, g: ofs.(DirGenerational)}
	ns := NewNamespace(c)
	walk := Walk{FollowLast: true}

	for i := 0; i < 3; i++ {
		if _, err := ns.Resolve("/a/nope", true); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("/a/nope: %v", err)
		}
		if gp, err := walk.Path(ns, "/a/nope"); err != nil || gp != "/a/nope" {
			t.Fatalf("walk /a/nope = %q, %v", gp, err)
		}
		if _, err := walk.Path(ns, "/no/such"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("walk /no/such: %v", err)
		}
		if i == 0 {
			c.lookups.Store(0)
		}
	}
	if n := c.lookups.Load(); n != 0 {
		t.Errorf("cached misses still made %d lookups", n)
	}

	adir, err := ns.Resolve("/a", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ofs.Create(adir.Node, "nope", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := ns.Resolve("/a/nope", true); err != nil {
		t.Fatalf("created /a/nope still missing: %v", err)
	}

	name := "maybe"
	c.doubt.Store(&name)
	if _, err := ns.Resolve("/maybe", true); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("doubtful /maybe: %v", err)
	}
	if _, err := walk.Path(ns, "/maybe/x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("doubtful walk /maybe/x: %v", err)
	}
	c.doubt.Store(nil)
	if err := os.Mkdir(filepath.Join(lowerDir, "maybe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ns.Resolve("/maybe", true); err != nil {
		t.Errorf("a doubtful miss was cached: %v", err)
	}
	if gp, err := walk.Path(ns, "/maybe/x"); err != nil || gp != "/maybe/x" {
		t.Errorf("a doubtful walk was cached: %q, %v", gp, err)
	}
}
