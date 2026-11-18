package vfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
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

	ofs := NewOverlayFS(newTestDirFS(lowerDir), newTestDirFS(upperDir))
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

	// Create /a/new via the overlay: it must now resolve (negatives aren't
	// cached, and Create bumps the generation regardless).
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

	// Copy-up of /a/g: resolve it (owner = lower), write through it, then the
	// next resolve must report the top layer as owner, not a cached lower node.
	loc, err := ns.Resolve("/a/g", false)
	must(err)
	g := loc.Node.(*ovNode)
	top := len(ofs.(*overlayFS).layers) - 1
	if g.owner == top {
		t.Fatal("precondition: /a/g should start in the lower layer")
	}
	if _, err := g.WritableUnderlying(); err != nil { // triggers copy-up
		t.Fatalf("copy-up: %v", err)
	}
	loc2, err := ns.Resolve("/a/g", false)
	must(err)
	if got := loc2.Node.(*ovNode).owner; got != top {
		t.Fatalf("copy-up not reflected — STALE NODE FROM CACHE: owner=%d want %d", got, top)
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
	ofs := NewOverlayFS(newTestDirFS(lowerDir), newTestDirFS(upperDir))
	ns := NewNamespace(ofs)
	dloc, _ := ns.Resolve("/d", true)

	done := make(chan struct{})
	go func() { // mutator: copy-up / create / remove, bumping the generation
		for i := 0; i < 2000; i++ {
			n := string(rune('a' + i%20))
			if loc, err := ns.Resolve("/d/f"+n, false); err == nil {
				if o, ok := loc.Node.(*ovNode); ok {
					o.WritableUnderlying()
				}
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
