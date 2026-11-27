package namespace

import (
	"errors"
	"io/fs"
	"testing"

	. "github.com/samyfodil/laboon/core"
)

// TestResolveCacheDirScoped checks a change to one directory keeps the cached
// walks that never looked in it, and voids every walk that did: those ending
// there, those passing through it, and those reaching it through a symlink.
func TestResolveCacheDirScoped(t *testing.T) {
	ofs, c, ns := cacheTree(t, map[string]string{
		"a/d/x/y": "y", "a/f": "f", "b/g": "g", "z/d/x/y": "zy",
	})
	root := mustLoc(t, ns, "/", true)
	if _, err := ofs.Create(root.Node, "l", CreateSpec{Kind: Symlink, Target: "a/d", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	prime := func() {
		mustLoc(t, ns, "/a/d/x/y", true)
		mustLoc(t, ns, "/a/f", true)
		mustLoc(t, ns, "/b/g", true)
		mustLoc(t, ns, "/l/x/y", true)
		walkPath(t, ns, Walk{Start: "/a/d", FollowLast: true}, "x/y")
		wantGone(t, ns, "/b/nope")
	}
	// The first create in /b copies /b up, which changes the root; the next
	// changes only /b.
	if _, err := ofs.Create(mustLoc(t, ns, "/b", true).Node, "first", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	prime()
	bdir := mustLoc(t, ns, "/b", true)
	if _, err := ofs.Create(bdir.Node, "other", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	c.lookups.Store(0)
	mustLoc(t, ns, "/a/d/x/y", true)
	mustLoc(t, ns, "/a/f", true)
	mustLoc(t, ns, "/l/x/y", true)
	walkPath(t, ns, Walk{Start: "/a/d", FollowLast: true}, "x/y")
	if n := c.lookups.Load(); n != 0 {
		t.Errorf("a create in /b cost %d lookups elsewhere", n)
	}
	mustLoc(t, ns, "/b/g", true)
	if _, err := ofs.Create(bdir.Node, "new", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	mustLoc(t, ns, "/b/new", true)

	// Swap /a/d for /z/d: everything below the old /a/d now names /z/d's tree.
	prime()
	adir := mustLoc(t, ns, "/a", true)
	zdir := mustLoc(t, ns, "/z", true)
	if err := ofs.Rename(adir.Node, "d", root.Node, "gone"); err != nil {
		t.Fatal(err)
	}
	if err := ofs.Rename(zdir.Node, "d", mustLoc(t, ns, "/a", true).Node, "d"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/a/d/x/y", "/l/x/y"} {
		if got := content(t, mustLoc(t, ns, p, true).Node); got != "zy" {
			t.Fatalf("%s after the swap reads %q", p, got)
		}
	}
	if got := content(t, mustLoc(t, ns, "/gone/x/y", true).Node); got != "y" {
		t.Fatalf("/gone/x/y reads %q", got)
	}
	wantGone(t, ns, "/z/d/x/y")
	if gp := walkPath(t, ns, Walk{Start: "/gone", FollowLast: true}, "x/../x/y"); gp != "/gone/x/y" {
		t.Fatalf("x/../x/y from /gone = %q", gp)
	}

	// A deep change, made in the top layer under a copied-up directory.
	prime()
	xdir := mustLoc(t, ns, "/a/d/x", true)
	if err := ofs.Remove(xdir.Node, "y", false); err != nil {
		t.Fatal(err)
	}
	wantGone(t, ns, "/a/d/x/y")
	wantGone(t, ns, "/l/x/y")
	if _, err := (Walk{Start: "/a/d", FollowLast: true}).Path(ns, "x/y/q"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("x/y/q from /a/d after the remove: %v", err)
	}

	// A move between two directories below the root voids both sides.
	mustLoc(t, ns, "/a/d/x", true)
	wantGone(t, ns, "/b/d/x")
	if err := ofs.Rename(mustLoc(t, ns, "/a", true).Node, "d", mustLoc(t, ns, "/b", true).Node, "d"); err != nil {
		t.Fatal(err)
	}
	wantGone(t, ns, "/a/d/x")
	mustLoc(t, ns, "/b/d/x", true)
	if gp := walkPath(t, ns, Walk{Start: "/b", FollowLast: true}, "d/x"); gp != "/b/d/x" {
		t.Fatalf("d/x from /b = %q", gp)
	}
}

// genOnly is a root that reports one generation for every change, as a root
// that cannot place its changes does.
type genOnly struct {
	FileSystem
	g Generational
}

func (o genOnly) Gen() uint64 { return o.g.Gen() }
func (o genOnly) Touch()      { o.g.Touch() }

// TestResolveCacheGlobalGen checks a root with only a global generation still
// has every change void every entry.
func TestResolveCacheGlobalGen(t *testing.T) {
	ofs, _, _ := cacheTree(t, map[string]string{"a/f": "f", "b/g": "g"})
	ns := NewNamespace(genOnly{FileSystem: ofs, g: ofs.(Generational)})
	if ns.dirGen != nil {
		t.Fatal("a global-generation root is treated as versioned per directory")
	}
	mustLoc(t, ns, "/a/f", true)
	wantGone(t, ns, "/b/new")
	adir := mustLoc(t, ns, "/a", true)
	if err := ofs.Remove(adir.Node, "f", false); err != nil {
		t.Fatal(err)
	}
	wantGone(t, ns, "/a/f")
	bdir := mustLoc(t, ns, "/b", true)
	if _, err := ofs.Create(bdir.Node, "new", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	mustLoc(t, ns, "/b/new", true)
}
