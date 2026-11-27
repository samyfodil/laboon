package namespace

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	. "github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
)

// cacheTree builds overlay(lower, upper) with the lower holding files (path ->
// content, "" for a directory) and returns it behind a lookup counter.
func cacheTree(t testing.TB, files map[string]string) (FileSystem, *countFS, *Namespace) {
	t.Helper()
	lowerDir := t.TempDir()
	for p, data := range files {
		hp := filepath.Join(lowerDir, p)
		if data == "" {
			if err := os.MkdirAll(hp, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(hp), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(hp, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ofs := overlayfs.OverlayFS(newTestDirFS(lowerDir), newTestDirFS(t.TempDir()))
	c := &countFS{FileSystem: ofs, g: ofs.(Generational)}
	return ofs, c, NewNamespace(c)
}

func mustLoc(t *testing.T, ns *Namespace, p string, follow bool) Loc {
	t.Helper()
	loc, err := ns.Resolve(p, follow)
	if err != nil {
		t.Fatalf("resolve %s: %v", p, err)
	}
	return loc
}

func content(t *testing.T, n Node) string {
	t.Helper()
	f, err := n.Open(os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, 64)
	k, _ := f.ReadAt(b, 0)
	return string(b[:k])
}

func wantGone(t *testing.T, ns *Namespace, p string) {
	t.Helper()
	if _, err := ns.Resolve(p, true); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s still resolves (stale cache): %v", p, err)
	}
}

func walkPath(t *testing.T, ns *Namespace, w Walk, p string) string {
	t.Helper()
	gp, err := w.Path(ns, p)
	if err != nil {
		t.Fatalf("walk %+v %s: %v", w, p, err)
	}
	return gp
}

// TestResolveCacheSurvivesWritableOpen checks that writing to a file already in
// the top layer keeps every cached resolution, while copying a lower file up
// discards them and the next resolution sees the top copy.
func TestResolveCacheSurvivesWritableOpen(t *testing.T) {
	ofs, c, ns := cacheTree(t, map[string]string{"a/low": "lower"})
	adir := mustLoc(t, ns, "/a", true)
	if _, err := ofs.Create(adir.Node, "up", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	up := mustLoc(t, ns, "/a/up", true)
	mustLoc(t, ns, "/a/low", true)
	c.lookups.Store(0)
	for i := 0; i < 3; i++ {
		f, err := mustLoc(t, ns, "/a/up", true).Node.Open(os.O_RDWR | os.O_APPEND)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		mode := uint32(0o600)
		if err := up.Node.SetAttr(AttrUpdate{Mode: &mode}); err != nil {
			t.Fatal(err)
		}
		mustLoc(t, ns, "/a/low", true)
	}
	if n := c.lookups.Load(); n != 0 {
		t.Errorf("writes to a top file cost %d lookups: the cache was dropped", n)
	}

	w, err := mustLoc(t, ns, "/a/low", true).Node.Open(os.O_WRONLY | os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	w.WriteAt([]byte("top"), 0)
	w.Close()
	if got := content(t, mustLoc(t, ns, "/a/low", true).Node); got != "top" {
		t.Fatalf("after copy-up /a/low reads %q: a stale lower node was served", got)
	}
}

// TestResolveCacheRename checks a rename voids absolute and relative entries
// for both the old and the new name.
func TestResolveCacheRename(t *testing.T) {
	ofs, _, ns := cacheTree(t, map[string]string{"a/d/x": "x"})
	rel := Walk{Start: "/a", FollowLast: true}
	if gp := walkPath(t, ns, rel, "d/x"); gp != "/a/d/x" {
		t.Fatalf("d/x from /a = %q", gp)
	}
	mustLoc(t, ns, "/a/d/x", true)
	wantGone(t, ns, "/a/e/x")
	adir := mustLoc(t, ns, "/a", true)
	if err := ofs.Rename(adir.Node, "d", adir.Node, "e"); err != nil {
		t.Fatal(err)
	}
	wantGone(t, ns, "/a/d/x")
	if _, err := rel.Path(ns, "d/x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("d/x from /a after rename: %v", err)
	}
	if gp := walkPath(t, ns, rel, "e/x"); gp != "/a/e/x" {
		t.Fatalf("e/x from /a = %q", gp)
	}
	mustLoc(t, ns, "/a/e/x", true)
}

// TestResolveCacheSymlinkSwap checks that a directory renamed away and replaced
// by a symlink is followed at once, by absolute and relative names alike: a
// cached walk through the old directory must not survive the swap.
func TestResolveCacheSymlinkSwap(t *testing.T) {
	ofs, _, ns := cacheTree(t, map[string]string{"a/d/f": "inside", "other/f": "outside"})
	rel := Walk{Start: "/a", FollowLast: true}
	if got := content(t, mustLoc(t, ns, "/a/d/f", true).Node); got != "inside" {
		t.Fatalf("/a/d/f = %q", got)
	}
	if gp := walkPath(t, ns, rel, "d/f"); gp != "/a/d/f" {
		t.Fatalf("d/f from /a = %q", gp)
	}
	if mustLoc(t, ns, "/a/d", false).Node.Kind() != Dir {
		t.Fatal("/a/d is not a directory")
	}
	adir := mustLoc(t, ns, "/a", true)
	if err := ofs.Rename(adir.Node, "d", adir.Node, "old"); err != nil {
		t.Fatal(err)
	}
	if _, err := ofs.Create(adir.Node, "d", CreateSpec{Kind: Symlink, Target: "/other", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if got := content(t, mustLoc(t, ns, "/a/d/f", true).Node); got != "outside" {
		t.Fatalf("/a/d/f after the swap = %q", got)
	}
	if gp := walkPath(t, ns, rel, "d/f"); gp != "/other/f" {
		t.Fatalf("d/f from /a after the swap = %q", gp)
	}
	if k := mustLoc(t, ns, "/a/d", false).Node.Kind(); k != Symlink {
		t.Fatalf("lstat /a/d after the swap: kind %v", k)
	}
	if loc := mustLoc(t, ns, "/a/d", true); loc.Path != "/other" {
		t.Fatalf("stat /a/d after the swap reached %q", loc.Path)
	}
}

// TestResolveCacheFollowLast checks the one entry kept for a path whose last
// component is not a symlink answers stat and lstat alike, while a final
// symlink keeps them apart, dangling or not.
func TestResolveCacheFollowLast(t *testing.T) {
	ofs, c, ns := cacheTree(t, map[string]string{"a/t": "target", "a/f": "file"})
	adir := mustLoc(t, ns, "/a", true)
	if _, err := ofs.Create(adir.Node, "l", CreateSpec{Kind: Symlink, Target: "t", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if _, err := ofs.Create(adir.Node, "dl", CreateSpec{Kind: Symlink, Target: "nope", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}

	stat := Walk{FollowLast: true}
	for i := 0; i < 2; i++ {
		if i == 1 {
			c.lookups.Store(0)
		}
		if gp := walkPath(t, ns, stat, "/a/f"); gp != "/a/f" {
			t.Fatalf("stat /a/f walked to %q", gp)
		}
		mustLoc(t, ns, "/a/f", false)
		if loc := mustLoc(t, ns, "/a/l", true); loc.Path != "/a/t" || loc.Node.Kind() != Reg {
			t.Fatalf("stat /a/l = %q kind %v", loc.Path, loc.Node.Kind())
		}
		if loc := mustLoc(t, ns, "/a/l", false); loc.Path != "/a/l" || loc.Node.Kind() != Symlink {
			t.Fatalf("lstat /a/l = %q kind %v", loc.Path, loc.Node.Kind())
		}
		if k := mustLoc(t, ns, "/a/dl", false).Node.Kind(); k != Symlink {
			t.Fatalf("lstat /a/dl kind %v", k)
		}
		wantGone(t, ns, "/a/dl")
	}
	if n := c.lookups.Load(); n != 0 {
		t.Errorf("cached stat/lstat pairs still made %d lookups", n)
	}
	ns.cacheMu.Lock()
	_, both := ns.cache.m[resolveKey{p: "/a/f", followLast: true}]
	ns.cacheMu.Unlock()
	if both {
		t.Error("a symlink-free path is cached under two keys")
	}

	if _, err := ofs.Create(adir.Node, "nope", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if loc := mustLoc(t, ns, "/a/dl", true); loc.Path != "/a/nope" {
		t.Fatalf("stat /a/dl once its target exists = %q", loc.Path)
	}
}

// TestResolveCacheMount checks a mount and an unmount void entries under the
// mount point, and nothing past a mount point is served from the cache.
func TestResolveCacheMount(t *testing.T) {
	_, _, ns := cacheTree(t, map[string]string{"m/x": "under"})
	mdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(mdir, "y"), []byte("mounted"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel := Walk{Start: "/m", FollowLast: true}
	mustLoc(t, ns, "/m/x", true)
	walkPath(t, ns, rel, "x")
	wantGone(t, ns, "/m/y")

	ns.MountShadow("/m", newTestDirFS(mdir))
	wantGone(t, ns, "/m/x")
	if _, err := rel.Path(ns, "x/z"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("x/z from /m under the mount: %v", err)
	}
	if got := content(t, mustLoc(t, ns, "/m/y", true).Node); got != "mounted" {
		t.Fatalf("/m/y = %q", got)
	}
	if err := os.Remove(filepath.Join(mdir, "y")); err != nil {
		t.Fatal(err)
	}
	wantGone(t, ns, "/m/y")

	ns.Unmount("/m")
	if got := content(t, mustLoc(t, ns, "/m/x", true).Node); got != "under" {
		t.Fatalf("/m/x after unmount = %q", got)
	}
	wantGone(t, ns, "/m/y")
}

// TestResolveCacheStartAndRoot checks a relative walk answers for the directory
// it starts in (a chdir changes it), and a chrooted walk is never answered by
// an unchrooted entry: an absolute symlink restarts at the process root.
func TestResolveCacheStartAndRoot(t *testing.T) {
	ofs, _, ns := cacheTree(t, map[string]string{"a/f": "a", "b/f": "b", "f": "top"})
	for i := 0; i < 2; i++ {
		if gp := walkPath(t, ns, Walk{Start: "/a", FollowLast: true}, "f"); gp != "/a/f" {
			t.Fatalf("f from /a = %q", gp)
		}
		if gp := walkPath(t, ns, Walk{Start: "/b", FollowLast: true}, "f"); gp != "/b/f" {
			t.Fatalf("f from /b = %q", gp)
		}
		if gp := walkPath(t, ns, Walk{Start: "/a", FollowLast: true}, "../b/f"); gp != "/b/f" {
			t.Fatalf("../b/f from /a = %q", gp)
		}
	}
	adir := mustLoc(t, ns, "/a", true)
	if _, err := ofs.Create(adir.Node, "l", CreateSpec{Kind: Symlink, Target: "/f", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if gp := walkPath(t, ns, Walk{Start: "/a", FollowLast: true}, "l"); gp != "/f" {
			t.Fatalf("l from /a = %q", gp)
		}
		if gp := walkPath(t, ns, Walk{Root: "/a", Start: "/a", FollowLast: true}, "l"); gp != "/a/f" {
			t.Fatalf("l from /a under root /a = %q", gp)
		}
		if gp := walkPath(t, ns, Walk{Root: "/a", FollowLast: true}, "/l"); gp != "/a/f" {
			t.Fatalf("/l under root /a = %q", gp)
		}
		if gp := walkPath(t, ns, Walk{Root: "/a", Start: "/a", FollowLast: true}, "../f"); gp != "/a/f" {
			t.Fatalf("../f from /a under root /a = %q", gp)
		}
	}
}

// TestResolveCacheSharedViews checks that two Namespace views over one overlay,
// as two guest processes have, see each other's changes at once.
func TestResolveCacheSharedViews(t *testing.T) {
	ofs, _, ns1 := cacheTree(t, map[string]string{"a/f": "f"})
	ns2 := NewNamespace(ofs)
	for _, ns := range []*Namespace{ns1, ns2} {
		mustLoc(t, ns, "/a/f", true)
		wantGone(t, ns, "/a/g")
	}
	adir := mustLoc(t, ns1, "/a", true)
	if err := ofs.Remove(adir.Node, "f", false); err != nil {
		t.Fatal(err)
	}
	if _, err := ofs.Create(adir.Node, "g", CreateSpec{Kind: Reg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []*Namespace{ns1, ns2} {
		wantGone(t, ns, "/a/f")
		mustLoc(t, ns, "/a/g", true)
	}
	ns1.Invalidate()
	ns2.cacheMu.Lock()
	e := ns2.cache.get(resolveKey{p: "/a/g"}, ofs.(Generational).Gen())
	ns2.cacheMu.Unlock()
	if e != nil {
		t.Error("Invalidate on one view left another's entries valid")
	}
}

// TestResolveCacheLRU checks the cache evicts its least recently used entry at
// the bound instead of dropping everything, and drops a stale entry it meets.
func TestResolveCacheLRU(t *testing.T) {
	var c resolveCache
	hot := resolveKey{p: "/hot"}
	c.put(&resolveEnt{key: hot, gen: 1})
	for i := 0; i < 2*resolveCacheMax; i++ {
		c.put(&resolveEnt{key: resolveKey{p: fmt.Sprint("/cold", i)}, gen: 1})
		if i%64 == 0 && c.get(hot, 1) == nil {
			t.Fatalf("hot entry evicted after %d inserts", i)
		}
	}
	if n := len(c.m); n != resolveCacheMax {
		t.Fatalf("cache holds %d entries, want %d", n, resolveCacheMax)
	}
	if c.get(resolveKey{p: "/cold0"}, 1) != nil {
		t.Error("the oldest cold entry survived")
	}
	if c.get(resolveKey{p: fmt.Sprint("/cold", 2*resolveCacheMax-1)}, 1) == nil {
		t.Error("the newest entry was evicted")
	}
	if c.get(hot, 2) != nil || c.get(hot, 1) != nil {
		t.Error("an entry from an older generation was served or kept")
	}
	n := 0
	for e := c.list.next; e != &c.list; e = e.next {
		n++
	}
	if n != len(c.m) {
		t.Fatalf("recency list holds %d entries, map %d", n, len(c.m))
	}
}
