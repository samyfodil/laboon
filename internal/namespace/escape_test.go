package namespace

import (
	"io"
	"os"
	"testing"

	. "github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

// An in-memory filesystem (memFS) is a complete guest root behind the plain
// FileSystem interface — the same surface a third party composes with WithFS. A
// guest's only reach into it is a path handed to the Namespace, so these tests
// try every way a path can "point out" of the tree (".." above the root, an
// absolute symlink, a "../" ladder in a symlink, a symlink naming a host-only
// path) and assert each one stays inside the in-memory namespace. The root holds
// a sentinel the host cannot: /etc/passwd = "MEMROOT". If any walk escaped to the
// host, the content would differ or a host-only path would resolve.

// writeMem creates a regular file with content through the plain FileSystem
// interface (Create + Open + WriteAt), so it works for any backend, not only one
// that implements the WriteFile extension.
func writeMem(t *testing.T, fsys FileSystem, parent Node, name, data string) {
	t.Helper()
	n, err := fsys.Create(parent, name, CreateSpec{Kind: Reg, Mode: 0o644})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	f, err := n.Open(os.O_RDWR)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte(data), 0); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func buildMemRoot(t *testing.T) FileSystem {
	t.Helper()
	fsys := memfs.NewMemFS()
	mkdir := func(parent Node, name string) Node {
		n, err := fsys.Create(parent, name, CreateSpec{Kind: Dir, Mode: 0o755})
		if err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		return n
	}
	write := func(parent Node, name, data string) {
		writeMem(t, fsys, parent, name, data)
	}
	symlink := func(parent Node, name, tgt string) {
		if _, err := fsys.Create(parent, name, CreateSpec{Kind: Symlink, Target: tgt}); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}
	root := fsys.Root()
	etc := mkdir(root, "etc")
	write(etc, "passwd", "MEMROOT") // the host's /etc/passwd never holds this
	sub := mkdir(root, "sub")
	mkdir(sub, "deep")

	// Adversarial links, all of which must stay inside the in-memory namespace.
	symlink(root, "abs", "/etc/passwd")                    // absolute -> restarts at ns root
	symlink(root, "climb", "../../../../../../etc/passwd") // ".." ladder from the root
	symlink(sub, "up", "../../../../etc/passwd")           // ".." ladder from a subdir
	symlink(root, "hostshadow", "/etc/shadow")             // a host-only path; ns has no such file
	symlink(root, "loop", "loop")                          // a symlink cycle
	return fsys
}

func TestInMemRootNoEscape(t *testing.T) {
	ns := NewNamespace(buildMemRoot(t))

	readVia := func(p string) (string, error) {
		loc, err := ns.Resolve(p, true)
		if err != nil {
			return "", err
		}
		if loc.FS != ns.root {
			t.Fatalf("%s resolved to a foreign filesystem %T — escape", p, loc.FS)
		}
		f, err := loc.Node.Open(os.O_RDONLY)
		if err != nil {
			return "", err
		}
		defer f.Close()
		b, err := io.ReadAll(io.NewSectionReader(f, 0, 1<<20))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	// Each of these must reach the in-namespace sentinel, never the host file.
	for _, p := range []string{
		"/etc/passwd",
		"/../../../../etc/passwd",             // ".." above the root clamps to the root
		"/abs",                                // absolute symlink restarts at the ns root
		"/climb",                              // symlink whose target climbs with ".."
		"/sub/up",                             // ".." ladder through a symlink in a subdir
		"/sub/deep/../../etc/passwd",          // in-tree ".."
		"/sub/../sub/deep/../..//etc//passwd", // redundant separators and "."-equivalents
	} {
		got, err := readVia(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got != "MEMROOT" {
			t.Fatalf("%s = %q, want the in-memory sentinel MEMROOT (host escape?)", p, got)
		}
	}

	// A symlink to a host-only path resolves inside the namespace, where no such
	// file exists — it must fail, not open the host's file.
	if loc, err := ns.Resolve("/hostshadow", true); err == nil {
		t.Fatalf("/hostshadow resolved to %q on %T; the namespace has no /etc/shadow, so a host escape is the only way this succeeds", loc.Path, loc.FS)
	}

	// A symlink cycle terminates instead of walking the host.
	if _, err := ns.Resolve("/loop", true); err == nil {
		t.Fatalf("/loop (a symlink cycle) resolved; expected a loop error")
	}
}

// TestInMemMountNoEscape mounts a second in-memory filesystem and checks that
// crossing into it works, that ".." climbs back into the root (still in the
// namespace), and that an absolute symlink inside the mount restarts at the
// namespace root — never the host.
func TestInMemMountNoEscape(t *testing.T) {
	root := buildMemRoot(t)
	ns := NewNamespace(root)
	sub := memfs.NewMemFS()
	writeMem(t, sub, sub.Root(), "secret", "MOUNT")
	if _, err := sub.Create(sub.Root(), "out", CreateSpec{Kind: Symlink, Target: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	ns.MountShadow("/mnt", sub)

	read := func(p string) (Loc, string) {
		loc, err := ns.Resolve(p, true)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		f, err := loc.Node.Open(os.O_RDONLY)
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}
		defer f.Close()
		b, _ := io.ReadAll(io.NewSectionReader(f, 0, 1<<20))
		return loc, string(b)
	}

	// Crossing into the mount reaches the mounted filesystem's own file.
	if loc, got := read("/mnt/secret"); loc.FS != sub || got != "MOUNT" {
		t.Fatalf("/mnt/secret = %q on %T, want MOUNT on the mounted fs", got, loc.FS)
	}
	// ".." out of the mount lands back in the root filesystem, still in-namespace.
	if loc, got := read("/mnt/../etc/passwd"); loc.FS != root || got != "MEMROOT" {
		t.Fatalf("/mnt/../etc/passwd = %q on %T, want MEMROOT on the root fs", got, loc.FS)
	}
	// An absolute symlink inside the mount restarts at the namespace root — so it
	// reaches the root's sentinel, not the host's /etc/passwd.
	if loc, got := read("/mnt/out"); loc.FS != root || got != "MEMROOT" {
		t.Fatalf("/mnt/out = %q on %T, want MEMROOT on the root fs (absolute symlink must restart at ns root)", got, loc.FS)
	}
}
