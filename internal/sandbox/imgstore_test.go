package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
	"github.com/samyfodil/laboon/filesystems/readonly"
)

func imgName(i int) string { return fmt.Sprintf("%032x", i) }

// imgClock dates the entries tests write, a second apart and all before now,
// so their order does not rest on the filesystem's timestamp granularity.
var imgClock = time.Now().Add(-time.Hour)

// putImg writes an entry as saveImage does and records it.
func putImg(t *testing.T, s *imgStore, i, size int) {
	t.Helper()
	p := s.path(imgName(i))
	if err := writeImgAtomic(p, make([]byte, size), nil); err != nil {
		t.Fatal(err)
	}
	if err := writeImgAtomic(p+imgMetaExt, []byte("{}"), nil); err != nil {
		t.Fatal(err)
	}
	imgClock = imgClock.Add(time.Second)
	if err := os.Chtimes(p+imgMetaExt, imgClock, imgClock); err != nil {
		t.Fatal(err)
	}
	s.saved(imgName(i))
}

func imgNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func haveImg(t *testing.T, s *imgStore, i int) bool {
	t.Helper()
	_, err := os.Stat(s.path(imgName(i)))
	_, merr := os.Stat(s.path(imgName(i)) + imgMetaExt)
	if (err == nil) != (merr == nil) {
		t.Fatalf("entry %d half there: image %v, metadata %v", i, err, merr)
	}
	return err == nil
}

func imgDirUse(t *testing.T, s *imgStore) (int, int64) {
	t.Helper()
	ents, total := s.scan()
	return len(ents), total
}

// TestImgStoreBounds: the directory is held to its file and byte bounds, the
// least recently used entry out first, and mapping an entry keeps it.
func TestImgStoreBounds(t *testing.T) {
	s := newImgStore(t.TempDir(), 3, 1000)
	for i := range 3 {
		putImg(t, s, i, 100)
	}
	s.used(imgName(0))
	putImg(t, s, 3, 100)
	if haveImg(t, s, 1) || !haveImg(t, s, 0) || !haveImg(t, s, 2) || !haveImg(t, s, 3) {
		t.Fatalf("count bound: %v", imgNames(t, s.dir))
	}
	putImg(t, s, 4, 700)
	if n, total := imgDirUse(t, s); haveImg(t, s, 2) || !haveImg(t, s, 4) || total > s.maxBytes || n > s.maxFiles {
		t.Fatalf("byte bound: %d bytes, %v", total, imgNames(t, s.dir))
	}
	if !s.fits(250) || s.fits(251) {
		t.Fatal("an entry over a quarter of the bound is stored")
	}
}

// TestImgStoreInUse: an entry whose image cannot be deleted (Windows: a run
// has it mapped) is skipped and kept whole; the next oldest goes instead.
func TestImgStoreInUse(t *testing.T) {
	s := newImgStore(t.TempDir(), 2, 1<<20)
	busy := s.path(imgName(0))
	s.remove = func(p string) error {
		if p == busy {
			return &os.PathError{Op: "remove", Path: p, Err: syscall.EACCES}
		}
		return os.Remove(p)
	}
	for i := range 3 {
		putImg(t, s, i, 10)
	}
	if !haveImg(t, s, 0) || haveImg(t, s, 1) || !haveImg(t, s, 2) {
		t.Fatalf("in-use entry: %v", imgNames(t, s.dir))
	}
	s.remove = os.Remove
	putImg(t, s, 3, 10)
	if haveImg(t, s, 0) || !haveImg(t, s, 2) || !haveImg(t, s, 3) {
		t.Fatalf("released entry not pruned: %v", imgNames(t, s.dir))
	}
}

// TestImgStoreScan: a save takes what is in the directory oldest use first,
// deleting dead writers' temporaries and nothing that is no entry; a run
// that only maps entries never lists it.
func TestImgStoreScan(t *testing.T) {
	dir := t.TempDir()
	old := newImgStore(dir, 10, 1<<20)
	for i := range 3 {
		putImg(t, old, i, 10)
	}
	base := time.Now().Add(-2 * time.Hour)
	for i, age := range []time.Duration{2, 0, 1} {
		at := base.Add(-age * time.Minute)
		if err := os.Chtimes(old.path(imgName(i))+imgMetaExt, at, at); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{imgTempPfx + "dead", "README"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := newImgStore(dir, 3, 1<<20)
	var removed []string
	s.remove = func(p string) error { removed = append(removed, filepath.Base(p)); return os.Remove(p) }
	s.used(imgName(1))
	if len(removed) != 0 {
		t.Fatal("a hit listed the directory")
	}
	putImg(t, s, 3, 10)
	if !haveImg(t, s, 1) || !haveImg(t, s, 2) || haveImg(t, s, 0) || !haveImg(t, s, 3) {
		t.Fatalf("oldest-use order: %v", imgNames(t, dir))
	}
	if _, err := os.Stat(filepath.Join(dir, imgTempPfx+"dead")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dead temporary kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "README")); err != nil {
		t.Fatal("a file that is no entry was deleted")
	}
	if _, total := imgDirUse(t, s); total != 3*12 {
		t.Fatalf("bytes = %d", total)
	}
}

// TestImgStoreShared: processes saving into one directory, each with its own
// store, hold it to one bound together, whatever order their saves come in.
func TestImgStoreShared(t *testing.T) {
	dir := t.TempDir()
	a, b := newImgStore(dir, 3, 1<<20), newImgStore(dir+string(filepath.Separator), 3, 1<<20)
	putImg(t, a, 0, 10)
	putImg(t, b, 1, 10)
	putImg(t, a, 2, 10)
	putImg(t, a, 3, 10)
	putImg(t, b, 4, 10)
	if n, _ := imgDirUse(t, a); n > 3 || haveImg(t, a, 0) || haveImg(t, a, 1) || !haveImg(t, a, 4) {
		t.Fatalf("shared bound: %v", imgNames(t, dir))
	}
}

// TestGoBuildID: the build ID is found in the head of a Windows executable,
// as the go tool reports it, and a file with none gives "".
func TestGoBuildID(t *testing.T) {
	if goBuildID(bytes.NewReader([]byte("MZ no id here"))) != "" {
		t.Fatal("an ID in a file with none")
	}
	head := append(bytes.Repeat([]byte{0}, 1000), "\xff Go build ID: \"a/b/c/d\"\n \xff"...)
	if id := goBuildID(bytes.NewReader(head)); id != "a/b/c/d" {
		t.Fatalf("synthetic: %q", id)
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "m.exe")
	build := exec.Command(gobin, "build", "-o", exe, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "GOWORK=off", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	want, err := exec.Command(gobin, "tool", "buildid", exe).Output()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got := goBuildID(f); got == "" || got != strings.TrimSpace(string(want)) {
		t.Fatalf("goBuildID = %q, go tool buildid = %q", got, want)
	}
}

// TestOpenReadStable: a program in the root's lower layer or in a read-only
// mount is stable; one in the writable upper, in a writable mount or with no
// host file behind it is not.
func TestOpenReadStable(t *testing.T) {
	// A host backend opens its root without following links, so its path is
	// the resolved one (darwin's temp dirs are under the /var link).
	dirs := make([]string, 4)
	for i := range dirs {
		d, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dirs[i] = d
	}
	root, upper, ro, rw := dirs[0], dirs[1], dirs[2], dirs[3]
	for _, p := range []string{filepath.Join(root, "lower"), filepath.Join(upper, "built"), filepath.Join(ro, "p"), filepath.Join(rw, "p")} {
		if err := os.WriteFile(p, []byte("\x7fELF"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mem := memfs.NewMemFS()
	if _, err := mem.Create(mem.Root(), "p", core.CreateSpec{Kind: core.Reg, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	fs, err := newDfs(HostRoot(root), upper, nil, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mounts: []Mount{{"/ro", readonly.ReadOnly(HostRoot(ro))}, {"/rw", HostRoot(rw)}, {"/mem", mem}}}
	g := newDguest(fs, nil, nil, 0, cfg)
	for p, want := range map[string]bool{"/lower": true, "/built": false, "/ro/p": true, "/rw/p": false, "/mem/p": false} {
		f, stable, e := g.openRead(p)
		if e != 0 {
			t.Fatalf("%s: errno %d", p, e)
		}
		f.Close()
		if stable != want {
			t.Errorf("%s: stable = %v, want %v", p, stable, want)
		}
	}
}
