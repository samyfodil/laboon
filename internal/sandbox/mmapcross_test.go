package sandbox

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/memfs"
)

// guestBin returns a static guest ELF built from testdata/<name>.c, so the mmap
// tests run on every host. On Linux it is built with the host gcc. On another OS
// a Linux guest cannot be built locally, so it is taken from $LC_GUEST_DIR/<name>
// — a directory of prebuilt guests for this arch that the cross-platform gate
// stages (built `gcc -static-pie`, because on macOS a non-PIE ET_EXEC forces the
// hypervisor backend, which copies file mappings into VM RAM instead of sharing
// them); the test skips when that is not provided. LC_MMAP_BIN remains a legacy
// single-guest override for mmapguest. It is built static-PIE on Linux too, so
// one build convention serves every host.
func guestBin(t *testing.T, name string) string {
	t.Helper()
	if dir := os.Getenv("LC_GUEST_DIR"); dir != "" {
		return filepath.Join(dir, name)
	}
	if name == "mmapguest" {
		if exe := os.Getenv("LC_MMAP_BIN"); exe != "" {
			return exe
		}
	}
	if runtime.GOOS != "linux" {
		t.Skipf("set LC_GUEST_DIR to a dir of static-PIE guests for this arch (testdata/%s.c)", name)
	}
	exe := filepath.Join(t.TempDir(), name)
	if b, err := exec.Command("gcc", "-O2", "-static-pie", "-w", "-o", exe, "../../testdata/"+name+".c").CombinedOutput(); err != nil {
		t.Skipf("static gcc unavailable: %v\n%s", err, b)
	}
	return exe
}

// mmapGuestBin is the multi-mode mmap guest (testdata/mmapguest.c).
func mmapGuestBin(t *testing.T) string { return guestBin(t, "mmapguest") }

// Writable MAP_SHARED of a non-host file works on every backend: cross-open
// coherence, a mapping store visible to read() with no msync, a write() visible
// through the mapping, and write-back to the composed filesystem. The guest runs
// on Linux and on macOS (where it exercises the darwin host-file backing).
func TestMmapSharedCrossPlatform(t *testing.T) {
	exe := mmapGuestBin(t)
	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "f", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	runMmapGuest(t, exe, mem, "MMAP-OK")
	if got := memReadAt(t, mem, "f", 0, 14); string(got) != "SHARED-WRITTEN" {
		t.Fatalf("offset 0 = %q, want SHARED-WRITTEN written back", got)
	}
	if got := memReadAt(t, mem, "f", 100, 5); string(got) != "WROTE" {
		t.Fatalf("offset 100 = %q, want the write() WROTE written back", got)
	}
}

// An msync of a shared mapping writes the backing back to the composed
// filesystem then, not only at teardown. The guest msyncs; the supervisor's
// write-back goes through vf.WriteAt, so counting those shows the msync produced
// a write-back of its own (one for the msync, one at teardown) rather than a
// single flush at the end. The guest's own stores go to the host backing, not
// here, so they are not counted.
func TestMmapMsyncWriteBack(t *testing.T) {
	exe := mmapGuestBin(t)
	cfs := newWBFS(4096)
	runMmapGuest(t, exe, cfs, "MMAP-OK")
	if n := cfs.file.writes.Load(); n < 2 {
		t.Fatalf("vf write-backs = %d, want >= 2 (one for the msync, one at teardown)", n)
	}
	cfs.file.mu.Lock()
	got := string(cfs.file.data[:14])
	cfs.file.mu.Unlock()
	if got != "SHARED-WRITTEN" {
		t.Fatalf("file = %q, want SHARED-WRITTEN written back", got)
	}
}

// runMmapGuest runs exe (with any guest args) and mem mounted at /data,
// requiring want in its output. The program path is resolved as a guest path
// under the host root, so on unix the root is "/" and the guest path is exe;
// on Windows, where "/" is not a host path, the root is the guest binary's
// directory and the guest runs it by its base name.
func runMmapGuest(t *testing.T, exe string, mem core.FileSystem, want string, args ...string) {
	t.Helper()
	root, gp := HostRoot("/"), exe
	if runtime.GOOS == "windows" {
		root, gp = HostRoot(filepath.Dir(exe)), "/"+filepath.Base(exe)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, gp, Config{
		Args:   append([]string{gp}, args...),
		RootFS: root,
		Mounts: []Mount{{Guest: "/data", FS: mem}},
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), want) {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

// Each unmap of a non-host file's shared mapping writes its backing back and
// releases it, instead of the backing living for the whole run. The guest maps,
// writes and unmaps twice; counting vf.WriteAt shows two write-backs (one per
// unmap) rather than a single flush at teardown, and the file ends with the
// second store.
func TestMmapReevict(t *testing.T) {
	exe := mmapGuestBin(t)
	cfs := newWBFS(4096)
	runMmapGuest(t, exe, cfs, "MMAP-OK", "reevict")
	if n := cfs.file.writes.Load(); n != 2 {
		t.Fatalf("vf write-backs = %d, want 2 (one per unmap, evicted each time)", n)
	}
	cfs.file.mu.Lock()
	got := string(cfs.file.data[:11])
	cfs.file.mu.Unlock()
	if got != "SECOND-STOR" {
		t.Fatalf("file = %q, want the second store written back", got)
	}
}

// A MAP_SHARED mapping of a non-host file is coherent across fork and its backing
// survives while a child maps it (the parent unmapping its copy must not evict
// it from under the child); both stores reach the composed filesystem.
func TestMmapForkShared(t *testing.T) {
	exe := mmapGuestBin(t)
	mem := memfs.NewMemFS()
	if _, err := mem.(core.WriteFileSystem).WriteFile(mem.Root(), "f", core.CreateSpec{Kind: core.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	runMmapGuest(t, exe, mem, "MMAP-OK", "fork")
	if got := memReadAt(t, mem, "f", 0, 6); string(got) != "PARENT" {
		t.Fatalf("offset 0 = %q, want PARENT", got)
	}
	if got := memReadAt(t, mem, "f", 100, 5); string(got) != "CHILD" {
		t.Fatalf("offset 100 = %q, want the fork child's store CHILD", got)
	}
}

func memReadAt(t *testing.T, mem core.FileSystem, name string, off int64, n int) []byte {
	t.Helper()
	node, err := mem.Lookup(mem.Root(), name)
	if err != nil {
		t.Fatal(err)
	}
	f, err := node.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return b
}

func memSize(t *testing.T, mem core.FileSystem, name string) int64 {
	t.Helper()
	node, err := mem.Lookup(mem.Root(), name)
	if err != nil {
		t.Fatal(err)
	}
	a, err := node.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return a.Size
}

// wbFS is a minimal filesystem with a single regular file "f" whose WriteAt
// calls are counted, so a test can see each write-back the supervisor makes.
type wbFS struct {
	root, file *wbNode
}

func newWBFS(size int) *wbFS {
	w := &atomic.Int64{}
	fsys := &wbFS{}
	fsys.root = &wbNode{id: core.NodeID{Dev: 99, Ino: 1}, dir: true, writes: w}
	fsys.file = &wbNode{id: core.NodeID{Dev: 99, Ino: 2}, data: make([]byte, size), writes: w}
	return fsys
}

func (c *wbFS) Root() core.Node { return c.root }
func (c *wbFS) Lookup(dir core.Node, name string) (core.Node, error) {
	if dir == c.root && name == "f" {
		return c.file, nil
	}
	return nil, &fs.PathError{Op: "lookup", Path: name, Err: fs.ErrNotExist}
}
func (c *wbFS) ReadDir(dir core.Node) ([]core.Dirent, error) {
	return []core.Dirent{{Name: "f", Kind: core.Reg, Ino: c.file.id.Ino}}, nil
}
func (c *wbFS) Create(core.Node, string, core.CreateSpec) (core.Node, error) {
	return nil, fs.ErrPermission
}
func (c *wbFS) Link(core.Node, string, core.Node) (core.Node, error) { return nil, fs.ErrPermission }
func (c *wbFS) Remove(core.Node, string, bool) error                 { return fs.ErrPermission }
func (c *wbFS) Rename(core.Node, string, core.Node, string) error    { return fs.ErrPermission }

type wbNode struct {
	id     core.NodeID
	dir    bool
	mu     sync.Mutex
	data   []byte
	writes *atomic.Int64
}

func (n *wbNode) ID() core.NodeID { return n.id }
func (n *wbNode) Kind() core.Kind {
	if n.dir {
		return core.Dir
	}
	return core.Reg
}
func (n *wbNode) Stat() (core.Attr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	a := core.Attr{Kind: n.Kind(), Mode: 0o644, Nlink: 1}
	if n.dir {
		a.Mode = 0o755
	} else {
		a.Size = int64(len(n.data))
	}
	return a, nil
}
func (n *wbNode) SetAttr(core.AttrUpdate) error { return nil }
func (n *wbNode) Readlink() (string, error)     { return "", fs.ErrInvalid }
func (n *wbNode) Open(int) (core.File, error)   { return &wbFile{n: n}, nil }

type wbFile struct{ n *wbNode }

func (f *wbFile) ReadAt(p []byte, off int64) (int, error) {
	f.n.mu.Lock()
	defer f.n.mu.Unlock()
	if off >= int64(len(f.n.data)) {
		return 0, io.EOF
	}
	k := copy(p, f.n.data[off:])
	if k < len(p) {
		return k, io.EOF
	}
	return k, nil
}
func (f *wbFile) WriteAt(p []byte, off int64) (int, error) {
	f.n.writes.Add(1)
	f.n.mu.Lock()
	defer f.n.mu.Unlock()
	if end := off + int64(len(p)); end > int64(len(f.n.data)) {
		f.n.data = append(f.n.data, make([]byte, end-int64(len(f.n.data)))...)
	}
	return copy(f.n.data[off:], p), nil
}
func (f *wbFile) Truncate(size int64) error {
	f.n.mu.Lock()
	defer f.n.mu.Unlock()
	if size <= int64(len(f.n.data)) {
		f.n.data = f.n.data[:size]
	} else {
		f.n.data = append(f.n.data, make([]byte, size-int64(len(f.n.data)))...)
	}
	return nil
}
func (f *wbFile) Close() error { return nil }
func (f *wbFile) Stat() (core.Info, error) {
	a, err := f.n.Stat()
	if err != nil {
		return nil, err
	}
	return core.FileInfo("", a, f.n.ID()), nil
}
