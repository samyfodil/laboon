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

	"github.com/samyfodil/laboon/internal/vfs"
)

// mmapGuestBin returns a guest built for the writable MAP_SHARED test. The guest
// must be PIE: a non-PIE ET_EXEC forces the hypervisor backend on arm64 macOS,
// which copies file mappings into VM RAM instead of sharing them. LC_MMAP_BIN,
// when set, is a prebuilt static-PIE guest for this arch (testdata/mmapguest.c,
// `gcc -static-pie`); the gate provides it on macOS, where a dynamic-PIE Go build
// would need a Linux loader the host root lacks. Otherwise, on Linux, the Go form
// is built -buildmode=pie and the host provides the loader.
func mmapGuestBin(t *testing.T) string {
	t.Helper()
	if exe := os.Getenv("LC_MMAP_BIN"); exe != "" {
		return exe
	}
	if runtime.GOOS != "linux" {
		t.Skip("set LC_MMAP_BIN to a static-PIE guest for this arch (testdata/mmapguest.c)")
	}
	exe := filepath.Join(t.TempDir(), "mmapguest")
	cmd := exec.Command("go", "build", "-buildmode=pie", "-o", exe, "../../testdata/mmapguest.go")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross build unavailable: %v\n%s", err, b)
	}
	return exe
}

// Writable MAP_SHARED of a non-host file works on every backend: cross-open
// coherence, a mapping store visible to read() with no msync, a write() visible
// through the mapping, and write-back to the composed filesystem. The guest runs
// on Linux and on macOS (where it exercises the darwin host-file backing).
func TestMmapSharedCrossPlatform(t *testing.T) {
	exe := mmapGuestBin(t)
	mem := vfs.NewMemFS()
	if _, err := mem.(vfs.WriteFileSystem).WriteFile(mem.Root(), "f", vfs.CreateSpec{Kind: vfs.Reg, Mode: 0o644}, make([]byte, 4096)); err != nil {
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

// runMmapGuest runs exe with mem mounted at /data and host root, requiring want
// in its output.
func runMmapGuest(t *testing.T, exe string, mem vfs.FileSystem, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := Run(ctx, exe, Config{
		Args:   []string{exe},
		RootFS: HostRoot("/"),
		Mounts: []Mount{{Guest: "/data", FS: mem}},
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), want) {
		t.Fatalf("code=%d err=%v out=%q", code, err, out.String())
	}
}

func memReadAt(t *testing.T, mem vfs.FileSystem, name string, off int64, n int) []byte {
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

func memSize(t *testing.T, mem vfs.FileSystem, name string) int64 {
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
	fsys.root = &wbNode{id: vfs.NodeID{Dev: 99, Ino: 1}, dir: true, writes: w}
	fsys.file = &wbNode{id: vfs.NodeID{Dev: 99, Ino: 2}, data: make([]byte, size), writes: w}
	return fsys
}

func (c *wbFS) Root() vfs.Node { return c.root }
func (c *wbFS) Lookup(dir vfs.Node, name string) (vfs.Node, error) {
	if dir == c.root && name == "f" {
		return c.file, nil
	}
	return nil, &fs.PathError{Op: "lookup", Path: name, Err: fs.ErrNotExist}
}
func (c *wbFS) ReadDir(dir vfs.Node) ([]vfs.Dirent, error) {
	return []vfs.Dirent{{Name: "f", Kind: vfs.Reg, Ino: c.file.id.Ino}}, nil
}
func (c *wbFS) Create(vfs.Node, string, vfs.CreateSpec) (vfs.Node, error) {
	return nil, fs.ErrPermission
}
func (c *wbFS) Link(vfs.Node, string, vfs.Node) (vfs.Node, error) { return nil, fs.ErrPermission }
func (c *wbFS) Remove(vfs.Node, string, bool) error               { return fs.ErrPermission }
func (c *wbFS) Rename(vfs.Node, string, vfs.Node, string) error   { return fs.ErrPermission }

type wbNode struct {
	id     vfs.NodeID
	dir    bool
	mu     sync.Mutex
	data   []byte
	writes *atomic.Int64
}

func (n *wbNode) ID() vfs.NodeID { return n.id }
func (n *wbNode) Kind() vfs.Kind {
	if n.dir {
		return vfs.Dir
	}
	return vfs.Reg
}
func (n *wbNode) Stat() (vfs.Attr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	a := vfs.Attr{Kind: n.Kind(), Mode: 0o644, Nlink: 1}
	if n.dir {
		a.Mode = 0o755
	} else {
		a.Size = int64(len(n.data))
	}
	return a, nil
}
func (n *wbNode) SetAttr(vfs.AttrUpdate) error { return nil }
func (n *wbNode) Readlink() (string, error)    { return "", fs.ErrInvalid }
func (n *wbNode) Open(int) (vfs.File, error)   { return &wbFile{n: n}, nil }

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
