package sandbox

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/samyfodil/laboon/internal/vfs"
)

// newTestBacking makes a shBacking over a fresh memFS file, with content in its
// memfd, registered on fs and reserved for pages mappings.
func newTestBacking(t *testing.T, fs *dfs, content []byte, pages int64) (*shBacking, vfs.FileSystem) {
	t.Helper()
	mem := vfs.NewMemFS()
	if _, err := mem.(vfs.WriteFileSystem).WriteFile(mem.Root(), "f", vfs.CreateSpec{Kind: vfs.Reg, Mode: 0o644}, make([]byte, len(content))); err != nil {
		t.Fatal(err)
	}
	node, err := mem.Lookup(mem.Root(), "f")
	if err != nil {
		t.Fatal(err)
	}
	vf, err := node.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.MemfdCreate("lc-test", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "lc-test")
	if err := f.Truncate(int64(len(content))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(content, 0); err != nil {
		t.Fatal(err)
	}
	sb := &shBacking{f: f, vf: vf, size: int64(len(content)), eof: int64(len(content))}
	sb.reserve(pages)
	fs.shMu.Lock()
	fs.putBacking(node.ID(), sb)
	fs.shMu.Unlock()
	return sb, mem
}

func memFileBytes(t *testing.T, mem vfs.FileSystem, n int) []byte {
	t.Helper()
	node, err := mem.Lookup(mem.Root(), "f")
	if err != nil {
		t.Fatal(err)
	}
	vf, err := node.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer vf.Close()
	b := make([]byte, n)
	vf.ReadAt(b, 0)
	return b
}

// A backing is written back to its file and released once its last mapped page
// is unmapped.
func TestShMapEvictOnLastUnmap(t *testing.T) {
	fs := &dfs{}
	m := newMemProc(1)
	content := []byte("EVICTED-DATA")
	sb, mem := newTestBacking(t, fs, content, 1)
	base := uint64(0x10000)
	m.addShMap(base, base+uint64(pageSize), sb, fs)
	if fs.sharedN.Load() != 1 {
		t.Fatalf("sharedN=%d, want 1 after mapping", fs.sharedN.Load())
	}

	m.removeShMap(base, base+uint64(pageSize), fs) // the last unmap
	if fs.sharedN.Load() != 0 || len(fs.shared) != 0 {
		t.Fatalf("sharedN=%d shared=%d, want 0 after last unmap (evicted)", fs.sharedN.Load(), len(fs.shared))
	}
	if got := memFileBytes(t, mem, len(content)); string(got) != string(content) {
		t.Fatalf("memFS = %q, want %q written back on eviction", got, content)
	}
}

// A partial unmap keeps the rest of the mapping (and the backing) live; only the
// final unmap of the last page evicts.
func TestShMapPartialUnmap(t *testing.T) {
	fs := &dfs{}
	m := newMemProc(1)
	sb, _ := newTestBacking(t, fs, make([]byte, 4*pageSize), 4)
	base := uint64(0x20000)
	m.addShMap(base, base+uint64(4*pageSize), sb, fs)

	m.removeShMap(base+uint64(pageSize), base+uint64(2*pageSize), fs) // unmap the 2nd page
	if fs.sharedN.Load() != 1 {
		t.Fatalf("evicted after a partial unmap; sharedN=%d maps=%d", fs.sharedN.Load(), sb.maps.Load())
	}
	if sb.maps.Load() != 3 {
		t.Fatalf("maps=%d, want 3 after unmapping 1 of 4 pages", sb.maps.Load())
	}
	m.removeShMap(base, base+uint64(4*pageSize), fs) // unmap everything that is left
	if fs.sharedN.Load() != 0 {
		t.Fatalf("not evicted after the last pages went; sharedN=%d", fs.sharedN.Load())
	}
}

// A fork child inherits the mapping and keeps the backing live: the parent
// unmapping its copy does not evict while the child still maps it.
func TestShMapForkKeepsLive(t *testing.T) {
	fs := &dfs{}
	parent := newMemProc(1)
	sb, _ := newTestBacking(t, fs, make([]byte, pageSize), 1)
	base := uint64(0x30000)
	parent.addShMap(base, base+uint64(pageSize), sb, fs)

	child := newMemProc(2)
	child.forkShMaps(parent, fs) // the child inherits the mapping
	if sb.maps.Load() != 2 {
		t.Fatalf("maps=%d, want 2 after fork", sb.maps.Load())
	}

	parent.removeShMap(base, base+uint64(pageSize), fs) // parent unmaps its copy
	if fs.sharedN.Load() != 1 {
		t.Fatalf("evicted while the child still maps it; sharedN=%d", fs.sharedN.Load())
	}
	child.dropShMaps(fs) // the child exits/execs
	if fs.sharedN.Load() != 0 {
		t.Fatalf("not evicted after the child dropped its mapping; sharedN=%d", fs.sharedN.Load())
	}
}
