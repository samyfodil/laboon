package rewrite

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// distinctCode is a syscall followed by a word that differs for each i.
func distinctCode(i int) []byte {
	return binary.LittleEndian.AppendUint32([]byte{0xb8, 0x27, 0, 0, 0, 0x0f, 0x05, 0xc3}, uint32(i))
}

// planFiles lists the plan files anywhere under dir.
func planFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && isPlanName(d.Name()) {
			out = append(out, path)
		}
		return nil
	})
	return out
}

func TestLRUBound(t *testing.T) {
	var l lru
	for i := range 100 {
		l.put([32]byte{byte(i)}, Plan{}, 10, 1<<20)
	}
	if l.order.Len() != 10 || len(l.idx) != 10 {
		t.Fatalf("count bound: %d entries, %d indexed, want 10", l.order.Len(), len(l.idx))
	}
	if _, ok := l.get([32]byte{99}); !ok {
		t.Fatal("the newest entry was evicted")
	}
	if _, ok := l.get([32]byte{89}); ok {
		t.Fatal("an entry past the bound was kept")
	}
	// A get makes an entry the most recent, so the next put evicts another.
	l.get([32]byte{90})
	l.put([32]byte{200}, Plan{}, 10, 1<<20)
	if _, ok := l.get([32]byte{90}); !ok {
		t.Fatal("the entry just used was evicted")
	}

	big := Plan{Sites: make([]Site, 1000)}
	var b lru
	for i := range 20 {
		b.put([32]byte{byte(i)}, big, 1000, 5*planSize(big))
	}
	if b.order.Len() != 5 || b.bytes != 5*planSize(big) {
		t.Fatalf("byte bound: %d entries, %d bytes, want 5 and %d", b.order.Len(), b.bytes, 5*planSize(big))
	}

	var c Cache
	for i := range maxMainPlans + 100 {
		c.Memo("t", distinctCode(i), func() (Plan, error) { return Plan{}, nil })
	}
	for i := range maxAnonPlans + 100 {
		c.AnonEntries(distinctCode(i), []int{0}, [][2]int{{0, 7}})
	}
	if c.main.order.Len() != maxMainPlans || c.anon.order.Len() != maxAnonPlans {
		t.Fatalf("cache holds %d and %d anonymous plans, want %d and %d", c.main.order.Len(), c.anon.order.Len(), maxMainPlans, maxAnonPlans)
	}
}

// TestAnonNeverOnDisk: code with no file behind it is memoized in memory only.
func TestAnonNeverOnDisk(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	for i := range 50 {
		code := distinctCode(i)
		if p := c.AnonEntries(code, []int{0}, [][2]int{{0, 7}}); len(p.Sites) != 1 {
			t.Fatalf("plan = %+v", p)
		}
		offs, err := c.AnonOffsets("t", code, func() ([]uint32, error) { return []uint32{5}, nil })
		if err != nil || len(offs) != 1 {
			t.Fatalf("offsets = %v, %v", offs, err)
		}
	}
	calls := 0
	c.AnonOffsets("t", distinctCode(3), func() ([]uint32, error) { calls++; return nil, nil })
	if calls != 0 {
		t.Fatal("an anonymous result was not memoized")
	}
	c.Sync()
	if fs := planFiles(t, dir); len(fs) != 0 {
		t.Fatalf("anonymous plans reached the disk: %v", fs)
	}
	c.Entries(distinctCode(1), []int{0}, [][2]int{{0, 7}})
	c.Sync()
	if fs := planFiles(t, dir); len(fs) != 1 || filepath.Base(filepath.Dir(fs[0])) != diskGen {
		t.Fatalf("plan files = %v, want one under %s", fs, diskGen)
	}
}

func TestDiskBound(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, strings.Repeat("ab", 32))
	oldGen := filepath.Join(dir, "v1-2")
	keep := filepath.Join(dir, "keep.txt")
	os.MkdirAll(oldGen, 0o700)
	otherGen := filepath.Join(dir, "v9-9")
	os.MkdirAll(otherGen, 0o700)
	otherPlan := filepath.Join(otherGen, strings.Repeat("ef", 32))
	for _, p := range []string{legacy, filepath.Join(oldGen, strings.Repeat("cd", 32)), filepath.Join(dir, ".plan-1"), keep, otherPlan} {
		if err := os.WriteFile(p, []byte{planVersion}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	idle := time.Now().Add(-otherGenIdle - time.Hour)
	if err := os.Chtimes(filepath.Join(oldGen, strings.Repeat("cd", 32)), idle, idle); err != nil {
		t.Fatal(err)
	}

	c := &Cache{disk: newDiskDir(dir)}
	c.disk.maxFiles = 10
	for i := range 50 {
		c.Plan(distinctCode(i))
	}
	c.Sync()
	if _, err := os.Stat(otherPlan); err != nil {
		t.Errorf("a plan of another generation in recent use was deleted: %v", err)
	}
	os.RemoveAll(otherGen)
	if fs := planFiles(t, dir); len(fs) != 10 {
		t.Fatalf("%d plan files, want 10", len(fs))
	}
	for _, p := range []string{legacy, oldGen, filepath.Join(dir, ".plan-1")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s of an old format was kept", p)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a file that is not a plan was deleted: %v", err)
	}
	// The newest plans are the ones kept, and they are found again.
	fresh := NewCache(dir)
	if _, ok := fresh.lookup(sha256.Sum256(distinctCode(49))); !ok {
		t.Fatal("the newest plan is not on disk")
	}
	if _, ok := fresh.lookup(sha256.Sum256(distinctCode(0))); ok {
		t.Fatal("the oldest plan was not pruned")
	}
	fresh.Sync()

	// A process that finds more than the bound prunes on its first write.
	d := newDiskDir(dir)
	d.maxFiles = 4
	more := &Cache{disk: d}
	more.Plan(distinctCode(100))
	more.Sync()
	if fs := planFiles(t, dir); len(fs) != 4 {
		t.Fatalf("%d plan files after a smaller bound, want 4", len(fs))
	}

	d = newDiskDir(dir)
	one := int64(len(encodePlan(Analyze(distinctCode(0)))))
	d.maxBytes = 3 * one
	byBytes := &Cache{disk: d}
	for i := 200; i < 210; i++ {
		byBytes.Plan(distinctCode(i))
	}
	byBytes.Sync()
	if fs := planFiles(t, dir); len(fs) != 3 || d.bytes != 3*one {
		t.Fatalf("%d plan files, %d bytes, want 3 and %d", len(fs), d.bytes, 3*one)
	}
}

// A process that only hits plans on disk never starts the writer: the hit is
// touched in place, the directory is not scanned, and Sync has nothing to wait
// for.
func TestDiskReadOnlyHasNoWriter(t *testing.T) {
	dir := t.TempDir()
	warm := NewCache(dir)
	warm.Plan(distinctCode(1))
	warm.Sync()
	legacy := filepath.Join(dir, strings.Repeat("ab", 32))
	if err := os.WriteFile(legacy, []byte{planVersion}, 0o600); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, diskGen, hexKey(sha256.Sum256(distinctCode(1))))
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(name, old, old); err != nil {
		t.Fatal(err)
	}

	c := NewCache(dir)
	if _, ok := c.lookup(sha256.Sum256(distinctCode(1))); !ok {
		t.Fatal("the plan on disk was not found")
	}
	c.disk.mu.Lock()
	busy, queued := c.disk.busy, len(c.disk.q)
	c.disk.mu.Unlock()
	if busy || queued != 0 {
		t.Fatalf("a read hit started the writer (busy %v, %d queued)", busy, queued)
	}
	c.Sync()
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("a read-only process scanned the directory")
	}
	if fi, err := os.Stat(name); err != nil || !fi.ModTime().After(old) {
		t.Fatalf("the hit was not touched: %v", err)
	}
}

func hexKey(k [32]byte) string { return hex.EncodeToString(k[:]) }
