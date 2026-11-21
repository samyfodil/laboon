package rewrite

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Cache memoizes Analyze by the SHA-256 of the code, in memory and,
// if Dir is set, on disk, so each library is disassembled once per machine.
//
// A cached plan is only a hint: Apply refuses to patch anything that is not
// a syscall instruction, and on Linux the stub's seccomp filter kills any
// syscall a bad plan leaves unpatched. Tampering with the cache can slow a
// guest down or break it, not let it out.
type Cache struct {
	Dir string

	mu  sync.Mutex
	mem map[[32]byte]Plan
}

// DefaultCache returns a cache under the user cache directory, or an
// in-memory one if there is none.
func DefaultCache() *Cache {
	c := &Cache{}
	if d, err := os.UserCacheDir(); err == nil {
		c.Dir = filepath.Join(d, "laboon", "plans")
	}
	return c
}

// Plan returns Analyze(code) (linear scan), computing it only on a miss.
func (c *Cache) Plan(code []byte) Plan {
	return c.memo(sha256.Sum256(code), func() Plan { return Analyze(code) })
}

// Entries returns AnalyzeEntries(code, entries, scav) (recursive descent),
// computing it only on a miss. It is keyed by the code alone: for a given
// binary the entries and sections are derived from the same bytes, so they
// are stable. The key names the analysis, distinct from the linear Plan's,
// and changes with it.
func (c *Cache) Entries(code []byte, entries []int, scav [][2]int) Plan {
	h := sha256.Sum256(code)
	key := sha256.Sum256(append([]byte("entries-2"), h[:]...))
	return c.memo(key, func() Plan { return AnalyzeEntries(code, entries, scav) })
}

// Offsets memoizes an analysis of data that yields instruction offsets. The
// key is salt plus data's SHA-256: callers name their analysis in salt, and
// change it when the analysis changes, so an old result is never reused. A
// failed compute is not cached.
func (c *Cache) Offsets(salt string, data []byte, compute func() ([]uint32, error)) ([]uint32, error) {
	h := sha256.Sum256(data)
	key := sha256.Sum256(append([]byte(salt), h[:]...))
	if p, ok := c.lookup(key); ok {
		offs := make([]uint32, len(p.Sites))
		for i, s := range p.Sites {
			offs[i] = s.Off
		}
		return offs, nil
	}
	offs, err := compute()
	if err != nil {
		return nil, err
	}
	var p Plan
	for _, o := range offs {
		p.Sites = append(p.Sites, Site{Off: o})
	}
	c.save(key, p)
	return offs, nil
}

// FileID identifies a file's contents by its metadata, so a caller that has
// analyzed a file once can find the result again without reading or hashing
// it. Any write to the file moves its mtime and ctime, and ctime cannot be
// set back; a replaced file has a new inode or a new ctime.
type FileID struct {
	Dev, Ino     uint64
	Size         int64
	Mtime, Ctime int64 // nanoseconds
}

// ByID memoizes compute under salt and a file's identity. salt names the
// analysis, as for Offsets; extra distinguishes regions of one file. A failed
// compute is not cached.
func (c *Cache) ByID(salt string, id FileID, extra []uint64, compute func() (Plan, error)) (Plan, error) {
	b := fmt.Appendf(nil, "%s\x00%d %d %d %d %d", salt, id.Dev, id.Ino, id.Size, id.Mtime, id.Ctime)
	for _, x := range extra {
		b = binary.LittleEndian.AppendUint64(b, x)
	}
	key := sha256.Sum256(b)
	if p, ok := c.lookup(key); ok {
		return p, nil
	}
	p, err := compute()
	if err != nil {
		return Plan{}, err
	}
	c.save(key, p)
	return p, nil
}

// Memo memoizes compute under salt and the SHA-256 of data, as Offsets does,
// for an analysis that yields a whole plan. A failed compute is not cached.
func (c *Cache) Memo(salt string, data []byte, compute func() (Plan, error)) (Plan, error) {
	h := sha256.Sum256(data)
	key := sha256.Sum256(append([]byte(salt), h[:]...))
	if p, ok := c.lookup(key); ok {
		return p, nil
	}
	p, err := compute()
	if err != nil {
		return Plan{}, err
	}
	c.save(key, p)
	return p, nil
}

// OffsetsByID is ByID for an analysis that yields instruction offsets.
func (c *Cache) OffsetsByID(salt string, id FileID, compute func() ([]uint32, error)) ([]uint32, error) {
	p, err := c.ByID(salt, id, nil, func() (Plan, error) {
		offs, err := compute()
		var p Plan
		for _, o := range offs {
			p.Sites = append(p.Sites, Site{Off: o})
		}
		return p, err
	})
	if err != nil {
		return nil, err
	}
	offs := make([]uint32, len(p.Sites))
	for i, s := range p.Sites {
		offs[i] = s.Off
	}
	return offs, nil
}

// memo returns the plan for key, computing it with compute only on a miss, in
// memory and (if Dir is set) on disk.
func (c *Cache) memo(key [32]byte, compute func() Plan) Plan {
	if p, ok := c.lookup(key); ok {
		return p
	}
	p := compute()
	c.save(key, p)
	return p
}

// lookup returns the plan for key from memory or, failing that, disk.
func (c *Cache) lookup(key [32]byte) (Plan, bool) {
	c.mu.Lock()
	p, ok := c.mem[key]
	c.mu.Unlock()
	if ok || c.Dir == "" {
		return p, ok
	}
	b, err := os.ReadFile(c.file(key))
	if err != nil {
		return Plan{}, false
	}
	if p, ok = decodePlan(b); ok {
		c.store(key, p)
	}
	return p, ok
}

// save records p under key in memory and, if Dir is set, on disk.
func (c *Cache) save(key [32]byte, p Plan) {
	c.store(key, p)
	if c.Dir != "" {
		// Best effort: a failed write only costs a re-analysis next time.
		writeAtomic(c.file(key), encodePlan(p))
	}
}

func (c *Cache) file(key [32]byte) string {
	return filepath.Join(c.Dir, hex.EncodeToString(key[:]))
}

func (c *Cache) store(key [32]byte, p Plan) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mem == nil {
		c.mem = map[[32]byte]Plan{}
	}
	c.mem[key] = p
}

// Plan files are a version byte followed by (offset uint32, steal uint8,
// cave int16) records, little-endian. The FS version adds the %fs sites: the
// syscall-site count (uint32) comes first, and (offset uint32, length uint8,
// steal uint8, cave int16) records follow the syscall sites. Versions 1 and 2
// predate stealing a run before a syscall, 3 and 4 caves, 6 a run or a cave
// for an %fs instruction; their plans are recomputed.
const (
	planVersion   = 5
	planVersionFS = 7
)

func encodePlan(p Plan) []byte {
	b := make([]byte, 1, 5+7*len(p.Sites)+8*len(p.FS))
	b[0] = planVersion
	if len(p.FS) > 0 {
		b[0] = planVersionFS
		b = binary.LittleEndian.AppendUint32(b, uint32(len(p.Sites)))
	}
	for _, s := range p.Sites {
		b = binary.LittleEndian.AppendUint32(b, s.Off)
		b = append(b, s.Steal)
		b = binary.LittleEndian.AppendUint16(b, uint16(s.Cave))
	}
	for _, s := range p.FS {
		b = binary.LittleEndian.AppendUint32(b, s.Off)
		b = append(b, s.Len, s.Steal)
		b = binary.LittleEndian.AppendUint16(b, uint16(s.Cave))
	}
	return b
}

func decodePlan(b []byte) (Plan, bool) {
	if len(b) == 0 {
		return Plan{}, false
	}
	n := -1
	switch b[0] {
	case planVersion:
		b = b[1:]
		if len(b)%7 != 0 {
			return Plan{}, false
		}
		n = len(b) / 7
	case planVersionFS:
		if len(b) < 5 {
			return Plan{}, false
		}
		n = int(binary.LittleEndian.Uint32(b[1:]))
		b = b[5:]
		if n > len(b)/7 || (len(b)-7*n)%8 != 0 {
			return Plan{}, false
		}
	default:
		return Plan{}, false
	}
	var p Plan
	for i := 0; i < n; i, b = i+1, b[7:] {
		p.Sites = append(p.Sites, Site{Off: binary.LittleEndian.Uint32(b), Steal: b[4], Cave: int16(binary.LittleEndian.Uint16(b[5:]))})
	}
	for ; len(b) > 0; b = b[8:] {
		p.FS = append(p.FS, FSSite{Off: binary.LittleEndian.Uint32(b), Len: b[4], Steal: b[5], Cave: int16(binary.LittleEndian.Uint16(b[6:]))})
	}
	return p, true
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".plan-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), path)
}
