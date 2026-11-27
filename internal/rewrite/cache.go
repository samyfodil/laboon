package rewrite

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
)

// Cache memoizes Analyze by the SHA-256 of the code, in memory and, if it
// has a directory, on disk, so each library is disassembled once per machine.
// The zero Cache keeps plans in memory only.
//
// Memory is two LRUs: one for plans of images and files, one for code with no
// file behind it (the Anon methods), so a guest minting code at run time can
// neither evict the image plans nor fill the disk.
//
// A cached plan is only a hint: Apply refuses to patch anything that is not
// a syscall instruction, and on Linux the stub's seccomp filter kills any
// syscall a bad plan leaves unpatched. Tampering with the cache can slow a
// guest down or break it, not let it out.
type Cache struct {
	disk *diskDir

	mu         sync.Mutex
	main, anon lru
}

// Memory bounds. An image's plan is a few thousand 8-byte sites at most, and
// a machine's working set of images and libraries is a few hundred, so 4096
// plans or 32 MiB keep all of them. Anonymous code is a JIT's output: rarely
// seen twice, it gets a small LRU that only catches the same bytes made
// executable again within a run.
const (
	maxMainPlans = 4096
	maxMainBytes = 32 << 20
	maxAnonPlans = 512
	maxAnonBytes = 4 << 20
)

// NewCache returns a cache that also keeps plans on disk under dir, so they
// outlive the process; an empty dir keeps them in memory only. Plans for code
// with no file behind it are never written there, and the directory is held
// to a bounded number of files and bytes, least recently used out first. The
// cache owns dir: what scan takes for an older format's plans (64-hex names
// and .plan- temporaries at the top, and in idle v<digits> subdirectories) is
// deleted.
func NewCache(dir string) *Cache {
	c := &Cache{}
	if dir != "" {
		c.disk = newDiskDir(dir)
	}
	return c
}

// Sync waits until the plans queued for disk are written. Writes happen in
// the background, off the caller's path; a process about to exit calls Sync
// so they are not lost.
func (c *Cache) Sync() {
	if c.disk != nil {
		c.disk.sync()
	}
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
	return c.memo(entriesKey(code), func() Plan { return AnalyzeEntries(code, entries, scav) })
}

// AnonEntries is Entries for code with no host file behind it (anonymous or
// JIT memory): its plan is kept only in the anonymous LRU, never on disk.
func (c *Cache) AnonEntries(code []byte, entries []int, scav [][2]int) Plan {
	key := entriesKey(code)
	if p, ok := c.anonGet(key); ok {
		return p
	}
	p := AnalyzeEntries(code, entries, scav)
	c.anonPut(key, p)
	return p
}

func entriesKey(code []byte) [32]byte {
	return saltKey("entries-2", code)
}

func saltKey(salt string, data []byte) [32]byte {
	h := sha256.Sum256(data)
	return sha256.Sum256(append([]byte(salt), h[:]...))
}

// Offsets memoizes an analysis of data that yields instruction offsets. The
// key is salt plus data's SHA-256: callers name their analysis in salt, and
// change it when the analysis changes, so an old result is never reused. A
// failed compute is not cached.
func (c *Cache) Offsets(salt string, data []byte, compute func() ([]uint32, error)) ([]uint32, error) {
	key := saltKey(salt, data)
	if p, ok := c.lookup(key); ok {
		return planOffsets(p), nil
	}
	offs, err := compute()
	if err != nil {
		return nil, err
	}
	c.save(key, offsetsPlan(offs))
	return offs, nil
}

// AnonOffsets is Offsets for code with no host file behind it, kept as
// AnonEntries keeps its plans.
func (c *Cache) AnonOffsets(salt string, data []byte, compute func() ([]uint32, error)) ([]uint32, error) {
	key := saltKey(salt, data)
	if p, ok := c.anonGet(key); ok {
		return planOffsets(p), nil
	}
	offs, err := compute()
	if err != nil {
		return nil, err
	}
	c.anonPut(key, offsetsPlan(offs))
	return offs, nil
}

func offsetsPlan(offs []uint32) Plan {
	var p Plan
	for _, o := range offs {
		p.Sites = append(p.Sites, Site{Off: o})
	}
	return p
}

func planOffsets(p Plan) []uint32 {
	offs := make([]uint32, len(p.Sites))
	for i, s := range p.Sites {
		offs[i] = s.Off
	}
	return offs
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
	key := saltKey(salt, data)
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
		return offsetsPlan(offs), err
	})
	if err != nil {
		return nil, err
	}
	return planOffsets(p), nil
}

// memo returns the plan for key, computing it with compute only on a miss.
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
	p, ok := c.main.get(key)
	c.mu.Unlock()
	if ok || c.disk == nil {
		return p, ok
	}
	if p, ok = c.disk.read(key); ok {
		c.mu.Lock()
		c.main.put(key, p, maxMainPlans, maxMainBytes)
		c.mu.Unlock()
	}
	return p, ok
}

// save records p under key in memory and queues it for disk.
func (c *Cache) save(key [32]byte, p Plan) {
	c.mu.Lock()
	c.main.put(key, p, maxMainPlans, maxMainBytes)
	c.mu.Unlock()
	if c.disk != nil {
		c.disk.write(key, encodePlan(p))
	}
}

func (c *Cache) anonGet(key [32]byte) (Plan, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.anon.get(key)
}

func (c *Cache) anonPut(key [32]byte, p Plan) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.anon.put(key, p, maxAnonPlans, maxAnonBytes)
}

// lru is a least-recently-used map of plans, bounded by count and by bytes.
type lru struct {
	idx   map[[32]byte]*list.Element
	order list.List // front is the most recent
	bytes int
}

type lruEnt struct {
	key  [32]byte
	plan Plan
	size int
}

// planSize is about what p holds in memory: its sites and the entry around it.
func planSize(p Plan) int {
	return 128 + 8*(len(p.Sites)+len(p.FS))
}

func (l *lru) get(key [32]byte) (Plan, bool) {
	e, ok := l.idx[key]
	if !ok {
		return Plan{}, false
	}
	l.order.MoveToFront(e)
	return e.Value.(*lruEnt).plan, true
}

func (l *lru) put(key [32]byte, p Plan, maxN, maxBytes int) {
	if l.idx == nil {
		l.idx = map[[32]byte]*list.Element{}
	}
	size := planSize(p)
	if e, ok := l.idx[key]; ok {
		ent := e.Value.(*lruEnt)
		l.bytes += size - ent.size
		ent.plan, ent.size = p, size
		l.order.MoveToFront(e)
	} else {
		l.idx[key] = l.order.PushFront(&lruEnt{key, p, size})
		l.bytes += size
	}
	for l.order.Len() > 1 && (l.order.Len() > maxN || l.bytes > maxBytes) {
		ent := l.order.Remove(l.order.Back()).(*lruEnt)
		delete(l.idx, ent.key)
		l.bytes -= ent.size
	}
}

// Plan files are a version byte followed by (offset uint32, steal uint8,
// cave int16) records, little-endian. The FS version adds the %fs sites: the
// syscall-site count (uint32) comes first, and (offset uint32, length uint8,
// steal uint8, cave int16) records follow the syscall sites. Versions 1 and 2
// predate stealing a run before a syscall, 3 and 4 caves, 6 a run or a cave
// for an %fs instruction; their plans are recomputed. A change to either
// version also moves the directory plans are kept in (diskGen), so files of
// an old format are deleted, once no build uses them, rather than kept.
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
