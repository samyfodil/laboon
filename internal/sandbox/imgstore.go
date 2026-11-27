package sandbox

import (
	"bytes"
	"container/list"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// imgStore bounds a directory of prepared images (imgcache_windows.go). An
// entry is two files, the image named by its key and its metadata beside it
// with imgMetaExt; the metadata's mtime is the entry's last use. The
// directory is listed once per process, on its first save; from then on the
// process keeps the count, the bytes and the least-recently-used order itself
// and prunes on each save, so a run that only maps entries never lists it.
// Processes sharing the directory each hold it near the bound as they see it.
//
// A file in use cannot be deleted on Windows (a run has its view mapped):
// such an entry is skipped and stays indexed, and the next one goes instead.
type imgStore struct {
	dir      string
	maxFiles int
	maxBytes int64
	remove   func(string) error

	mu      sync.Mutex
	scanned bool
	bytes   int64
	lru     list.List // least recently used first: *imgEntry
	idx     map[string]*list.Element
}

type imgEntry struct {
	name string
	size int64
}

// Prepared images are as large as the programs' code, tens of MiB for a
// runtime like node; 1 GiB holds a machine's working set of them.
const (
	maxImgFiles = 256
	maxImgBytes = 1 << 30
	imgMetaExt  = ".json"
	imgTempPfx  = ".img-"
)

var imgStores = struct {
	sync.Mutex
	m map[string]*imgStore
}{m: map[string]*imgStore{}}

// imgStoreAt is the process's store for dir, shared by every run using it.
func imgStoreAt(dir string) *imgStore {
	imgStores.Lock()
	defer imgStores.Unlock()
	s := imgStores.m[dir]
	if s == nil {
		s = newImgStore(dir, maxImgFiles, maxImgBytes)
		imgStores.m[dir] = s
	}
	return s
}

func newImgStore(dir string, maxFiles int, maxBytes int64) *imgStore {
	return &imgStore{dir: dir, maxFiles: maxFiles, maxBytes: maxBytes, remove: os.Remove, idx: map[string]*list.Element{}}
}

func (s *imgStore) path(name string) string { return filepath.Join(s.dir, name) }

// used marks an entry just mapped as recently used, on disk for the next
// process's listing and in this one's index.
func (s *imgStore) used(name string) {
	now := time.Now()
	if os.Chtimes(s.path(name)+imgMetaExt, now, now) != nil {
		return
	}
	s.mu.Lock()
	if e := s.idx[name]; e != nil {
		s.lru.MoveToBack(e)
	}
	s.mu.Unlock()
}

// fits reports whether an entry of size bytes may be stored at all.
func (s *imgStore) fits(size int64) bool { return size <= s.maxBytes/4 }

// saved records an entry just written, of size bytes in all, and prunes.
func (s *imgStore) saved(name string, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.scanned {
		s.scan()
		s.scanned = true
	}
	if e := s.idx[name]; e != nil {
		ent := e.Value.(*imgEntry)
		s.bytes += size - ent.size
		ent.size = size
		s.lru.MoveToBack(e)
	} else {
		s.idx[name] = s.lru.PushBack(&imgEntry{name, size})
		s.bytes += size
	}
	s.prune(name)
}

// prune deletes the least recently used entries past the bounds, never keep
// (the one just saved). An entry whose image will not go is in use and stays.
func (s *imgStore) prune(keep string) {
	for e := s.lru.Front(); e != nil && (s.lru.Len() > s.maxFiles || s.bytes > s.maxBytes); {
		next := e.Next()
		ent := e.Value.(*imgEntry)
		if ent.name != keep && s.drop(ent.name) {
			s.lru.Remove(e)
			delete(s.idx, ent.name)
			s.bytes -= ent.size
		}
		e = next
	}
}

// drop deletes an entry: the image first, so its metadata, which a reader
// takes first, never outlives a deleted image while the image is in use.
func (s *imgStore) drop(name string) bool {
	if err := s.remove(s.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	s.remove(s.path(name) + imgMetaExt)
	return true
}

// scan indexes the directory's entries, oldest use first, and deletes the
// temporaries of writers that died before renaming (one still being written
// by another process is open, so on Windows it stays; elsewhere that write
// is lost, which only costs a later run the work).
func (s *imgStore) scan() {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	type found struct {
		size int64
		used time.Time
		meta bool
	}
	byName := map[string]*found{}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, imgTempPfx) {
			s.remove(s.path(n))
			continue
		}
		key, meta := strings.CutSuffix(n, imgMetaExt)
		if !isImgName(key) {
			continue
		}
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		f := byName[key]
		if f == nil {
			f = &found{}
			byName[key] = f
		}
		f.size += fi.Size()
		if meta || !f.meta {
			f.used, f.meta = fi.ModTime(), meta
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		if s.idx[n] == nil {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, j int) bool { return byName[names[i]].used.Before(byName[names[j]].used) })
	for _, n := range names {
		s.idx[n] = s.lru.PushBack(&imgEntry{n, byName[n].size})
		s.bytes += byName[n].size
	}
}

func isImgName(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// writeImgAtomic writes a then b to path through a temporary in its directory.
func writeImgAtomic(path string, a, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), imgTempPfx+"*")
	if err != nil {
		return err
	}
	_, err = f.Write(a)
	if err == nil {
		_, err = f.Write(b)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// goBuildIDPrefix starts the build ID the Go linker puts at the start of the
// text of a non-ELF executable (PE, Mach-O).
var goBuildIDPrefix = []byte("\xff Go build ID: \"")

// goBuildID is the Go build ID in the head of a non-ELF executable, "" if it
// has none. It is derived from the linker's inputs and output, so it names
// the build: the same supervisor rebuilt keeps it, any change to its code
// gives a new one.
func goBuildID(r io.Reader) string {
	head := make([]byte, 32<<10)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return ""
	}
	head = head[:n]
	i := bytes.Index(head, goBuildIDPrefix)
	if i < 0 {
		return ""
	}
	id := head[i+len(goBuildIDPrefix):]
	j := bytes.IndexByte(id, '"')
	if j <= 0 {
		return ""
	}
	return string(id[:j])
}
