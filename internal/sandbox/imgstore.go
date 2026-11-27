package sandbox

import (
	"bytes"
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
// with imgMetaExt; the metadata's mtime is the entry's last use. Each save
// lists the directory and prunes it, so every process sharing it holds it to
// one bound; a run that only maps entries never lists it. A save already
// writes a whole image, so the listing costs it little.
//
// A file in use cannot be deleted on Windows (a run has its view mapped, a
// writer has its temporary open): such an entry is skipped, and the next one
// goes instead.
type imgStore struct {
	dir      string
	maxFiles int
	maxBytes int64
	remove   func(string) error
}

type imgEntry struct {
	name string
	size int64
	used time.Time
	meta bool
}

// Prepared images are as large as the programs' code, tens of MiB for a
// runtime like node; 1 GiB holds a machine's working set of them.
const (
	maxImgFiles = 256
	maxImgBytes = 1 << 30
	imgMetaExt  = ".json"
	imgTempPfx  = ".img-"
)

// imgSaves serializes the process's prunes.
var imgSaves sync.Mutex

func newImgStore(dir string, maxFiles int, maxBytes int64) *imgStore {
	return &imgStore{dir: dir, maxFiles: maxFiles, maxBytes: maxBytes, remove: os.Remove}
}

func (s *imgStore) path(name string) string { return filepath.Join(s.dir, name) }

// used marks an entry just mapped as recently used.
func (s *imgStore) used(name string) {
	now := time.Now()
	os.Chtimes(s.path(name)+imgMetaExt, now, now)
}

// fits reports whether an entry of size bytes may be stored at all.
func (s *imgStore) fits(size int64) bool { return size <= s.maxBytes/4 }

// saved prunes the directory after name was written, never deleting name.
func (s *imgStore) saved(name string) {
	imgSaves.Lock()
	defer imgSaves.Unlock()
	ents, total := s.scan()
	n := len(ents)
	for _, e := range ents {
		if n <= s.maxFiles && total <= s.maxBytes {
			return
		}
		if e.name != name && s.drop(e.name) {
			n--
			total -= e.size
		}
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

// scan lists the directory's entries, oldest use first, with their total
// size, and deletes the temporaries of writers that died before renaming.
func (s *imgStore) scan() ([]*imgEntry, int64) {
	dents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, 0
	}
	byName := map[string]*imgEntry{}
	var ents []*imgEntry
	var total int64
	for _, d := range dents {
		n := d.Name()
		if strings.HasPrefix(n, imgTempPfx) {
			s.remove(s.path(n))
			continue
		}
		key, meta := strings.CutSuffix(n, imgMetaExt)
		if !isImgName(key) {
			continue
		}
		fi, err := d.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		e := byName[key]
		if e == nil {
			e = &imgEntry{name: key}
			byName[key] = e
			ents = append(ents, e)
		}
		e.size += fi.Size()
		total += fi.Size()
		if meta || !e.meta {
			e.used, e.meta = fi.ModTime(), meta
		}
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].used.Before(ents[j].used) })
	return ents, total
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
