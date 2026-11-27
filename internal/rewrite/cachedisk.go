package rewrite

import (
	"container/list"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Disk bounds. A plan file is a few bytes to a few tens of KiB, and the
// files a machine reuses are its images and libraries, a few hundred; 4096
// files keep them with room to spare, and 64 MiB caps the rare large plans.
// The queue bounds what waits for the writer; past it a plan is not
// persisted, which only costs a re-analysis in a later process.
const (
	maxDiskFiles = 4096
	maxDiskBytes = 64 << 20
	maxDiskQueue = 256
)

// diskGen names the subdirectory plans of the current file format live in.
// Plans of any other generation are deleted when a process first writes.
var diskGen = fmt.Sprintf("v%d-%d", planVersion, planVersionFS)

// diskDir keeps plan files under root/diskGen. A writer goroutine, started
// when there is something to write and gone when there is not, applies the
// queued writes, so no caller ever waits on the filesystem for one. On its
// first run in a process it lists the directory once; from then on it keeps
// the count, the bytes and the least-recently-used order itself and prunes on
// each write. Other processes writing the same directory make those numbers
// approximate: each one holds the directory near the bound as it sees it.
type diskDir struct {
	root, dir       string
	maxFiles        int
	maxBytes, bytes int64

	mu   sync.Mutex
	idle sync.Cond
	q    []diskOp
	busy bool

	// The writer's own state; only one writer runs at a time.
	scanned bool
	files   list.List // least recently used first: *diskFile
	idx     map[string]*list.Element
}

type diskOp struct {
	name string
	data []byte // nil marks a read hit: the file is touched, not written
}

type diskFile struct {
	name string
	size int64
}

func newDiskDir(root string) *diskDir {
	d := &diskDir{root: root, dir: filepath.Join(root, diskGen), maxFiles: maxDiskFiles, maxBytes: maxDiskBytes, idx: map[string]*list.Element{}}
	d.idle.L = &d.mu
	return d
}

func (d *diskDir) read(key [32]byte) (Plan, bool) {
	name := hex.EncodeToString(key[:])
	b, err := os.ReadFile(filepath.Join(d.dir, name))
	if err != nil {
		return Plan{}, false
	}
	p, ok := decodePlan(b)
	if ok {
		d.enqueue(diskOp{name: name})
	}
	return p, ok
}

func (d *diskDir) write(key [32]byte, b []byte) {
	d.enqueue(diskOp{name: hex.EncodeToString(key[:]), data: b})
}

func (d *diskDir) enqueue(op diskOp) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.q) >= maxDiskQueue {
		return
	}
	d.q = append(d.q, op)
	if !d.busy {
		d.busy = true
		go d.drain()
	}
}

func (d *diskDir) sync() {
	d.mu.Lock()
	for d.busy {
		d.idle.Wait()
	}
	d.mu.Unlock()
}

func (d *diskDir) drain() {
	if !d.scanned {
		d.scan()
		d.scanned = true
	}
	for {
		d.mu.Lock()
		ops := d.q
		d.q = nil
		if len(ops) == 0 {
			d.busy = false
			d.idle.Broadcast()
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()
		for _, op := range ops {
			d.apply(op)
		}
	}
}

func (d *diskDir) apply(op diskOp) {
	path := filepath.Join(d.dir, op.name)
	e := d.idx[op.name]
	if op.data == nil {
		now := time.Now()
		if os.Chtimes(path, now, now) == nil && e != nil {
			d.files.MoveToBack(e)
		}
		return
	}
	// Best effort: a failed write only costs a re-analysis next time.
	if writeAtomic(path, op.data) != nil {
		return
	}
	size := int64(len(op.data))
	if e != nil {
		f := e.Value.(*diskFile)
		d.bytes += size - f.size
		f.size = size
		d.files.MoveToBack(e)
	} else {
		d.idx[op.name] = d.files.PushBack(&diskFile{op.name, size})
		d.bytes += size
	}
	d.prune()
}

func (d *diskDir) prune() {
	for d.files.Len() > 0 && (d.files.Len() > d.maxFiles || d.bytes > d.maxBytes) {
		f := d.files.Remove(d.files.Front()).(*diskFile)
		delete(d.idx, f.name)
		d.bytes -= f.size
		os.Remove(filepath.Join(d.dir, f.name))
	}
}

// scan deletes what older formats left in root and indexes the current
// generation's files, oldest first. A temporary file is one a writer died
// before renaming, or, rarely, one another process is writing, which then
// only loses that write.
func (d *diskDir) scan() {
	if ents, err := os.ReadDir(d.root); err == nil {
		for _, e := range ents {
			name := filepath.Join(d.root, e.Name())
			switch {
			case e.Name() == diskGen:
			case isPlanName(e.Name()) || strings.HasPrefix(e.Name(), ".plan-"):
				os.Remove(name)
			case e.IsDir() && isGenName(e.Name()):
				removePlans(name)
				os.Remove(name)
			}
		}
	}
	ents, err := os.ReadDir(d.dir)
	if err != nil {
		return
	}
	type found struct {
		diskFile
		mtime time.Time
	}
	var fs []found
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".plan-") {
			os.Remove(filepath.Join(d.dir, e.Name()))
			continue
		}
		if !isPlanName(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() {
			fs = append(fs, found{diskFile{e.Name(), fi.Size()}, fi.ModTime()})
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].mtime.Before(fs[j].mtime) })
	for _, f := range fs {
		if _, ok := d.idx[f.name]; ok {
			continue
		}
		df := f.diskFile
		d.idx[f.name] = d.files.PushBack(&df)
		d.bytes += f.size
	}
	d.prune()
}

// removePlans deletes the plan files in dir, a directory of an older
// generation, and nothing else.
func removePlans(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if isPlanName(e.Name()) || strings.HasPrefix(e.Name(), ".plan-") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func isPlanName(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isGenName(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, c := range s[1:] {
		if (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
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
