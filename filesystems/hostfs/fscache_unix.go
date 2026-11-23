//go:build darwin || linux

package hostfs

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// CachedFS remembers lookups so a path walk costs no host calls once its
// components have been seen. The lower layer is read-only, so its lstat and
// readlink answers hold for the whole run. The upper layer changes only through
// the supervisor; the paths found missing there are remembered until the next
// change to it, and a path below a missing directory is missing too, and so is
// what a lookup reads of a path found there (its kind and inode, which only a
// change to the layer's names alters). Without a root, guest paths are host
// paths anyone may change, and nothing is cached.
type CachedFS struct {
	HostFS
	lower, upper string   // layer roots with a trailing separator, "" if none
	own          []string // the supervisor's writable directories, should the root hold them

	mu     sync.Mutex
	stats  map[string]lstatResult
	links  map[string]linkResult
	absent map[string]bool     // upper paths that did not exist
	ids    map[string]idResult // upper paths found, for a lookup
	gen    uint64              // upper layer changes; a lookup older than one is not kept
}

type idResult struct {
	fi  os.FileInfo
	gen uint64
}

type lstatResult struct {
	fi  os.FileInfo
	err error
}

type linkResult struct {
	target string
	err    error
}

// cacheMax bounds each table; a full one starts over.
const cacheMax = 1 << 17

func newCachedFS(h HostFS, rootAbs, upperAbs string) HostFS {
	c := &CachedFS{HostFS: h}
	if rootAbs == "" {
		return h
	}
	c.lower = withSep(rootAbs)
	if upperAbs != "" {
		c.upper = withSep(upperAbs)
	}
	if d := os.TempDir(); d != "" {
		c.own = append(c.own, withSep(d))
	}
	c.own = append(c.own, "/tmp/lcn.")
	return c
}

// withSep is dir with one trailing separator (the root "/" has it already).
func withSep(dir string) string {
	if strings.HasSuffix(dir, string(filepath.Separator)) {
		return dir
	}
	return dir + string(filepath.Separator)
}

// inLower reports whether p is in the read-only lower layer. A root of / (or
// of the temp directory) holds the upper layer and the supervisor's own files
// too; a root below the temp directory, as a test's is, holds none of them.
func (c *CachedFS) inLower(p string) bool {
	if !under(p, c.lower) || c.inUpper(p) {
		return false
	}
	for _, d := range c.own {
		if strings.HasPrefix(p, d) && !(len(c.lower) > len(d) && strings.HasPrefix(c.lower, d)) {
			return false
		}
	}
	return true
}

func (c *CachedFS) inUpper(p string) bool { return c.upper != "" && under(p, c.upper) }

// under reports whether p is the directory dir (given with its trailing
// separator) or a path below it.
func under(p, dir string) bool {
	return strings.HasPrefix(p, dir) || len(p) == len(dir)-1 && strings.HasPrefix(dir, p)
}

// missing reports whether upper path p, or a directory above it, was found
// missing since the last change to the upper layer.
func (c *CachedFS) missing(p string) bool {
	for q := p; len(q) >= len(c.upper); q = filepath.Dir(q) {
		if c.absent[q] {
			return true
		}
	}
	return false
}

func (c *CachedFS) hLstat(p string) (os.FileInfo, error) {
	switch {
	case c.inLower(p):
		c.mu.Lock()
		r, ok := c.stats[p]
		c.mu.Unlock()
		if ok {
			return r.fi, r.err
		}
		fi, err := c.HostFS.hLstat(p)
		c.mu.Lock()
		if c.stats == nil || len(c.stats) >= cacheMax {
			c.stats = map[string]lstatResult{}
		}
		c.stats[p] = lstatResult{fi, err}
		c.mu.Unlock()
		return fi, err
	case c.inUpper(p):
		c.mu.Lock()
		gone := c.missing(p)
		gen := c.gen
		c.mu.Unlock()
		if gone {
			return nil, &os.PathError{Op: "lstat", Path: p, Err: syscall.ENOENT}
		}
		fi, err := c.HostFS.hLstat(p)
		if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.ENOENT {
			c.mu.Lock()
			if c.gen == gen {
				if c.absent == nil || len(c.absent) >= cacheMax {
					c.absent = map[string]bool{}
				}
				c.absent[p] = true
			}
			c.mu.Unlock()
		}
		return fi, err
	}
	return c.HostFS.hLstat(p)
}

// hLstatID is an lstat for a lookup, which reads only the kind and the device
// and inode of the result.
func (c *CachedFS) hLstatID(p string) (os.FileInfo, error) {
	if !c.inUpper(p) {
		return c.hLstat(p)
	}
	c.mu.Lock()
	r, ok := c.ids[p]
	gen := c.gen
	c.mu.Unlock()
	if ok && r.gen == gen {
		return r.fi, nil
	}
	fi, err := c.hLstat(p)
	if err == nil {
		c.mu.Lock()
		if c.gen == gen {
			if c.ids == nil || len(c.ids) >= cacheMax {
				c.ids = map[string]idResult{}
			}
			c.ids[p] = idResult{fi, gen}
		}
		c.mu.Unlock()
	}
	return fi, err
}

func (c *CachedFS) hReadlink(p string) (string, error) {
	if !c.inLower(p) {
		return c.HostFS.hReadlink(p)
	}
	c.mu.Lock()
	r, ok := c.links[p]
	c.mu.Unlock()
	if ok {
		return r.target, r.err
	}
	// Most components are not links: the lstat, cached for the lookups
	// that follow, says so without the readlink's open of the parent.
	var t string
	fi, err := c.hLstat(p)
	switch {
	case err != nil:
		if pe, ok := err.(*os.PathError); ok {
			err = &os.PathError{Op: "readlink", Path: p, Err: pe.Err}
		}
	case fi.Mode()&os.ModeSymlink == 0:
		err = &os.PathError{Op: "readlink", Path: p, Err: syscall.EINVAL}
	default:
		t, err = c.HostFS.hReadlink(p)
	}
	c.mu.Lock()
	if c.links == nil || len(c.links) >= cacheMax {
		c.links = map[string]linkResult{}
	}
	c.links[p] = linkResult{t, err}
	c.mu.Unlock()
	return t, err
}

// changed forgets the upper layer's missing paths once a change to it is
// done: something may exist there now.
func (c *CachedFS) Changed() {
	c.mu.Lock()
	c.gen++
	clear(c.absent)
	c.mu.Unlock()
}

func (c *CachedFS) hOpen(p string, flag int, perm os.FileMode) (*os.File, error) {
	if flag&os.O_CREATE != 0 {
		defer c.Changed()
	}
	return c.HostFS.hOpen(p, flag, perm)
}

func (c *CachedFS) hMkdir(p string, perm uint32) error {
	defer c.Changed()
	return c.HostFS.hMkdir(p, perm)
}

func (c *CachedFS) hSymlink(target, p string) error {
	defer c.Changed()
	return c.HostFS.hSymlink(target, p)
}

func (c *CachedFS) hMkfifo(p string, perm uint32) error {
	defer c.Changed()
	return c.HostFS.hMkfifo(p, perm)
}

func (c *CachedFS) hMksock(p string, perm uint32) error {
	defer c.Changed()
	return c.HostFS.hMksock(p, perm)
}

func (c *CachedFS) hRename(from, to string, exchange bool) error {
	defer c.Changed()
	return c.HostFS.hRename(from, to, exchange)
}

func (c *CachedFS) hUnlink(p string, dir bool) error {
	defer c.Changed()
	return c.HostFS.hUnlink(p, dir)
}

func (c *CachedFS) hLink(from, to string) error {
	defer c.Changed()
	return c.HostFS.hLink(from, to)
}

func (c *CachedFS) hClone(from, to string) error {
	defer c.Changed()
	return c.HostFS.hClone(from, to)
}

func (c *CachedFS) hCloneFile(f *os.File, to string) error {
	defer c.Changed()
	return c.HostFS.hCloneFile(f, to)
}
