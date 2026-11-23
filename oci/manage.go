package oci

import (
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

// refFileFor is the cache file that records which unpacked image a ref names.
// The key matches Pull/Store: amd64 keeps the bare name, other arches add a
// suffix, so one ref can name an image per architecture.
func refFileFor(dir string, r name.Reference, arch string) string {
	key := r.Name()
	if arch != "amd64" {
		key += "@" + arch
	}
	// url.PathEscape leaves ':' (a ref's tag, and a digest's algorithm separator)
	// unescaped, but NTFS reads a ':' in a filename as an alternate-data-stream
	// separator — "img:latest" becomes the empty file "img" with the data in a
	// ":latest" stream — so escape it too, keeping the name one real file on every OS.
	return filepath.Join(dir, "refs", strings.ReplaceAll(url.PathEscape(key), ":", "%3A"))
}

// Local returns a previously pulled or stored image for ref without touching a
// registry, or an error that unwraps to fs.ErrNotExist when it is not cached.
// Its Digest identifies the unpacked contents and Root is the rootfs directory;
// callers use it to ask whether an image exists and what its digest is. opt.Arch
// (default: the host's) selects the architecture, as in Pull.
func Local(ref string, opt Options) (*Image, error) {
	arch := opt.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	dir, err := cacheDir(opt.CacheDir)
	if err != nil {
		return nil, err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	return local(dir, refFileFor(dir, r, arch), ref)
}

// Remove deletes ref from the cache. The unpacked image it named is removed too
// once no other ref names it. A ref that is not cached is not an error.
func Remove(ref string, opt Options) error {
	arch := opt.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	dir, err := cacheDir(opt.CacheDir)
	if err != nil {
		return err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return err
	}
	refFile := refFileFor(dir, r, arch)
	hex, err := os.ReadFile(refFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.Remove(refFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if h := strings.TrimSpace(string(hex)); validHex(h) {
		_, err := removeImage(dir, h)
		return err
	}
	return nil
}

// removeImage removes the unpacked image hex unless a ref names it, under its
// lock, so neither a store in progress nor one finished meanwhile loses it.
// Its config goes first: a rootfs without one is never taken for whole.
func removeImage(dir, hex string) (bool, error) {
	unlock, err := lockImage(dir, hex)
	if err != nil {
		return false, err
	}
	defer unlock()
	if referenced(dir, hex, "") {
		return false, nil
	}
	if err := os.Remove(filepath.Join(dir, hex, "config.json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, os.RemoveAll(filepath.Join(dir, hex))
}

// Sweep bounds the image cache on a build node, which pulls accumulate on. It
// first removes unpacked images no ref names -- orphans from an interrupted pull
// or a removed ref. Then, if budget > 0 and the cache still exceeds it, it
// removes images, and the refs that name them, from least- to most-recently used
// (Pull and Local mark an image used) until the cache is at most budget bytes. It
// returns the bytes freed.
func Sweep(opt Options, budget int64) (int64, error) {
	dir, err := cacheDir(opt.CacheDir)
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	type img struct {
		hex  string
		size int64
		used time.Time
	}
	var imgs []img
	var total int64
	for _, e := range entries {
		if !e.IsDir() || !validHex(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		sz := dirSize(p)
		at := time.Time{}
		if fi, err := os.Stat(p); err == nil {
			at = fi.ModTime()
		}
		imgs = append(imgs, img{e.Name(), sz, at})
		total += sz
	}
	var freed int64
	remove := func(hex string, sz int64) {
		removeRefs(dir, hex)
		if gone, err := removeImage(dir, hex); gone && err == nil {
			freed += sz
			total -= sz
		}
	}
	// Orphans first: an image no ref names is never reachable again.
	live := imgs[:0]
	for _, m := range imgs {
		if referenced(dir, m.hex, "") {
			live = append(live, m)
		} else {
			remove(m.hex, m.size)
		}
	}
	if budget <= 0 || total <= budget {
		return freed, nil
	}
	// Still over budget: drop the least-recently used until it fits.
	sort.Slice(live, func(i, j int) bool { return live[i].used.Before(live[j].used) })
	for _, m := range live {
		if total <= budget {
			break
		}
		remove(m.hex, m.size)
	}
	return freed, nil
}

// referenced reports whether any ref other than skip names the image hex.
func referenced(dir, hex, skip string) bool {
	entries, err := os.ReadDir(filepath.Join(dir, "refs"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == skip {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "refs", e.Name()))
		if err == nil && strings.TrimSpace(string(b)) == hex {
			return true
		}
	}
	return false
}

// removeRefs deletes every ref that names the image hex.
func removeRefs(dir, hex string) {
	entries, err := os.ReadDir(filepath.Join(dir, "refs"))
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(dir, "refs", e.Name())
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == hex {
			os.Remove(p)
		}
	}
}

// dirSize is the total size of the files under p.
func dirSize(p string) int64 {
	var n int64
	filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}
