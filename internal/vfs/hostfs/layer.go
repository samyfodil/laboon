package hostfs

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/samyfodil/laboon/core"
)

// Layer is one overlay layer, backed by a host directory (aufs/overlayfs style):
// its files, directories and symlinks are real on disk, a deletion is an OCI
// whiteout marker (".wh.<name>") and an opaque directory a ".wh..wh..opq" marker,
// so the directory is a complete image layer on its own. The only state not on
// disk is the override map: the guest-visible owner, mode and special-node kind
// that the host file cannot hold because laboon runs unprivileged. It is small —
// one entry per path the guest changed that way — and can be saved to a sidecar.
// A Layer is safe for concurrent use.
type Layer struct {
	dir string

	mu   sync.Mutex
	over map[string]*core.Override
	wh   map[string]bool // whiteout index: deleted paths, mirrored by on-disk .wh. markers
}

// NewLayer makes a layer backed by the host directory dir (created if absent).
func NewLayer(dir string) (*Layer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Layer{dir: dir, over: map[string]*core.Override{}, wh: map[string]bool{}}, nil
}

// Dir is the layer's host directory.
func (l *Layer) Dir() string { return l.dir }

// SaveMeta writes the override map to the layer's sidecar file, so the guest
// owner, mode and special-node metadata persist with the directory.
func (l *Layer) SaveMeta() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.over) == 0 {
		return nil
	}
	b := core.EncodeMeta(l.over)
	if len(b) == 0 {
		return nil
	}
	return os.WriteFile(filepath.Join(l.dir, core.MetaFileName), b, 0o600)
}

// LoadOverrides reads the guest metadata a layer directory's sidecar records
// (non-root owners and the special mode bits a host file cannot hold), keyed by
// layer-relative slash path. A consumer that materializes the directory as a
// plain tree (a build root, a sandbox lower) uses it to restore what the host
// files cannot carry. Absent or unreadable sidecar yields an empty map.
func LoadOverrides(dir string) map[string]core.Override {
	b, err := os.ReadFile(filepath.Join(dir, core.MetaFileName))
	if err != nil {
		return nil
	}
	out := map[string]core.Override{}
	core.DecodeMeta(b, func(p string, o core.Override) { out[p] = o })
	return out
}

// SaveOverrides writes the metadata sidecar in dir from m (slash paths relative
// to dir, no leading slash, as LoadOverrides reads them). The OCI unpacker uses
// it to carry owners and special mode bits a non-root host cannot set on the
// unpacked files. Nothing is written when m records no override.
func SaveOverrides(dir string, m map[string]*core.Override) error {
	b := core.EncodeMeta(m)
	if len(b) == 0 {
		return nil
	}
	return os.WriteFile(filepath.Join(dir, core.MetaFileName), b, 0o600)
}

// LoadMetaInto reads a layer directory's path-keyed override sidecar and keys it
// into store by each path's current host inode, so a reconstructed overlay (a
// reloaded build step, a kept upper reopened) recovers the guest metadata the
// host files cannot hold. A dir with no sidecar loads nothing.
func LoadMetaInto(dir string, store *core.MetaStore) {
	b, err := os.ReadFile(filepath.Join(dir, core.MetaFileName))
	if err != nil {
		return
	}
	core.DecodeMeta(b, func(p string, o core.Override) {
		fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil {
			return
		}
		if id, ok := core.StatID(fi); ok {
			oo := o
			store.Update(id, func(d *core.Override) { *d = oo })
		}
	})
}

// loadMeta reads the sidecar override map if present.
func (l *Layer) loadMeta() {
	b, err := os.ReadFile(filepath.Join(l.dir, core.MetaFileName))
	if err != nil {
		return
	}
	core.DecodeMeta(b, func(p string, o core.Override) {
		oc := o
		l.over[p] = &oc
	})
}

func split(p string) []string {
	p = clean(p)
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// host is the host path of a layer path.
func (l *Layer) host(p string) string {
	return filepath.Join(l.dir, filepath.FromSlash(clean(p)))
}

func (l *Layer) ov(p string) *core.Override {
	p = clean(p)
	o := l.over[p]
	if o == nil {
		o = &core.Override{}
		l.over[p] = o
	}
	return o
}

// --- building a layer ---------------------------------------------------------

func (l *Layer) mkparent(p string) error {
	return os.MkdirAll(filepath.Dir(l.host(p)), 0o755)
}

// Mkdir creates a directory at p.
func (l *Layer) Mkdir(p string, mode uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.mkparent(p); err != nil {
		return err
	}
	return os.Mkdir(l.host(p), core.HostMode(mode, true))
}

// Put creates a regular file at p with the given bytes and mode.
func (l *Layer) Put(p string, mode uint32, data []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.mkparent(p); err != nil {
		return err
	}
	if err := os.WriteFile(l.host(p), data, core.HostMode(mode, false)); err != nil {
		return err
	}
	l.recordMode(p, mode, false)
	return nil
}

// Symlink creates a symlink at p pointing to target.
func (l *Layer) Symlink(p, target string, mode uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.mkparent(p); err != nil {
		return err
	}
	os.Remove(l.host(p))
	return os.Symlink(target, l.host(p))
}

// Hardlink adds the name newp for the file already at oldp (a host hardlink, so
// they share one inode).
func (l *Layer) Hardlink(newp, oldp string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.mkparent(newp); err != nil {
		return err
	}
	os.Remove(l.host(newp))
	return os.Link(l.host(oldp), l.host(newp))
}

// Special records a device, fifo or socket node at p as a placeholder file with
// its kind in the override map (an unprivileged layer cannot make a real one).
func (l *Layer) Special(p string, k core.Kind, rdev uint64, mode uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.mkparent(p); err != nil {
		return err
	}
	if err := os.WriteFile(l.host(p), nil, 0o600); err != nil {
		return err
	}
	o := l.ov(p)
	o.Special, o.Kind, o.Rdev, o.Mode, o.HasMode = true, k, rdev, mode&0o7777, true
	return nil
}

// Whiteout records that p deletes the lower layers' entry there: an in-memory
// index entry (fast to check) backed by an on-disk marker (so the layer is
// durable and serializable).
func (l *Layer) Whiteout(p string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := clean(p)
	dir, base := path.Split(cp)
	if err := os.MkdirAll(l.host(dir), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(l.host(dir), core.WhiteoutPrefix+base), nil, 0o600); err != nil {
		return err
	}
	l.wh[cp] = true
	return nil
}

// Unwhiteout removes the whiteout at p (a path recreated over a deletion).
func (l *Layer) Unwhiteout(p string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := clean(p)
	dir, base := path.Split(cp)
	os.Remove(filepath.Join(l.host(dir), core.WhiteoutPrefix+base))
	delete(l.wh, cp)
}

// IsWhiteout reports whether p is whited out in this layer.
func (l *Layer) IsWhiteout(p string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.wh[clean(p)]
}

// DropDir removes the layer's on-disk copy of the directory p — including any
// whiteout or opaque marker files it holds — and forgets the whiteout keys at or
// below p. It is a no-op if the layer has nothing there.
func (l *Layer) DropDir(p string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := clean(p)
	if err := os.RemoveAll(l.host(cp)); err != nil {
		return err
	}
	prefix := cp + "/"
	for k := range l.wh {
		if k == cp || strings.HasPrefix(k, prefix) {
			delete(l.wh, k)
		}
	}
	return nil
}

// SetOpaque marks the directory at p as hiding every lower entry.
func (l *Layer) SetOpaque(p string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(l.host(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(l.host(p), core.OpaqueMarker), nil, 0o600)
}

// SetMode sets the guest permission bits at p.
func (l *Layer) SetMode(p string, mode uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordMode(p, mode, isDirHost(l.host(p)))
	return nil
}

// recordMode sets the host file's permission and, only when the host cannot hold
// the exact guest bits, records them in the override map; otherwise it clears any
// stale override. The caller holds l.mu.
func (l *Layer) recordMode(p string, mode uint32, dir bool) {
	hm := core.HostMode(mode, dir)
	os.Chmod(l.host(p), hm)
	p = clean(p)
	if uint32(hm)&0o7777 == mode&0o7777 {
		if o := l.over[p]; o != nil {
			o.HasMode = false
			l.gc(p)
		}
		return
	}
	o := l.ov(p)
	o.Mode, o.HasMode = mode&0o7777, true
}

// gc drops an override that no longer records anything. The caller holds l.mu.
func (l *Layer) gc(p string) {
	p = clean(p)
	if o := l.over[p]; o != nil && !o.HasMode && !o.HasOwner && !o.Special {
		delete(l.over, p)
	}
}

// SetOwner sets the guest owner at p.
func (l *Layer) SetOwner(p string, uid, gid uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	o := l.ov(p)
	o.Uid, o.Gid, o.HasOwner = uid, gid, true
	return nil
}

// SetOwnerAll sets the owner of every path in the layer, for COPY --chown.
func (l *Layer) SetOwnerAll(uid, gid uint32) {
	filepath.WalkDir(l.dir, func(hp string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, e := filepath.Rel(l.dir, hp)
		if e != nil || rel == "." {
			return nil
		}
		name := filepath.ToSlash(rel)
		if strings.HasPrefix(path.Base(name), core.WhiteoutPrefix) {
			return nil
		}
		l.SetOwner(name, uid, gid)
		return nil
	})
}

// SetModeAll sets mode (the full 07777, including setuid/setgid/sticky) on every
// entry, recording an override where the host file cannot hold the exact bits.
// It is COPY/ADD --chmod, whose special bits a plain host file drops.
func (l *Layer) SetModeAll(mode uint32) {
	filepath.WalkDir(l.dir, func(hp string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, e := filepath.Rel(l.dir, hp)
		if e != nil || rel == "." {
			return nil
		}
		name := filepath.ToSlash(rel)
		if core.Internal(path.Base(name)) || d.Type()&os.ModeSymlink != 0 {
			return nil // markers/sidecar, and symlinks carry no mode
		}
		l.SetMode(name, mode)
		return nil
	})
}

// --- reading a layer ----------------------------------------------------------

// Stat returns what the layer records at p: a file, a whiteout, or nothing.
func (l *Layer) Stat(p string) (core.Attr, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p = clean(p)
	if l.wh[p] {
		return core.Attr{Whiteout: true}, true
	}
	fi, err := os.Lstat(l.host(p))
	if err != nil {
		return core.Attr{}, false
	}
	a := l.attrLocked(p, fi)
	return a, true
}

func (l *Layer) attrLocked(p string, fi os.FileInfo) core.Attr {
	a := core.Attr{Mode: uint32(fi.Mode().Perm())}
	switch {
	case fi.IsDir():
		a.Kind = core.Dir
		if _, err := os.Lstat(filepath.Join(l.host(p), core.OpaqueMarker)); err == nil {
			a.Opaque = true
		}
	case fi.Mode()&os.ModeSymlink != 0:
		a.Kind = core.Symlink
		a.Target, _ = os.Readlink(l.host(p))
	default:
		a.Kind = core.Reg
	}
	if o := l.over[p]; o != nil {
		if o.Special {
			a.Kind, a.Rdev = o.Kind, o.Rdev
		}
		if o.HasMode {
			a.Mode = o.Mode
		}
		if o.HasOwner {
			a.Uid, a.Gid = o.Uid, o.Gid
		}
	}
	return a
}

// ReadFile returns the bytes of the regular file at p.
func (l *Layer) ReadFile(p string) ([]byte, error) {
	return os.ReadFile(l.host(p))
}

// adopt copies the path p from src into this layer with the attributes a — a
// copy-up. The parent must already exist.
func (l *Layer) adopt(src *Layer, p string, a core.Attr) error {
	if err := l.mkparent(p); err != nil {
		return err
	}
	switch {
	case a.Kind == core.Dir:
		if err := os.MkdirAll(l.host(p), core.HostMode(a.Mode, true)); err != nil {
			return err
		}
	case a.Kind == core.Symlink:
		os.Remove(l.host(p))
		if err := os.Symlink(a.Target, l.host(p)); err != nil {
			return err
		}
	case a.Kind >= core.Fifo: // a special node placeholder
		if err := os.WriteFile(l.host(p), nil, 0o600); err != nil {
			return err
		}
	default: // regular file
		if err := copyFile(src.host(p), l.host(p), core.HostMode(a.Mode, false)); err != nil {
			return err
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.Kind != core.Symlink {
		l.recordMode(p, a.Mode, a.Kind == core.Dir)
	}
	if a.Uid != 0 || a.Gid != 0 {
		o := l.ov(p)
		o.Uid, o.Gid, o.HasOwner = a.Uid, a.Gid, true
	}
	if a.Kind >= core.Fifo {
		o := l.ov(p)
		o.Special, o.Kind, o.Rdev = true, a.Kind, a.Rdev
	}
	return nil
}

// removeOverride drops any override recorded for p.
func (l *Layer) removeOverride(p string) {
	l.mu.Lock()
	delete(l.over, clean(p))
	l.mu.Unlock()
}

// Entries lists directory p's own entries, whether it is opaque, and whether it
// is a directory in this layer.
func (l *Layer) Entries(p string) (entries []core.Entry, opaque, ok bool) {
	ents, err := os.ReadDir(l.host(p))
	if err != nil {
		return nil, false, false
	}
	for _, e := range ents {
		name := e.Name()
		switch {
		case name == core.MetaFileName:
			// internal sidecar, not a layer entry
		case name == core.OpaqueMarker:
			opaque = true
		case strings.HasPrefix(name, core.WhiteoutPrefix):
			entries = append(entries, core.Entry{Name: name[len(core.WhiteoutPrefix):], Whiteout: true})
		default:
			entries = append(entries, core.Entry{Name: name, Kind: kindOf(e)})
		}
	}
	return entries, opaque, true
}

func kindOf(e os.DirEntry) core.Kind {
	switch {
	case e.IsDir():
		return core.Dir
	case e.Type()&os.ModeSymlink != 0:
		return core.Symlink
	}
	return core.Reg
}

func isDirHost(hp string) bool {
	fi, err := os.Lstat(hp)
	return err == nil && fi.IsDir()
}
