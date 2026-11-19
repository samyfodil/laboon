//go:build darwin || linux || windows

package sandbox

import (
	"os"
	"path"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/internal/namespace"
)

// Guest file permission checks against the process's fs credentials. Image
// (lower) files and files a root process made are owned by root; files a
// process makes under another fsuid/fsgid record that owner in the overlay's
// side table (overlay_darwin.go), keyed by the upper file's host inode.

// fsCred returns the caller's file-access credentials, and false when every
// DAC check passes anyway (fsuid 0 with the DAC capabilities), the common case.
func (g *dguest) fsCred() (dacCred, bool) {
	fs := g.dfs
	fs.mu.Lock()
	defer fs.mu.Unlock()
	c := &g.ps.cred
	const all = 1<<capDacOverride | 1<<capDacReadSearch | 1<<capFowner
	if c.fsuid == 0 && c.capEff&all == all {
		return dacCred{}, false
	}
	return dacCred{uid: c.fsuid, gid: c.fsgid, groups: slices.Clone(c.groups), caps: c.capEff}, true
}

// ownerOf returns a host inode's guest owner and its Linux permission bits
// (the overlay side table's, when chown, chmod or a non-root create set them).
func (g *dguest) ownerOf(fi os.FileInfo) (uid, gid, mode uint32) {
	st := g.linuxStat(fi)
	return st.uid, st.gid, st.mode & 0o7777
}

func (g *dguest) dacFile(c *dacCred, fi os.FileInfo, want int) bool {
	uid, gid, mode := g.ownerOf(fi)
	return dacPermits(c, uid, gid, mode, fi.IsDir(), want)
}

// dacCheck checks want on an existing guest path. A missing path passes:
// the caller's own lookup reports it.
func (g *dguest) dacCheck(gp string, want int) lxErrno {
	c, ok := g.fsCred()
	if !ok {
		return 0
	}
	fi, e := g.lstatGuest(gp)
	if e != 0 || g.dacFile(&c, fi, want) {
		return 0
	}
	return lxEACCES
}

// dacOpen checks an open of gp with Linux open flags.
func (g *dguest) dacOpen(gp string, flags int64) lxErrno {
	const oPath = 0x200000
	c, ok := g.fsCred()
	if !ok {
		return 0
	}
	fi, le := g.lstatGuest(gp)
	if le != 0 {
		if le == lxENOENT && flags&lxOCreat != 0 {
			return g.dacCheck(path.Dir(gp), mayWrite|mayExec)
		}
		return 0
	}
	if flags&oPath != 0 {
		return 0
	}
	want := 0
	switch flags & lxOAccmod {
	case lxORdonly:
		want = mayRead
	case lxOWronly:
		want = mayWrite
	case lxORdwr:
		want = mayRead | mayWrite
	}
	if flags&lxOTrunc != 0 {
		want |= mayWrite
	}
	if !g.dacFile(&c, fi, want) {
		return lxEACCES
	}
	return 0
}

// dacCreate checks that gp may be created in its directory.
func (g *dguest) dacCreate(gp string) lxErrno {
	return g.dacCheck(path.Dir(gp), mayWrite|mayExec)
}

// dacUnlink checks that gp may be removed from its directory (write and
// search on the directory, and the sticky-bit rule).
func (g *dguest) dacUnlink(gp string) lxErrno {
	c, ok := g.fsCred()
	if !ok {
		return 0
	}
	dfi, e := g.lstatGuest(path.Dir(gp))
	if e != 0 {
		return 0
	}
	if !g.dacFile(&c, dfi, mayWrite|mayExec) {
		return lxEACCES
	}
	fi, e := g.lstatGuest(gp)
	if e != 0 {
		return 0
	}
	duid, _, dmode := g.ownerOf(dfi)
	fuid, _, _ := g.ownerOf(fi)
	if !dacStickyOK(&c, duid, dmode, fuid) {
		return lxEPERM
	}
	return 0
}

// create makes name in the directory ploc as the caller's new file at gp, as
// Linux does, owned from the moment it exists: by the caller's fsuid, and its
// fsgid unless the directory is set-group-ID, whose group it takes. The owner
// goes into the create, which the overlay records under its own lock; for a
// backend that does not keep it, dacOwn records it while gp is marked as being
// made, which a stat of gp waits out (makes).
func (g *dguest) create(ploc namespace.Loc, gp string, spec core.CreateSpec) (core.Node, error) {
	fs := g.dfs
	fs.mu.Lock()
	spec.Uid, spec.Gid = g.ps.cred.fsuid, g.ps.cred.fsgid
	fs.mu.Unlock()
	if dfi, e := g.lstatGuest(path.Dir(gp)); e == 0 && dfi.Mode()&os.ModeSetgid != 0 {
		_, spec.Gid, _ = g.ownerOf(dfi)
	}
	g.ov.mk.begin(gp)
	defer g.ov.mk.end(gp)
	n, err := ploc.FS.Create(ploc.Node, path.Base(gp), spec)
	if err == nil {
		g.dacOwn(gp, spec.Uid, spec.Gid)
	}
	return n, err
}

// makes is the guest paths creates are making, from before the name appears
// until the owner is recorded.
type makes struct {
	n    atomic.Int32
	mu   sync.Mutex
	cond sync.Cond
	m    map[string]int
}

func (m *makes) begin(gp string) {
	m.mu.Lock()
	if m.m == nil {
		m.m, m.cond.L = map[string]int{}, &m.mu
	}
	m.m[gp]++
	m.n.Add(1)
	m.mu.Unlock()
}

func (m *makes) end(gp string) {
	m.mu.Lock()
	if m.m[gp]--; m.m[gp] == 0 {
		delete(m.m, gp)
	}
	m.n.Add(-1)
	m.cond.Broadcast()
	m.mu.Unlock()
}

// await waits until no create is making gp.
func (m *makes) await(gp string) {
	if m.n.Load() == 0 {
		return
	}
	m.mu.Lock()
	for m.m[gp] > 0 {
		m.cond.Wait()
	}
	m.mu.Unlock()
}

// dacOwn records uid and gid as the owner of the file the caller just created
// at gp, for a backend whose create does not keep the owner itself.
func (g *dguest) dacOwn(gp string, uid, gid uint32) {
	fi, e := g.lstatNode(gp)
	if e != 0 {
		return
	}
	k := inodeKey(fi)
	if _, ok := g.ov.get(k); !ok && uid == 0 && gid == 0 {
		return
	}
	// Also overwrites a stale owner left by an earlier file with this inode.
	g.ov.update(k, func(m *imeta) { m.uid, m.gid, m.hasOwner = uid, gid, uid != 0 || gid != 0 })
}

// dacAccess is access(2)/faccessat2: mode is F_OK or a mask of R_OK, W_OK and
// X_OK, checked with the real ids unless AT_EACCESS; with the real ids a
// non-root caller has no capabilities and root has its permitted set.
func (g *dguest) dacAccess(gp string, mode, flags int64) lxErrno {
	const atEaccess = 0x200
	fi, e := g.lstatGuest(gp)
	if e != 0 || mode == 0 {
		return e
	}
	var c dacCred
	fs := g.dfs
	fs.mu.Lock()
	cr := &g.ps.cred
	if flags&atEaccess != 0 {
		c = dacCred{uid: cr.fsuid, gid: cr.fsgid, groups: slices.Clone(cr.groups), caps: cr.capEff}
	} else {
		c = dacCred{uid: cr.ruid, gid: cr.rgid, groups: slices.Clone(cr.groups)}
		if cr.ruid == 0 {
			c.caps = cr.capPrm
		}
	}
	fs.mu.Unlock()
	if !g.dacFile(&c, fi, int(mode&7)) {
		return lxEACCES
	}
	return 0
}
