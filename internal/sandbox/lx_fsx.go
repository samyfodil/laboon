//go:build darwin || linux || windows

package sandbox

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/samyfodil/laboon/internal/vfs"
)

// checkpointMeta projects the inode-keyed side table (the live authority for the
// guest owner, mode and special-node kind a host file cannot itself carry) onto
// the top layer's path-keyed override, once, after the guest's writers have
// stopped. It walks the kept upper and derives each real path's metadata from
// its inode's entry, so it captures everything the run recorded there — notably
// a mode preserved by a copy-up, which the per-syscall path never mirrored. A
// guest-made fifo is real on the host during the run; here it becomes the
// placeholder-plus-kind a serialized layer needs. Replaces the per-syscall
// mirror into the path map, which duplicated this authority and could drift.
func (fs *dfs) checkpointMeta() error {
	if fs.top == nil || fs.upperAbs == "" {
		return nil
	}
	top := fs.top
	return filepath.WalkDir(fs.upperAbs, func(hp string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(fs.upperAbs, hp)
		if err != nil || rel == "." {
			return err
		}
		if vfs.Internal(filepath.Base(hp)) { // whiteout/opaque markers, the sidecar
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil // a symlink carries no owner/mode override
		}
		gp := "/" + filepath.ToSlash(rel)
		m, ok := fs.ov.get(inodeKey(fi))
		if fi.Mode()&os.ModeNamedPipe != 0 {
			perm := uint32(fi.Mode().Perm())
			if ok && m.hasMode {
				perm = m.mode
			}
			top.Special(gp, vfs.Fifo, 0, perm)
		} else if ok && m.hasMode {
			top.SetMode(gp, m.mode)
		}
		if ok && m.hasOwner {
			top.SetOwner(gp, m.uid, m.gid)
		}
		return nil
	})
}

// Namespace-changing and attribute syscalls over the overlay: rename, link,
// symlink, mknod, chmod/chown (ownership in the side table), utimens,
// truncate, statfs, umask, access.

const (
	lxMknodat       = 33
	lxSymlinkat     = 36
	lxLinkat        = 37
	lxRenameat      = 38
	lxStatfs        = 43
	lxFstatfs       = 44
	lxTruncate      = 45
	lxFtruncate     = 46
	lxFchmod        = 52
	lxFchmodat      = 53
	lxFchownat      = 54
	lxFchown        = 55
	lxUtimensat     = 88
	lxUmask         = 166
	lxRenameat2     = 276
	lxFchmodat2     = 452
	lxAtRemovedir   = 0x200
	lxAtEaccess     = 0x200
	lxAtSymlinkFoll = 0x400

	lxRenameNoreplace = 1
	lxRenameExchange  = 2
	lxRenameWhiteout  = 4

	lxUtimeNow  = 1<<30 - 1
	lxUtimeOmit = 1<<30 - 2

	lxSIFMT  = 0xf000
	lxSIFIFO = 0x1000
	lxSIFCHR = 0x2000
	lxSIFDIR = 0x4000
	lxSIFBLK = 0x6000
	lxSIFREG = 0x8000
	lxSIFLNK = 0xa000
	lxSIFSCK = 0xc000

	lxOverlayfsMagic = 0x794c7630
)

// procFs is the per-process filesystem context threads share (CLONE_FS): the
// umask and the working directory. The cwd is a guest path that a rename of
// it (or of a directory above it), by any process, moves along.
type procFs struct {
	umask   atomic.Uint32
	cwd     atomic.Pointer[string]
	root    atomic.Pointer[string] // chroot: the overlay path the guest sees as "/", nil for the overlay root
	pivoted atomic.Bool            // a pivot_root left an old root stacked here, awaiting one umount
}

func newProcFs() *procFs {
	p := &procFs{}
	p.umask.Store(0o022)
	root := "/"
	p.cwd.Store(&root)
	return p
}

func (p *procFs) clone() *procFs {
	n := &procFs{}
	n.umask.Store(p.umask.Load())
	n.cwd.Store(p.cwd.Load())
	n.root.Store(p.root.Load())
	n.pivoted.Store(p.pivoted.Load())
	return n
}

// chrootRoot is the overlay-absolute directory the process sees as "/", or ""
// when it has not chrooted (the overlay root).
func (g *dguest) chrootRoot() string {
	if g.pfs == nil {
		return ""
	}
	if r := g.pfs.root.Load(); r != nil && *r != "/" {
		return *r
	}
	return ""
}

// chroot sets the process root. Like Linux it needs CAP_SYS_ADMIN and leaves
// the working directory where it was (now possibly outside the new root, which
// a following chdir fixes). Chromium's sandbox chroots to an empty directory to
// drop filesystem access; the re-rooting is real, so a later path lookup under
// the old tree no longer resolves.
func (g *dguest) chroot(pathAddr uint64) int64 {
	if !g.capableFs(capSysAdmin) {
		return sErr(lxEPERM)
	}
	gp, e := g.lookup(lxAtFdcwd, pathAddr, true)
	if e != 0 {
		return sErr(e)
	}
	fi, se := g.lstatGuest(gp)
	if se != 0 {
		return sErr(se)
	}
	if !fi.IsDir() {
		return sErr(lxENOTDIR)
	}
	if g.pfs == nil {
		g.pfs = newProcFs()
	}
	g.pfs.root.Store(&gp)
	return 0
}

// visibleCwd maps an overlay-absolute working directory to what the guest sees
// through its chroot: paths under the chroot lose the prefix, a chroot that the
// cwd is no longer within reads as unreachable, as Linux reports.
func (g *dguest) visibleCwd(cwd string) string {
	root := g.chrootRoot()
	if root == "" {
		return cwd
	}
	if cwd == root {
		return "/"
	}
	if rest, ok := strings.CutPrefix(cwd, root+"/"); ok {
		return "/" + rest
	}
	return "(unreachable)/"
}

// capableFs reports whether the process holds a capability, for the fs layer.
func (g *dguest) capableFs(cap uint) bool {
	g.dfs.mu.Lock()
	defer g.dfs.mu.Unlock()
	return g.ps.cred.capable(cap)
}

// getCwd is g's working directory, always rooted ("/").
func (g *dguest) getCwd() string {
	if g.pfs == nil {
		return "/"
	}
	return *g.pfs.cwd.Load()
}

func (g *dguest) setCwd(gp string) {
	if g.pfs == nil {
		g.pfs = newProcFs()
	}
	g.pfs.cwd.Store(&gp)
}

// moveCwds follows a rename of op to np (and np to op, for an exchange) in
// every live process's working directory.
func (fs *dfs) moveCwds(op, np string, exchange bool) {
	fs.mu.Lock()
	seen := map[*procFs]bool{}
	for _, p := range fs.procs {
		if p.g == nil || p.g.pfs == nil || seen[p.g.pfs] {
			continue
		}
		pf := p.g.pfs
		seen[pf] = true
		cwd := *pf.cwd.Load()
		if n, ok := movedPath(cwd, op, np); ok {
			pf.cwd.Store(&n)
		} else if n, ok := movedPath(cwd, np, op); ok && exchange {
			pf.cwd.Store(&n)
		}
	}
	fs.mu.Unlock()
}

func (g *dguest) getUmask() uint32 {
	if g.pfs == nil {
		return 0o022
	}
	return g.pfs.umask.Load()
}

func init() {
	reg := func(nr uint64, h func(g *dguest, a [6]uint64) int64) { syscalls[nr] = h }
	reg(lxRenameat, func(g *dguest, a [6]uint64) int64 {
		return g.renameat2(int64(a[0]), a[1], int64(a[2]), a[3], 0)
	})
	reg(lxRenameat2, func(g *dguest, a [6]uint64) int64 {
		return g.renameat2(int64(a[0]), a[1], int64(a[2]), a[3], uint32(a[4]))
	})
	reg(lxLinkat, func(g *dguest, a [6]uint64) int64 {
		return g.linkat(int64(a[0]), a[1], int64(a[2]), a[3], int64(a[4]))
	})
	reg(lxSymlinkat, func(g *dguest, a [6]uint64) int64 { return g.symlinkat(a[0], int64(a[1]), a[2]) })
	reg(lxMknodat, func(g *dguest, a [6]uint64) int64 { return g.mknodat(int64(a[0]), a[1], uint32(a[2]), a[3]) })
	reg(lxFchmodat, func(g *dguest, a [6]uint64) int64 { return g.fchmodat(int64(a[0]), a[1], uint32(a[2]), 0) })
	reg(lxFchmodat2, func(g *dguest, a [6]uint64) int64 {
		return g.fchmodat(int64(a[0]), a[1], uint32(a[2]), int64(a[3]))
	})
	reg(lxFchmod, func(g *dguest, a [6]uint64) int64 { return g.fchmod(int64(a[0]), uint32(a[1])) })
	reg(lxFchownat, func(g *dguest, a [6]uint64) int64 {
		return g.fchownat(int64(a[0]), a[1], uint32(a[2]), uint32(a[3]), int64(a[4]))
	})
	reg(lxFchown, func(g *dguest, a [6]uint64) int64 {
		return g.fchownat(int64(a[0]), 0, uint32(a[1]), uint32(a[2]), lxAtEmptyPath)
	})
	reg(lxUtimensat, func(g *dguest, a [6]uint64) int64 { return g.utimensat(int64(a[0]), a[1], a[2], int64(a[3])) })
	reg(lxTruncate, func(g *dguest, a [6]uint64) int64 { return g.truncate(a[0], int64(a[1])) })
	reg(lxFtruncate, func(g *dguest, a [6]uint64) int64 { return g.ftruncate(int64(a[0]), int64(a[1])) })
	reg(lxStatfs, func(g *dguest, a [6]uint64) int64 { return g.statfs(lxAtFdcwd, a[0], a[1]) })
	reg(lxFstatfs, func(g *dguest, a [6]uint64) int64 { return g.statfs(int64(a[0]), 0, a[1]) })
	reg(lxUmask, func(g *dguest, a [6]uint64) int64 {
		if g.pfs == nil {
			g.pfs = newProcFs()
		}
		return int64(g.pfs.umask.Swap(uint32(a[0]) & 0o777))
	})
}

// pathArg reads a path argument and resolves it against dirfd. An empty path
// with AT_EMPTY_PATH (or a NULL path, where the syscall allows one) names
// dirfd's own file; d is then that open file.
func (g *dguest) pathArg(dirfd int64, addr uint64, follow bool, flags int64) (gp string, d *dfile, e lxErrno) {
	p := ""
	if addr != 0 {
		s, err := g.readCStr(addr)
		if err != nil {
			return "", nil, lxEFAULT
		}
		p = s
	}
	dirfd = int64(int32(dirfd))
	if p == "" {
		if addr != 0 && flags&lxAtEmptyPath == 0 {
			return "", nil, lxENOENT
		}
		if dirfd == lxAtFdcwd {
			return g.getCwd(), nil, 0
		}
		d, ok := g.ft.get(int(dirfd))
		if !ok {
			return "", nil, lxEBADF
		}
		return d.name(), d, 0
	}
	gp, e = g.lookup(dirfd, addr, follow)
	return gp, nil, e
}

// lastName returns the final component of a raw path argument ("" for "/").
func lastName(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (g *dguest) rawPath(addr uint64) string {
	p, err := g.readCStr(addr)
	if err != nil {
		return ""
	}
	return p
}

func (g *dguest) unlinkat(dirfd int64, pathAddr uint64, flags int64) int64 {
	if flags&^lxAtRemovedir != 0 {
		return sErr(lxEINVAL)
	}
	rmdir := flags&lxAtRemovedir != 0
	gp, errno := g.lookup(dirfd, pathAddr, false)
	if errno != 0 {
		return sErr(errno)
	}
	if g.dfs.isNsBind(gp) {
		// A namespace file is a bind-mount point; like the kernel, refuse to
		// remove it until it is unmounted (umount2 clears the binding).
		return sErr(lxEBUSY)
	}
	if r, ok := g.pseudoChange(gp, false); ok {
		return r
	}
	if e := g.dacUnlink(gp); e != 0 {
		return sErr(e)
	}
	if rmdir {
		switch lastName(g.rawPath(pathAddr)) {
		case ".":
			return sErr(lxEINVAL)
		case "..":
			return sErr(lxENOTEMPTY)
		}
	}
	if gp == "/" {
		return sErr(lxEBUSY)
	}
	fi, e := g.lstatGuest(gp)
	if e != 0 {
		return sErr(e)
	}
	if g.upperAbs == "" {
		return sErr(lxEROFS)
	}
	if rmdir {
		if !fi.IsDir() {
			return sErr(lxENOTDIR)
		}
		if !g.isEmptyDir(gp) {
			return sErr(lxENOTEMPTY)
		}
	} else if fi.IsDir() {
		return sErr(lxEISDIR)
	}
	// Remove through the overlay Namespace: resolve the parent and Remove the
	// child. The backend drops the upper copy (recursively for a dir whose top
	// copy holds only markers) and writes the lower-hiding whiteout — the
	// upper/DropDir/hideLower dance, now in one place.
	ploc, err := g.vns().Resolve(path.Dir(gp), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	if err := ploc.FS.Remove(ploc.Node, path.Base(gp), fi.IsDir()); err != nil {
		return sErr(osErrno(err))
	}
	g.notifyRemoved(gp, fi.IsDir())
	return 0
}

func (g *dguest) mkdirat(dirfd int64, pathAddr uint64, mode int64) int64 {
	gp, errno := g.lookup(dirfd, pathAddr, false)
	if errno != 0 {
		return sErr(errno)
	}
	if r, ok := g.pseudoChange(gp, true); ok {
		return r
	}
	if _, e := g.lstatGuest(gp); e == 0 {
		return sErr(lxEEXIST)
	} else if e != lxENOENT {
		return sErr(e)
	}
	if e := g.dacCreate(gp); e != 0 {
		return sErr(e)
	}
	ploc, err := g.vns().Resolve(path.Dir(gp), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	if _, err := g.create(ploc, gp, vfs.CreateSpec{Kind: vfs.Dir, Mode: g.createPerm(mode)}); err != nil {
		return sErr(osErrno(err))
	}
	g.notify(gp, inCreate|inIsdir, 0)
	return 0
}

func (g *dguest) renameat2(odfd int64, oaddr uint64, ndfd int64, naddr uint64, flags uint32) int64 {
	if flags&^(lxRenameNoreplace|lxRenameExchange|lxRenameWhiteout) != 0 ||
		flags&(lxRenameNoreplace|lxRenameExchange) == lxRenameNoreplace|lxRenameExchange ||
		flags&lxRenameWhiteout != 0 {
		return sErr(lxEINVAL)
	}
	exchange := flags&lxRenameExchange != 0
	op, e := g.lookup(odfd, oaddr, false)
	if e != 0 {
		return sErr(e)
	}
	np, e := g.lookup(ndfd, naddr, false)
	if e != 0 {
		return sErr(e)
	}
	for _, n := range []string{lastName(g.rawPath(oaddr)), lastName(g.rawPath(naddr))} {
		if n == "." || n == ".." {
			return sErr(lxEBUSY)
		}
	}
	if op == "/" || np == "/" {
		return sErr(lxEBUSY)
	}
	sfi, e := g.lstatGuest(op)
	if e != 0 {
		return sErr(e)
	}
	dfi, de := g.lstatGuest(np)
	dexists := de == 0
	if !dexists {
		if de != lxENOENT {
			return sErr(de)
		}
		if _, pe := g.lstatGuest(path.Dir(np)); pe != 0 {
			return sErr(pe)
		}
	}
	if e := g.dacUnlink(op); e != 0 {
		return sErr(e)
	}
	if dexists {
		if e := g.dacUnlink(np); e != 0 {
			return sErr(e)
		}
	} else if e := g.dacCreate(np); e != 0 {
		return sErr(e)
	}
	switch {
	case exchange && !dexists:
		return sErr(lxENOENT)
	case dexists && flags&lxRenameNoreplace != 0:
		return sErr(lxEEXIST)
	case op == np:
		return 0
	case strings.HasPrefix(np, op+"/"):
		return sErr(lxEINVAL)
	case exchange && strings.HasPrefix(op, np+"/"):
		return sErr(lxEINVAL)
	}
	if dexists && !exchange {
		if inodeKey(sfi) == inodeKey(dfi) {
			return 0 // hard links to one inode: POSIX says do nothing
		}
		switch {
		case sfi.IsDir() && !dfi.IsDir():
			return sErr(lxENOTDIR)
		case !sfi.IsDir() && dfi.IsDir():
			return sErr(lxEISDIR)
		case dfi.IsDir() && !g.isEmptyDir(np):
			return sErr(lxENOTEMPTY)
		}
		if strings.HasPrefix(op, np+"/") {
			return sErr(lxENOTEMPTY)
		}
	}
	if g.upperAbs == "" {
		return sErr(lxEROFS)
	}
	if !exchange {
		// Rename through the overlay backend: it deep-copies the source subtree up
		// (so a merged directory's lower entries move too), renames in the top, and
		// whiteouts the old path. The sandbox keeps the metadata retarget, cwd move,
		// and inotify. Exchange keeps the engine below (no FileSystem.Rename flag).
		ploc, err := g.vns().Resolve(path.Dir(op), true)
		if err != nil {
			return sErr(osErrno(err))
		}
		dloc, err := g.vns().Resolve(path.Dir(np), true)
		if err != nil {
			return sErr(osErrno(err))
		}
		if err := ploc.FS.Rename(ploc.Node, path.Base(op), dloc.Node, path.Base(np)); err != nil {
			return sErr(osErrno(err))
		}
		g.ov.retarget(op, np, false)
		g.dfs.moveCwds(op, np, false)
		g.notifyMoved(op, np, sfi.IsDir())
		return 0
	}
	// RENAME_EXCHANGE through the overlay backend: it deep-copies both subtrees up
	// and swaps them atomically in the top. The sandbox keeps the metadata retarget,
	// cwd move, and inotify.
	floc, err := g.vns().Resolve(path.Dir(op), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	tloc, err := g.vns().Resolve(path.Dir(np), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	xr, ok := floc.FS.(vfs.ExchangeRenamer)
	if !ok {
		return sErr(lxEINVAL)
	}
	if err := xr.RenameExchange(floc.Node, path.Base(op), tloc.Node, path.Base(np)); err != nil {
		return sErr(osErrno(err))
	}
	g.ov.retarget(op, np, true)
	g.dfs.moveCwds(op, np, true)
	g.notifyMoved(op, np, sfi.IsDir())
	g.notifyMoved(np, op, dfi.IsDir())
	return 0
}

// fdOfPseudo returns the open file behind a /proc/<pid>/fd/<n> magic node, or
// nil when n is not such a node.
func fdOfPseudo(n vfs.Node) *dfile {
	if pn, ok := n.(*pnodeNode); ok && pn.n != nil && pn.n.kind == pFdObj {
		return pn.n.fd
	}
	return nil
}

// linkUnnamed gives an O_TMPFILE file a name at np. It has no host name to link,
// so the name is created in the backend (which copies up its parents) and the
// file's data copied into it.
func (g *dguest) linkUnnamed(od *dfile, np string) int64 {
	if od.f == nil {
		return sErr(lxEBADF)
	}
	fi, err := od.f.Stat()
	if err != nil {
		return sErr(osErrno(err))
	}
	dloc, err := g.vns().Resolve(path.Dir(np), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	c, err := dloc.FS.Create(dloc.Node, path.Base(np), vfs.CreateSpec{Kind: vfs.Reg, Mode: uint32(fi.Mode().Perm())})
	if err != nil {
		return sErr(osErrno(err))
	}
	w, err := c.Open(os.O_WRONLY)
	if err != nil {
		return sErr(osErrno(err))
	}
	of, ok := w.(*os.File)
	if !ok {
		w.Close()
		return sErr(lxEINVAL)
	}
	_, cerr := io.Copy(of, io.NewSectionReader(od.f, 0, fi.Size()))
	of.Close()
	if cerr != nil {
		return sErr(osErrno(cerr))
	}
	od.fx.unnamed = false
	g.notify(np, inCreate, 0)
	return 0
}

func (g *dguest) linkat(odfd int64, oaddr uint64, ndfd int64, naddr uint64, flags int64) int64 {
	if flags&^(lxAtSymlinkFoll|lxAtEmptyPath) != 0 {
		return sErr(lxEINVAL)
	}
	op, od, e := g.pathArg(odfd, oaddr, flags&lxAtSymlinkFoll != 0, flags)
	if e != 0 {
		return sErr(e)
	}
	np, e := g.lookup(ndfd, naddr, false)
	if e != 0 {
		return sErr(e)
	}
	if _, de := g.lstatGuest(np); de == 0 {
		return sErr(lxEEXIST)
	} else if de != lxENOENT {
		return sErr(de)
	}
	if e := g.dacCreate(np); e != 0 {
		return sErr(e)
	}
	if od != nil && od.fx.unnamed {
		return g.linkUnnamed(od, np)
	}
	sfi, e := g.lstatGuest(op)
	if e != 0 {
		return sErr(e)
	}
	if sfi.IsDir() {
		return sErr(lxEPERM)
	}
	// Hard-link through the overlay backend: it copies the source up (so the
	// link and its target share one upper inode, and thus one metadata record)
	// and links it under the new name.
	sloc, err := g.vns().Resolve(op, false)
	if err != nil {
		return sErr(osErrno(err))
	}
	// A /proc/<pid>/fd/<n> source names an already-open file: the O_TMPFILE
	// materialization apk and dpkg use (write an unnamed file, then link
	// /proc/self/fd/N to its final name). Link the file behind the fd — its data
	// for an unnamed one, its real path for a named one.
	if d := fdOfPseudo(sloc.Node); d != nil {
		if d.fx.unnamed {
			return g.linkUnnamed(d, np)
		}
		if nm := d.name(); strings.HasPrefix(nm, "/") {
			if sloc, err = g.vns().Resolve(nm, false); err != nil {
				return sErr(osErrno(err))
			}
		}
	}
	dloc, err := g.vns().Resolve(path.Dir(np), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	// A hard link cannot cross filesystems (a pseudo mount like /proc, or any
	// other mount): Linux returns EXDEV, as does this.
	if sloc.FS != dloc.FS {
		return sErr(lxEXDEV)
	}
	if _, err := dloc.FS.Link(dloc.Node, path.Base(np), sloc.Node); err != nil {
		return sErr(osErrno(err))
	}
	g.notify(op, inAttrib, 0)
	g.notify(np, inCreate, 0)
	return 0
}

func (g *dguest) symlinkat(targetAddr uint64, ndfd int64, naddr uint64) int64 {
	target, err := g.readCStr(targetAddr)
	if err != nil {
		return sErr(lxEFAULT)
	}
	if target == "" {
		return sErr(lxENOENT)
	}
	np, e := g.lookup(ndfd, naddr, false)
	if e != 0 {
		return sErr(e)
	}
	if _, de := g.lstatGuest(np); de == 0 {
		return sErr(lxEEXIST)
	} else if de != lxENOENT {
		return sErr(de)
	}
	if e := g.dacCreate(np); e != 0 {
		return sErr(e)
	}
	ploc, err := g.vns().Resolve(path.Dir(np), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	if _, err := g.create(ploc, np, vfs.CreateSpec{Kind: vfs.Symlink, Target: target}); err != nil {
		return sErr(osErrno(err))
	}
	g.notify(np, inCreate, 0)
	return 0
}

func (g *dguest) mknodat(dirfd int64, pathAddr uint64, mode uint32, dev uint64) int64 {
	np, e := g.lookup(dirfd, pathAddr, false)
	if e != 0 {
		return sErr(e)
	}
	kind := vfs.Reg
	switch mode & lxSIFMT {
	case 0, lxSIFREG:
	case lxSIFIFO:
		kind = vfs.Fifo
	case lxSIFCHR, lxSIFBLK:
		// A container runtime populates the container's /dev with the standard
		// device nodes. The backend holds a device as a placeholder plus its
		// number in the overlay metadata; open maps the number to a host device.
		if !g.ps.cred.capable(capMknod) {
			return sErr(lxEPERM)
		}
		if mode&lxSIFMT == lxSIFCHR {
			kind = vfs.Chardev
		} else {
			kind = vfs.Blockdev
		}
	case lxSIFSCK:
		kind = vfs.Socket
	case lxSIFDIR:
		return sErr(lxEPERM)
	default:
		return sErr(lxEINVAL)
	}
	if _, de := g.lstatGuest(np); de == 0 {
		return sErr(lxEEXIST)
	} else if de != lxENOENT {
		return sErr(de)
	}
	if e := g.dacCreate(np); e != 0 {
		return sErr(e)
	}
	perm := g.createPerm(int64(mode))
	ploc, err := g.vns().Resolve(path.Dir(np), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	spec := vfs.CreateSpec{Kind: kind, Mode: perm}
	if kind == vfs.Chardev || kind == vfs.Blockdev {
		spec.Rdev = dev
	}
	if _, err := g.create(ploc, np, spec); err != nil {
		return sErr(osErrno(err))
	}
	g.notify(np, inCreate, 0)
	return 0
}

// attrTarget returns the host object a metadata change on gp (or on the open
// file d) applies to, copying it up first: an open upper or unnamed file is
// changed through its descriptor so the change follows the inode.
type attrTarget struct {
	f    *os.File
	host string
	fi   os.FileInfo
}

// fdInPlace reports whether a metadata change on the open file d applies to its
// descriptor directly: an unnamed (O_TMPFILE) file, a rootless run, or a file
// already in the writable upper. Any other target (a lower-backed or O_PATH fd,
// or a pathname) resolves through the Namespace, which copies it up.
func (g *dguest) fdInPlace(d *dfile) bool {
	return d != nil && d.f != nil &&
		(d.fx.unnamed || g.upperAbs == "" || strings.HasPrefix(d.f.Name(), g.upperAbs+string(filepath.Separator)))
}

// inPlaceTarget is the in-place target for an open file (see fdInPlace).
func (g *dguest) inPlaceTarget(d *dfile) (attrTarget, lxErrno) {
	fi, err := fileStat(d.f)
	if err != nil {
		return attrTarget{}, osErrno(err)
	}
	return attrTarget{f: d.f, fi: fi}, 0
}

func (g *dguest) chmodTarget(t attrTarget, m uint32) error {
	if t.f != nil {
		return fchmodOf(t.f, m)
	}
	if t.fi.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	return g.hChmod(t.host, m)
}

// setMode gives the target guest permission bits perm (and touches its ctime).
func (g *dguest) setMode(t attrTarget, perm uint32) lxErrno {
	if err := g.chmodTarget(t, hostPerm(perm, t.fi.IsDir())); err != nil {
		return osErrno(err)
	}
	k := inodeKey(t.fi)
	g.ov.update(k, func(m *imeta) {
		m.hasMode = perm&0o7777 != hostPerm(perm, t.fi.IsDir())
		m.mode = perm & 0o7777
	})
	return 0
}

func (g *dguest) fchmodat(dirfd int64, pathAddr uint64, mode uint32, flags int64) int64 {
	if flags&^(lxAtSymlinkNofollow|lxAtEmptyPath) != 0 {
		return sErr(lxEINVAL)
	}
	gp, d, e := g.pathArg(dirfd, pathAddr, flags&lxAtSymlinkNofollow == 0, flags)
	if e != 0 {
		return sErr(e)
	}
	if d != nil && d.f == nil && !d.fx.opath {
		return sErr(lxEBADF)
	}
	if !g.fdInPlace(d) {
		// chmod routes through the overlay Namespace: resolve the node (a pathname,
		// or a lower/O_PATH fd whose path copies up in the backend) and set its mode;
		// the sub-floor override runs in the backend. Without AT_SYMLINK_NOFOLLOW the
		// final symlink is followed (chmod operates on the target) -- including a
		// /proc/<pid>/fd/<n> magic link, how a runtime chmods a device it holds open.
		loc, err := g.vns().Resolve(gp, flags&lxAtSymlinkNofollow == 0)
		if err != nil {
			return sErr(osErrno(err))
		}
		if loc.Node.Kind() == vfs.Symlink {
			return sErr(lxEOPNOTSUPP)
		}
		m := mode & 0o7777
		if err := loc.Node.SetAttr(vfs.AttrUpdate{Mode: &m}); err != nil {
			return sErr(osErrno(err))
		}
		g.notify(gp, inAttrib, 0)
		return 0
	}
	t, e := g.inPlaceTarget(d)
	if e != 0 {
		return sErr(e)
	}
	if t.fi.Mode()&os.ModeSymlink != 0 {
		return sErr(lxEOPNOTSUPP)
	}
	if e := g.setMode(t, mode&0o7777); e != 0 {
		return sErr(e)
	}
	g.notify(gp, inAttrib, 0)
	return 0
}

func (g *dguest) fchmod(fd int64, mode uint32) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok || d.fx.opath {
		return sErr(lxEBADF)
	}
	if d.f == nil {
		return 0 // stub-served stdio: a tty the guest does not own
	}
	if !strings.HasPrefix(d.name(), "/") {
		// A socket, pipe or anon-inode descriptor has no filesystem path (its
		// name is "socket:", "pipe:[n]", "anon_inode:..."); fchmod sets the mode
		// on the descriptor's own inode. A container runtime (conmon) chmods its
		// unbound console-attach socket and its stderr pipe this way, so it must
		// not resolve a path. (An unnamed memfd keeps a "/memfd:" name and is
		// handled in place below.) A host that keeps no mode for the object
		// (a Windows socket or pipe) leaves it to the description.
		if modeless(d.f) {
			d.fx.perm.Store(permSet | mode&0o7777)
			return 0
		}
		if err := d.f.Chmod(os.FileMode(mode & 0o7777)); err != nil {
			return sErr(osErrno(err))
		}
		return 0
	}
	if !g.fdInPlace(d) {
		loc, err := g.vns().Resolve(d.name(), false)
		if err != nil {
			return sErr(osErrno(err))
		}
		m := mode & 0o7777
		if err := loc.Node.SetAttr(vfs.AttrUpdate{Mode: &m}); err != nil {
			return sErr(osErrno(err))
		}
		g.notify(d.name(), inAttrib, 0)
		return 0
	}
	t, e := g.inPlaceTarget(d)
	if e != 0 {
		return sErr(e)
	}
	if e := g.setMode(t, mode&0o7777); e != 0 {
		return sErr(e)
	}
	g.notify(d.name(), inAttrib, 0)
	return 0
}

func (g *dguest) fchownat(dirfd int64, pathAddr uint64, uid, gid uint32, flags int64) int64 {
	if flags&^(lxAtSymlinkNofollow|lxAtEmptyPath) != 0 {
		return sErr(lxEINVAL)
	}
	gp, d, e := g.pathArg(dirfd, pathAddr, flags&lxAtSymlinkNofollow == 0, flags)
	if e != 0 {
		return sErr(e)
	}
	if d != nil && d.f == nil && !d.fx.opath {
		return 0 // stub-served stdio
	}
	if pathAddr == 0 && d != nil && d.fx.opath {
		return sErr(lxEBADF) // fchown on an O_PATH fd
	}
	if d != nil && !strings.HasPrefix(d.name(), "/") {
		// A socket, pipe or anon-inode fd has no path-backed inode to resolve; a
		// runtime chowns the container's std streams (a pipe) as root, so accept
		// it as a virtual no-op rather than failing to resolve the name.
		return 0
	}
	if !g.fdInPlace(d) {
		// A pathname (or lower-backed fd) chown routes through the overlay
		// Namespace, copying up in the backend. chown clears the
		// set-user-ID bit (and set-group-ID when group-executable) on a non-dir,
		// non-symlink; a -1 id leaves that id unchanged. Without AT_SYMLINK_NOFOLLOW
		// the final symlink is followed (incl. a /proc/<pid>/fd magic link, how a
		// runtime chowns a device it holds open).
		loc, err := g.vns().Resolve(gp, flags&lxAtSymlinkNofollow == 0)
		if err != nil {
			return sErr(osErrno(err))
		}
		cur, ce := g.statGuest(gp)
		if ce != 0 {
			return sErr(ce)
		}
		isSym := loc.Node.Kind() == vfs.Symlink
		perm := cur.mode & 0o7777
		if loc.Node.Kind() != vfs.Dir && !isSym {
			perm &^= 0o4000
			if perm&0o010 != 0 {
				perm &^= 0o2000
			}
		}
		if uid == ^uint32(0) {
			uid = cur.uid
		}
		if gid == ^uint32(0) {
			gid = cur.gid
		}
		u := vfs.AttrUpdate{Uid: &uid, Gid: &gid}
		if !isSym {
			u.Mode = &perm
		}
		if err := loc.Node.SetAttr(u); err != nil {
			return sErr(osErrno(err))
		}
		g.notify(gp, inAttrib, 0)
		return 0
	}
	t, e := g.inPlaceTarget(d)
	if e != 0 {
		return sErr(e)
	}
	cur := g.linuxStat(t.fi)
	perm := cur.mode & 0o7777
	if !t.fi.IsDir() && t.fi.Mode()&os.ModeSymlink == 0 {
		// chown clears set-user-ID, and set-group-ID when group-executable.
		perm &^= 0o4000
		if perm&0o010 != 0 {
			perm &^= 0o2000
		}
	}
	if uid == ^uint32(0) {
		uid = cur.uid
	}
	if gid == ^uint32(0) {
		gid = cur.gid
	}
	if t.fi.Mode()&os.ModeSymlink == 0 {
		if e := g.setMode(t, perm); e != 0 {
			return sErr(e)
		}
	}
	g.ov.update(inodeKey(t.fi), func(m *imeta) {
		m.uid, m.gid = uid, gid
		m.hasOwner = uid != 0 || gid != 0
	})
	g.notify(gp, inAttrib, 0)
	return 0
}

func (g *dguest) utimensat(dirfd int64, pathAddr, timesAddr uint64, flags int64) int64 {
	if flags&^(lxAtSymlinkNofollow|lxAtEmptyPath) != 0 {
		return sErr(lxEINVAL)
	}
	var ts [2]syscall.Timespec
	now := time.Now()
	nowTs := syscall.NsecToTimespec(now.UnixNano())
	omit := [2]bool{}
	if timesAddr == 0 {
		ts[0], ts[1] = nowTs, nowTs
	} else {
		b, err := g.readMem(timesAddr, 32)
		if err != nil {
			return sErr(lxEFAULT)
		}
		for i := range ts {
			sec, nsec := int64(le64(b[16*i:])), int64(le64(b[16*i+8:]))
			switch {
			case nsec == lxUtimeNow:
				ts[i] = nowTs
			case nsec == lxUtimeOmit:
				omit[i] = true
			case nsec < 0 || nsec > 999999999:
				return sErr(lxEINVAL)
			default:
				ts[i] = syscall.Timespec{Sec: sec, Nsec: nsec}
			}
		}
	}
	if pathAddr == 0 && dirfd != lxAtFdcwd {
		flags |= lxAtEmptyPath
	}
	gp, d, e := g.pathArg(dirfd, pathAddr, flags&lxAtSymlinkNofollow == 0, flags)
	if e != 0 {
		return sErr(e)
	}
	if d != nil && d.f == nil && !d.fx.opath {
		return 0 // stub-served stdio
	}
	if omit[0] && omit[1] {
		if _, e := g.lstatGuest(gp); e != 0 && d == nil {
			return sErr(e)
		}
		return 0
	}
	if !g.fdInPlace(d) {
		// A pathname (or lower-backed fd) utimes routes through the overlay
		// Namespace: resolve the node and set its times (copy-up and the host
		// utimes run in the backend). An omitted time the backend keeps.
		loc, err := g.vns().Resolve(gp, false)
		if err != nil {
			return sErr(osErrno(err))
		}
		var u vfs.AttrUpdate
		if !omit[0] {
			a := tsNano(ts[0])
			u.Atime = &a
		}
		if !omit[1] {
			m := tsNano(ts[1])
			u.Mtime = &m
		}
		if err := loc.Node.SetAttr(u); err != nil {
			return sErr(osErrno(err))
		}
		g.notify(gp, inAttrib, 0)
		return 0
	}
	t, e := g.inPlaceTarget(d)
	if e != 0 {
		return sErr(e)
	}
	st, _ := statOf(t.fi)
	if omit[0] {
		ts[0] = st.atime
	}
	if omit[1] {
		ts[1] = st.mtime
	}
	if err := futimesOf(t.f, ts[0], ts[1]); err != nil {
		return sErr(osErrno(err))
	}
	g.notify(gp, inAttrib, 0)
	return 0
}

func (g *dguest) truncate(pathAddr uint64, length int64) int64 {
	gp, e := g.lookup(lxAtFdcwd, pathAddr, true)
	if e != 0 {
		return sErr(e)
	}
	fi, e := g.lstatGuest(gp)
	if e != 0 {
		return sErr(e)
	}
	if fi.IsDir() {
		return sErr(lxEISDIR)
	}
	if !fi.Mode().IsRegular() {
		return sErr(lxEINVAL)
	}
	if length < 0 {
		return sErr(lxEINVAL)
	}
	// Truncate through the overlay backend: a writable open copies the file up,
	// and the top copy's descriptor is truncated.
	loc, err := g.vns().Resolve(gp, true)
	if err != nil {
		return sErr(osErrno(err))
	}
	f, err := loc.Node.Open(os.O_WRONLY)
	if err != nil {
		return sErr(osErrno(err))
	}
	of, ok := f.(*os.File)
	if !ok {
		f.Close()
		return sErr(lxEINVAL)
	}
	err = of.Truncate(length)
	if err == nil {
		g.fileModified(of)
	}
	of.Close()
	if err != nil {
		return sErr(osErrno(err))
	}
	g.notify(gp, inModify, 0)
	return 0
}

func (g *dguest) ftruncate(fd int64, length int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok || d.fx.opath {
		return sErr(lxEBADF)
	}
	if length < 0 {
		return sErr(lxEINVAL)
	}
	if d.isDir || !d.writable() {
		return sErr(lxEINVAL)
	}
	if d.rf != nil { // a regular file, whatever backs it
		a, _, err := d.rf.attr()
		if err != nil {
			return sErr(osErrno(err))
		}
		if e := d.checkSeals(a.Size, length, false); e != 0 {
			return sErr(e)
		}
		if err := d.rf.truncate(length); err != nil {
			return sErr(osErrno(err))
		}
		g.modified(d)
		return 0
	}
	if d.f == nil {
		if d.mem != nil && d.mem.vf != nil { // memFS not yet on regFile
			if err := d.mem.vf.Truncate(length); err != nil {
				return sErr(osErrno(err))
			}
			return 0
		}
		return sErr(lxEINVAL)
	}
	fi, err := fileStat(d.f)
	if err != nil {
		return sErr(osErrno(err))
	}
	if !fi.Mode().IsRegular() {
		return sErr(lxEINVAL)
	}
	if e := d.checkSeals(fi.Size(), length, false); e != 0 {
		return sErr(e)
	}
	if err := d.f.Truncate(length); err != nil {
		return sErr(osErrno(err))
	}
	g.modified(d)
	return 0
}

// statfs fills a Linux struct statfs (arm64: 120 bytes, 64-bit words).
func (g *dguest) statfs(dirfd int64, pathAddr, bufAddr uint64) int64 {
	var s hostStatfs
	var err error
	var fsp string
	if pathAddr == 0 {
		d, ok := g.ft.get(int(dirfd))
		if !ok {
			return sErr(lxEBADF)
		}
		switch {
		case d.f != nil:
			s, err = fstatfsOf(d.f)
			fsp = d.name()
		case d.fx.opath:
			fsp = d.name()
			s, err = g.statfsPath(fsp)
		default:
			fsp = "/dev" // stub-served stdio: the guest's /dev
			s, err = g.statfsPath(fsp)
		}
	} else {
		gp, e := g.lookup(lxAtFdcwd, pathAddr, true)
		if e != 0 {
			return sErr(e)
		}
		fsp = gp
		s, err = g.statfsPath(gp)
	}
	if err != nil {
		return sErr(osErrno(err))
	}
	var b [120]byte
	magic := fsMagic(fsp)
	if magic == lxOverlayfsMagic && s.ftype != 0 {
		// A non-pseudo path reports the real backing host filesystem's type, not
		// laboon's internal overlay: the guest sees an ordinary filesystem (ext4,
		// xfs, btrfs, tmpfs...), so a container runtime's overlay storage driver,
		// which refuses to stack overlay on overlayfs, proceeds as it would on a
		// real host. Pseudo mounts keep their own magic below.
		magic = s.ftype
	}
	if m, ok := g.dfs.dynMagic(fsp); ok {
		// A pseudo filesystem mounted at a non-canonical path (a container
		// runtime mounts proc/sysfs/cgroup2 under its rootfs, then pivot_roots)
		// reports its own f_type, which fsMagic's canonical-path test misses.
		magic = m
	}
	if g.dfs.isNsBind(fsp) {
		magic = 0x6e736673 // NSFS_MAGIC: a persisted namespace file
	}
	put64(b[0:], magic)
	put64(b[8:], s.bsize)
	put64(b[16:], s.blocks)
	put64(b[24:], s.bfree)
	put64(b[32:], s.bavail)
	put64(b[40:], s.files)
	put64(b[48:], s.ffree)
	put32(b[56:], s.fsid[0])
	put32(b[60:], s.fsid[1])
	put64(b[64:], 255)         // f_namelen
	put64(b[72:], s.bsize)     // f_frsize
	put64(b[80:], 0x20|0x1000) // ST_VALID|ST_RELATIME
	if err := g.writeMem(bufAddr, b[:]); err != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

// fsMagic is the f_type a path's filesystem reports: the real magic for the
// pseudo mounts (so a runtime that checks e.g. /sys/fs/cgroup is cgroup2 is
// satisfied). For any other path it returns lxOverlayfsMagic as a sentinel that
// statfs replaces with the real backing host filesystem's type when known.
func fsMagic(gp string) uint64 {
	switch {
	case gp == "/sys/fs/cgroup" || strings.HasPrefix(gp, "/sys/fs/cgroup/"):
		return 0x63677270 // CGROUP2_SUPER_MAGIC
	case gp == "/proc" || strings.HasPrefix(gp, "/proc/"):
		return 0x9fa0 // PROC_SUPER_MAGIC
	case gp == "/sys" || strings.HasPrefix(gp, "/sys/"):
		return 0x62656572 // SYSFS_MAGIC
	case gp == "/dev/shm" || strings.HasPrefix(gp, "/dev/shm/"):
		return 0x01021994 // TMPFS_MAGIC
	}
	return lxOverlayfsMagic
}

// statfsPath reports the statfs of the filesystem backing gp through the overlay
// backend (which answers from the layer that owns the node). A pseudo path, whose
// synthetic filesystem has no statfs of its own, reports the guest's root fs.
func (g *dguest) statfsPath(gp string) (hostStatfs, error) {
	// gp is already symlink-resolved by the caller (lookup for a pathname, open
	// time for an O_PATH fd), so do not follow the last component again — an
	// O_PATH|O_NOFOLLOW fd names the symlink itself, whose fs statfs reports.
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return hostStatfs{}, err
	}
	sf, ok := loc.FS.(vfs.StatFSer)
	if !ok {
		if loc, err = g.vns().Resolve("/", false); err != nil {
			return hostStatfs{}, err
		}
		if sf, ok = loc.FS.(vfs.StatFSer); !ok {
			return hostStatfs{}, os.ErrInvalid
		}
	}
	st, err := sf.StatFS(loc.Node)
	if err != nil {
		return hostStatfs{}, err
	}
	return hostStatfs{bsize: st.Bsize, blocks: st.Blocks, bfree: st.Bfree,
		bavail: st.Bavail, files: st.Files, ffree: st.Ffree, fsid: st.Fsid, ftype: st.Type}, nil
}

// faccessat2 checks access as the guest's root: anything that exists is
// readable and writable; execute needs some x bit on a non-directory.
func (g *dguest) faccessat2(dirfd int64, pathAddr uint64, mode, flags int64) int64 {
	if mode&^7 != 0 || flags&^(lxAtEaccess|lxAtSymlinkNofollow|lxAtEmptyPath) != 0 {
		return sErr(lxEINVAL)
	}
	gp, d, e := g.pathArg(dirfd, pathAddr, flags&lxAtSymlinkNofollow == 0, flags)
	if e != 0 {
		return sErr(e)
	}
	if d != nil && d.f == nil && !d.fx.opath {
		return 0
	}
	return sErr(g.dacAccess(gp, mode, flags))
}
