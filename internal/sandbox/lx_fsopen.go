//go:build darwin || linux || windows

package sandbox

import (
	"os"
	"path"
	"strings"
	"sync/atomic"

	"github.com/samyfodil/laboon/internal/vfs"
)

// open(2) semantics over the overlay: openat/openat2 flags, O_PATH and
// O_TMPFILE descriptions, memfd_create, close_range.

// Linux open flags not in the shared block (arm64 values).
const (
	lxONoctty    = 0x100
	lxODsync     = 0x1000
	lxOAsync     = 0x2000
	lxODirectory = 0x4000
	lxONofollow  = 0x8000
	lxODirect    = 0x10000
	lxOLargefile = 0x20000
	lxONoatime   = 0x40000
	lxOSync      = 0x101000
	lxOPath      = 0x200000
	lxOTmpfile   = 0x400000 // __O_TMPFILE; O_TMPFILE adds O_DIRECTORY

	// status flags F_GETFL reports and F_SETFL may change
	lxOStatusKeep = lxOAccmod | lxOAppend | lxODsync | lxOSync | lxODirect | lxOLargefile | lxONoatime | lxOPath | lxOAsync
	lxOSetflMask  = lxOAppend | lxONonblock | lxOAsync | lxODirect | lxONoatime

	lxOpenat2     = 437
	lxCloseRange  = 436
	lxMemfdCreate = 279

	lxResolveNoXdev       = 0x01
	lxResolveNoMagiclinks = 0x02
	lxResolveNoSymlinks   = 0x04
	lxResolveBeneath      = 0x08
	lxResolveInRoot       = 0x10
	lxResolveCached       = 0x20

	lxMfdCloexec      = 1
	lxMfdAllowSealing = 2
	lxMfdHugetlb      = 4
	lxMfdNoexecSeal   = 8
	lxMfdExec         = 0x10
	lxMfdHugeMask     = 0x3f << 26 // MFD_HUGE_* page-size bits

	lxSealSeal   = 1
	lxSealShrink = 2
	lxSealGrow   = 4
	lxSealWrite  = 8
	lxSealFWrite = 0x10
)

// permSet marks fileX.perm as set.
const permSet = 1 << 31

// fileX is the filesystem state of an open-file description beyond the host
// file: the Linux status flags, O_PATH/unnamed markers, memfd seals, the
// inotify instance behind an inotify fd and the lock bookkeeping.
type fileX struct {
	oflags   int64 // access mode + status flags (lxOStatusKeep), when hasFlags
	hasFlags bool
	opath    bool // O_PATH: names a file, no I/O (f is nil)
	unnamed  bool // O_TMPFILE or memfd: no name in the guest namespace
	memfd    bool
	seals    atomic.Uint32
	pipeSz   atomic.Int32
	in       *inotify
	dn       atomic.Pointer[inotify] // F_NOTIFY on a directory
	sigio    atomic.Int32            // F_SETSIG
	locked   atomic.Bool             // holds flock or OFD locks, released with the description
	moved    atomic.Pointer[string]  // the guest path after a rename moved the file
	perm     atomic.Uint32           // permSet | the mode fchmod gave an object the host keeps none for
	ov       *ovState                // registry the description is tracked in for renames
}

// name is the description's current guest path: where it was opened, or where
// a later rename of it (or of a directory above it) moved it.
func (d *dfile) name() string {
	if p := d.fx.moved.Load(); p != nil {
		return *p
	}
	return d.gp
}

// movedPath maps p from under a to under b.
func movedPath(p, a, b string) (string, bool) {
	if p == a {
		return b, true
	}
	if strings.HasPrefix(p, a+"/") {
		return b + p[len(a):], true
	}
	return "", false
}

func (o *ovState) trackFile(d *dfile) {
	o.filesMu.Lock()
	if o.files == nil {
		o.files = map[*dfile]struct{}{}
	}
	o.files[d] = struct{}{}
	o.filesMu.Unlock()
	d.fx.ov = o
}

func (o *ovState) untrackFile(d *dfile) {
	o.filesMu.Lock()
	delete(o.files, d)
	o.filesMu.Unlock()
}

// retarget moves open descriptions under from to the same place under to (and,
// for an exchange, the other way), as Linux open files follow their inode.
func (o *ovState) retarget(from, to string, exchange bool) {
	o.filesMu.Lock()
	defer o.filesMu.Unlock()
	for d := range o.files {
		p := d.name()
		np, ok := movedPath(p, from, to)
		if !ok && exchange {
			np, ok = movedPath(p, to, from)
		}
		if ok {
			d.fx.moved.Store(&np)
		}
	}
}

// writable reports whether the description was opened for writing.
func (d *dfile) writable() bool {
	if !d.fx.hasFlags {
		return true
	}
	m := d.fx.oflags & lxOAccmod
	return m == lxOWronly || m == lxORdwr
}

// checkSeals enforces memfd seals for a size change from size to newSize (and
// a data write when write is set).
func (d *dfile) checkSeals(size, newSize int64, write bool) lxErrno {
	s := d.fx.seals.Load()
	if s == 0 {
		return 0
	}
	switch {
	case write && s&(lxSealWrite|lxSealFWrite) != 0:
		return lxEPERM
	case newSize < size && s&lxSealShrink != 0:
		return lxEPERM
	case newSize > size && s&lxSealGrow != 0:
		return lxEPERM
	}
	return 0
}

func init() {
	syscalls[lxOpenat2] = func(g *dguest, a [6]uint64) int64 { return g.openat2(int64(a[0]), a[1], a[2], a[3]) }
	syscalls[lxCloseRange] = func(g *dguest, a [6]uint64) int64 { return g.closeRange(uint32(a[0]), uint32(a[1]), uint32(a[2])) }
	syscalls[lxMemfdCreate] = func(g *dguest, a [6]uint64) int64 { return g.memfdCreate(a[0], uint32(a[1])) }
}

type openHow struct {
	flags, mode, resolve uint64
	raced                bool // a create lost to another process's: open what it made
}

func (g *dguest) openat(dirfd int64, pathAddr uint64, flags, mode int64) int64 {
	p, err := g.readCStr(pathAddr)
	if err != nil {
		return sErr(lxEFAULT)
	}
	// open(2) ignores unknown flag bits; openat2 rejects them.
	return g.openPath(dirfd, p, openHow{flags: uint64(uint32(flags)), mode: uint64(mode) & 0o7777})
}

func (g *dguest) openat2(dirfd int64, pathAddr, howAddr, size uint64) int64 {
	if size < 24 {
		return sErr(lxEINVAL)
	}
	if size > 4096 {
		return sErr(lxE2BIG)
	}
	b, err := g.readMem(howAddr, int(size))
	if err != nil {
		return sErr(lxEFAULT)
	}
	for _, x := range b[24:] {
		if x != 0 {
			return sErr(lxE2BIG)
		}
	}
	how := openHow{flags: le64(b), mode: le64(b[8:]), resolve: le64(b[16:])}
	// open and openat reach the shared table through toGeneric, which swaps the
	// few open flags whose bit differs on x86-64 to the generic values the code
	// below uses; openat2's flags come from this struct, so swap them here too.
	how.flags = oflagsToGeneric(how.flags)
	const known = lxOAccmod | lxOCreat | lxOExcl | lxONoctty | lxOTrunc | lxOAppend | lxONonblock |
		lxODsync | lxOAsync | lxODirectory | lxONofollow | lxODirect | lxOLargefile | lxONoatime |
		lxOCloexec | lxOSync | lxOPath | lxOTmpfile
	if how.flags&^known != 0 || how.flags&lxOAccmod == 3 {
		return sErr(lxEINVAL)
	}
	if how.mode != 0 && how.flags&(lxOCreat|lxOTmpfile) == 0 || how.mode&^0o7777 != 0 {
		return sErr(lxEINVAL)
	}
	if how.resolve&^0x3f != 0 || how.resolve&(lxResolveBeneath|lxResolveInRoot) == lxResolveBeneath|lxResolveInRoot {
		return sErr(lxEINVAL)
	}
	if how.flags&lxOPath != 0 && how.flags&^(lxOPath|lxOCloexec|lxODirectory|lxONofollow) != 0 {
		return sErr(lxEINVAL)
	}
	if how.resolve&lxResolveCached != 0 && how.flags&(lxOCreat|lxOTrunc|lxOTmpfile) != 0 {
		return sErr(lxEAGAIN)
	}
	p, err := g.readCStr(pathAddr)
	if err != nil {
		return sErr(lxEFAULT)
	}
	return g.openPath(dirfd, p, how)
}

// resolveHow resolves p against dirfd under openat2's RESOLVE_* restrictions.
// IN_ROOT treats dirfd as the root; BENEATH refuses to leave it; NO_SYMLINKS
// refuses any symlink. Without restrictions it is the ordinary lookup.
func (g *dguest) resolveHow(dirfd int64, p string, follow bool, resolve uint64) (string, lxErrno) {
	if resolve&(lxResolveBeneath|lxResolveInRoot|lxResolveNoSymlinks) == 0 {
		gp, e := g.guestAbs(dirfd, p)
		if e != 0 {
			return "", e
		}
		return g.resolve(gp, follow)
	}
	base := g.getCwd()
	if dirfd = int64(int32(dirfd)); dirfd != lxAtFdcwd {
		d, ok := g.ft.get(int(dirfd))
		if !ok {
			return "", lxEBADF
		}
		base = d.name()
	}
	root := "/"
	if resolve&(lxResolveBeneath|lxResolveInRoot) != 0 {
		root = base
		if path.IsAbs(p) {
			if resolve&lxResolveBeneath != 0 {
				return "", lxEXDEV
			}
			p = strings.TrimLeft(p, "/")
		}
	}
	beneath := resolve&lxResolveBeneath != 0
	parts := strings.Split(p, "/")
	cur := base
	if path.IsAbs(p) {
		cur = "/"
	}
	hops := 0
	under := func(x string) bool { return root == "/" || x == root || strings.HasPrefix(x, root+"/") }
	for i := 0; i < len(parts); i++ {
		c := parts[i]
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			if cur == root {
				if beneath {
					return "", lxEXDEV
				}
				continue // IN_ROOT: ".." at the root stays there
			}
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, c)
		if i == len(parts)-1 && !follow {
			return next, 0
		}
		t, ok := g.linkTarget(next)
		if !ok {
			cur = next
			continue
		}
		if resolve&lxResolveNoSymlinks != 0 {
			return "", lxELOOP
		}
		if hops++; hops > 40 {
			return "", lxELOOP
		}
		if path.IsAbs(t) {
			if beneath {
				return "", lxEXDEV
			}
			cur = root
			t = strings.TrimLeft(t, "/")
		}
		parts = append(strings.Split(t, "/"), parts[i+1:]...)
		i = -1
		if !under(cur) {
			return "", lxEXDEV
		}
	}
	return cur, 0
}

func (g *dguest) openPath(dirfd int64, p string, how openHow) (fd int64) {
	flags := int64(how.flags)
	if p == "" {
		return sErr(lxENOENT)
	}
	if len(p) >= 4096 {
		return sErr(lxENAMETOOLONG)
	}
	opath := flags&lxOPath != 0
	if opath {
		flags &= lxOPath | lxOCloexec | lxODirectory | lxONofollow
	}
	tmpfile := flags&lxOTmpfile != 0
	creat := flags&lxOCreat != 0 && !tmpfile
	excl := creat && flags&lxOExcl != 0
	slash := strings.HasSuffix(p, "/")
	follow := (flags&lxONofollow == 0 && !excl) || slash
	gp, e := g.resolveHow(dirfd, p, follow, how.resolve)
	if e != 0 {
		return sErr(e)
	}
	if !opath {
		if fd, ok := g.openTTY(gp, flags); ok {
			return fd
		}
		if fd, ok := g.pseudoOpen(gp, flags); ok {
			return fd // /proc, /sys, /dev (procfs_darwin.go)
		}
	}
	if (creat || flags&lxOAccmod != lxORdonly) && g.readOnlyMount(gp) {
		return sErr(lxEROFS)
	}
	if de := g.dacOpen(gp, flags); de != 0 {
		return sErr(de)
	}
	fi, se := g.lstatGuest(gp)
	if se != 0 {
		if se != lxENOENT || !creat {
			return sErr(se)
		}
		if slash {
			return sErr(lxEISDIR)
		}
		if flags&lxODirectory != 0 {
			return sErr(lxEINVAL)
		}
		fd := g.createFile(gp, flags, int64(how.mode))
		if fd == sErr(lxEEXIST) && !excl && !how.raced {
			// Another process made it since the lookup: O_CREAT without
			// O_EXCL opens what is there, as on Linux.
			how.raced = true
			return g.openPath(dirfd, p, how)
		}
		return fd
	}
	isDir := fi.IsDir()
	switch {
	case excl:
		return sErr(lxEEXIST)
	case fi.Mode()&os.ModeSymlink != 0 && !opath:
		return sErr(lxELOOP)
	case flags&lxODirectory != 0 && !isDir:
		return sErr(lxENOTDIR)
	case slash && !isDir:
		return sErr(lxENOTDIR)
	}
	if opath {
		d := &dfile{gp: gp, stub: -1, isDir: isDir}
		d.fx.opath = true
		d.fx.oflags, d.fx.hasFlags = lxOPath, true
		if !isDir {
			// Pin the object so the descriptor survives its name being removed
			// and can be re-opened for exec (fexecve) or stat, as Linux O_PATH
			// does. A pseudo/synthetic node has no host file and stays path-based.
			if loc, err := g.vns().Resolve(gp, false); err == nil {
				d.pathFD = pinPathFD(loc.Node)
			}
		}
		return g.installD(d, flags)
	}
	if tmpfile {
		if !isDir {
			return sErr(lxENOTDIR)
		}
		return g.openTmpfile(gp, flags, int64(how.mode))
	}
	wr := flags&lxOAccmod != lxORdonly
	if isDir {
		if wr || creat {
			return sErr(lxEISDIR)
		}
		loc, err := g.vns().Resolve(gp, false)
		if err != nil {
			return sErr(osErrno(err))
		}
		f, mem, e := g.openDir(loc, gp)
		if e != 0 {
			return sErr(e)
		}
		d := &dfile{f: f, gp: gp, isDir: true, stub: -1, mem: mem}
		// Pin the directory's identity so getdents enumerates the directory that
		// was opened, not whichever one later occupies this path: if the path is
		// rmdir'd and remade, or another directory is renamed onto it, a fresh
		// resolve of the (unchanged) path would otherwise list the impostor.
		// canon survives copy-up, so a later write into the directory does not
		// make it look replaced.
		d.dirID, d.dirIDok = g.ov.canon(loc.Node.ID()), true
		return g.installD(d, flags)
	}
	if fi.Mode()&os.ModeNamedPipe != 0 {
		// A FIFO blocks on open until its peer end is open; run that wait as an
		// interruptible rendezvous rather than an uncancelable host open.
		return g.openFifo(gp, flags)
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		// A device node the guest made with mknod (a container runtime fills the
		// container's /dev): the backend holds a placeholder, so open the host
		// device its number maps to, as the synthetic /dev nodes do.
		return g.openVirtualDev(gp, flags)
	}
	if !fi.Mode().IsRegular() {
		// Other specials (devices, sockets) are opened in place through the
		// backend (a special node is not copied up); writing one does not
		// modify the file.
		hf := goOpenFlags(flags) &^ (os.O_CREATE | os.O_EXCL | os.O_TRUNC)
		if flags&lxONonblock != 0 {
			hf |= hostONonblock
		}
		loc, err := g.vns().Resolve(gp, false)
		if err != nil {
			return sErr(osErrno(err))
		}
		nf, err := loc.Node.Open(hf)
		if err != nil {
			return sErr(osErrno(err))
		}
		of, ok := nf.(*os.File)
		if !ok {
			return g.installVFile(gp, loc.Node, nf, flags)
		}
		return g.install(of, gp, flags)
	}
	if wr || flags&lxOTrunc != 0 {
		if g.upperAbs == "" && g.rootAbs != "" {
			return sErr(lxEROFS)
		}
		// A writable open copies the file up and opens the top copy, in the
		// backend (ovNode.Open on a write flag copies up first).
		loc, err := g.vns().Resolve(gp, true)
		if err != nil {
			return sErr(osErrno(err))
		}
		nf, err := loc.Node.Open(goOpenFlags(flags) &^ (os.O_CREATE | os.O_EXCL))
		if err != nil {
			return sErr(osErrno(err))
		}
		of, ok := nf.(*os.File)
		if !ok {
			return g.installVFile(gp, loc.Node, nf, flags)
		}
		if flags&lxOTrunc != 0 {
			g.fileModified(of)
		}
		fd := g.install(of, gp, flags)
		if fd >= 0 && flags&lxOTrunc != 0 {
			g.notify(gp, inModify, 0)
		}
		return fd
	}
	// A read-only open of a regular file (dirs, fifos, devices and writable opens
	// are handled above). A host backend returns an *os.File; an in-memory backend
	// (tmpfs, WithFS) returns a vfs.File served through the vfs interface.
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return sErr(osErrno(err))
	}
	nf, err := loc.Node.Open(goOpenFlags(flags) &^ (os.O_CREATE | os.O_EXCL | os.O_TRUNC))
	if err != nil {
		return sErr(osErrno(err))
	}
	if of, ok := nf.(*os.File); ok {
		return g.install(of, gp, flags)
	}
	return g.installVFile(gp, loc.Node, nf, flags)
}

// openVirtualDev opens a mknod'd char device by mapping its device number to
// the matching host device, the same set the synthetic /dev nodes expose.
// readOnlyMount reports whether gp resolves into a read-only bind mount, so a
// write-mode open there is refused with EROFS.
func (g *dguest) readOnlyMount(gp string) bool {
	loc, err := g.vns().Resolve(gp, false)
	return err == nil && vfs.IsReadOnly(loc.FS)
}

func (g *dguest) openVirtualDev(gp string, flags int64) int64 {
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return sErr(osErrno(err))
	}
	a, err := loc.Node.Stat()
	if err != nil {
		return sErr(osErrno(err))
	}
	if fd, ok := g.openDeviceBacking(gp, a.Rdev, flags); ok {
		return fd
	}
	host, full, ok := hostDevByRdev(a.Rdev)
	if !ok {
		return sErr(lxENXIO) // a device laboon does not back
	}
	f, err := hostDevOpen(host, goOpenFlags(flags)&^(os.O_CREATE|os.O_TRUNC|os.O_EXCL))
	if err != nil {
		return sErr(osErrno(err))
	}
	return g.installD(&dfile{f: f, gp: gp, stub: -1, full: full}, flags)
}

// hostDevByRdev maps a Linux character-device number to the host device laboon
// serves it with (full reads as zeros but fails writes with ENOSPC).
func hostDevByRdev(rdev uint64) (host string, full, ok bool) {
	switch rdev {
	case lxMakedev(1, 3):
		return "/dev/null", false, true
	case lxMakedev(1, 5):
		return "/dev/zero", false, true
	case lxMakedev(1, 7):
		return "/dev/zero", true, true
	case lxMakedev(1, 8):
		return "/dev/random", false, true
	case lxMakedev(1, 9):
		return "/dev/urandom", false, true
	case lxMakedev(5, 0):
		return "/dev/tty", false, true
	}
	return "", false, false
}

// createFile creates gp (which does not exist) in the upper layer.
func (g *dguest) createFile(gp string, flags, mode int64) int64 {
	perm := g.createPerm(mode)
	// Create the empty file in the backend (copy-up of parents, mode floor and
	// sub-floor override all there), then open it for the fd.
	ploc, err := g.vns().Resolve(path.Dir(gp), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	if ploc.FS == g.overlay && g.upperAbs == "" && g.rootAbs != "" {
		return sErr(lxEROFS) // the overlay root is read-only without a writable upper
	}
	// A bind or tmpfs mount is its own writable filesystem, so a create under it
	// proceeds even when the overlay root has no upper.
	c, err := g.create(ploc, gp, vfs.CreateSpec{Kind: vfs.Reg, Mode: perm})
	if err != nil {
		return sErr(osErrno(err))
	}
	nf, err := c.Open(goOpenFlags(flags) &^ (os.O_CREATE | os.O_EXCL))
	if err != nil {
		return sErr(osErrno(err))
	}
	of, ok := nf.(*os.File)
	if !ok {
		fd := g.installVFile(gp, c, nf, flags)
		if fd >= 0 {
			g.notify(gp, inCreate, 0)
		}
		return fd
	}
	fd := g.install(of, gp, flags)
	if fd >= 0 {
		g.notify(gp, inCreate, 0)
	}
	return fd
}

// openTmpfile makes an O_TMPFILE file: a host temp file, unlinked at once, that
// linkat(AT_EMPTY_PATH) can later give a name (by cloning it).
func (g *dguest) openTmpfile(dir string, flags, mode int64) int64 {
	if flags&lxOAccmod == lxORdonly {
		return sErr(lxEINVAL)
	}
	f, err := anonFile(g.dfs.tmpDir, "lc-tmpfile-")
	if err != nil {
		return sErr(osErrno(err))
	}
	perm := g.createPerm(mode)
	fchmodOf(f, hostPerm(perm, false))
	d := &dfile{f: f, gp: path.Join(dir, "#tmpfile"), stub: -1}
	d.fx.unnamed = true
	if hostPerm(perm, false) != perm {
		if fi, err := fileStat(f); err == nil {
			g.ov.update(inodeKey(fi), func(m *imeta) { m.mode, m.hasMode = perm, true })
		}
	}
	return g.installD(d, flags)
}

// installVFile tracks a non-host regular file (in-memory, user-defined): the
// description is backed by the filesystem's vfs.File handle vf over node, not a
// host fd. laboon owns the offset and serves read/write/lseek/fstat/ftruncate by
// driving vf's ReadAt/WriteAt/Truncate and the node's Stat (regfile.go); mmap
// copies the content in, or maps it directly if vf is an *os.File (mmap_linux.go).
func (g *dguest) installVFile(gp string, node vfs.Node, vf vfs.File, flags int64) int64 {
	return g.installD(&dfile{gp: gp, stub: -1, vf: vf, vn: node}, flags)
}

// install tracks a freshly opened host file as a new description with the
// open flags' status bits, honoring O_CLOEXEC and O_NONBLOCK.
func (g *dguest) install(f *os.File, gp string, flags int64) int64 {
	fi, err := fileStat(f)
	if err != nil {
		f.Close()
		return sErr(osErrno(err))
	}
	d := &dfile{f: f, gp: gp, isDir: fi.IsDir(), stub: -1}
	return g.installD(d, flags)
}

func (g *dguest) installD(d *dfile, flags int64) int64 {
	if !d.fx.opath {
		d.fx.oflags = flags&lxOStatusKeep | lxOLargefile
		d.fx.hasFlags = true
	}
	d.nonblock.Store(flags&lxONonblock != 0)
	if !d.fx.unnamed && strings.HasPrefix(d.gp, "/") {
		g.ov.trackFile(d)
	}
	fd := g.ft.add(d, 0)
	if flags&lxOCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	if !d.fx.opath {
		g.notifyFd(d, inOpen)
	}
	return int64(fd)
}

func (g *dguest) memfdCreate(nameAddr uint64, flags uint32) int64 {
	if flags&^(lxMfdCloexec|lxMfdAllowSealing|lxMfdHugetlb|lxMfdNoexecSeal|lxMfdExec|lxMfdHugeMask) != 0 ||
		flags&(lxMfdNoexecSeal|lxMfdExec) == lxMfdNoexecSeal|lxMfdExec {
		return sErr(lxEINVAL)
	}
	name, err := g.readCStr(nameAddr)
	if err != nil {
		return sErr(lxEFAULT)
	}
	if len(name) > 249 {
		return sErr(lxEINVAL)
	}
	f, err := anonFile(g.dfs.tmpDir, "lc-memfd-")
	if err != nil {
		return sErr(osErrno(err))
	}
	perm := uint32(0o777)
	if flags&lxMfdNoexecSeal != 0 {
		perm = 0o666
	}
	fchmodOf(f, perm)
	d := &dfile{f: f, gp: "/memfd:" + name + " (deleted)", stub: -1}
	d.fx.unnamed, d.fx.memfd = true, true
	switch {
	case flags&lxMfdNoexecSeal != 0:
		d.fx.seals.Store(0x20) // F_SEAL_EXEC
	case flags&lxMfdAllowSealing == 0:
		d.fx.seals.Store(lxSealSeal)
	}
	of := int64(lxORdwr)
	if flags&lxMfdCloexec != 0 {
		of |= lxOCloexec
	}
	return g.installD(d, of)
}

func (g *dguest) closeRange(first, last, flags uint32) int64 {
	const unshare, cloexec = 2, 4
	if flags&^(unshare|cloexec) != 0 || first > last {
		return sErr(lxEINVAL)
	}
	if flags&unshare != 0 {
		t := g.ft.clone()
		g.release()
		g.ft = t
	}
	g.ft.mu.Lock()
	var fds []int
	for fd := range g.ft.fds {
		if uint32(fd) >= first && uint32(fd) <= last {
			fds = append(fds, fd)
		}
	}
	g.ft.mu.Unlock()
	for _, fd := range fds {
		if flags&cloexec != 0 {
			g.ft.setCloexec(fd, true)
		} else {
			g.closeFd(int64(fd))
		}
	}
	return 0
}
