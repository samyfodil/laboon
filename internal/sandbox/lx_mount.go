package sandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/bind"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
)

// Mount flags (uapi/linux/mount.h).
const (
	lxUmount2    = 39
	lxMount      = 40
	lxPivotRoot  = 41
	msRemount    = 0x20
	msBind       = 0x1000
	msRec        = 0x4000
	msPrivate    = 0x40000
	msSlave      = 0x80000
	msShared     = 0x100000
	msUnbindable = 0x200000
)

// dynMount is a mount(2) mount, kept on the dfs so each guest namespace can
// replay it (an exec'd container process inherits its parent's mounts). ns is
// the mount namespace that created it; its mounts are torn down when that
// namespace's last process exits (0 is the root namespace, kept for the run).
type dynMount struct {
	at  string
	mfs core.FileSystem
	ns  int
}

func init() {
	syscalls[lxMount] = func(g *dguest, a [6]uint64) int64 { return g.mount(a[0], a[1], a[2], a[3], a[4]) }
	syscalls[lxUmount2] = func(g *dguest, a [6]uint64) int64 { return g.umount2(a[0]) }
	syscalls[lxPivotRoot] = func(g *dguest, a [6]uint64) int64 { return g.pivotRoot(a[0]) }
}

// pivotRoot makes new_root the process's root, as a container runtime does
// after assembling the container's mounts. laboon tracks a per-process root
// (like chroot), so this re-roots the caller and the processes it goes on to
// exec; the old root is simply dropped rather than relocated to put_old (the
// runtime unmounts and removes it immediately). This is a single mount
// namespace, so the re-root is not isolated from unrelated processes.
func (g *dguest) pivotRoot(newAddr uint64) int64 {
	if !g.capableFs(capSysAdmin) {
		return sErr(lxEPERM)
	}
	gp, e := g.lookup(lxAtFdcwd, newAddr, true)
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
	g.pfs.pivoted.Store(true) // the old root is now stacked here, awaiting one umount
	return 0
}

// mount serves a guest mount(2). laboon has a single mount namespace, so a
// propagation-type change is a no-op and a remount of unmodelled flags is
// accepted. A new filesystem is added to the vfs Namespace as a core.FileSystem,
// so paths under it resolve through the same confined chokepoint; it is never a
// direct host path. Binding a path and the non-tmpfs filesystems are not yet
// supported.
func (g *dguest) mount(srcAddr, tgtAddr, fsAddr, flags, dataAddr uint64) int64 {
	const propagation = msPrivate | msSlave | msShared | msUnbindable
	switch {
	case flags&propagation != 0 && flags&^uint64(propagation|msRec) == 0:
		return 0
	case flags&msRemount != 0:
		return 0
	}
	if !g.ps.cred.capable(capSysAdmin) {
		return sErr(lxEPERM)
	}
	target, e := g.lookup(lxAtFdcwd, tgtAddr, true)
	if e != 0 {
		return sErr(e)
	}
	if flags&msBind != 0 {
		if g.nsFile(srcAddr) {
			// A container runtime persists a network namespace by bind-mounting
			// /proc/<pid>/ns/net onto a file under /run/netns. laboon models a
			// namespace as an id, not a bind-mountable nsfs file; the target
			// already exists, so accept the mount and record it (pinning the
			// caller's current network namespace, the usual self/thread-self
			// source) so statfs reports nsfs there, setns through it rejoins that
			// same namespace, and the file cannot be removed until it is unmounted.
			g.dfs.addNsBind(target, g.ps.netns.Load())
			return 0
		}
		return g.mountBind(srcAddr, target)
	}
	fstype, err := g.readCStr(fsAddr)
	if err != nil {
		return sErr(lxEFAULT)
	}
	switch fstype {
	case "tmpfs", "ramfs":
		// A real in-memory filesystem: volatile and separate from the rootfs, as
		// the kernel tmpfs is (writes do not land in the container's overlay upper).
		// /dev/shm is provisioned host-backed elsewhere, since it needs a real host
		// fd for MAP_SHARED; a file mmapped MAP_SHARED on this tmpfs gets ENODEV.
		data, _ := g.readCStr(dataAddr)
		return g.mountMem(target, data)
	case "mqueue":
		// It needs only a writable mount point here; the container workloads this
		// serves do not exercise its object semantics.
		return g.mountFS(target)
	case "devpts":
		return g.mountPseudo(target, newPnodeFS(g.ptsDir(), devDevtmp, devptsMagic, target))
	case "proc":
		return g.mountPseudo(target, newPnodeFS(g.procRoot(), devProc, procMagic, target))
	case "sysfs":
		return g.mountPseudo(target, newPnodeFS(sysRoot(g.cgStore()), devSys, sysfsMagic, target))
	case "cgroup2":
		return g.mountPseudo(target, newPnodeFS(cgroupDir(g.cgStore()), devSys, cgroupMagic, target))
	case "overlay":
		data, _ := g.readCStr(dataAddr)
		return g.mountOverlay(target, data)
	default:
		return sErr(lxENOSYS)
	}
}

// mountOverlay services `mount -t overlay` (what a container runtime's overlay
// storage driver issues to assemble a container rootfs): it unions the lowerdirs
// and the upperdir the data string names into a real copy-on-write view and
// mounts it at target. Each layer is a directory resolved through the Namespace
// like any other path (overlayLayer), so a layer named with ".." or a symlink
// stays inside the guest's own tree. lowerdir is colon-separated,
// highest-precedence first; overlayFS takes layers lowest first with the
// writable top last.
func (g *dguest) mountOverlay(target, data string) int64 {
	lower, upper, _ := parseOverlayOpts(data)
	if len(lower) == 0 && upper == "" {
		return sErr(lxEINVAL)
	}
	if upper != "" {
		lower = append([]string{upper}, lower...)
	}
	layers := make([]core.FileSystem, len(lower))
	for i, p := range lower {
		l, e := g.overlayLayer(p)
		if e != 0 {
			return sErr(e)
		}
		layers[len(lower)-1-i] = l
	}
	ovl := overlayfs.OverlayFS(layers...)
	if err := g.vns().Mount(target, ovl); err != nil {
		return sErr(osErrno(err))
	}
	g.addDynMount(target, ovl)
	return 0
}

// overlayLayer presents the directory a guest overlay mount names as a layer as
// a filesystem of its own (a bind view). Under laboon's own union it is the view
// of the layer that holds the directory, which is where a runtime extracted the
// layer's files: the whiteout and opaque markers the nested union reads and
// writes there are then its own, not hidden by the outer union.
func (g *dguest) overlayLayer(p string) (core.FileSystem, lxErrno) {
	gp, e := g.walkAt(lxAtFdcwd, p, true)
	if e != 0 {
		return nil, e
	}
	loc, err := g.vns().Resolve(gp, true)
	if err != nil {
		return nil, osErrno(err)
	}
	if loc.Node.Kind() != core.Dir {
		return nil, lxENOTDIR
	}
	fsys, n := loc.FS, loc.Node
	if l, ok := fsys.(core.Layered); ok {
		fsys, n = l.Layer(n)
	}
	return bind.Bind(fsys, n), 0
}

// parseOverlayOpts pulls lowerdir/upperdir/workdir out of an overlay mount's
// comma-separated option string (other options are ignored). lowerdir is a
// colon-separated list of paths.
func parseOverlayOpts(data string) (lower []string, upper, work string) {
	for _, kv := range strings.Split(data, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "lowerdir":
			lower = strings.Split(v, ":")
		case "upperdir":
			upper = v
		case "workdir":
			work = v
		}
	}
	return lower, upper, work
}

// mountMem services `mount -t tmpfs|ramfs` at target: a fresh tmpfs, volatile
// and separate from the rootfs as the kernel's is, the same wherever it is
// mounted. Its files are run-private host files, so a MAP_SHARED mapping maps
// them directly. The root is sticky and world-writable unless a mode= option
// sets its permission bits.
func (g *dguest) mountMem(target, data string) int64 {
	backing, err := g.dfs.tmpLayer()
	if err != nil {
		return sErr(osErrno(err))
	}
	mode, ok := tmpfsMode(data)
	if !ok {
		mode = 0o1777
	}
	if err := backing.Root().SetAttr(core.AttrUpdate{Mode: &mode}); err != nil {
		return sErr(osErrno(err))
	}
	return g.mountPseudo(target, tmpfsFS{backing})
}

// tmpfsMode reads the octal mode= option from a tmpfs mount's option string.
func tmpfsMode(data string) (uint32, bool) {
	for _, kv := range strings.Split(data, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "mode" {
			if m, err := strconv.ParseUint(v, 8, 32); err == nil {
				return uint32(m) & 0o7777, true
			}
		}
	}
	return 0, false
}

// mountPseudo mounts a synthetic filesystem (proc, sysfs, cgroup2) at target. A
// container runtime remounts these inside the container after pivot_root; the
// pseudo content is generated per reading guest, so the single shared instance
// still reports each reader's own view.
func (g *dguest) mountPseudo(target string, mfs core.FileSystem) int64 {
	if err := g.vns().Mount(target, mfs); err != nil {
		return sErr(osErrno(err))
	}
	g.addDynMount(target, mfs)
	return 0
}

// addDynMount records a mount in the shared table, tagged with the caller's
// mount namespace, and bumps the generation so every guest rebuilds its view to
// include it. Tagging is what lets dropMntnsMounts tear it down when the
// container that made it exits.
func (g *dguest) addDynMount(at string, mfs core.FileSystem) {
	fs := g.dfs
	fs.dynMu.Lock()
	fs.dynMounts = append(fs.dynMounts, dynMount{at: at, mfs: mfs, ns: g.ps.mntns})
	fs.dynMu.Unlock()
	fs.dynGen.Add(1)
}

// dropMntnsMounts tears down the mounts a mount namespace created once its last
// process has exited, as the kernel frees a mount namespace when its final
// member goes. Without it a container's relocated /proc and tmpfs mounts would
// outlive the container, and docker's vfs driver removing the rootfs afterwards
// would trip on the synthetic nodes those mounts still show (EPERM on
// <rootfs>/proc/self). The generation bump makes every guest rebuild its view
// without them.
func (fs *dfs) dropMntnsMounts(ns int) {
	fs.dynMu.Lock()
	var kept []dynMount
	changed := false
	for _, m := range fs.dynMounts {
		if m.ns == ns {
			changed = true
			continue
		}
		kept = append(kept, m)
	}
	if changed {
		fs.dynMounts = kept
	}
	fs.dynMu.Unlock()
	if changed {
		fs.dynGen.Add(1)
	}
}

// umount2 removes a mount laboon added with mount(2). A container runtime
// unmounts the old root in a loop until umount fails, so a target that is not a
// tracked mount point must report EINVAL (as the kernel does for a non-mount);
// always reporting success spins that loop forever.
func (g *dguest) umount2(tgtAddr uint64) int64 {
	target, e := g.lookup(lxAtFdcwd, tgtAddr, true)
	if e != 0 {
		return sErr(e)
	}
	fs := g.dfs
	if fs.isNsBind(target) {
		// Detach a persisted namespace bind-mount so the file can then be removed.
		fs.rmNsBind(target)
		return 0
	}
	fs.dynMu.Lock()
	idx := -1
	for i, m := range fs.dynMounts {
		if m.at == target {
			idx = i
		}
	}
	if idx >= 0 {
		fs.dynMounts = append(fs.dynMounts[:idx], fs.dynMounts[idx+1:]...)
	}
	fs.dynMu.Unlock()
	if idx >= 0 {
		fs.dynGen.Add(1) // every view rebuilds without it, with what it covered back
		return 0
	}
	// pivot_root stacks the old root for one detach; the first umount after it
	// (the old root, not a tracked mount) succeeds, later ones report EINVAL so
	// a runtime's "unmount until it fails" loop terminates.
	if g.pfs != nil && g.pfs.pivoted.CompareAndSwap(true, false) {
		return 0
	}
	return sErr(lxEINVAL) // nothing mounted here
}

// mountBind binds the subtree at source onto target: target then resolves to
// source's node through a bind.Bind filesystem in the Namespace, so it stays on
// the same confined backend and chokepoint. MS_REC is treated as a plain bind
// — submounts under source are not replicated (a single-namespace limitation).
func (g *dguest) mountBind(srcAddr uint64, target string) int64 {
	src, e := g.lookup(lxAtFdcwd, srcAddr, true)
	if e != 0 {
		return sErr(e)
	}
	loc, err := g.vns().Resolve(src, true)
	if err != nil {
		return sErr(osErrno(err))
	}
	bind := bind.Bind(loc.FS, loc.Node)
	if err := g.vns().Mount(target, bind); err != nil {
		return sErr(osErrno(err))
	}
	g.addDynMount(target, bind)
	return 0
}

// mountFS mounts a fresh writable filesystem at target, backed by a confined
// host layer under the run's temp dir (cleaned when the run ends). It is a
// core.FileSystem in the Namespace, so every path under it resolves through the
// same chokepoint and confined backend as the rest of the guest's view.
func (g *dguest) mountFS(target string) int64 {
	backing, err := g.dfs.tmpLayer()
	if err != nil {
		return sErr(osErrno(err))
	}
	return g.mountPseudo(target, backing)
}

// tmpLayer makes a fresh writable filesystem: a confined host directory under
// the run's temp dir, removed when the run ends. Its backend is rooted at the
// directory itself, whatever the run's root, so no host call made for the
// guest's tree follows a symlink the guest put there.
func (fs *dfs) tmpLayer() (*hostfs.HostDirFS, error) {
	dir, err := os.MkdirTemp(fs.tmpDir, "lc-mount-")
	if err != nil {
		return nil, err
	}
	// The no-symlink resolution refuses a root whose own path has one (/tmp on
	// macOS).
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		return nil, err
	}
	backing := hostfs.NewHostDirFS(dir, hostfs.NewRawHostFS(dir))
	backing.SetConfine(true)             // a guest-mutable tree
	backing.SetMeta(core.NewMetaStore()) // carry device-node kind/rdev the placeholder cannot
	return backing, nil
}

// tmpfsFS is a tmpfs backed by a run-private host directory: volatile like the
// kernel's, with host files a MAP_SHARED mapping can map directly.
type tmpfsFS struct{ *hostfs.HostDirFS }

func (tmpfsFS) fsType() uint64 { return tmpfsMagic }

// shmFS is the run's /dev/shm, shared by every guest: a sticky, world-writable
// tmpfs, as the kernel's is.
func (fs *dfs) shmFS() core.FileSystem {
	fs.shmOnce.Do(func() {
		t, err := fs.tmpLayer()
		if err != nil {
			return
		}
		mode := uint32(0o1777)
		if t.Root().SetAttr(core.AttrUpdate{Mode: &mode}) == nil {
			fs.shm = tmpfsFS{t}
		}
	})
	return fs.shm
}
