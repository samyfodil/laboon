//go:build darwin || linux || windows

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/bind"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/filesystems/overlayfs"
	"github.com/samyfodil/laboon/filesystems/readonly"
	"github.com/samyfodil/laboon/internal/namespace"
)

// Confined filesystem for the macOS backend. The supervisor owns the fd table
// and resolves every guest path within Config.Root, then performs the open /
// read / seek itself and moves bytes to and from guest memory over the channel
// (readMem/writeMem via the stub's peek/poke). Linux enforces confinement with
// openat2(RESOLVE_IN_ROOT); macOS has no such primitive, so symlinks are
// resolved in the guest namespace (resolve) and only then joined under the
// root: every host path handed to the OS is symlink-free below the root.

// dfs is the shared state of one Run that every guest process references: the
// filesystem (read-only lower Root + ephemeral writable upper + whiteouts) and
// the process table (channel-slot pool, pid allocation, the live processes and
// the exit statuses wait4 reaps). A fork adds a process here; an exit records
// its status. The one mutex guards all of it — both are low-frequency.
type dfs struct {
	vcpus     vcpuSet         // darwin, windows: the CPUs threads' rseq areas name (lx_rseq.go)
	hostFS    hostfs.HostFS   // platform host ops the overlay's HostDirFS layers run on
	rootFS    core.FileSystem // Config.RootFS: the guest root as a backend, "" rootAbs — any FileSystem, no host path behind it
	rootAbs   string          // cleaned absolute Config.Root (lower layer), "" if none
	upperAbs  string          // ephemeral writable upper dir, "" if no root
	workAbs   string          // private dir beside the upper layer for staging host objects
	keepUpper bool            // upperAbs is the caller's, kept after the run
	tmpDir    string          // the run's temp directory (newRunTmp)
	emptyOnce sync.Once
	shmOnce   sync.Once
	shm       core.FileSystem // the run's /dev/shm (shmFS)
	emptyPath string          // the run's empty directory (openEmpty)
	emptyErr  error
	appendMu  sync.Mutex // serializes O_APPEND writes to a backing that cannot append itself

	mem  []byte          // shared channel region, inherited across the stub's forks
	done <-chan struct{} // the main stub died
	wg   sync.WaitGroup  // child serve goroutines

	mu   sync.Mutex
	cond *sync.Cond // signalled when a child exits (for wait4)
	ov   ovState    // ownership/mode side table, inotify watches

	fifoMu sync.Mutex         // guards fifos
	fifos  map[string]*fifoRv // FIFO open rendezvous, by resolved guest path

	dynMu     sync.Mutex    // guards dynMounts
	dynMounts []dynMount    // mount(2) mounts, replayed into each guest namespace
	dynGen    atomic.Uint64 // bumped on every dynMounts change; a guest rebuilds its view when its stamp is stale

	bindOnce sync.Once  // builds the Config.Mounts file binds once
	binds    []dynMount // Config.Mounts host-directory binds (a host dir at a guest path), shared by every guest

	cgOnce  sync.Once // builds cgroups on first /sys/fs/cgroup use
	cgroups *cgStore  // the sandbox's shared writable cgroup v2 hierarchy

	nsBindMu sync.Mutex       // guards nsBinds
	nsBinds  map[string]int32 // namespace bind-mount path -> pinned network namespace

	shMu    sync.Mutex                 // guards shared
	shared  map[core.NodeID]*shBacking // the one MAP_SHARED backing per non-host file, keyed by vnode (sharedback.go)
	sharedN atomic.Int64               // number of live backings; zero makes every read/write skip the lookup

	slots    indexPool
	backed   int                   // slots taken so far: [0, backed) (takeSlot)
	backSlot func(int) bool        // backs a slot's pages of the shared region, nil where they back themselves
	hops     hopTable              // each stub process's host-op entry (Linux)
	exited   map[int]chan struct{} // host pid -> closed once that stub process has ended (watchStub)
	nextPid  int
	initNs   *pidns          // the host pid namespace (id 0, identity)
	nextNsID int             // next pid-namespace id
	procs    map[int]*dproc  // by guest pid
	pt       map[int]*pstate // processes (thread groups) by tgid, live and zombie
	tracing  ptraceBackend
	run      *runInfo // what starting another stub process needs
	tmp      []string // temp files to delete at end of run (exec sites)

	top     *hostfs.Layer        // the writable upper layer: the durable metadata sidecar and whiteout markers (the overlay backend does the copy-up)
	ns      *namespace.Namespace // the shared overlay view (no pseudo mounts); a guest uses its own g.ns built from fs.overlay
	overlay core.FileSystem      // the overlay backend both ns and each guest's g.ns mount on /

	term    termState
	pst     procState // /proc, /sys, /dev
	uts     utsState
	netOnce sync.Once
	net     *dnet // sockets' shared state, set up on first use

	memUsed atomic.Int64 // guest memory committed, for Config.MaxBytes (Linux, where the supervisor maps it)

	sr atomic.Pointer[sigRun] // the run's signal state, from newSigRun until its close

	devs devSet // attached Config.Devices: /dev nodes and their host backings
}

// dproc is one live guest process in the registry: the real OS pid of its stub
// (for teardown), its parent, and its channel (to wake a serve goroutine parked
// in os_sync when the process is torn down), keyed by guest pid in dfs.procs.
type dproc struct {
	ospid  int
	ppid   int
	thread bool // a clone(CLONE_VM) thread: never a wait4 child
	ch     *hostChan
	stop   chan struct{}
	g      *dguest
	ps     *pstate // the process (thread group) this pid belongs to
}

// newDfs sets up the guest root, a core.FileSystem. A host-directory root
// (HostRoot) runs through the confined host-overlay machinery with a writable
// upper (upper kept after the run if set, else a fresh one under tmp); any other
// backend (in-memory, custom) is used as the root directly, with no host path.
func newDfs(rootFS core.FileSystem, upper string, mem []byte, done <-chan struct{}, tmp string) (*dfs, error) {
	fs := &dfs{
		mem: mem, done: done, tmpDir: tmp,
		slots:    indexPool{limit: maxSlots},
		exited:   map[int]chan struct{}{},
		nextPid:  2, // pid 1 is the main process
		initNs:   newInitNs(),
		nextNsID: 1,
		procs:    map[int]*dproc{},
		pt:       map[int]*pstate{},
	}
	fs.cond = sync.NewCond(&fs.mu)
	fs.ov.store = core.NewMetaStore() // inode-keyed guest metadata, shared with the overlay backend
	if fs.takeSlot() != 0 {           // slot 0 is the main process
		return nil, errors.New("sandbox: no memory for the channel")
	}
	// A host-directory root is a host path behind the FileSystem: it runs the
	// confined host-overlay path below, not the generic-backend path.
	root, isHost := HostRootPath(rootFS)
	if isHost {
		rootFS = nil
	}
	if rootFS != nil {
		// The root is a FileSystem the embedder composed (WithMount "/"):
		// the vfs layer touches no host path for it. hostfs.HostFS stays empty — the host is
		// reached only through a backend (a writable upper or a bind), never the root.
		fs.rootFS = rootFS
		fs.hostFS = hostfs.NewHostFS("", "", "")
		fs.buildNS()
		return fs, nil
	}
	if root == "" {
		// No root filesystem: the guest's / is an empty, run-private tree; the
		// guest sees nothing of the host's.
		fs.hostFS = hostfs.NewHostFS("", "", "")
		t, err := fs.tmpLayer()
		if err != nil {
			return nil, err
		}
		t.SetMeta(fs.ov.store)
		mode := uint32(0o755)
		if err := t.Root().SetAttr(core.AttrUpdate{Mode: &mode}); err != nil {
			return nil, err
		}
		fs.rootFS = t
		fs.buildNS()
		return fs, nil
	}
	if err := fs.mountHostImage(root, upper); err != nil {
		return nil, err
	}
	return fs, nil
}

// mountHostImage sets up a host-directory image as the guest root: the read-only
// image as the overlay's lower layer, a writable upper (kept if upper is given,
// else an ephemeral one under the run's temp dir), their shared metadata store,
// and the image's owner/mode sidecar hydrated into it. It is the host-storage
// setup the run-root uses; the generic fs routing (newDfs) only invokes it, so
// the host paths and host I/O for the root live here, not in the routing layer.
func (fs *dfs) mountHostImage(root, upper string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return err
	}
	fs.rootAbs = abs
	dirs := []*string{&fs.upperAbs, &fs.workAbs}
	if upper != "" {
		if fs.upperAbs, err = filepath.Abs(upper); err == nil {
			fs.upperAbs, err = filepath.EvalSymlinks(fs.upperAbs)
		}
		if err != nil {
			return err
		}
		fs.keepUpper = true
		dirs = dirs[1:]
	}
	for _, d := range dirs {
		t, err := os.MkdirTemp(fs.tmpDir, "lc-upper-")
		if err != nil {
			fs.close()
			return err
		}
		if *d, err = filepath.EvalSymlinks(t); err != nil {
			os.RemoveAll(t)
			fs.close()
			return err
		}
	}
	fs.hostFS = hostfs.NewHostFS(fs.rootAbs, fs.upperAbs, fs.workAbs)
	// The writable upper as a hostfs.Layer: it owns the on-disk metadata sidecar
	// (the durable record of the guest owner/mode/special-kind a host file cannot
	// hold) and the whiteout markers. The overlay backend does the copy-up; this
	// layer persists and reads back what outlives the run on a kept upper.
	top, err := hostfs.NewLayer(fs.upperAbs)
	if err != nil {
		fs.close()
		return err
	}
	fs.top = top
	fs.buildNS()
	return nil
}

// buildNS composes the guest's filesystem as a vfs Namespace: the overlay union
// (read-only root as the lower layer, the writable upper on top, sharing the
// inode-keyed metadata store) mounted on /, each layer backed by the platform
// HostDirFS so WinFS reparse symlinks and the confined openat2 stay inside the
// backend. It is the homogeneous view the live ops migrate onto; until a given
// op is routed it runs beside the helpers, proven equivalent by conformance.
func (fs *dfs) buildNS() {
	// With a host image: the read-only root as the lower layer, the writable
	// upper on top when there is one, unioned by overlayFS. Both layer backends
	// share the
	// live hostfs.HostFS, whose cache knows rootAbs as the read-only lower and upperAbs
	// as the writable upper (routed by path prefix), so the Namespace sees the
	// same invalidation the live writes trigger — one cache, not a second that
	// would go stale against the running overlay.
	switch {
	case fs.rootFS != nil:
		// The root is a backend the embedder supplied, with no host path behind it:
		// used as the root as given (a writable backend, e.g. memFS, catches writes;
		// a read-only one makes the root read-only). A configured writable upper still
		// unions a copy-up layer on top, exactly as for a host-path lower.
		if fs.upperAbs == "" {
			fs.overlay = fs.rootFS
		} else {
			up := hostfs.NewHostDirFS(fs.upperAbs, fs.hostFS)
			up.SetConfine(true)
			up.SetMeta(fs.ov.store) // the leaf and the sandbox share one metadata authority
			fs.overlay = overlayfs.OverlayFS(fs.rootFS, up)
		}
	default:
		lower := hostfs.NewHostDirFS(fs.rootAbs, fs.hostFS)
		lower.SetMeta(fs.ov.store)
		lower.LoadSidecar()
		layers := []core.FileSystem{lower}
		if fs.upperAbs != "" {
			up := hostfs.NewHostDirFS(fs.upperAbs, fs.hostFS)
			up.SetConfine(true) // the writable, guest-mutable layer
			up.SetMeta(fs.ov.store)
			layers = append(layers, up)
		}
		fs.overlay = overlayfs.OverlayFS(layers...)
	}
	fs.ns = namespace.NewNamespace(fs.overlay)
}

// vns returns this guest's namespace view, built on first use: the shared root
// backend plus this
// guest's own /proc, /sys and /dev mounts. Each guest (thread) builds its own so
// the per-reader /proc (self, thread-self, the pid-namespace listing) is correct.
// It is never nil for a live guest: buildNS always runs during newDfs.
func (g *dguest) vns() *namespace.Namespace {
	gen := g.dfs.dynGen.Load()
	if (g.pns == nil || g.pnsGen != gen) && !g.pnsBuild {
		// Building the namespace resolves each mount point, which can walk a
		// /proc/<pid>/fd magic link whose lstat re-enters vns before the build
		// finishes. Guard against that so it uses the in-progress view rather
		// than recursing without bound.
		g.pnsBuild = true
		ns := g.dfs.guestNS(g)
		g.pns, g.pnsGen, g.pnsBuild = ns, gen, false
	}
	if g.pns == nil {
		return namespace.NewNamespace(g.dfs.overlay) // re-entered during the first build
	}
	return g.pns
}

// guestNS builds a guest's namespace: the shared root backend plus this guest's
// own /proc and /sys pseudo mounts and the /dev synthetic∪overlay union.
// cgStore returns the sandbox's shared cgroup v2 hierarchy, built on first use.
func (fs *dfs) cgStore() *cgStore {
	fs.cgOnce.Do(func() { fs.cgroups = newCGStore() })
	return fs.cgroups
}

func (fs *dfs) guestNS(g *dguest) *namespace.Namespace {
	ns := namespace.NewNamespace(fs.overlay)
	// The kernel filesystems are there whether or not the image has their mount
	// points.
	ns.MountShadow("/proc", newPnodeFS(g.procRoot(), devProc, procMagic, "/proc"))
	ns.MountShadow("/sys", newPnodeFS(sysRoot(fs.cgStore()), devSys, sysfsMagic, "/sys"))
	ns.MountShadow(cgRoot, newPnodeFS(cgroupDir(fs.cgStore()), devSys, cgroupMagic, cgRoot))
	// /dev unions the synthetic device nodes over the overlay's own /dev.
	var ovDev core.Node
	if loc, err := fs.ns.Resolve("/dev", true); err == nil {
		ovDev = loc.Node
	}
	ns.MountShadow("/dev", &devFS{syn: g.devRoot(), ovFS: fs.overlay, ovDev: ovDev, dev: devDevtmp})
	if shm := fs.shmFS(); shm != nil {
		ns.MountShadow("/dev/shm", shm)
	}
	fs.ensureBinds(g.cfg.Mounts)
	for _, m := range fs.binds {
		ns.MountShadow(m.at, m.mfs) // Config.Mounts host-directory binds
	}
	fs.dynMu.Lock()
	dm := fs.dynMounts
	fs.dynMu.Unlock()
	for _, m := range dm {
		// A guest sees the mount(2) mounts of its own mount namespace, plus the
		// root namespace's (a CLONE_NEWNS child inherits those). A mount made in
		// one namespace must not appear in a sibling's -- e.g. one nested
		// container must not see another's mounts.
		if m.ns == g.ps.mntns || m.ns == 0 {
			ns.Mount(m.at, m.mfs)
		}
	}
	return ns
}

// progNS is the view a program the run starts is found in: the root with
// Config.Mounts on it, as each guest's Namespace has them.
func (fs *dfs) progNS(mounts []Mount) *namespace.Namespace {
	ns := namespace.NewNamespace(fs.overlay)
	fs.ensureBinds(mounts)
	for _, m := range fs.binds {
		ns.MountShadow(m.at, m.mfs)
	}
	return ns
}

// ensureBinds builds the Config.Mounts once: each mounts its FileSystem at the
// guest path. The FileSystem is whatever the caller composed — hostfs.Dir for a
// confined host-directory bind (which forwards an AF_UNIX connect under it to the
// host socket there), a ReadOnly wrapper, an in-memory store, a union — so the
// routing layer takes no host path of its own.
// bindProgram makes the host program a rootless run names reachable at its own
// path in the guest's empty root, and nothing else of the host: a read-only bind
// of that one file, its parent directories made in the root as a mount target's
// are. It returns the program's guest path.
func (fs *dfs) bindProgram(host string) (string, error) {
	at, mfs, err := programBind(host, fs.rootFS)
	if err != nil {
		return "", err
	}
	fs.binds = append(fs.binds, dynMount{at: at, mfs: mfs})
	return at, nil
}

// programBind returns the guest path and the read-only single-file filesystem
// of the host program at host, after making its parent directories in root.
func programBind(host string, root core.FileSystem) (string, core.FileSystem, error) {
	abs, err := filepath.Abs(host)
	if err != nil {
		return "", nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", nil, err
	}
	dir, name := filepath.Split(real)
	dir = filepath.Clean(dir)
	hfs := hostfs.NewHostDirFS(dir, hostfs.NewRawHostFS(dir))
	hfs.SetConfine(true)
	n, err := hfs.Lookup(hfs.Root(), name)
	if err != nil {
		return "", nil, err
	}
	if n.Kind() != core.Reg {
		return "", nil, fmt.Errorf("program %s is not a regular file", host)
	}
	at := path.Clean("/" + filepath.ToSlash(abs))
	cur := root.Root()
	for _, c := range strings.Split(strings.Trim(path.Dir(at), "/"), "/") {
		if c == "" {
			continue
		}
		next, err := root.Lookup(cur, c)
		if errors.Is(err, os.ErrNotExist) {
			next, err = root.Create(cur, c, core.CreateSpec{Kind: core.Dir, Mode: 0o755})
		}
		if err != nil {
			return "", nil, err
		}
		cur = next
	}
	return at, readonly.ReadOnly(bind.Bind(hfs, n)), nil
}

func (fs *dfs) ensureBinds(mounts []Mount) {
	fs.bindOnce.Do(func() {
		for _, m := range mounts {
			at := path.Clean(m.Guest)
			if at == "/" || at == "." {
				continue // the root is Config.RootFS, not a dynamic mount
			}
			if m.FS != nil {
				fs.binds = append(fs.binds, dynMount{at: at, mfs: m.FS})
			}
		}
	})
}

func (fs *dfs) close() {
	fs.flushSharedMem() // write back and release the MAP_SHARED backings of non-host files
	dropIPC(fs)
	fs.closeDevices()
	if fs.keepUpper && fs.top != nil {
		// The guest's writers have stopped; project the inode-keyed metadata (the
		// live cache) onto the top layer's path map and persist it to the sidecar,
		// the durable record. Whiteouts are already on disk (written live).
		fs.top.Persist(fs.ov.store)
		fs.top.SaveMeta()
	}
	for _, d := range []string{fs.upperAbs, fs.workAbs} {
		if d != "" && (d != fs.upperAbs || !fs.keepUpper) {
			os.RemoveAll(d)
		}
	}
	fs.mu.Lock()
	tmp := fs.tmp
	fs.mu.Unlock()
	for _, p := range tmp {
		os.Remove(p)
	}
	if fs.net != nil {
		fs.net.close()
	}
}

// addTmp registers a temp file to delete at end of run. execve writes site
// files the stub reads asynchronously after the repExec reply, so they cannot
// be removed inline (the stub may not have read them yet).
func (fs *dfs) addTmp(path string) {
	fs.mu.Lock()
	fs.tmp = append(fs.tmp, path)
	fs.mu.Unlock()
}

// allocSlot reserves a free channel slot, or -1 if the pool is full.
func (fs *dfs) allocSlot() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	i := fs.takeSlot()
	if i >= 0 {
		// No stub runs on it yet: clear a stDead its last user left.
		atomic.StoreUint32(&(*chanPage)(unsafe.Pointer(&fs.mem[i*slotSize])).state, 0)
	}
	return i
}

// takeSlot takes the lowest free slot, its pages of the shared region backed
// (backSlot), or -1. The slots taken so far are [0, fs.backed): a slot past
// them is the next one. fs.mu held, or fs not yet shared.
func (fs *dfs) takeSlot() int {
	i := fs.slots.take()
	if i >= fs.backed {
		if fs.backSlot != nil && !fs.backSlot(i) {
			fs.slots.put(i)
			return -1
		}
		fs.backed = i + 1
	}
	return i
}

// releaseSlot frees g's slot once its serve loop is done, unless g led a
// process that lives on without it (slotHeld).
func (fs *dfs) releaseSlot(g *dguest) {
	if !g.slotHeld {
		fs.freeSlot(g.slot)
	}
}

func (fs *dfs) freeSlot(i int) {
	fs.mu.Lock()
	fs.slots.put(i)
	fs.mu.Unlock()
}

func (fs *dfs) allocPid() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	pid := fs.nextPid
	fs.nextPid++
	return pid
}

func (fs *dfs) addProc(gpid int, p *dproc) {
	fs.mu.Lock()
	fs.procs[gpid] = p
	fs.mu.Unlock()
}

// stopMu serializes closing a process's stop channel: several goroutines
// (a stub's end, a pooled stub's waiter, exec, teardown) may each find it due.
var stopMu sync.Mutex

// closeStop closes c unless it is already closed.
func closeStop(c chan struct{}) {
	stopMu.Lock()
	defer stopMu.Unlock()
	select {
	case <-c:
	default:
		close(c)
	}
}

// stubGone ends the serve goroutines of everything that ran in stub process
// ospid, which has ended.
func (fs *dfs) stubGone(ospid int) {
	fs.reapWhere(func(p *dproc) bool { return p.ospid == ospid })
}

func (fs *dfs) reapWhere(gone func(*dproc) bool) {
	type target struct {
		ch   *hostChan
		stop chan struct{}
		pid  int
	}
	var dead []target
	fs.mu.Lock()
	for tid, p := range fs.procs {
		if gone(p) {
			dead = append(dead, target{p.ch, p.stop, tid})
		}
	}
	if len(dead) > 0 {
		fs.cond.Broadcast()
	}
	fs.mu.Unlock()
	for _, d := range dead {
		fs.endServe(d.pid, d.stop, d.ch)
		if d.ch != nil {
			d.ch.gone()
		}
	}
}

// endServe ends the serve loop of thread tid: its process's stop closes, its
// channel goes dead (its wait returns errExited, a stub thread still waiting
// exits), and a wait of its in a supervisor-served call is woken. The channel
// is ended only while tid is still registered with it: once its serve loop
// has retired it, its slot may be another thread's.
func (fs *dfs) endServe(tid int, stop chan struct{}, ch *hostChan) {
	if stop != nil {
		closeStop(stop)
	}
	if ch != nil {
		fs.mu.Lock()
		if p := fs.procs[tid]; p != nil && p.ch == ch {
			ch.end()
		}
		fs.mu.Unlock()
	}
	fs.wakeServed(tid)
}

// retire ends the serve loop of thread tid, whose channel ch the caller found
// registered (takeOverGroup, which then drops the registration): it is still
// the thread's, since a slot is freed only once its serve loop has ended.
func (fs *dfs) retire(tid int, stop chan struct{}, ch *hostChan) {
	if stop != nil {
		closeStop(stop)
	}
	if ch != nil {
		ch.end()
	}
	fs.wakeServed(tid)
}

func (fs *dfs) wakeServed(tid int) {
	if sr := fs.sigs(); sr != nil {
		if t := sr.thread(tid); t != nil {
			sr.wake(t)
		}
	}
}

// killAll SIGKILLs every live child stub and wakes its serve goroutine (which
// may be parked in os_sync on the now-dead stub), so no orphan stub or stuck
// goroutine outlives the run. Used on teardown.
func (fs *dfs) killAll() {
	fs.mu.Lock()
	ps := make([]*dproc, 0, len(fs.procs))
	tids := make([]int, 0, len(fs.procs))
	for tid, p := range fs.procs {
		ps = append(ps, p)
		tids = append(tids, tid)
	}
	fs.cond.Broadcast()
	fs.mu.Unlock()
	for i, p := range ps {
		if p.ospid > 0 {
			osKill(p.ospid)
		}
		fs.endServe(tids[i], p.stop, p.ch)
	}
}

// isWhite reports whether the lower layer is hidden at gp: gp or one of its
// ancestors was removed (or renamed away) and possibly recreated in the upper.
func (fs *dfs) isWhite(gp string) bool {
	if fs.ns == nil {
		return false
	}
	// Ask the overlay backend, which reads the on-disk whiteout markers — the one
	// source of truth, consistent with whiteouts the backend itself writes.
	return fs.ns.Whiteouted(gp)
}

func (fs *dfs) setWhite(gp string, on bool) {
	if fs.top == nil {
		return
	}
	if on {
		fs.top.Whiteout(gp)
	} else {
		fs.top.Unwhiteout(gp)
	}
	if fs.ns != nil {
		fs.ns.Invalidate()
	}
	// A whiteout is written to the upper outside hostfs.HostFS (and may materialize an
	// upper directory to hold it), so invalidate the lookup cache: the Namespace
	// reads these markers from disk and must not see a stale "absent".
	fs.upperChanged()
}

// dguest is one guest process: its channel slot, cwd and fd table. Processes
// created by fork share the dfs and the open-file descriptions in their tables.
type dguest struct {
	*dfs
	cfg    Config
	ch     *hostChan
	mem    []byte           // shared channel region
	slot   int              // this process's channel slot (its scratch lives there)
	pid    int              // guest pid for a process, guest tid for a thread (what gettid returns)
	robust [2]atomic.Uint64 // set_robust_list's head and length
	tgid   int              // thread-group id: the process pid getpid returns (== pid for a process)
	ppid   int

	ft       *ftable              // open-file table: shared across a thread group (CLONE_FILES), copied by fork
	pfs      *procFs              // umask and cwd: shared by threads, copied by fork
	mp       *memProc             // host-fd pairing with the stub: shared by threads, new per fork
	pi       *procInfo            // what /proc shows of this process; shared by its threads
	pns      *namespace.Namespace // this guest's namespace view (overlay + its own /proc,/sys); built lazily by vns
	pnsGen   uint64               // dfs.dynGen when pns was built; a mismatch rebuilds it to track mount/umount
	pnsBuild bool                 // vns is building pns; guards re-entry (a mount point that walks a /proc fd link)

	isThread bool // created by clone(CLONE_VM): its exit (nr 93) retires only this slot
	slotHeld bool // it led a process that outlived it, which keeps its slot (leaderExited)

	rseqReg  [3]uint64 // the thread's registered rseq area, length and signature
	vcpu     int       // darwin, windows: the CPU its rseq area names + 1, 0 for none (lx_rseq.go)
	forkTid  int       // a fork child's host pid, before its stub reports it (Linux)
	forkMask []byte    // the forking thread's CPU affinity, for a fork child's first thread (Linux)

	ps     *pstate // process state shared by the thread group (ids, limits, wait)
	traced atomic.Bool

	restart func() int64 // what restart_syscall resumes: Linux's restart_block (see lxRestartSyscall)

	args  argSet // the inputs of the syscall being served, as the stub copied them
	outW  uint64 // how much of its output vector the guest can write, as the stub measured it at the call's entry (macOS, Windows: noteOut)
	iobuf []byte // reused scratch for gathering a guest write's buffers (per thread, so no lock)
	rbuf  []byte // reused scratch for a socket receive, distinct from iobuf so a read+write path cannot alias
}

// gbuf returns this thread's write-scratch buffer grown to n, reused across
// syscalls so a socket write does not allocate one per call. Only this thread's
// serveThread touches it, and it is never held across a channel round-trip:
// what is kept past the syscall (a queued datagram, a query answered later) is
// a copy, or the thread's next write changes it.
func (g *dguest) gbuf(n int) []byte {
	if cap(g.iobuf) < n {
		g.iobuf = make([]byte, n)
	}
	return g.iobuf[:n]
}

// rbufOf returns this thread's receive-scratch buffer grown to n. The received
// bytes are scattered into guest memory before the syscall returns and no caller
// reads recvResult.data afterward, so reuse across receives is safe.
func (g *dguest) rbufOf(n int) []byte {
	if cap(g.rbuf) < n {
		g.rbuf = make([]byte, n)
	}
	return g.rbuf[:n]
}

// dfile is an open-file description. It is shared (refcounted) between fd
// table entries created by dup and by fork, as on Linux; the host file closes
// when the last reference goes. A stdio entry (stub >= 0) is also the stub's
// own host fd of that number, which the stub serves itself on the fast path.
type dfile struct {
	f       *os.File
	hf      core.File  // a host-backed file's vfs handle: fstat goes through it (hf.Stat), f is only the borrowed data-plane descriptor; nil for non-host and non-file fds
	vinfo   core.Info  // a precomputed vfs-node stat for an object with no openable host handle (a mknod'd device backed by a host /dev node, a directory): fstat reports this, not the raw backing fd
	vf      core.File  // a non-host regular file's backing (in-memory, user-defined); nil for host and non-regular fds
	vn      core.Node  // its node, for fstat and SEEK_END
	fs      *dfs       // set with vf/vn: reaches the per-vnode MAP_SHARED backing (sharedback.go)
	fpos    int64      // its file offset (laboon owns it; the backing has only ReadAt/WriteAt)
	fmu     sync.Mutex // serializes fpos across concurrent read/write on a shared description
	mapf    *os.File   // darwin: an unlinked temp file holding a non-host file's content for the stub to map; nil until first mmap
	shbf    *os.File   // darwin: the per-vnode shared backing (sharedback.go) the stub maps for a writable MAP_SHARED mapping; borrowed, not closed here
	gp      string     // guest path (resolved, rooted), for relative lookups
	isDir   bool
	stub    int         // the stub's host stdio fd this description is, or -1
	tty     bool        // a host terminal
	dents   []dirent    // merged directory listing, built on first getdents64
	dpos    int         // cursor into dents
	dmu     sync.Mutex  // guards dents/dpos: a description is shared across threads and forks
	dirID   core.NodeID // the opened directory's copy-up-stable identity, for getdents
	dirIDok bool        // dirID was captured (a real directory opened by openat)
	refs    atomic.Int32

	rkind atomic.Uint32 // the host file's readKind, once asked

	nonblock atomic.Bool // O_NONBLOCK: a status flag of the description, as on Linux
	ev       *eventfd    // set for an eventfd (f is its readiness pipe's read end)
	ep       *epoll      // set for an epoll instance (f is its kqueue)
	epw      epWatch     // the epolls this description is registered in
	fx       fileX       // status flags, O_PATH, memfd seals, inotify, locks
	pathFD   *os.File    // O_PATH: a confined host O_PATH handle pinning the object (f stays nil), so it survives its name being removed and can be re-opened for exec/stat
	pinned   *dfile      // O_PATH where the host has no such handle: the regular file held open for reading, for the same
	tfd      *timerfd    // set for a timerfd (f is its readiness pipe's read end)
	pty      *ptmx       // set for any end of a supervisor terminal (tty.go)
	mem      *memFile    // set for a synthetic /proc or /sys file (no host file)
	pipe     *pipeObj    // set for a pipe end: both ends, for reopening via /proc/<pid>/fd
	fifo     *fifoRv     // set for a named-pipe end: its open rendezvous, to drop its count on close
	sk       *dsock      // set for a socket (f is the host socket)
	pid      int         // set for a pidfd: the process it refers to
	sf       *sigFile    // set for a signalfd (f is its readiness pipe)
	full     bool        // /dev/full: writes fail with ENOSPC
	null     bool        // the run's null device for discarded stdio (windows: the stub serves it)
}

// dirent is one entry of a merged (upper over lower) directory listing.
type dirent struct {
	name string
	ino  uint64
	typ  byte // Linux DT_* d_type
}

// ftable is a guest process's open-file table (the Linux files_struct): the fd
// -> open-file-description map plus the per-fd close-on-exec flags. It is
// refcounted and shared by pointer across a thread group that cloned with
// CLONE_FILES, so a fd one thread opens or closes is seen by its peers. A fork
// instead gets its own copy (clone), with each entry's dfile still shared
// (refcounted) so parent and child share the open-file description and offset.
//
// The mutex guards only the maps: a lookup returns the *dfile and the actual IO
// happens after the lock is dropped (IO on a *os.File is itself serialized by
// Go). refs counts the dguests pointing here; the last one out drops every fd.
type ftable struct {
	mu      sync.Mutex
	fds     map[int]*dfile
	cloexec map[int]bool
	refs    int
	max     int // RLIMIT_NOFILE soft limit: fds must stay below it (0 = none)
	lowFd   int // lower bound on the lowest free fd: no fd below it is free
}

func newFtable() *ftable {
	return &ftable{fds: map[int]*dfile{}, cloexec: map[int]bool{}, refs: 1}
}

func (t *ftable) get(fd int) (*dfile, bool) {
	fd = int(int32(fd)) // a Linux fd argument is an int: the upper half is not part of it
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.fds[fd]
	return d, ok
}

func (t *ftable) isCloexec(fd int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cloexec[fd]
}

func (t *ftable) setCloexec(fd int, on bool) {
	if fd < 0 {
		return
	}
	t.mu.Lock()
	t.cloexec[fd] = on
	t.mu.Unlock()
}

// allocLocked returns the lowest free fd >= min, or -1 when none is free
// below the RLIMIT_NOFILE limit; the caller holds mu.
// allocLocked returns the lowest free fd >= min; the caller claims it at once
// (every caller sets t.fds[fd] under the same lock), so a successful search that
// started at the lowFd hint advances the hint past it. The hint skips the dense
// run of low fds a server already holds, making the common open O(1) not O(n).
func (t *ftable) allocLocked(min int) int {
	fd := min
	if t.lowFd > fd {
		fd = t.lowFd
	}
	for ; t.max == 0 || fd < t.max; fd++ {
		if _, taken := t.fds[fd]; !taken {
			if min <= t.lowFd { // searched from the hint: everything below fd is now taken
				t.lowFd = fd + 1
			}
			return fd
		}
	}
	return -1
}

// installAt places d at a known-free fd (stdio at startup), bumping its ref.
func (t *ftable) installAt(fd int, d *dfile) {
	d.refs.Add(1)
	t.mu.Lock()
	t.fds[fd] = d
	t.mu.Unlock()
}

// add installs d at the lowest free fd >= min and returns it. With the table
// full it returns -EMFILE and drops d's host resources if nothing else holds it.
func (t *ftable) add(d *dfile, min int) int {
	d.refs.Add(1)
	t.mu.Lock()
	fd := t.allocLocked(min)
	if fd >= 0 {
		t.fds[fd] = d
	}
	t.mu.Unlock()
	if fd < 0 {
		d.unref()
		return int(sErr(lxEMFILE))
	}
	return fd
}

// remove drops fd, closing the host file on the dfile's last reference.
func (t *ftable) remove(fd int) bool {
	fd = int(int32(fd))
	t.mu.Lock()
	d, ok := t.fds[fd]
	if ok {
		delete(t.fds, fd)
		delete(t.cloexec, fd)
		if fd < t.lowFd { // this fd is free again; the hint must not skip it
			t.lowFd = fd
		}
	}
	t.mu.Unlock()
	if !ok {
		return false
	}
	d.unref()
	return true
}

// dupTo points newfd at oldfd's description (closing whatever newfd held),
// returning newfd or EBADF. The caller rejects oldfd == newfd where it must.
func (t *ftable) dupTo(oldfd, newfd int, cloexec bool) int64 {
	t.mu.Lock()
	d, ok := t.fds[oldfd]
	if !ok {
		t.mu.Unlock()
		return sErr(lxEBADF)
	}
	if newfd < 0 || newfd >= lxNrOpen || (t.max != 0 && newfd >= t.max) {
		t.mu.Unlock()
		return sErr(lxEBADF)
	}
	var victim *dfile
	if oldfd != newfd {
		victim = t.fds[newfd]
		d.refs.Add(1)
		t.fds[newfd] = d
	}
	t.cloexec[newfd] = cloexec
	t.mu.Unlock()
	if victim != nil {
		victim.unref()
	}
	return int64(newfd)
}

// dupFrom points the lowest free fd >= min at oldfd's description (dup, F_DUPFD).
func (t *ftable) dupFrom(oldfd, min int, cloexec bool) int64 {
	t.mu.Lock()
	d, ok := t.fds[oldfd]
	if !ok {
		t.mu.Unlock()
		return sErr(lxEBADF)
	}
	if t.max != 0 && min >= t.max {
		t.mu.Unlock()
		return sErr(lxEINVAL)
	}
	newfd := t.allocLocked(min)
	if newfd < 0 {
		t.mu.Unlock()
		return sErr(lxEMFILE)
	}
	d.refs.Add(1)
	t.fds[newfd] = d
	t.cloexec[newfd] = cloexec
	t.mu.Unlock()
	return int64(newfd)
}

// clone copies the table for fork: a fresh map whose entries share this table's
// descriptions (each dfile ref bumped).
func (t *ftable) clone() *ftable {
	nt := newFtable()
	t.mu.Lock()
	nt.max = t.max
	for fd, d := range t.fds {
		d.refs.Add(1)
		nt.fds[fd] = d
		nt.cloexec[fd] = t.cloexec[fd]
	}
	t.mu.Unlock()
	return nt
}

// share takes a reference for a CLONE_FILES thread and returns the same table.
func (t *ftable) share() *ftable {
	t.mu.Lock()
	t.refs++
	t.mu.Unlock()
	return t
}

func newDguest(fs *dfs, ch *hostChan, mem []byte, slot int, cfg Config) *dguest {
	g := &dguest{dfs: fs, cfg: cfg, ch: ch, mem: mem, slot: slot, ft: newFtable(), pfs: newProcFs(), pi: fs.pst.boot}
	for fd, f := range []any{cfg.Stdin, cfg.Stdout, cfg.Stderr} {
		hf, _ := f.(*os.File)
		g.ft.installAt(fd, stdioFile(hf, fd))
	}
	return g
}

// child builds a derived guest sharing this one's dfs, cwd and the given fd
// table. fork and cloneThread differ only in that table and the address space.
func (g *dguest) child(ch *hostChan, slot, pid int, ft *ftable) *dguest {
	return &dguest{dfs: g.dfs, cfg: g.cfg, ch: ch, mem: g.mem, slot: slot, pid: pid, tgid: pid, ppid: g.pid, ft: ft, pfs: g.pfs, pi: g.pi}
}

// fork returns the child's copy of this process: same cwd, its own fd table
// whose entries share this one's open-file descriptions, and a fresh address
// space (its own futex table). cloneThread builds threads directly via child().
func (g *dguest) fork(ch *hostChan, slot, pid int) *dguest {
	c := g.child(ch, slot, pid, g.ft.clone())
	c.pi = g.pi.forked()
	c.rseqReg = g.rseqReg
	if g.pfs != nil {
		c.pfs = g.pfs.clone()
	}
	return c
}

// release drops this guest's reference to its fd table; the last thread out of
// a shared table closes every fd it still holds (pipe ends, open files).
func (g *dguest) release() {
	g.dropVcpu()
	if g.mp != nil {
		g.mp.release(g)
	}
	g.ft.mu.Lock()
	g.ft.refs--
	last := g.ft.refs == 0
	if last {
		for fd, d := range g.ft.fds {
			delete(g.ft.fds, fd)
			d.unref()
		}
	}
	g.ft.mu.Unlock()
	if last {
		g.dropPosixLocks(nil)
	}
}

// closeExec drops the close-on-exec fds at execve.
func (g *dguest) closeExec() {
	g.ft.mu.Lock()
	var toDrop []int
	for fd, on := range g.ft.cloexec {
		if on {
			toDrop = append(toDrop, fd)
		}
	}
	g.ft.mu.Unlock()
	for _, fd := range toDrop {
		g.ft.remove(fd)
	}
	syncStdio()
}

// Linux open flag bits (arch-generic).
const (
	lxOWronly  = 1
	lxORdwr    = 2
	lxOCreat   = 0x40
	lxOExcl    = 0x80
	lxOTrunc   = 0x200
	lxOAppend  = 0x400
	lxOCloexec = 0x80000
)

// goOpenFlags maps the Linux open flags we honor to os.OpenFile flags.
func goOpenFlags(flags int64) int {
	var f int
	switch flags & lxOAccmod {
	case lxOWronly:
		f = os.O_WRONLY
	case lxORdwr:
		f = os.O_RDWR
	default:
		f = os.O_RDONLY
	}
	if flags&lxOCreat != 0 {
		f |= os.O_CREATE
	}
	if flags&lxOExcl != 0 {
		f |= os.O_EXCL
	}
	if flags&lxOTrunc != 0 {
		f |= os.O_TRUNC
	}
	if flags&lxOAppend != 0 {
		f |= os.O_APPEND
	}
	return f
}

// ---- guest memory over the channel -------------------------------------------

// readCStr reads a NUL-terminated string from guest memory (bounded). Each peek
// is clamped to the current 16 KiB page: the string's length is unknown, so a
// fixed scratchLen read near a page boundary could run into an adjacent
// unmapped/guard page (musl maps PROT_NONE guards next to live data) and fault
// the stub. The NUL always lies within a mapped page, so stopping at the page
// edge still finds it.
func (g *dguest) readCStr(addr uint64) (string, error) {
	if s, ok := g.argCStr(addr); ok {
		return s, nil
	}
	const max = 4096
	var b []byte
	for uint64(len(b)) < max {
		a := addr + uint64(len(b))
		chunk := uint64(scratchLen)
		if toPage := strPage - (a & (strPage - 1)); toPage < chunk {
			chunk = toPage
		}
		buf := g.ioBuf(int(chunk))
		if err := g.getBuf(a, buf); err != nil {
			return "", err
		}
		if i := indexByte(buf, 0); i >= 0 {
			b = append(b, buf[:i]...)
			return string(b), nil
		}
		b = append(b, buf...)
	}
	return string(b), nil
}

// readStrv reads a NULL-terminated vector of C strings (argv/envp).
func (g *dguest) readStrv(addr uint64) ([]string, error) {
	var out []string
	for addr != 0 && len(out) < 4096 {
		b, err := g.readMem(addr+uint64(8*len(out)), 8)
		if err != nil {
			return nil, err
		}
		p := le64(b)
		if p == 0 {
			break
		}
		s, err := g.readCStr(p)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func le64(b []byte) uint64 { return uint64(le32(b)) | uint64(le32(b[4:]))<<32 }

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// ---- path confinement --------------------------------------------------------

// lxAtFdcwd is the Linux AT_FDCWD (-100), the value the guest passes. It is NOT
// unix.AT_FDCWD, which is the Darwin value (-2): the guest's syscall ABI is
// Linux's, so dirfd arguments must be compared against the Linux constant.
const lxAtFdcwd = -100

// rootDir is the overlay-absolute directory the process sees as "/".
func (g *dguest) rootDir() string {
	if r := g.chrootRoot(); r != "" {
		return r
	}
	return "/"
}

// resolve follows symlinks in gp, an absolute path in the Namespace (already
// joined onto the process root), and returns the symlink-free path it names. followLast controls
// the final component (lstat/readlink/unlink don't follow).
func (g *dguest) resolve(gp string, followLast bool) (string, lxErrno) {
	w := namespace.Walk{Root: g.rootDir(), Start: "/", FollowLast: followLast}
	return g.walk(w, strings.TrimLeft(gp, "/"))
}

// walk resolves p in the guest's Namespace as w says.
func (g *dguest) walk(w namespace.Walk, p string) (string, lxErrno) {
	gp, err := w.Path(g.vns(), p)
	if err != nil {
		return "", osErrno(err)
	}
	return gp, 0
}

// walkAt resolves the guest path argument p, relative to dirfd, to the
// symlink-free path it names.
func (g *dguest) walkAt(dirfd int64, p string, followLast bool) (string, lxErrno) {
	w := namespace.Walk{Root: g.rootDir(), FollowLast: followLast}
	if !path.IsAbs(p) {
		var e lxErrno
		if w.Start, e = g.startDir(dirfd); e != 0 {
			return "", e
		}
	}
	return g.walk(w, p)
}

// startDir is the directory a relative path from dirfd starts at.
func (g *dguest) startDir(dirfd int64) (string, lxErrno) {
	if dirfd = int64(int32(dirfd)); dirfd == lxAtFdcwd {
		return g.getCwd(), 0
	}
	d, ok := g.ft.get(int(dirfd))
	if !ok {
		return "", lxEBADF
	}
	return d.name(), 0
}

// linkTarget reads gp as a symlink through the overlay (upper wins, whiteouts
// hide the lower). gp's parents are already resolved, so the host path has no
// symlink below the root. magic reports a synthetic link, whose absolute
// target names an open object by its full path whatever the process root.
func (g *dguest) linkTarget(gp string) (t string, ok, magic bool) {
	if t, ok, handled := g.pseudoLink(gp); handled {
		return t, ok, true
	}
	// The overlay decision — which layer backs gp, with upper winning and a
	// whiteout hiding the lower — is the vfs Namespace's: it resolves gp through
	// the overlay union (whose layers do the platform host I/O), and Readlink
	// reads the symlink off whichever layer won. Correct on every host.
	loc, err := g.vns().Resolve(gp, false)
	if err != nil || loc.Node.Kind() != core.Symlink {
		// Only a symlink has a link target. A synthetic node (e.g. a proc or
		// tmpfs mount relocated under a container rootfs) is a directory whose
		// Readlink returns an empty string without error; treating that as a
		// symlink-to-"" made resolve() rejoin to the parent and drop the final
		// component, so an O_PATH open of <rootfs>/proc recorded <rootfs> and a
		// runtime's /proc/self/fd check ("possibly malicious path") failed.
		return "", false, false
	}
	t, err = loc.Node.Readlink()
	return t, err == nil, false
}

// lookup resolves a guest path argument (dirfd-relative) to a symlink-free
// guest path.
func (g *dguest) lookup(dirfd int64, pathAddr uint64, followLast bool) (string, lxErrno) {
	p, err := g.readCStr(pathAddr)
	if err != nil {
		return "", lxEFAULT
	}
	if p == "" {
		return "", lxENOENT
	}
	if len(p) >= 4096 {
		return "", lxENAMETOOLONG
	}
	// A trailing slash follows a final symlink and requires a directory.
	slash := len(p) > 1 && p[len(p)-1] == '/'
	gp, e := g.walkAt(dirfd, p, followLast || slash)
	if e != 0 || !slash {
		return gp, e
	}
	if fi, e := g.lstatGuest(gp); e == 0 && !fi.IsDir() {
		return "", lxENOTDIR
	}
	return gp, 0
}

// ---- syscall handlers --------------------------------------------------------

// Linux O_* access-mode bits (arch-independent low bits).
const (
	lxORdonly = 0
	lxOAccmod = 3
)

// openFile opens a resolved guest path for reading through the overlay. gp is
// already symlink-free, so the final component is not followed (a symlink there
// is refused, as the confined host open would).
func (g *dguest) openFile(gp string) (*os.File, lxErrno) {
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return nil, osErrno(err)
	}
	f, err := loc.Node.Open(os.O_RDONLY)
	if (err == errPseudoOpen || errors.Is(err, core.ErrNoHostFile)) && loc.Node.Kind() == core.Dir {
		// A directory with no host file to open: a pseudo filesystem
		// (proc/sysfs/cgroup2) relocated under a container rootfs, or an in-memory
		// backend (tmpfs, WithMount). Back the descriptor with an empty directory;
		// getdents reads the real listing through the namespace by path, as it does
		// for the canonical /proc, /sys, /dev. A container runtime opens
		// <rootfs>/sys to create mount points under it.
		of, e := g.dfs.openEmpty()
		if e != nil {
			return nil, osErrno(e)
		}
		return of, 0
	}
	if err != nil {
		return nil, osErrno(err)
	}
	of, ok := hostDupOf(f, gp)
	if !ok {
		// A non-host regular file (an in-memory backend: tmpfs, WithMount) a caller
		// here must read as a host file — loading an executable to map and rewrite.
		// Copy it into a temporary host file. (A plain read-only open does not reach
		// here; it is served through the core.File directly.)
		return g.spillToHost(f)
	}
	f.Close()
	return of, 0
}

// spillToHost copies a non-host file's content into a temporary host file and
// returns it, for a caller that must have a real host file (the loader maps and
// rewrites an executable). The temp file is unlinked, so it is reclaimed when the
// returned handle is closed.
func (g *dguest) spillToHost(vf core.File) (*os.File, lxErrno) {
	tmp, err := hostfs.AnonFile(g.dfs.tmpDir, "lc-spill-")
	if err != nil {
		vf.Close()
		return nil, osErrno(err)
	}
	buf := make([]byte, 1<<20)
	for off := int64(0); ; {
		n, rerr := vf.ReadAt(buf, off)
		if n > 0 {
			if _, werr := tmp.WriteAt(buf[:n], off); werr != nil {
				tmp.Close()
				vf.Close()
				return nil, osErrno(werr)
			}
			off += int64(n)
		}
		if rerr != nil {
			vf.Close()
			if rerr != io.EOF {
				tmp.Close()
				return nil, lxEIO
			}
			return tmp, 0
		}
		if n == 0 {
			vf.Close()
			return tmp, 0
		}
	}
}

// openDir opens a directory for getdents and fchdir. A host backend gives a host
// file. A non-host directory — a pseudo filesystem (/proc, /sys) or an in-memory
// backend (tmpfs, WithMount) — has no host file, so it is backed by an empty host
// directory and getdents reads the real listing through the namespace by path.
// For an in-memory backend the node is returned too, so fstat answers from it
// rather than the placeholder; a pseudo node keeps the placeholder's attributes.
func (g *dguest) openDir(loc namespace.Loc, gp string) (*os.File, *memFile, lxErrno) {
	f, err := loc.Node.Open(os.O_RDONLY)
	if err == nil {
		if of, ok := hostDupOf(f, gp); ok {
			f.Close()
			return of, nil, 0
		}
		f.Close() // a backend returning a non-host File for a directory: treat as in-memory
	} else if err == errPseudoOpen {
		ed, e := g.dfs.openEmpty()
		if e != nil {
			return nil, nil, osErrno(e)
		}
		return ed, nil, 0
	} else if !errors.Is(err, core.ErrNoHostFile) {
		return nil, nil, osErrno(err)
	}
	ed, e := g.dfs.openEmpty()
	if e != nil {
		return nil, nil, osErrno(e)
	}
	return ed, &memFile{vn: loc.Node, name: path.Base(gp)}, 0
}

// file returns fd's host file, EBADF for unknown fds.
func (g *dguest) file(fd int64) (*dfile, lxErrno) {
	d, ok := g.ft.get(int(fd))
	if !ok || d.f == nil {
		return nil, lxEBADF
	}
	return d, 0
}

// stubFd returns the stub's host stdio fd behind a guest fd, for the stub to
// do the IO on, or -1 when the supervisor must: not stdio, O_NONBLOCK (the
// host fd is blocking), or a terminal (the stub's background reads stop it).
func (g *dguest) stubFd(fd int64) int {
	if d, ok := g.ft.get(int(fd)); ok && d.stub >= 0 && !d.tty && !d.nonblock.Load() {
		return d.stub
	}
	return -1
}

func (g *dguest) writeFile(fd int64, bufAddr uint64, n int64) int64 {
	if d, ok := g.ft.get(int(fd)); ok && d.vf != nil {
		if n < 0 {
			return sErr(lxEINVAL)
		}
		return g.regWrite(d, [][2]uint64{{bufAddr, uint64(n)}}, -1)
	}
	d, e := g.file(fd)
	if e != 0 {
		if r, ok := g.memWrite(fd, bufAddr, n); ok {
			return r
		}
		return sErr(e)
	}
	if n < 0 {
		return sErr(lxEINVAL)
	}
	if d.pipe != nil && d.pipe.io != nil {
		return g.pipeVector(d, [][2]uint64{{bufAddr, uint64(n)}}, true)
	}
	if d.ev != nil {
		return g.eventfdWrite(d, bufAddr, n)
	}
	if d.sk != nil {
		return g.sockWrite(d, [][2]uint64{{bufAddr, uint64(n)}})
	}
	if r, ok := g.termWrite(d, bufAddr, n); ok {
		return r
	}
	if d.fx.in != nil || d.tfd != nil || d.pid != 0 {
		return sErr(lxEINVAL)
	}
	if d.full {
		return sErr(lxENOSPC)
	}
	if d.fx.memfd {
		if e := d.sealCheckWrite(-1, int(n)); e != 0 {
			return sErr(e)
		}
	}
	return g.writeHost(d, [][2]uint64{{bufAddr, uint64(n)}}, n)
}

// plainHost reports whether writes to d go straight to its host file, which
// takes a whole vector at once: not a special file writeFile serves itself.
func (g *dguest) plainHost(fd int64, d *dfile) bool {
	_, e := g.file(fd)
	return e == 0 && (d.pipe == nil || d.pipe.io == nil) && d.ev == nil && d.sk == nil && d.pty == nil &&
		d.fx.in == nil && d.tfd == nil && d.pid == 0 && !d.full && !d.fx.memfd
}

// writeHost writes the n bytes at the guest's iovecs v to d's host file, a
// chunk at a time so a large write does not stage all of it here, each chunk
// in one host call, as the kernel takes a vector whole: a pipe gets up to
// PIPE_BUF of it atomically. Where the guest's bytes stop being readable the
// write goes as far as Linux's would (writeFaulting).
func (g *dguest) writeHost(d *dfile, v [][2]uint64, n int64) int64 {
	var total int64
	for total < n || n == 0 {
		// A vector gathers into a buffer of its own: the window is where a
		// copy from guest memory lands first on some hosts (macOS), which an
		// iovec past the first would overwrite the earlier ones with.
		buf := g.ioBuf(int(min(n-total, ioChunk)))
		if len(v) > 1 {
			buf = g.gbuf(len(buf))
		}
		got := g.gatherPrefix(v, int(total), buf)
		var m int
		var err error
		switch nb := d.nonblock.Load(); {
		case got < len(buf):
			if m, err = g.writeFaulting(d.f, buf[:got], len(buf)-got, nb); err == errFaultWrite && total == 0 {
				return sErr(lxEFAULT)
			}
		case nb:
			m, err = writeNonblock(d.f, buf)
		default:
			m, err = g.writeIntr(d.f, buf)
		}
		if err == errSigIntr && m == 0 && total == 0 {
			return restartSys
		}
		if err != nil && m <= 0 {
			if total == 0 {
				return sErr(osErrno(err))
			}
			break
		}
		total += int64(m)
		if m < len(buf) || n == 0 {
			break
		}
	}
	g.modified(d)
	return total
}

// readKind is what a read of a host file can do, which its kind fixes: wait
// for a writer (a FIFO or a socket), or not; unknown until asked.
type readKind uint32

const (
	kindUnknown readKind = iota
	kindMayBlock
	kindNoBlock
)

// errFaultWrite is a write that ran into guest memory that cannot be read,
// where the host cannot fault at that point as the guest's kernel would.
var errFaultWrite = errors.New("the guest's buffer faults")

// errFaultRead is a read whose data the guest's buffer has no room for.
var errFaultRead = lxErr(lxEFAULT)

// gatherPrefix copies the bytes at byte off of the guest's iovecs v into buf
// as far as they are readable, and returns how many it copied.
func (g *dguest) gatherPrefix(v [][2]uint64, off int, buf []byte) int {
	w := 0
	for _, x := range v {
		l := int(min(x[1], maxRW))
		if off >= l {
			off -= l
			continue
		}
		take := min(l-off, len(buf)-w)
		if g.argGet(x[0]+uint64(off), buf[w:w+take]) != nil {
			return w + g.readPrefix(x[0]+uint64(off), buf[w:w+take])
		}
		w += take
		off = 0
		if w == len(buf) {
			break
		}
	}
	return w
}

func (g *dguest) read(fd int64, bufAddr uint64, n int64) int64 {
	if d, ok := g.ft.get(int(fd)); ok && d.vf != nil {
		if n < 0 {
			return sErr(lxEINVAL)
		}
		return g.regRead(d, [][2]uint64{{bufAddr, uint64(n)}}, -1)
	}
	d, e := g.file(fd)
	if e != 0 {
		if r, ok := g.memRead(fd, bufAddr, n); ok {
			return r
		}
		return sErr(e)
	}
	if n < 0 {
		return sErr(lxEINVAL)
	}
	if d.pipe != nil && d.pipe.io != nil {
		return g.pipeVector(d, [][2]uint64{{bufAddr, uint64(n)}}, false)
	}
	want := n
	n = min(n, ioChunk)
	if d.sf != nil {
		return g.sigFileRead(d, bufAddr, n)
	}
	if d.ev != nil {
		return g.eventfdRead(d, bufAddr, n)
	}
	if d.pid != 0 {
		return sErr(lxEINVAL)
	}
	if d.sk != nil {
		return g.sockRead(d, [][2]uint64{{bufAddr, uint64(n)}})
	}
	if r, ok := g.termRead(d, bufAddr, n); ok {
		return r
	}
	if d.fx.in != nil {
		return g.inotifyRead(d, bufAddr, n)
	}
	if d.tfd != nil {
		return g.timerfdRead(d, bufAddr, n)
	}
	if d.stub >= 0 {
		return g.stdioRead(d, bufAddr, n)
	}
	if d.isDir {
		return sErr(lxEISDIR)
	}
	if want > n && d.fillsReads() {
		return g.readFull(d, bufAddr, want, -1)
	}
	return g.readHost(d, [][2]uint64{{bufAddr, uint64(n)}}, int(n))
}

// readHost reads up to n bytes from d's host file into the guest's iovecs v,
// in one host call, as the kernel fills a vector from one read. Where the
// guest's buffer stops being writable the read goes as far as Linux's would
// (readFaulting): what does not fit stays in the pipe or socket, and a file's
// offset moves only past what the guest got.
func (g *dguest) readHost(d *dfile, v [][2]uint64, n int) int64 {
	buf := g.ioBuf(n)
	var m int
	var err error
	switch p, nb := g.writableVecPrefix(v, n), d.nonblock.Load(); {
	case p < len(buf):
		if m, err = g.readFaulting(d.f, buf[:p], len(buf)-p, nb); err == errSigIntr {
			return restartSys
		}
	case nb:
		if m, err = readNonblockKind(d.f, buf, d.readKind()); err != nil {
			return sErr(osErrno(err))
		}
	default:
		if m, err = g.readIntr(d.f, buf, d.readKind()); err == errSigIntr {
			return restartSys
		}
	}
	if m == 0 && err != nil {
		if errors.Is(err, os.ErrClosed) {
			return sErr(lxEBADF)
		}
		if err != io.EOF {
			return sErr(osErrno(err))
		}
		return 0
	}
	if e := g.scatter(v, 0, buf[:m]); e != 0 {
		return sErr(e)
	}
	if m > 0 {
		g.notifyFd(d, inAccess)
	}
	return int64(m)
}

// plainRead reports whether reads of d go straight to its host file, which
// fills a whole vector at once: not a special file read serves itself.
func (g *dguest) plainRead(fd int64, d *dfile) bool {
	_, e := g.file(fd)
	return e == 0 && (d.pipe == nil || d.pipe.io == nil) && d.sf == nil && d.ev == nil && d.pid == 0 && d.sk == nil &&
		d.pty == nil && d.fx.in == nil && d.tfd == nil && d.stub < 0 && !d.isDir && !d.tty && !d.fillsReads()
}

// fillsReads reports whether a read on d returns all it asks for unless it
// hits end of file, as Linux reads a regular file or a zero-like device.
func (d *dfile) fillsReads() bool {
	switch d.gp {
	case "/dev/zero", "/dev/full", "/dev/urandom", "/dev/random":
		return true
	}
	if d.f == nil || d.pipe != nil || d.tty || d.pty != nil || d.mem != nil {
		return false
	}
	mode, _, err := d.hostStat()
	return err == nil && mode.IsRegular()
}

// readFull reads up to n bytes of d into guest memory a chunk at a time,
// stopping at end of file; at off unless off is -1, else at the file offset.
func (g *dguest) readFull(d *dfile, bufAddr uint64, n, off int64) int64 {
	buf := g.ioBuf(int(min(n, ioChunk)))
	var total int64
	for total < n {
		b := buf[:min(n-total, int64(len(buf)))]
		var m int
		var err error
		switch {
		case off < 0:
			m, err = d.f.Read(b)
		default:
			m, err = d.readAt(b, off+total)
		}
		if m > 0 {
			if g.putBuf(bufAddr+uint64(total), b[:m]) != nil {
				if total == 0 {
					return sErr(lxEFAULT)
				}
				break
			}
			total += int64(m)
		}
		if err != nil && err != io.EOF && total == 0 {
			return sErr(ioErrno(err))
		}
		if err != nil || m < len(b) {
			break
		}
	}
	if total > 0 {
		g.notifyFd(d, inAccess)
	}
	return total
}

// iovecs reads cnt struct iovec {base, len} from guest memory.
func (g *dguest) iovecs(iov uint64, cnt int64) ([][2]uint64, lxErrno) {
	if cnt < 0 || cnt > 1024 {
		return nil, lxEINVAL
	}
	b, err := g.argRead(iov, int(16*cnt))
	if err != nil {
		return nil, lxEFAULT
	}
	v := make([][2]uint64, cnt)
	for i := range v {
		v[i] = [2]uint64{le64(b[16*i:]), le64(b[16*i+8:])}
		if int64(v[i][1]) < 0 {
			return nil, lxEINVAL
		}
	}
	return v, 0
}

func (g *dguest) writev(fd int64, iov uint64, cnt int64) int64 {
	v, e := g.iovecs(iov, cnt)
	if e != 0 {
		return sErr(e)
	}
	if d, ok := g.ft.get(int(fd)); ok && d.vf != nil {
		return g.regWrite(d, v, -1)
	}
	if d, ok := g.ft.get(int(fd)); ok && d.sk != nil {
		return g.sockWrite(d, v) // one send: a datagram is the whole vector
	}
	if d, ok := g.ft.get(int(fd)); ok && d.pipe != nil && d.pipe.io != nil {
		return g.pipeVector(d, v, true)
	}
	if d, ok := g.ft.get(int(fd)); ok && g.plainHost(fd, d) {
		return g.writeHost(d, v, int64(iovTotal(v)))
	}
	// A file without a vector write of its own takes the iovecs one at a time,
	// as the kernel's loop does.
	var total int64
	for _, x := range v {
		if x[1] == 0 {
			continue
		}
		r := g.writeFile(fd, x[0], int64(x[1]))
		if r < 0 {
			if total > 0 {
				return total
			}
			return r
		}
		total += r
	}
	return total
}

func (g *dguest) readv(fd int64, iov uint64, cnt int64) int64 {
	v, e := g.iovecs(iov, cnt)
	if e != 0 {
		return sErr(e)
	}
	if d, ok := g.ft.get(int(fd)); ok && d.vf != nil {
		return g.regRead(d, v, -1)
	}
	if d, ok := g.ft.get(int(fd)); ok && d.sk != nil {
		return g.sockRead(d, v)
	}
	if d, ok := g.ft.get(int(fd)); ok && d.pipe != nil && d.pipe.io != nil {
		return g.pipeVector(d, v, false)
	}
	if d, ok := g.ft.get(int(fd)); ok && g.plainRead(fd, d) && iovTotal(v) <= ioChunk {
		return g.readHost(d, v, iovTotal(v))
	}
	var total int64
	for _, x := range v {
		if x[1] == 0 {
			continue
		}
		r := g.read(fd, x[0], int64(x[1]))
		if r < 0 {
			if total > 0 {
				return total
			}
			return r
		}
		total += r
		if r < int64(x[1]) {
			break // short read: don't block for more
		}
	}
	return total
}

func (g *dguest) lseek(fd, off, whence int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok || d.fx.opath {
		return sErr(lxEBADF)
	}
	if d.vf != nil { // a regular file, whatever backs it
		r, err := d.vfSeek(off, int(whence))
		if err != nil {
			return sErr(osErrno(err))
		}
		return r
	}
	if r, ok := g.memLseek(fd, off, whence); ok {
		return r
	}
	if d.f == nil || d.ev != nil || d.ep != nil || d.fx.in != nil || d.name() == "pipe:" || d.served() {
		return sErr(lxESPIPE)
	}
	if d.isDir {
		// The offset of a directory is the merged listing's resume token
		// (getdents64's d_off); 0 rewinds and re-reads the directory.
		d.dmu.Lock()
		defer d.dmu.Unlock()
		switch {
		case whence == io.SeekStart && off >= 0:
		case whence == io.SeekCurrent && off == 0:
			return int64(d.dpos)
		default:
			return sErr(lxEINVAL)
		}
		if off == 0 {
			d.dents = nil
		}
		d.dpos = int(off)
		return off
	}
	switch whence {
	case io.SeekStart, io.SeekCurrent, io.SeekEnd:
	case 3, 4: // SEEK_DATA, SEEK_HOLE
		pos, err := d.seekDataHole(off, whence == 4)
		if err != nil {
			return sErr(osErrno(err))
		}
		return pos
	default:
		return sErr(lxEINVAL)
	}
	pos, err := d.f.Seek(off, int(whence))
	if err != nil {
		if e := osErrno(err); e == lxENXIO || e == lxESPIPE {
			return sErr(e)
		}
		return sErr(lxEINVAL)
	}
	return pos
}

func (g *dguest) closeFd(fd int64) int64 {
	if fd < 3 {
		defer syncStdio()
	}
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	if d.held() {
		g.dropPosixLocks(d)
	}
	last := d.refs.Load() == 1
	if !g.ft.remove(int(fd)) {
		return sErr(lxEBADF)
	}
	if last && d.held() {
		if d.writable() && d.fx.hasFlags {
			g.notifyFd(d, inCloseWrite)
		} else {
			g.notifyFd(d, inCloseNow)
		}
	}
	return 0
}

func (g *dguest) pipe2(fdsAddr uint64, flags int64) int64 {
	r, w, transport, err := g.pipeFiles()
	if err != nil {
		return sErr(osErrno(err))
	}
	po := &pipeObj{io: transport}
	rd := &dfile{f: r, gp: "pipe:", stub: -1, pipe: po}
	wd := &dfile{f: w, gp: "pipe:", stub: -1, pipe: po}
	po.ends = [2]*dfile{rd, wd}
	rd.nonblock.Store(flags&lxONonblock != 0)
	wd.nonblock.Store(flags&lxONonblock != 0)
	rd.fx.oflags, rd.fx.hasFlags = lxORdonly, true
	wd.fx.oflags, wd.fx.hasFlags = lxOWronly, true
	rfd := g.ft.add(rd, 0)
	wfd := g.ft.add(wd, 0)
	if rfd < 0 || wfd < 0 {
		g.ft.remove(rfd)
		g.ft.remove(wfd)
		return sErr(lxEMFILE)
	}
	if flags&lxOCloexec != 0 {
		g.ft.setCloexec(rfd, true)
		g.ft.setCloexec(wfd, true)
	}
	var b [8]byte
	put32(b[:], uint32(rfd))
	put32(b[4:], uint32(wfd))
	if err := g.writeMem(fdsAddr, b[:]); err != nil {
		g.ft.remove(rfd)
		g.ft.remove(wfd)
		return sErr(lxEFAULT)
	}
	return 0
}

func (g *dguest) dup(fd int64) int64 {
	return g.ft.dupFrom(int(fd), 0, false)
}

func (g *dguest) dup3(oldfd, newfd, flags int64) int64 {
	// The kernel takes the fds as unsigned: a negative one is out of range.
	oldfd, newfd = int64(uint32(oldfd)), int64(uint32(newfd))
	if flags&^lxOCloexec != 0 || oldfd == newfd {
		return sErr(lxEINVAL)
	}
	if newfd < 3 {
		defer syncStdio()
	}
	return g.ft.dupTo(int(oldfd), int(newfd), flags&lxOCloexec != 0)
}

// Linux fcntl commands.
const (
	lxFDupfd        = 0
	lxFGetfd        = 1
	lxFSetfd        = 2
	lxFGetfl        = 3
	lxFSetfl        = 4
	lxFSetown       = 8
	lxFGetown       = 9
	lxFSetsig       = 10
	lxFGetsig       = 11
	lxFSetownEx     = 15
	lxFGetownEx     = 16
	lxFGetlease     = 1025
	lxFDupfdCloexec = 1030
	lxFSetpipeSz    = 1031
	lxFGetpipeSz    = 1032
	lxFAddSeals     = 1033
	lxFGetSeals     = 1034

	lxPipeDefSize = 65536
	lxPipeBuf     = 4096
	lxPipeMaxSize = 1048576
	lxNrOpen      = 1048576
)

func (g *dguest) fcntl(fd, cmd int64, arg uint64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	switch cmd {
	case lxFDupfd, lxFDupfdCloexec:
		if int64(arg) < 0 || arg >= lxNrOpen {
			return sErr(lxEINVAL)
		}
		return g.ft.dupFrom(int(fd), int(arg), cmd == lxFDupfdCloexec)
	case lxFGetfd:
		if g.ft.isCloexec(int(fd)) {
			return 1 // FD_CLOEXEC
		}
		return 0
	case lxFSetfd:
		g.ft.setCloexec(int(fd), arg&1 != 0)
		return 0
	case lxFGetfl:
		fl := int64(lxORdwr)
		if d.fx.hasFlags {
			fl = d.fx.oflags
		}
		if d.nonblock.Load() {
			fl |= lxONonblock
		}
		return fl
	case lxFSetfl:
		if d.fx.opath {
			return sErr(lxEBADF)
		}
		d.nonblock.Store(arg&lxONonblock != 0)
		if d.stub >= 0 {
			syncStdio()
		}
		if fd, ok := d.hostFd(); ok && (d.fx.oflags^int64(arg))&lxOAppend != 0 && d.fx.hasFlags {
			setHostAppend(fd, arg&lxOAppend != 0)
		}
		if d.fx.hasFlags {
			d.fx.oflags = d.fx.oflags&^(lxOSetflMask&^lxONonblock) | int64(arg)&(lxOSetflMask&^lxONonblock)
		}
		return 0
	case lxFGetlk, lxFSetlk, lxFSetlkw, lxFOfdGetlk, lxFOfdSetlk, lxFOfdSetlkw:
		return g.fcntlLock(d, cmd, arg)
	case lxFGetown, lxFSetown:
		return 0
	case lxFGetsig:
		return int64(d.fx.sigio.Load())
	case lxFSetsig:
		if arg > 64 {
			return sErr(lxEINVAL)
		}
		d.fx.sigio.Store(int32(arg))
		return 0
	case lxFNotify:
		return g.fcntlNotify(d, int(fd), arg)
	case lxFGetlease:
		return lxFUnlck
	case lxFGetpipeSz, lxFSetpipeSz:
		if !d.isPipe() {
			return sErr(lxEBADF)
		}
		if cmd == lxFGetpipeSz {
			if n := d.pipeSize().Load(); n > 0 {
				return int64(n)
			}
			return lxPipeDefSize
		}
		if arg > lxPipeMaxSize {
			return sErr(lxEPERM)
		}
		n := int64(4096)
		for n < int64(arg) {
			n <<= 1
		}
		if d.pipe != nil && d.pipe.io != nil {
			d.pipe.mu.Lock()
			defer d.pipe.mu.Unlock()
			if e := d.pipe.io.resize(int32(n)); e != 0 {
				return sErr(e)
			}
		} else if hfd, ok := d.hostFd(); ok {
			if e := setHostPipeSize(hfd, int(n)); e != 0 {
				return sErr(e)
			}
		}
		d.pipeSize().Store(int32(n))
		return n
	case lxFAddSeals:
		if !d.fx.memfd {
			return sErr(lxEINVAL)
		}
		if !d.writable() {
			return sErr(lxEPERM)
		}
		for {
			cur := d.fx.seals.Load()
			if cur&lxSealSeal != 0 {
				return sErr(lxEPERM)
			}
			if d.fx.seals.CompareAndSwap(cur, cur|uint32(arg)&0x3f) {
				return 0
			}
		}
	case lxFGetSeals:
		if !d.fx.memfd {
			return sErr(lxEINVAL)
		}
		return int64(d.fx.seals.Load())
	}
	return sErr(lxEINVAL)
}

// fstat / newfstatat fill a linux arm64 struct stat (128 bytes) from the host.
func (g *dguest) fstatFd(fd int64, statAddr uint64) int64 {
	s, e := g.fdStat(fd)
	if e != 0 {
		return sErr(e)
	}
	return g.putMem(statAddr, s.stat())
}

// fdStat describes an open file: an O_PATH fd its named object, an eventfd,
// epoll or inotify fd an anonymous inode, anything else its host file.
func (g *dguest) fdStat(fd int64) (lxStat, lxErrno) {
	d, ok := g.ft.get(int(fd))
	if !ok {
		return lxStat{}, lxEBADF
	}
	return g.fdStatOf(d)
}

// fdStatOf is fstat of an open description, independent of its fd number: an
// O_PATH fd reports its pinned name's stat, a synthetic file its node, an
// anonymous object (eventfd, epoll, signalfd, pidfd, timerfd) an anon inode,
// and anything else its host file. It is also a followed stat of
// /proc/<pid>/fd/<n>, whose magic link references this same object rather than
// re-resolving the name it displays.
func (g *dguest) fdStatOf(d *dfile) (lxStat, lxErrno) {
	if d.fx.opath {
		return g.statGuest(d.name())
	}
	if d.pty != nil {
		return g.ptyStat(d)
	}
	if d.vf != nil { // a regular file, whatever backs it
		return g.vfFstat(d)
	}
	if d.mem != nil && d.mem.vn != nil { // a non-host directory placeholder (its regular files go through d.vf)
		a, err := d.mem.vn.Stat()
		if err != nil {
			return lxStat{}, osErrno(err)
		}
		return nodeStat(a, d.mem.vn.ID()), 0
	}
	if d.hf != nil { // a host-backed file: fstat through its vfs handle, not the raw fd
		info, err := d.hf.Stat()
		if err != nil {
			return lxStat{}, osErrno(err)
		}
		st := nodeStat(info.Attr(), info.ID())
		if p := d.perm().Load(); p&permSet != 0 {
			st.mode = st.mode&^0o7777 | p&0o7777
		}
		return st, 0
	}
	if d.vinfo != nil { // a mknod'd device or a directory: its vfs-node stat, not the raw backing fd's
		st := nodeStat(d.vinfo.Attr(), d.vinfo.ID())
		if p := d.perm().Load(); p&permSet != 0 {
			st.mode = st.mode&^0o7777 | p&0o7777
		}
		return st, 0
	}
	if d.f == nil {
		if d.mem != nil {
			return g.linuxStat(pfi{name: d.mem.name, n: d.mem.n}), 0
		}
		return lxStat{}, lxEBADF
	}
	fi, err := g.fileInfo(d)
	if err != nil {
		return lxStat{}, osErrno(err)
	}
	if d.ev != nil || d.ep != nil || d.fx.in != nil || d.pid != 0 || d.sf != nil {
		_, ino := HostDevIno(fi)
		return anonStat(ino), 0
	}
	st := g.linuxStat(fi)
	if p := d.perm().Load(); p&permSet != 0 {
		st.mode = st.mode&^0o7777 | p&0o7777
	}
	return st, 0
}

func (g *dguest) putMem(addr uint64, b []byte) int64 {
	if err := g.putOut(addr, b); err != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

// AT_SYMLINK_NOFOLLOW / AT_EMPTY_PATH.
const (
	lxAtSymlinkNofollow = 0x100
	lxAtEmptyPath       = 0x1000
)

func (g *dguest) newfstatat(dirfd int64, pathAddr, statAddr uint64, flags int64) int64 {
	s, e := g.statPath(dirfd, pathAddr, flags)
	if e != 0 {
		return sErr(e)
	}
	return g.putMem(statAddr, s.stat())
}

// statPath is the lookup behind newfstatat and statx.
func (g *dguest) statPath(dirfd int64, pathAddr uint64, flags int64) (lxStat, lxErrno) {
	dirfd = int64(int32(dirfd))
	const atNoAutomount, atStatxSync = 0x800, 0x6000
	if flags&^(lxAtSymlinkNofollow|lxAtEmptyPath|atNoAutomount|atStatxSync) != 0 {
		return lxStat{}, lxEINVAL
	}
	p := ""
	if pathAddr != 0 {
		var err error
		if p, err = g.readCStr(pathAddr); err != nil {
			return lxStat{}, lxEFAULT
		}
	}
	if p == "" {
		if flags&lxAtEmptyPath == 0 {
			return lxStat{}, lxENOENT
		}
		if dirfd == lxAtFdcwd {
			return g.statGuest(g.getCwd())
		}
		return g.fdStat(dirfd)
	}
	follow := flags&lxAtSymlinkNofollow == 0
	gp, errno := g.lookup(dirfd, pathAddr, follow)
	if errno != 0 {
		return lxStat{}, errno
	}
	if follow {
		if s, e, ok := g.fdLinkStat(gp); ok {
			return s, e
		}
	}
	return g.statGuest(gp)
}

// applyInitDir points the init process at cfg.Dir (the image's WorkingDir, or
// WithDir) when it names a directory, which must exist — as docker errors when
// its --workdir does not. An empty Dir leaves the guest at "/". Shared by every
// platform's init path so a built image's WORKDIR is honored the same way.
func (g *dguest) applyInitDir(cfg Config) error {
	g.ensureDevices()
	if cfg.Dir == "" {
		return nil
	}
	dir := path.Clean("/" + cfg.Dir)
	fi, se := g.lstatGuest(dir)
	if se != 0 {
		return fmt.Errorf("working directory %q: %w", cfg.Dir, lxErr(se))
	}
	if !fi.IsDir() {
		return fmt.Errorf("working directory %q: %w", cfg.Dir, lxErr(lxENOTDIR))
	}
	g.setCwd(dir)
	return nil
}

// lstatGuest lstats a resolved guest path through the overlay (upper wins,
// whiteouts hide the lower), so stat/getdents see written and deleted files.
// A create registers before its name appears and records the owner before it
// ends, so waiting after the lookup catches any create the lookup could have
// seen half done.
func (g *dguest) lstatGuest(gp string) (os.FileInfo, lxErrno) {
	fi, e := g.lstatNode(gp)
	if g.ov.mk.await(gp) {
		return g.lstatNode(gp)
	}
	return fi, e
}

// lstatNode is lstatGuest without waiting for a create making gp.
func (g *dguest) lstatNode(gp string) (os.FileInfo, lxErrno) {
	if fi, e, ok := g.ttyLstat(gp); ok {
		return fi, e
	}
	// /proc, /sys and /dev are mounts in the namespace, so their stat resolves
	// there like any other path. The overlay decision — upper wins, a whiteout
	// hides the lower — is the Namespace's; the resolved node's attributes become
	// the FileInfo the internal helpers consume (DAC and the stat reply re-derive
	// the guest owner and mode from the shared store).
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return nil, osErrno(err)
	}
	a, err := loc.Node.Stat()
	if err != nil {
		return nil, osErrno(err)
	}
	return core.FileInfo(path.Base(gp), a, loc.Node.ID()), 0
}

// statGuest builds a guest stat reply for a resolved guest path through the
// overlay Namespace: the merged node (upper over lower, whiteouts applied) is
// resolved once and its attributes become the reply, so the stat syscall runs
// through vfs rather than the duplicated upper/lower dance. Pseudo and tty paths
// keep their synthetic stat.
func (g *dguest) statGuest(gp string) (lxStat, lxErrno) {
	st, e := g.statNode(gp)
	if g.ov.mk.await(gp) {
		return g.statNode(gp)
	}
	return st, e
}

func (g *dguest) statNode(gp string) (lxStat, lxErrno) {
	if fi, e, ok := g.ttyLstat(gp); ok {
		if e != 0 {
			return lxStat{}, e
		}
		return g.linuxStat(fi), 0
	}
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return lxStat{}, osErrno(err)
	}
	a, err := loc.Node.Stat()
	if err != nil {
		return lxStat{}, osErrno(err)
	}
	return nodeStat(a, loc.Node.ID()), 0
}

// HostDevIno returns the file's device (a Linux dev_t) and inode numbers. They must be
// unique per file: musl's dynamic loader tells shared libraries apart by
// (st_dev, st_ino), so a zero inode makes it load only one of them.
func HostDevIno(fi os.FileInfo) (dev, ino uint64) {
	if ci, ok := fi.(core.Info); ok {
		id := ci.ID()
		return id.Dev, id.Ino
	}
	if n, ok := fi.Sys().(*pnode); ok {
		return n.dev, n.ino
	}
	if st, ok := hostfs.StatOf(fi); ok {
		return st.Dev(), st.Ino()
	}
	return 0, 0
}

func (g *dguest) getcwd(bufAddr uint64, n int64) int64 {
	cwd := g.getCwd()
	if _, e := g.lstatGuest(cwd); e != 0 {
		return sErr(lxENOENT) // the cwd was removed
	}
	cwd = g.visibleCwd(cwd)
	b := append([]byte(cwd), 0)
	if int64(len(b)) > n {
		return sErr(lxERANGE)
	}
	if err := g.writeMem(bufAddr, b); err != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(b))
}

// getdents64 fills a linux_dirent64 stream from a merged directory listing
// (upper over lower, whiteouts removed), built once on the first call and
// consumed across calls until it returns 0 (end of directory).
func (g *dguest) getdents64(fd int64, bufAddr uint64, count int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	if d.fx.opath {
		return sErr(lxEBADF)
	}
	if !d.isDir {
		return sErr(lxENOTDIR)
	}
	d.dmu.Lock()
	defer d.dmu.Unlock()
	if d.dents == nil {
		d.dents = g.readDirNS(d.name(), d)
		d.dpos = 0
	}
	var out []byte
	for d.dpos < len(d.dents) {
		e := d.dents[d.dpos]
		// struct linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) name[]+NUL,
		// each record padded to an 8-byte boundary.
		reclen := (19 + len(e.name) + 1 + 7) &^ 7
		if int64(len(out)+reclen) > count {
			break
		}
		rec := make([]byte, reclen)
		put64(rec[0:], e.ino)
		put64(rec[8:], uint64(d.dpos+1)) // d_off: resume token = next index
		rec[16] = byte(reclen)
		rec[17] = byte(reclen >> 8)
		rec[18] = e.typ
		copy(rec[19:], e.name)
		out = append(out, rec...)
		d.dpos++
	}
	if len(out) == 0 {
		if d.dpos >= len(d.dents) {
			return 0 // end of directory
		}
		return sErr(lxEINVAL) // buffer too small for even one entry
	}
	if err := g.writeMem(bufAddr, out); err != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(out))
}

// readDirNS lists a directory through the Namespace: the pseudo mounts (/proc,
// /sys, /dev) from their own nodes, every other path through the overlay (upper
// over lower, whiteouts and opaque markers applied by the backend), with d_ino
// carried on each Dirent so no per-entry stat is needed. The order is fixed when
// the listing is built, so an entry's index is a stable d_off for the life of
// the open directory.
func (g *dguest) readDirNS(gp string, pin *dfile) []dirent {
	loc, err := g.vns().Resolve(gp, true)
	if err != nil {
		return nil
	}
	if pin != nil && pin.dirIDok && g.ov.canon(loc.Node.ID()) != pin.dirID {
		// The path now resolves to a different directory than the one this
		// description was opened on (it was removed and remade, or another
		// directory was renamed onto its path). As on Linux, where the open
		// descriptor keeps enumerating the original inode, do not enumerate the
		// impostor; report an empty (removed) directory.
		return nil
	}
	selfIno := loc.Node.ID().Ino
	parentIno := uint64(1)
	if pl, e := g.vns().Resolve(path.Dir(gp), true); e == nil {
		parentIno = pl.Node.ID().Ino
	}
	ents := []dirent{{name: ".", ino: selfIno, typ: dtDir}, {name: "..", ino: parentIno, typ: dtDir}}
	des, err := loc.FS.ReadDir(loc.Node)
	if err != nil {
		return ents
	}
	for _, de := range des {
		ents = append(ents, dirent{name: de.Name, ino: de.Ino, typ: direntKind(de.Kind)})
	}
	return ents
}

// direntKind maps a core.Kind to a Linux DT_* directory-entry type.
func direntKind(k core.Kind) byte {
	switch k {
	case core.Dir:
		return dtDir
	case core.Symlink:
		return dtLnk
	case core.Fifo:
		return dtFifo
	case core.Socket:
		return dtSock
	case core.Chardev:
		return dtChr
	case core.Blockdev:
		return dtBlk
	}
	return dtReg
}

// Linux DT_* directory-entry types.
const (
	dtFifo = 1
	dtChr  = 2
	dtDir  = 4
	dtBlk  = 6
	dtReg  = 8
	dtLnk  = 10
	dtSock = 12
)

func (g *dguest) readlinkat(dirfd int64, pathAddr, bufAddr uint64, bufsiz int64) int64 {
	if bufsiz <= 0 {
		return sErr(lxEINVAL)
	}
	var gp string
	if g.rawPath(pathAddr) == "" {
		// "" names the dirfd itself, which must be an O_PATH|O_NOFOLLOW symlink.
		d, ok := g.ft.get(int(dirfd))
		if !ok || !d.fx.opath {
			return sErr(lxENOENT)
		}
		gp = d.name()
	} else {
		var errno lxErrno
		if gp, errno = g.lookup(dirfd, pathAddr, false); errno != 0 {
			return sErr(errno)
		}
	}
	target, lerr := g.readlinkGuest(gp)
	if lerr != 0 {
		return sErr(lerr)
	}
	b := []byte(target)
	if int64(len(b)) > bufsiz {
		b = b[:bufsiz]
	}
	if err := g.writeMem(bufAddr, b); err != nil {
		return sErr(lxEFAULT)
	}
	return int64(len(b)) // readlink returns the byte count, no NUL
}

func (g *dguest) readlinkGuest(gp string) (string, lxErrno) {
	if t, e, ok := g.pseudoReadlink(gp); ok {
		return t, e
	}
	if t, ok, _ := g.linkTarget(gp); ok {
		return t, 0
	}
	if _, e := g.lstatGuest(gp); e != 0 {
		return "", e
	}
	return "", lxEINVAL // exists but is not a symlink
}

// statx fills a linux arm64 struct statx (256 bytes). The mask argument is
// advisory; every basic field and btime is always reported.
func (g *dguest) statx(dirfd int64, pathAddr uint64, flags int64, bufAddr uint64) int64 {
	s, e := g.statPath(dirfd, pathAddr, flags)
	if e != 0 {
		return sErr(e)
	}
	return g.putMem(bufAddr, s.statx())
}

// uname fills a Linux struct utsname (6 NUL-terminated 65-byte fields).
func (g *dguest) uname(addr uint64) int64 {
	var buf [390]byte
	node, domain := g.utsNS().get()
	fields := [6]string{utsSysname, node, utsRelease, utsVersion, utsMachine, domain}
	for i, f := range fields {
		copy(buf[i*65:i*65+64], f) // leave the 65th byte NUL
	}
	if err := g.writeMem(addr, buf[:]); err != nil {
		return sErr(lxEFAULT)
	}
	return 0
}

func (g *dguest) chdir(pathAddr uint64) int64 {
	gp, errno := g.lookup(lxAtFdcwd, pathAddr, true)
	if errno != 0 {
		return sErr(errno)
	}
	fi, se := g.lstatGuest(gp)
	if se != 0 {
		return sErr(se)
	}
	if !fi.IsDir() {
		return sErr(lxENOTDIR)
	}
	g.setCwd(gp)
	return 0
}

func (g *dguest) fchdir(fd int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	if !d.isDir {
		return sErr(lxENOTDIR)
	}
	g.setCwd(d.name())
	return 0
}

// ---- helpers -----------------------------------------------------------------

func osErrno(err error) lxErrno {
	var le lxErr
	if errors.As(err, &le) {
		return lxErrno(le)
	}
	var ce core.Errno
	if errors.As(err, &ce) {
		return lxErrno(ce)
	}
	if e, ok := hostErrnoOf(err); ok {
		return e
	}
	if errors.Is(err, core.ErrNotDir) {
		return lxENOTDIR
	}
	if errors.Is(err, core.ErrCrossDevice) {
		return lxEXDEV
	}
	if errors.Is(err, core.ErrLoop) {
		return lxELOOP
	}
	if errors.Is(err, os.ErrNotExist) {
		return lxENOENT
	}
	if errors.Is(err, os.ErrPermission) {
		return lxEACCES
	}
	return lxEIO
}

func put32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func put64(b []byte, v uint64) {
	put32(b, uint32(v))
	put32(b[4:], uint32(v>>32))
}
