//go:build darwin || linux || windows

package sandbox

import (
	"strings"
)

// Namespaces are modeled as ids, not bind-mountable nsfs files (lx_cred.go's
// unshare), so joining one through a descriptor only has to move the caller's
// id. A container runtime creates a network namespace, persists it by
// bind-mounting /proc/<pid>/ns/net (accepted in lx_mount.go), then has the
// container open that file and setns into it; the net effect laboon needs is an
// isolated (non-host) network namespace for the container.

const (
	lxSetns = 268

	setnsNewCgroup = 0x02000000
	setnsNewUts    = 0x04000000
	setnsNewIpc    = 0x08000000
	setnsNewUser   = 0x10000000
	setnsNewPid    = 0x20000000
	setnsNewNet    = 0x40000000
	setnsNewNs     = 0x00020000
)

func init() {
	syscalls[lxSetns] = func(g *dguest, a [6]uint64) int64 { return g.setns(int64(a[0]), int64(a[1])) }
}

func (g *dguest) setns(fd, nstype int64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	if nstype&^int64(setnsNewCgroup|setnsNewUts|setnsNewIpc|setnsNewUser|setnsNewPid|setnsNewNet|setnsNewNs) != 0 {
		return sErr(lxEINVAL)
	}
	if nstype&setnsNewNet != 0 {
		// Join a network namespace. A bind-mounted namespace file pins a specific
		// one, so joining it through that file enters that same namespace (how a
		// runtime hands a container's netns to the process that runs in it);
		// joining any other namespace descriptor moves the caller into a fresh
		// isolated one (laboon has no other per-namespace network state).
		if ns, ok := g.dfs.nsBindNetns(d.name()); ok {
			g.ps.netns.Store(ns)
		} else {
			fs := g.dfs
			fs.mu.Lock()
			g.ps.netns.Store(int32(fs.nextNsID))
			fs.nextNsID++
			fs.mu.Unlock()
		}
	}
	// The other namespace kinds carry no state laboon changes here; accept the
	// join so a runtime's namespace setup proceeds.
	return 0
}

// addNsBind records that a namespace file was bind-mounted onto path, pinning
// the given network namespace. statfs then reports nsfs there (a runtime checks
// the magic before joining it) and setns through the file enters that namespace.
func (fs *dfs) addNsBind(p string, netns int32) {
	fs.nsBindMu.Lock()
	if fs.nsBinds == nil {
		fs.nsBinds = map[string]int32{}
	}
	fs.nsBinds[p] = netns
	fs.nsBindMu.Unlock()
}

func (fs *dfs) rmNsBind(p string) {
	fs.nsBindMu.Lock()
	delete(fs.nsBinds, p)
	fs.nsBindMu.Unlock()
}

func (fs *dfs) isNsBind(p string) bool {
	fs.nsBindMu.Lock()
	defer fs.nsBindMu.Unlock()
	_, ok := fs.nsBinds[p]
	return ok
}

// nsBindNetns returns the network namespace a bind-mounted namespace file pins.
func (fs *dfs) nsBindNetns(p string) (int32, bool) {
	fs.nsBindMu.Lock()
	defer fs.nsBindMu.Unlock()
	ns, ok := fs.nsBinds[p]
	return ns, ok
}

// nsFile reports whether the path at srcAddr names a namespace file
// (/proc/<pid>/ns/net and its siblings, as a proc mount serves them), the
// source of a namespace bind-mount.
func (g *dguest) nsFile(srcAddr uint64) bool {
	gp, e := g.lookup(lxAtFdcwd, srcAddr, true)
	if e != 0 {
		return false
	}
	n, e, ok := g.pseudo(gp)
	if !ok || e != 0 || n.kind != pLink || !magicTarget(n.target) {
		return false
	}
	kind, _, _ := strings.Cut(n.target, ":")
	switch kind {
	case "net", "uts", "ipc", "pid", "mnt", "cgroup", "user", "time":
		return true
	}
	return false
}
