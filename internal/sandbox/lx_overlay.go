//go:build darwin || linux || windows

package sandbox

import (
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/samyfodil/laboon/core"
)

// Overlay bookkeeping beyond the upper/lower split: the whiteout set (fs.whiteout)
// hides the lower layer at a path and everything below it, so a whited-out
// path recreated in the upper is opaque. Guest ownership and any permission bits
// the host file cannot carry live in a side table keyed by the upper file's host
// inode, so they follow renames and hard links: every upper file keeps at least
// u+rw (u+rwx for directories) on the host, because the guest runs as root and
// the supervisor does not.

type ovState struct {
	inodeMeta       // guest modes and owners, plus the copy-up origin map (a core.MetaStore)
	mk        makes // paths being created, until their owner is recorded

	filesMu sync.Mutex
	files   map[*dfile]struct{} // named open descriptions, retargeted by rename

	inotifyMu sync.Mutex
	watchers  []*inotify
	nwatch    atomic.Int32
	cookie    atomic.Uint32
}

func inodeKey(fi os.FileInfo) ikey {
	dev, ino := hostDevIno(fi)
	return ikey{dev, ino}
}

// originOf maps a copied-up top inode to the lower inode it came from (via the
// shared MetaStore the overlay backend records into), so file locks keep one
// identity across a copy-up.
func (o *ovState) originOf(k ikey) ikey {
	id := o.store.OriginOf(core.NodeID{Dev: k.dev, Ino: k.ino})
	return ikey{id.Dev, id.Ino}
}

// createPerm applies the process umask to a create mode.
func (g *dguest) createPerm(mode int64) uint32 {
	return uint32(mode) & 0o7777 &^ g.getUmask()
}

// isEmptyDir reports whether the merged directory gp has no entries.
func (g *dguest) isEmptyDir(gp string) bool {
	return len(g.readDirNS(gp, nil)) <= 2
}

func timespecTime(ts syscall.Timespec) time.Time { return time.Unix(ts.Sec, ts.Nsec) }

// ---- Linux stat --------------------------------------------------------------

// lxStat is one inode's attributes in Linux terms, shared by stat and statx.
type lxStat struct {
	dev, ino, rdev             uint64
	mode, nlink, uid, gid      uint32
	size, blocks               int64
	blksize                    uint32
	atime, mtime, ctime, btime syscall.Timespec
}

// lxModeKind maps a core.Kind to the Linux S_IFMT type bits of st_mode.
func lxModeKind(k core.Kind) uint32 {
	switch k {
	case core.Dir:
		return 0x4000
	case core.Symlink:
		return 0xa000
	case core.Chardev:
		return 0x2000
	case core.Blockdev:
		return 0x6000
	case core.Fifo:
		return 0x1000
	case core.Socket:
		return 0xc000
	}
	return 0x8000 // regular
}

// nodeInfo is an os.FileInfo backed by a resolved vfs node's attributes, so the
// internal helpers (DAC, existence and mode checks, the stat reply builder) see
// a node resolved through the Namespace as the os.FileInfo they already consume.
// Its Sys is a *hostStat carrying the winning layer's identity and host mode;
// linuxStat/ownerOf apply the guest owner and sub-floor mode overrides from the
// shared store keyed by that identity, exactly as for a real host FileInfo.
type nodeInfo struct {
	name string
	st   hostStat
}

func (n *nodeInfo) Name() string       { return n.name }
func (n *nodeInfo) Size() int64        { return n.st.size }
func (n *nodeInfo) ModTime() time.Time { return timespecTime(n.st.mtime) }
func (n *nodeInfo) IsDir() bool        { return n.st.mode&0o170000 == 0o040000 }
func (n *nodeInfo) Sys() any           { return &n.st }

func (n *nodeInfo) Mode() os.FileMode {
	m := os.FileMode(n.st.mode & 0o777)
	switch n.st.mode & 0o170000 {
	case 0o040000:
		m |= os.ModeDir
	case 0o120000:
		m |= os.ModeSymlink
	case 0o010000:
		m |= os.ModeNamedPipe
	case 0o140000:
		m |= os.ModeSocket
	case 0o020000:
		m |= os.ModeDevice | os.ModeCharDevice
	case 0o060000:
		m |= os.ModeDevice
	}
	if n.st.mode&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if n.st.mode&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if n.st.mode&0o1000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

// newNodeInfo builds the os.FileInfo for a node resolved through the Namespace.
// The host mode (not the guest override) goes into the *hostStat: linuxStat and
// ownerOf re-derive the guest owner and mode from the store, so this must carry
// the same raw bits a host lstat of the winning layer would.
func newNodeInfo(name string, a core.Attr, id core.NodeID) *nodeInfo {
	st := hostStat{
		dev: id.Dev, ino: id.Ino, rdev: a.Rdev,
		mode:  lxModeKind(a.Kind) | a.Mode&0o7777,
		nlink: uint32(a.Nlink),
		size:  a.Size, blocks: a.Blocks, blksize: 4096,
		atime: syscall.NsecToTimespec(a.Atime),
		mtime: syscall.NsecToTimespec(a.Mtime),
		ctime: syscall.NsecToTimespec(a.Ctime),
		btime: syscall.NsecToTimespec(a.Btime),
	}
	if a.Blksize > 0 {
		st.blksize = uint32(a.Blksize)
	}
	if st.nlink == 0 {
		st.nlink = 1
	}
	return &nodeInfo{name: name, st: st}
}

// nodeStat builds a guest stat reply from a resolved vfs node's attributes and
// identity, the homogeneous counterpart of linuxStat: the overlay backend has
// already applied the MetaStore overrides (sub-floor mode, non-root owner,
// special kind) in Node.Stat, so they are not reapplied here.
// The guest runs as root, so uid/gid default to 0 (the host owner of an upper
// file is the unprivileged supervisor and is never the guest's view); a non-root
// owner is carried as a MetaStore override, applied by the caller.
func nodeStat(a core.Attr, id core.NodeID) lxStat {
	s := lxStat{
		dev: id.Dev, ino: id.Ino, rdev: a.Rdev,
		mode:  lxModeKind(a.Kind) | a.Mode&0o7777,
		nlink: uint32(a.Nlink),
		size:  a.Size, blocks: a.Blocks, blksize: 4096,
		atime: syscall.NsecToTimespec(a.Atime),
		mtime: syscall.NsecToTimespec(a.Mtime),
		ctime: syscall.NsecToTimespec(a.Ctime),
		btime: syscall.NsecToTimespec(a.Btime),
	}
	if a.Blksize > 0 {
		s.blksize = uint32(a.Blksize)
	}
	if s.nlink == 0 {
		s.nlink = 1
	}
	return s
}

func (g *dguest) linuxStat(fi os.FileInfo) lxStat {
	s := lxStat{blksize: 4096, nlink: 1}
	st, ok := statOf(fi)
	if !ok { // a synthetic /proc, /sys or /dev node
		s.mode = lxModeOf(fi)
		s.dev, s.ino = hostDevIno(fi)
		s.rdev = lxRdev(fi)
		s.size = fi.Size()
		if fi.IsDir() {
			s.nlink = procDirNlink(fi)
		}
		t := syscall.NsecToTimespec(fi.ModTime().UnixNano())
		s.atime, s.mtime, s.ctime, s.btime = t, t, t, t
		return s
	}
	s.mode = st.mode
	s.dev = st.dev
	s.ino = st.ino
	s.rdev = lxRdev(fi)
	s.nlink = st.nlink
	if fi.IsDir() {
		// APFS counts every entry in a directory's links. Report 1, as Linux
		// overlayfs does for a merged directory: "subdirectory count unknown".
		s.nlink = 1
	}
	s.size = st.size
	s.blocks = st.blocks
	if st.blksize > 0 {
		s.blksize = st.blksize
	}
	s.atime, s.mtime, s.ctime, s.btime = st.atime, st.mtime, st.ctime, st.btime
	if m, ok := g.ov.get(inodeKey(fi)); ok {
		if m.hasMode {
			s.mode = s.mode&^0o7777 | m.mode
		}
		if m.hasOwner {
			s.uid, s.gid = m.uid, m.gid
		}
	}
	return s
}

// procDirNlink is a synthetic directory's link count, as Linux reports it: 2
// (for . and ..) plus one per subdirectory. /proc/<pid>/task is a subdirectory
// per thread, so Chromium's sandbox, which CHECKs st_nlink >= 3 there to
// confirm the process is single-threaded, sees the real thread count.
func procDirNlink(fi os.FileInfo) uint32 {
	pn, ok := fi.Sys().(*pnode)
	if !ok {
		return 2
	}
	if pn.nlink != nil {
		return pn.nlink()
	}
	n := uint32(2)
	if pn.kids != nil {
		for _, c := range pn.kids() {
			if c.n != nil && c.n.kind == pDir {
				n++
			}
		}
	}
	return n
}

// anonStat describes an anonymous-inode fd (eventfd, epoll, inotify, memfd-less
// specials): no file type, mode 0600, as Linux's anon_inodefs reports.
func anonStat(ino uint64) lxStat {
	return lxStat{mode: 0o600, nlink: 1, blksize: 4096, ino: ino, dev: 0xd}
}

// Linux statx mask bits.
const (
	lxStatxBasic = 0x7ff
	lxStatxBtime = 0x800
	lxStatxMntID = 0x1000
)

func (s *lxStat) statx() []byte {
	var b [256]byte
	put32(b[0:], lxStatxBasic|lxStatxBtime|lxStatxMntID)
	put32(b[4:], s.blksize)
	put32(b[16:], s.nlink)
	put32(b[20:], s.uid)
	put32(b[24:], s.gid)
	b[28], b[29] = byte(s.mode), byte(s.mode>>8)
	put64(b[32:], s.ino)
	put64(b[40:], uint64(s.size))
	put64(b[48:], uint64(s.blocks))
	for i, t := range []syscall.Timespec{s.atime, s.btime, s.ctime, s.mtime} {
		put64(b[64+16*i:], uint64(t.Sec))
		put32(b[72+16*i:], uint32(t.Nsec))
	}
	put32(b[128:], lxMajor(s.rdev))
	put32(b[132:], lxMinor(s.rdev))
	put32(b[136:], lxMajor(s.dev))
	put32(b[140:], lxMinor(s.dev))
	put64(b[144:], 1) // stx_mnt_id: one mount, the overlay root
	return b[:]
}

func lxMajor(d uint64) uint32 { return uint32(d>>32&0xfffff000 | d>>8&0xfff) }
func lxMinor(d uint64) uint32 { return uint32(d>>12&0xffffff00 | d&0xff) }
