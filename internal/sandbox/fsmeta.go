package sandbox

import "github.com/samyfodil/laboon/core"

// Guest ownership and any permission bits an upper file cannot carry on the
// host live in a side table keyed by the upper file's host inode, so they
// follow renames and hard links: every upper file keeps at least u+rw (u+rwx
// for directories) on the host, because the guest runs as root and the
// supervisor does not. The table is a core.MetaStore — the same type the overlay
// backend uses — so when the live overlay routes onto that backend the two
// become one authority for guest metadata rather than parallel tables.

type ikey struct{ dev, ino uint64 }

type imeta struct {
	mode     uint32 // guest permission bits (07777), when hasMode
	uid, gid uint32
	hasMode  bool
	hasOwner bool
}

// inodeMeta is the sandbox's view of a core.MetaStore, translating the backend's
// Override to the sandbox's imeta at the boundary so call sites are unchanged.
// The store keeps the lock-free empty fast path, so a stat with no overrides
// recorded takes no lock.
type inodeMeta struct{ store *core.MetaStore }

func (o *inodeMeta) get(k ikey) (imeta, bool) {
	ov, ok := o.store.Get(core.NodeID{Dev: k.dev, Ino: k.ino})
	if !ok {
		return imeta{}, false
	}
	return imeta{mode: ov.Mode, uid: ov.Uid, gid: ov.Gid, hasMode: ov.HasMode, hasOwner: ov.HasOwner}, true
}

func (o *inodeMeta) update(k ikey, f func(m *imeta)) {
	o.store.Update(core.NodeID{Dev: k.dev, Ino: k.ino}, func(ov *core.Override) {
		m := imeta{mode: ov.Mode, uid: ov.Uid, gid: ov.Gid, hasMode: ov.HasMode, hasOwner: ov.HasOwner}
		f(&m)
		ov.Mode, ov.Uid, ov.Gid, ov.HasMode, ov.HasOwner = m.mode, m.uid, m.gid, m.hasMode, m.hasOwner
	})
}

// canon maps a node identity to the one that survives copy-up: a top-layer file
// copied up from a lower resolves back to the lower identity it came from, so a
// directory opened before copy-up and the same directory read after it compare
// equal. Any identity not copied up maps to itself.
func (o *inodeMeta) canon(id core.NodeID) core.NodeID { return o.store.OriginOf(id) }

// hostPerm is the host permission an upper file with guest bits perm carries.
func hostPerm(perm uint32, dir bool) uint32 {
	if dir {
		return perm&0o777 | 0o700
	}
	return perm&0o777 | 0o600
}
