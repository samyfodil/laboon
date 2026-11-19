package core

import (
	"sync"
	"sync/atomic"
)

// MetaStore is an inode-keyed table of the metadata a host file cannot itself
// carry — a mode below the owner-rw floor, a non-root owner, a special-node
// kind. Keying by {dev,ino} is what makes two hardlinks share one entry and a
// rename keep it. The overlay backend owns one; when the live sandbox routes its
// overlay onto the backend, it shares this same store, so there is a single
// authority for guest metadata rather than the sandbox's inode table and the
// backend's running in parallel. Safe for concurrent use.
type MetaStore struct {
	mu     sync.Mutex
	n      atomic.Int32 // len(m), read lock-free so an empty store costs no lock on the stat path
	m      map[NodeID]*Override
	origin map[NodeID]NodeID // runtime only (never persisted): a copied-up top inode -> the lower inode it came from, so a file lock keeps one identity across copy-up
}

// NewMetaStore returns an empty store.
func NewMetaStore() *MetaStore { return &MetaStore{m: map[NodeID]*Override{}} }

// Empty reports (lock-free) whether the store holds nothing, so a caller can
// skip it on the common path where no override exists.
func (s *MetaStore) Empty() bool { return s.n.Load() == 0 }

// Get returns a copy of the override recorded for id and whether any is. It
// takes no lock when the store is empty, the overwhelmingly common stat case.
func (s *MetaStore) Get(id NodeID) (Override, bool) {
	if s.n.Load() == 0 {
		return Override{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.m[id]; o != nil {
		return *o, true
	}
	return Override{}, false
}

// Update applies f to id's override, creating it if absent and dropping it if f
// leaves nothing recorded.
func (s *MetaStore) Update(id NodeID, f func(*Override)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.m[id]
	if o == nil {
		o = &Override{}
		s.m[id] = o
	}
	f(o)
	if !o.HasMode && !o.HasOwner && !o.Special {
		delete(s.m, id)
	}
	s.n.Store(int32(len(s.m)))
}

// SetOrigin records that the copied-up top inode up came from the lower inode
// lower, so a lock taken on the file before copy-up and one taken after resolve
// to the same identity. Runtime only; not persisted.
func (s *MetaStore) SetOrigin(up, lower NodeID) {
	s.mu.Lock()
	if s.origin == nil {
		s.origin = map[NodeID]NodeID{}
	}
	s.origin[up] = lower
	s.mu.Unlock()
}

// OriginOf maps a copied-up top inode to the lower inode it came from; any other
// id maps to itself.
func (s *MetaStore) OriginOf(id NodeID) NodeID {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lo, ok := s.origin[id]; ok {
		return lo
	}
	return id
}

// Delete drops id's override.
func (s *MetaStore) Delete(id NodeID) {
	s.mu.Lock()
	delete(s.m, id)
	s.n.Store(int32(len(s.m)))
	s.mu.Unlock()
}
