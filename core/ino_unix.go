//go:build unix

package core

import (
	"os"
	"syscall"
)

// fileID returns a file's inode identity and link count, for detecting
// hardlinks (two names that are one inode) when serializing a layer directory.
func FileID(fi os.FileInfo) (id uint64, nlink uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Ino, uint64(st.Nlink), true
}

// StatID returns a file's full {device, inode} identity, the key an inode-keyed
// metadata table uses (two hardlinks share it; it survives a rename).
func StatID(fi os.FileInfo) (NodeID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return NodeID{}, false
	}
	return NodeID{Dev: uint64(st.Dev), Ino: st.Ino}, true
}
