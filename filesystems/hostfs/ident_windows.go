//go:build windows

package hostfs

import "os"

// fileIdent is a file's NTFS file id and link count, for spotting the names that
// share an inode (a hardlink group). The os.FileInfo of a walk or lstat carries
// neither, so it is read from a handle; the FileInfo is unused.
func fileIdent(hp string, _ os.FileInfo) (id uint64, nlink uint64, ok bool) {
	k, fi, err := keyOf(hp)
	if err != nil {
		return 0, 0, false
	}
	return k.id, uint64(fi.NumberOfLinks), true
}

// pathDevIno is the identity a node of the file at hp reports: its volume serial
// and file id, read from a handle as the walk's os.FileInfo carries neither.
func pathDevIno(hp string, _ os.FileInfo) (dev, ino uint64) {
	k, _, err := keyOf(hp)
	if err != nil {
		return 0, 0
	}
	return uint64(k.vol), k.id
}

// hostSymlinks reports that a layer holds a symlink as a host symlink, and
// hostModes that a layer file holds its permission bits. NTFS links need a
// privilege and are not Linux symlinks, so a layer here keeps a placeholder
// file holding the target, typed in its metadata; NTFS has no modes, so every
// mode is metadata too.
const (
	hostSymlinks = false
	hostModes    = false
)

// hostTyped is the guest mode, type bits included, WinFS keeps for hp in its
// side table: a symlink, fifo or socket it made, or a mode it was given.
func hostTyped(hp string) (uint32, bool) {
	k, _, err := keyOf(hp)
	if err != nil {
		return 0, false
	}
	return metaGet(k)
}
