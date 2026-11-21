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
