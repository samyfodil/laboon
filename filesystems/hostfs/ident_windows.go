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
