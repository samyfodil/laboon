//go:build !windows

package hostfs

import (
	"os"

	"github.com/samyfodil/laboon/core"
)

// fileIdent is a file's inode id and link count, for spotting the names that
// share an inode (a hardlink group). A POSIX os.FileInfo carries both, so the
// path is unused.
func fileIdent(_ string, fi os.FileInfo) (id uint64, nlink uint64, ok bool) {
	return core.FileID(fi)
}

// pathDevIno is the identity a node of the file at hp reports, which a POSIX
// os.FileInfo carries.
func pathDevIno(_ string, fi os.FileInfo) (dev, ino uint64) {
	return HostDevIno(fi)
}

// hostSymlinks reports that a layer holds a symlink as a host symlink, and
// hostModes that a layer file holds its permission bits.
const (
	hostSymlinks = true
	hostModes    = true
)

// hostTyped is the guest mode, type bits included, the host keeps for hp
// beside the file itself; a unix host file carries its own.
func hostTyped(string) (uint32, bool) { return 0, false }
