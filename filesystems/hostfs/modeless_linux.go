package hostfs

import "os"

// Modeless reports whether the host keeps no permission bits for an object:
// on Linux never (a socket and a pipe have inodes of their own).
func Modeless(*os.File) bool { return false }
