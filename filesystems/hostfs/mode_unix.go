//go:build !windows

package hostfs

import "github.com/samyfodil/laboon/core"

// subFloor reports whether the host file cannot hold mode exactly, so the guest
// mode must be kept in the override instead of on the file. On a POSIX host that
// is precisely when the owner-writable floor HostMode imposes (so the supervisor
// can always reach the file) changes the mode.
func subFloor(mode uint32, dir bool) bool {
	return uint32(core.HostMode(mode, dir))&0o7777 != mode&0o7777
}
