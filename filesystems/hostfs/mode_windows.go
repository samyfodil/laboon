//go:build windows

package hostfs

// subFloor reports whether NTFS cannot hold mode exactly, so the guest mode must
// be kept in the override instead of on the file. NTFS has no POSIX bits: every
// file reports 0o666 and every directory 0o777 (no owner/group/other split, no
// execute, no setuid/setgid/sticky), so any other mode is sub-floor. (core.HostMode
// models only the POSIX owner-writable floor, which is why it cannot answer this.)
func subFloor(mode uint32, dir bool) bool {
	floor := uint32(0o666)
	if dir {
		floor = 0o777
	}
	return floor != mode&0o7777
}
