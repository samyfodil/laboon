package oci

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile holds an exclusive lock on p, creating it, until unlock; another
// process taking it waits, and a process that dies lets go.
func lockFile(p string) (unlock func(), err error) {
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, ^uint32(0), ^uint32(0), ol); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
