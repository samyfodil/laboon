//go:build !windows

package oci

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile holds an exclusive lock on p, creating it, until unlock; another
// process taking it waits, and a process that dies lets go.
func lockFile(p string) (unlock func(), err error) {
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
