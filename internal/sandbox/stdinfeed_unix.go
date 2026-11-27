//go:build linux || darwin

package sandbox

import (
	"os"

	"golang.org/x/sys/unix"
)

// pipeHeld is how many bytes the pipe whose read end is f holds.
func pipeHeld(f *os.File) (int, error) {
	return unix.IoctlGetInt(hostFd(f), hostFIONREAD)
}
