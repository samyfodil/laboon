//go:build linux || darwin

package sandbox

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// peakRSS is the test process's peak resident size in bytes.
func peakRSS() int64 {
	var ru unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return ru.Maxrss
	}
	return ru.Maxrss << 10
}
