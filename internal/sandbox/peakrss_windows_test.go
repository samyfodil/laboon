package sandbox

import "os"

// peakRSS is the test process's peak working set in bytes.
func peakRSS() int64 {
	_, _, mc, ok := hostProcUsage(os.Getpid())
	if !ok {
		return 0
	}
	return int64(mc.peakWorkingSetSize)
}
