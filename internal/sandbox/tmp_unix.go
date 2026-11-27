//go:build darwin || linux

package sandbox

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// sweepTmp removes dead supervisors' run directories and their socket
// directories, /tmp/lcn.<pid>-*.
func sweepTmp() {
	sweepDead(os.TempDir(), "lc-run-")
	sweepDead("/tmp", "lcn.")
}

func pidGone(pid int) bool { return unix.Kill(pid, 0) == unix.ESRCH }

// netTmpPrefix names this process's socket directories under /tmp.
func netTmpPrefix() string {
	return fmt.Sprintf("lcn.%d-", os.Getpid())
}
