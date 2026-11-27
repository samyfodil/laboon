//go:build windows

package sandbox

import (
	"os"

	"golang.org/x/sys/windows"
)

func sweepTmp() { sweepDead(os.TempDir(), "lc-run-") }

// pidGone: no process has the id, or the one that has it has exited and only
// lives on as a handle someone holds.
func pidGone(pid int) bool {
	const stillActive = 259
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err == windows.ERROR_INVALID_PARAMETER
	}
	defer windows.CloseHandle(h)
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code != stillActive
}
