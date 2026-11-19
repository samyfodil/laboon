//go:build windows

package hostfs

import "github.com/samyfodil/laboon/core"

// Linux errnos the windows backend returns where no Windows error maps to them
// cleanly; osErrno recovers the number at the host-call boundary.
const (
	lxEISDIR  = core.Errno(21)
	lxENOTDIR = core.Errno(20)
	lxELOOP   = core.Errno(40)
	lxEINVAL  = core.Errno(22)
)
