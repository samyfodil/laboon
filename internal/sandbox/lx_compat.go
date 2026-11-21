//go:build darwin || linux || windows

package sandbox

// Advisory and informational calls whose Linux result the supervisor must
// serve on every host, so the same guest program is not served on one OS and
// ENOSYS on another. The macOS and Windows stubs answer the memory ones
// (mlock, mincore) in-guest because they own the address space; these
// registrations are the fallback for a host that forwards them. Behaviour need
// not be bit-identical across hosts, only a plausible Linux result.

// Shared asm-generic numbers for these calls. They live here, not in a
// per-OS file, so the cross-platform handlers below (and their Windows and
// macOS counterparts) can name them.
const (
	lxMlock         = 228
	lxMunlock       = 229
	lxMlockall      = 230
	lxMunlockall    = 231
	lxMincore       = 232
	lxMlock2        = 284
	lxGetcpu        = 168
	lxSetRobustList = 99
	lxGetRobustList = 100
	lxMembarrier    = 283

	lxMclCurrent  = 1 // MCL_CURRENT
	lxMclFuture   = 2 // MCL_FUTURE
	lxMclOnfault  = 4 // MCL_ONFAULT
	lxMlockOnfaul = 1 // MLOCK_ONFAULT
)

func init() {
	// Locking is not honoured (the sandbox never pins guest pages); the calls
	// validate their arguments and report success, the compatibility behaviour
	// Linux programs expect when RLIMIT_MEMLOCK is generous.
	regSys(lxMlock, func(g *dguest, a [6]uint64) int64 { return mlockRange(a[0], a[1]) })
	regSys(lxMunlock, func(g *dguest, a [6]uint64) int64 { return mlockRange(a[0], a[1]) })
	regSys(lxMlock2, func(g *dguest, a [6]uint64) int64 {
		if a[2]&^uint64(lxMlockOnfaul) != 0 {
			return sErr(lxEINVAL)
		}
		return mlockRange(a[0], a[1])
	})
	regSys(lxMlockall, func(g *dguest, a [6]uint64) int64 { return mlockAll(a[0]) })
	regSys(lxMunlockall, func(g *dguest, a [6]uint64) int64 { return 0 })

	// getcpu reports the CPU and node the thread runs on, as the vDSO the
	// guest has does.
	regSys(lxGetcpu, func(g *dguest, a [6]uint64) int64 { return g.getcpu(a[0], a[1]) })
}

// mlockRange validates a lock range and succeeds without pinning. A range that
// wraps the address space is EINVAL, as on Linux.
func mlockRange(addr, length uint64) int64 {
	if addr+length < addr {
		return sErr(lxEINVAL)
	}
	return 0
}

// mlockAll validates mlockall flags and succeeds. At least one of
// MCL_CURRENT/MCL_FUTURE must be set, MCL_ONFAULT needs one of them, and no
// other bit is allowed.
func mlockAll(flags uint64) int64 {
	if flags == 0 || flags&^uint64(lxMclCurrent|lxMclFuture|lxMclOnfault) != 0 || flags == lxMclOnfault {
		return sErr(lxEINVAL)
	}
	return 0
}
