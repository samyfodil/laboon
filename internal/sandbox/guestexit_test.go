package sandbox

import (
	"testing"

	"github.com/samyfodil/laboon/filesystems/memfs"
)

// A guest's libc startup and exit must run cleanly. On aarch64 glibc's _start
// reads x0 as the dynamic linker's fini pointer and registers it as an exit
// callback when nonzero, so a backend that enters the guest with a stale x0 (the
// macOS stub once did) makes glibc jump to garbage at process exit, long after
// main returned. musl ignores the parameter, so this reproduces only with a
// glibc guest — which is why the matrix stages both libcs. The minimal guest
// just writes a marker and returns 0; the crash, if present, is at exit.
func TestGuestStartupExit(t *testing.T) {
	exe := guestBin(t, "startup")
	runMmapGuest(t, exe, memfs.NewMemFS(), "STARTUP-OK")
}
