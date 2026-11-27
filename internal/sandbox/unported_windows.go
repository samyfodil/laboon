//go:build windows

package sandbox

import "sync"

// Subsystems the Windows backend has not ported yet: SysV shared memory,
// signal waits (M3). Each
// stands in with the shape the shared code expects and fails its syscalls
// with ENOSYS or the errno Linux gives an unsupported object.

type runInfo struct{}

// memProc is a process's stub pairing: w is the stub (shared by the
// process's threads and, until it execs, a CLONE_VM child). Its SysV
// attachments and SEM_UNDO adjustments are settled when the address space
// ends (endWinProcess), not per thread, so release does nothing.
type memProc struct {
	w       *wguest
	mu      sync.Mutex
	names   map[uint64]fileName
	shm     map[uint64]*shmAttach
	semadj  map[int]map[uint16]int
	backing map[uint64]*backingRef // shared-futex key -> the MAP_SHARED backing the stub maps for it (sharedback.go)
}

func newMemProc() *memProc {
	return &memProc{names: map[uint64]fileName{}, shm: map[uint64]*shmAttach{}, semadj: map[int]map[uint16]int{}, backing: map[uint64]*backingRef{}}
}

func (m *memProc) stubFd(g *dguest, d *dfile) (int, lxErrno) { return 0, lxENOSYS }

func (m *memProc) release(g *dguest) {}

// share is called when a thread is created: threads of one process share the
// stub pairing, so the same memProc is reused.
func (m *memProc) share() *memProc { return m }

const (
	lcShmat       = 0x4c430003
	lcShmAttached = 0x4c430004
	lcShmGone     = 0x4c430005
)

type fileRegistry struct{ mu sync.Mutex }

func (r *fileRegistry) closed(d *dfile) {}

var stubFiles = &fileRegistry{}

func (g *dguest) stdioRead(d *dfile, bufAddr uint64, n, ask int64) int64 { return sErr(lxEIO) }

func (t *sigThread) wakeWrite() {}
