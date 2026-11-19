package sandbox

import (
	"os"

	"github.com/samyfodil/laboon/core"
	"golang.org/x/sys/unix"
)

// oPathHost is the host flags for pinning a file without following a final
// symlink or opening it for I/O.
const oPathHost = unix.O_PATH | unix.O_NOFOLLOW

type devIno struct{ dev, ino uint64 }

func osFstatIno(f *os.File) (devIno, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return devIno{}, err
	}
	return devIno{st.Dev, st.Ino}, nil
}

// pinPathFD opens a confined host O_PATH handle to node, pinning its object so
// the descriptor keeps referring to it after its name is removed (O_PATH inode
// semantics). It returns nil when the backend has no single host file (a
// pseudo or synthetic node), in which case the O_PATH fd stays path-based.
func pinPathFD(n core.Node) *os.File {
	f, err := n.Open(oPathHost)
	if err != nil {
		return nil
	}
	of, ok := f.(*os.File)
	if !ok {
		f.Close()
		return nil
	}
	return of
}

// reopenReadable re-opens a pinned O_PATH handle for reading. The only way to
// get a readable handle from an O_PATH fd is through the supervisor's own
// /proc/self/fd entry; the access derives solely from the already-confined
// O_PATH capability (never a guest path or fd number), and the identity is
// verified so a racing replacement cannot redirect it.
func reopenReadable(p *os.File) (*os.File, lxErrno) {
	return reopenMode(p, os.O_RDONLY)
}

// reopenMode re-opens a pinned O_PATH handle with the host access mode in hf (as
// reopenReadable does, but honoring O_WRONLY/O_RDWR). A container runtime opens
// its exec fifo O_PATH, unlinks it, then reopens it O_WRONLY through
// /proc/self/fd to signal the container to start, so the mode must carry.
func reopenMode(p *os.File, hf int) (*os.File, lxErrno) {
	a, err := osFstatIno(p)
	if err != nil {
		return nil, lxEACCES
	}
	f, err := os.OpenFile(procFdPath(int(p.Fd())), hf&^(os.O_CREATE|os.O_EXCL|os.O_TRUNC), 0)
	if err != nil {
		return nil, osErrno(err)
	}
	b, err := osFstatIno(f)
	if err != nil || a != b {
		f.Close()
		return nil, lxEACCES
	}
	return f, 0
}

// pinExeFD pins the inode f refers to as a fresh confined O_PATH handle, so
// /proc/<pid>/exe keeps resolving the exec'd binary after its name is removed.
// It re-opens through the supervisor's own fd (the O_PATH capability for f),
// independent of f's lifetime.
func pinExeFD(f *os.File) *os.File {
	if f == nil {
		return nil
	}
	fd, err := unix.Open(procFdPath(int(f.Fd())), unix.O_PATH|unix.O_CLOEXEC, 0) // follow the proc magic link to the inode
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), "exe")
}
