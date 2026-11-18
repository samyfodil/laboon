package sandbox

import "golang.org/x/sys/unix"

// SysV shmat and shmdt for the Linux stub, which the macOS stub serves itself:
// the supervisor maps the segment's file shared into the stub, as a
// MAP_SHARED file mapping, and keeps the attachment by address (memProc.shm)
// for shmdt, fork (forkShm), exec and exit (detachAll).

const (
	lxShmat = 196
	lxShmdt = 197

	shmRdonly = 0o10000
	shmRnd    = 0o20000
	shmRemap  = 0o40000
	shmExec   = 0o100000
)

func init() {
	syscalls[lxShmat] = func(g *dguest, a [6]uint64) int64 { return g.shmat(int(int32(a[0])), a[1], int64(int32(a[2]))) }
	syscalls[lxShmdt] = func(g *dguest, a [6]uint64) int64 { return g.shmdt(a[0]) }
}

func (g *dguest) shmat(id int, addr uint64, flg int64) int64 {
	if flg&shmRnd != 0 {
		addr &^= pageSize - 1 // SHMLBA is a page
	} else if addr%pageSize != 0 {
		return sErr(lxEINVAL)
	}
	ns := g.ipc()
	ns.mu.Lock()
	s := ns.shm[id]
	if s == nil {
		ns.mu.Unlock()
		return sErr(lxEINVAL)
	}
	s.d.refs.Add(1) // held while mapping, against a concurrent IPC_RMID
	ns.mu.Unlock()
	defer s.d.unref()
	prot := uint64(unix.PROT_READ | unix.PROT_WRITE)
	if flg&shmRdonly != 0 {
		prot = unix.PROT_READ
	}
	if flg&shmExec != 0 {
		prot |= unix.PROT_EXEC
	}
	flags := uint64(unix.MAP_SHARED)
	switch {
	case addr != 0 && flg&shmRemap != 0:
		flags |= unix.MAP_FIXED
	case addr != 0:
		flags |= unix.MAP_FIXED_NOREPLACE
	}
	size := alignUp(s.size)
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	if addr != 0 && g.isReserved(addr, size) {
		return sErr(lxEINVAL)
	}
	r := g.mmapShared(hostFd(s.d.f), [6]uint64{addr, size, prot, flags, 0, 0})
	if r == sErr(lxEEXIST) {
		return sErr(lxEINVAL) // the range is taken and SHM_REMAP not given
	}
	if r < 0 {
		return r
	}
	ns.mu.Lock()
	s.nattch++
	s.atime = now()
	s.lpid = g.tgid
	ns.mu.Unlock()
	g.mp.shm[uint64(r)] = &shmAttach{id: id, seg: s}
	return r
}

// shmdt detaches the segment attached at addr, all of it.
func (g *dguest) shmdt(addr uint64) int64 {
	g.mp.mu.Lock()
	at := g.mp.shm[addr]
	if at == nil {
		g.mp.mu.Unlock()
		return sErr(lxEINVAL)
	}
	delete(g.mp.shm, addr)
	g.untrack(addr, alignUp(at.seg.size))
	g.host(unix.SYS_MUNMAP, addr, alignUp(at.seg.size))
	g.mp.mu.Unlock()
	g.ipc().detach(g.tgid, at)
	return 0
}
