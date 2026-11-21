//go:build darwin || linux || windows

package sandbox

// Glue between the process model (proc_darwin.go) and signal delivery
// (signal_darwin.go): exits notify the parent through its signal state, waits
// and execs consult it, and PR_SET_PDEATHSIG goes through real delivery.

func init() {
	childExited = func(fs *dfs, ppid, pid, sig, status int) {
		sr := fs.sigs()
		sr.mu.Lock()
		if p := sr.procs[pid]; p != nil {
			sr.st(pOff(p.slot)+spMem, 0) // its memory no longer counts against the cap
			delete(sr.procs, pid)
			sr.countProcs()
			for _, t := range p.threads {
				delete(sr.threads, t.tid)
				t.closeWake()
			}
			sr.reapLocked(p)
		}
		parent := sr.procs[ppid]
		files := sr.fileList()
		sr.mu.Unlock()
		for _, sf := range files {
			if sf.pidfd && sf.tgid == pid {
				sf.setArmed(true)
			}
		}
		if parent == nil || sig == 0 {
			return
		}
		si := sigInfo{code: cldExited, a: uint64(uint32(pid)), b: uint64(uint32((status >> 8) & 0xff))}
		if status&0x7f != 0 {
			si.code, si.b = cldKilled, uint64(uint32(status&0x7f))
		}
		sr.send(parent, nil, sig, si, nil)
	}
	sigchldIgnored = func(fs *dfs, ppid int) bool {
		sr := fs.sigs()
		parent := sr.proc(ppid)
		if parent == nil {
			return false
		}
		a := sr.act(parent, sigCHLD)
		return a.handler == sigIgn || a.flags&saNoCldWait != 0
	}
	waitInterrupted = func(g *dguest) (int64, bool) {
		if g.sigIntr() {
			return restartSys, true
		}
		return 0, false
	}
	execHook = func(g *dguest) { g.sigExec() }
	procSignal = func(fs *dfs, pid, sig int) {
		sr := fs.sigs()
		if p := sr.proc(pid); p != nil {
			sr.send(p, nil, sig, sigInfo{code: siKernel}, nil)
		}
	}
}

// isZombie reports whether pid has exited but not yet been waited for.
func (fs *dfs) isZombie(pid int) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	p := fs.pt[pid]
	return p != nil && p.zombie
}
