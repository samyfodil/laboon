//go:build windows

package sandbox

import "golang.org/x/sys/windows"

// Host process control over a stub process by its OS pid.

func osKick(pid int) {}

func osKill(pid int) {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return
	}
	windows.TerminateProcess(h, 128+9)
	windows.CloseHandle(h)
}

// hostStop parks every thread of process p (a job-control stop) by
// suspending it; hostCont resumes the threads it parked. Only p's threads
// are touched: a CLONE_VM child shares its parent's stub process.
func (sr *sigRun) hostStop(p *sigProc) {
	inj := sr.injector()
	if inj == nil {
		return
	}
	inj.mu.Lock()
	_, stopped := inj.parked[p.tgid]
	inj.mu.Unlock()
	if !stopped {
		// A stopped stub cannot cool the shared code it runs: it cools it
		// first, and heats again only once it goes on (codeStop, codeGo).
		sr.codeStop(p)
	}
	threads := sr.threadsOf(p)
	inj.mu.Lock()
	defer inj.mu.Unlock()
	if inj.parked == nil {
		inj.parked = map[int][]int{}
	}
	if _, ok := inj.parked[p.tgid]; ok {
		return
	}
	var tids []int
	for _, t := range threads {
		if r, ok := inj.threads[t.tid]; ok {
			if suspendThread(r.handle) {
				tids = append(tids, t.tid)
			}
		}
	}
	inj.parked[p.tgid] = tids
}

// hostContThread lets thread t of stopped process p go on alone: only the
// threads hostStop parked are suspended, each on its own.
func (sr *sigRun) hostContThread(p *sigProc, t *sigThread) bool {
	inj := sr.injector()
	if inj == nil {
		return false
	}
	inj.mu.Lock()
	defer inj.mu.Unlock()
	tids := inj.parked[p.tgid]
	for i, tid := range tids {
		if tid == t.tid {
			if r, ok := inj.threads[tid]; ok {
				windows.ResumeThread(r.handle)
			}
			inj.parked[p.tgid] = append(tids[:i], tids[i+1:]...)
			return true
		}
	}
	return false
}

// hostStopThread parks thread t again while process p stays stopped; if p's
// stop has no parked threads left to join, it parks the whole process.
func (sr *sigRun) hostStopThread(p *sigProc, t *sigThread) {
	inj := sr.injector()
	if inj == nil {
		return
	}
	inj.mu.Lock()
	tids, ok := inj.parked[p.tgid]
	if !ok {
		inj.mu.Unlock()
		sr.hostStop(p)
		return
	}
	defer inj.mu.Unlock()
	for _, tid := range tids {
		if tid == t.tid {
			return
		}
	}
	if r, ok := inj.threads[t.tid]; ok {
		if suspendThread(r.handle) {
			inj.parked[p.tgid] = append(tids, t.tid)
		}
	}
}

func (sr *sigRun) hostCont(p *sigProc) {
	inj := sr.injector()
	if inj == nil {
		return
	}
	sr.codeGo(p, func() {
		inj.mu.Lock()
		defer inj.mu.Unlock()
		for _, tid := range inj.parked[p.tgid] {
			if r, ok := inj.threads[tid]; ok {
				windows.ResumeThread(r.handle)
			}
		}
		delete(inj.parked, p.tgid)
	})
}

// watchStub has stub process ospid's end run stubGone, whatever the cause,
// once the registry names ospid. Its own handle keeps ospid from naming
// another process until then.
func (fs *dfs) watchStub(ospid int, proc windows.Handle) {
	cur := windows.CurrentProcess()
	var h windows.Handle
	if err := windows.DuplicateHandle(cur, proc, cur, &h, windows.SYNCHRONIZE, false, 0); err != nil {
		windows.TerminateProcess(proc, 128+9) // unwatchable: end it, so stubGone is true
		fs.stubGone(ospid)
		return
	}
	fs.wg.Add(1)
	go func() {
		defer fs.wg.Done()
		windows.WaitForSingleObject(h, windows.INFINITE)
		fs.stubGone(ospid)
		windows.CloseHandle(h)
	}()
}

// awaitStubGone waits for an exiting stub process to be gone, after which
// nothing in it touches its channel slot. It has been told to exit, and the
// run's kill-on-close job ends it at teardown.
// exitRusage is the usage of g's process, about to exit.
func (g *dguest) exitRusage() rusage { return hostRusage(g.ps.ospid) }

func (fs *dfs) awaitStubGone(ospid int) {
	if ospid <= 0 {
		return
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(ospid))
	if err != nil {
		return
	}
	windows.WaitForSingleObject(h, windows.INFINITE)
	windows.CloseHandle(h)
}
