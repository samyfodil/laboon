//go:build windows

package sandbox

import (
	"sync"

	"golang.org/x/sys/windows"
)

// stubPool keeps a stub started ahead for the next exec: creating and
// initializing a process costs Windows about 200 ms, most of an exec. A
// pooled stub reports ready on a spare slot of its own and waits there until
// boot claims it for a process's slot (repAdopt).
type stubPool struct {
	mu      sync.Mutex
	cond    *sync.Cond // signalled when a stub being started is ready or failed
	ready   []*pooledStub
	filling int
}

type pooledStub struct {
	sp   *stubProc
	ch   *hostChan
	slot int
}

// poolSize is how many stubs wait ready. A run that forks is likely to exec;
// one that never forks never starts one.
const poolSize = 2

// fill starts stubs in the background until poolSize are ready or starting.
func (r *procRun) fill(fs *dfs) {
	p := &r.pool
	p.mu.Lock()
	if p.cond == nil {
		p.cond = sync.NewCond(&p.mu)
	}
	n := poolSize - len(p.ready) - p.filling
	p.filling += max(n, 0)
	p.mu.Unlock()
	for range n {
		// Counted with the serve goroutines, which the run waits for
		// (its stubs killed) before it unmaps the slots.
		fs.wg.Add(1)
		go func() {
			defer fs.wg.Done()
			ps := r.startPooled(fs)
			p.mu.Lock()
			p.filling--
			if ps != nil {
				p.ready = append(p.ready, ps)
			}
			p.cond.Broadcast()
			p.mu.Unlock()
		}()
	}
}

func (r *procRun) startPooled(fs *dfs) *pooledStub {
	idx := fs.allocSlot()
	if idx < 0 {
		return nil
	}
	ch := newHostChan(newChannel(fs.mem, idx, 0, fs.done, nil))
	pg := ch.page
	pg.state, pg.kind, pg.stubSleep, pg.supSleep, pg.rip, pg.alive = 0, 0, 0, 0, 0, 0
	var err error
	if ch.evStub, err = windows.CreateEvent(nil, 0, 0, nil); err != nil {
		fs.freeSlot(idx)
		return nil
	}
	if ch.evSup, err = windows.CreateEvent(nil, 0, 0, nil); err != nil {
		windows.CloseHandle(ch.evStub)
		fs.freeSlot(idx)
		return nil
	}
	ps := &pooledStub{ch: ch, slot: idx}
	if ps.sp, err = startStub(r.job, []windows.Handle{r.chans.section(idx), ch.evStub, ch.evSup}, uint64(idx*slotSize)); err != nil {
		ps.release(fs)
		return nil
	}
	if ch.setProc(ps.sp.proc) != nil || ch.wait() != nil || pg.kind != msgReady || r.adoptStub(ps.sp.proc, pg.args[1]) != nil {
		windows.TerminateProcess(ps.sp.proc, 1)
		ps.sp.close()
		ps.release(fs)
		return nil
	}
	return ps
}

// claim moves a pooled stub onto ch's slot, waiting for one being started,
// or returns nil when there is none. The stub reports ready on ch next; the
// caller releases the spare slot once it has.
func (r *procRun) claim(fs *dfs, ch *hostChan, slot int) *pooledStub {
	p := &r.pool
	for {
		p.mu.Lock()
		for len(p.ready) == 0 && p.filling > 0 {
			p.cond.Wait()
		}
		if len(p.ready) == 0 {
			p.mu.Unlock()
			return nil
		}
		ps := p.ready[0]
		p.ready = p.ready[1:]
		p.mu.Unlock()
		if ev, err := windows.WaitForSingleObject(ps.sp.proc, 0); err != nil || ev != uint32(windows.WAIT_TIMEOUT) {
			ps.sp.close()
			ps.release(fs)
			continue
		}
		cur := windows.CurrentProcess()
		var dStub, dSup windows.Handle
		err1 := windows.DuplicateHandle(cur, ch.evStub, ps.sp.proc, &dStub, 0, false, windows.DUPLICATE_SAME_ACCESS)
		err2 := windows.DuplicateHandle(cur, ch.evSup, ps.sp.proc, &dSup, 0, false, windows.DUPLICATE_SAME_ACCESS)
		if err1 != nil || err2 != nil {
			windows.TerminateProcess(ps.sp.proc, 1)
			ps.sp.close()
			ps.release(fs)
			continue
		}
		ch.page.stdio, ch.page.pinfo = uint64(dStub), uint64(dSup)
		ps.ch.page.args[0] = uint64(slot * slotSize)
		ps.ch.reply(repAdopt)
		return ps
	}
}

// release frees the spare slot a pooled stub waited on.
func (ps *pooledStub) release(fs *dfs) {
	ps.ch.closeEvents()
	fs.freeSlot(ps.slot)
}
