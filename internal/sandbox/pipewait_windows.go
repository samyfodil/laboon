//go:build windows

package sandbox

import (
	"os"

	"golang.org/x/sys/windows"
)

// startIO is scoped to a serve loop, not a stub process: exec replaces the
// process handle, and a CLONE_VM child can die while its host process lives.
func (c *hostChan) startIO() (func(), error) {
	h, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	c.ioMu.Lock()
	c.ioDeath = h
	c.ioGone = make(chan struct{})
	if c.ioDead {
		close(c.ioGone)
		windows.SetEvent(h)
	}
	c.ioMu.Unlock()
	finish, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-c.done:
		case <-c.stop:
		case <-finish:
			return
		}
		c.endIO()
	}()
	return func() {
		close(finish)
		<-joined
		c.ioMu.Lock()
		c.ioDeath = 0
		windows.CloseHandle(h)
		c.ioMu.Unlock()
	}, nil
}

// endIO is idempotent; the stub-death watcher calls it through hostChan.end.
// ioMu also prevents SetEvent racing CloseHandle after the serve loop ends.
func (c *hostChan) endIO() {
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	if c.ioDead {
		return
	}
	c.ioDead = true
	if c.stopW != nil {
		close(c.stopW)
	}
	if c.ioGone != nil {
		close(c.ioGone)
	}
	if c.ioDeath != 0 {
		windows.SetEvent(c.ioDeath)
	}
}

func (t *sigThread) closeWake() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.wr >= 0 {
		windows.CloseHandle(windows.Handle(t.wr))
		t.wr = -1
	}
}

// hostWake returns a duplicate of this thread's signal wake event, reset
// first: a signal before the reset is seen by the caller's check of pending
// signals, which must follow; a later one leaves the event set. The duplicate
// pins the event's lifetime; the caller closes it.
func (g *dguest) hostWake() (windows.Handle, error) {
	t := g.sigs().thread(g.pid)
	if t == nil {
		return 0, os.ErrDeadlineExceeded
	}
	t.mu.Lock()
	if t.wr < 0 {
		h, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			t.mu.Unlock()
			return 0, err
		}
		t.wr = int(h)
	}
	var wake windows.Handle
	self := windows.CurrentProcess()
	err := windows.DuplicateHandle(self, windows.Handle(t.wr), self, &wake, 0, false, windows.DUPLICATE_SAME_ACCESS)
	if err == nil {
		err = windows.ResetEvent(wake)
	}
	t.mu.Unlock()
	if err != nil {
		if wake != 0 {
			windows.CloseHandle(wake)
		}
		return 0, err
	}
	return wake, nil
}
