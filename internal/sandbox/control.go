//go:build darwin || linux || windows

package sandbox

import (
	"os"
	"sync"
	"syscall"
)

// Control is a handle to a running guest: its host leader pid and a way to
// deliver a signal to the guest's init process. Run publishes it once the guest
// is up and revokes it as the run tears down, so a Signal that races the end of
// the run is a safe no-op (ESRCH), never a use of freed state. The zero value is
// ready; pass a *Control in Config.Control to receive the handle.
type Control struct {
	mu    sync.Mutex
	pid   int                 // the leader the run ended with
	pidOf func() int          // the leader now, while the run is up
	send  func(sig int) error // nil until the guest starts and once it ends
}

func (c *Control) publish(pidOf func() int, send func(int) error) {
	c.mu.Lock()
	c.pidOf, c.send = pidOf, send
	c.mu.Unlock()
}

func (c *Control) revoke() {
	c.mu.Lock()
	if c.pidOf != nil {
		c.pid, c.pidOf = c.pidOf(), nil
	}
	c.send = nil
	c.mu.Unlock()
}

// Pid is the host process-group leader of the run, or 0 before it starts. It is
// a host pid (the stub process), the one `ps` shows, not the guest's own pid 1.
func (c *Control) Pid() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pidOf != nil {
		return c.pidOf()
	}
	return c.pid
}

// Signal delivers sig to the guest's init process (pid 1) as a real signal the
// guest can handle, so SIGTERM asks it to shut down (unlike a context cancel,
// which SIGKILLs the run). It returns ESRCH before the run starts or after it
// ends and EINVAL for a signal it cannot map to the guest's Linux ABI; a nil or
// zero signal reports only whether the guest is still live.
func (c *Control) Signal(sig os.Signal) error {
	if c == nil {
		return syscall.ESRCH
	}
	n, err := linuxSignal(sig)
	if err != nil {
		return err
	}
	// The lock spans the delivery so a concurrent revoke (teardown) waits for an
	// in-flight Signal before it frees the signal subsystem, and a Signal that
	// arrives after revoke sees send == nil.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.send == nil {
		return syscall.ESRCH
	}
	return c.send(n)
}

// signalGuest1 queues sig to the guest's init process through the signal
// subsystem, as a signal the guest can handle. It reports ESRCH if pid 1 is
// already gone; a zero signal only checks that it is live.
func (fs *dfs) signalGuest1(sig int) error {
	sr := fs.sigs()
	if sr == nil {
		return syscall.ESRCH
	}
	p := sr.proc(1)
	if p == nil {
		return syscall.ESRCH
	}
	if sig != 0 {
		sr.send(p, nil, sig, sigInfo{code: siKernel}, nil)
	}
	return nil
}

// publishControl and revokeControl wire a run's Control, if the caller passed
// one, so each Run adds only a one-line call. pidOf reports the run's host
// leader.
func publishControl(cfg Config, pidOf func() int, fs *dfs) {
	if cfg.Control != nil {
		cfg.Control.publish(pidOf, fs.signalGuest1)
	}
}

// initOspid is the host process the guest's init runs in now: an exec into a
// new stub moves it.
func (fs *dfs) initOspid() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if ps := fs.pt[1]; ps != nil {
		return ps.ospid
	}
	return 0
}

func revokeControl(cfg Config) {
	if cfg.Control != nil {
		cfg.Control.revoke()
	}
}
