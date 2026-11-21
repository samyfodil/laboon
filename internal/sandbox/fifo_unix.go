//go:build darwin || linux

package sandbox

import (
	"os"
	"sync"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// fifo returns the rendezvous for a FIFO at resolved guest path gp, creating it
// once. It persists for the run and is reused (counts fall back to zero as ends
// close), so there is no entry teardown to race against.
func (fs *dfs) fifo(gp string) *fifoRv {
	fs.fifoMu.Lock()
	defer fs.fifoMu.Unlock()
	if fs.fifos == nil {
		fs.fifos = map[string]*fifoRv{}
	}
	rv := fs.fifos[gp]
	if rv == nil {
		rv = &fifoRv{}
		rv.cond = sync.NewCond(&rv.mu)
		fs.fifos[gp] = rv
	}
	return rv
}

// openFifo opens a FIFO through the rendezvous. rv.mu is held throughout: the
// backend opens below are non-blocking (the counts gate them so the peer is
// present), so nothing blocks here except the explicit interruptible waits,
// which release the lock. rv.mu is a leaf — taken only here and in drop — so
// holding it across the backend open and the install cannot invert with another
// lock. errRestart (a signal or teardown ended a wait) restarts the open or
// surfaces as EINTR, as a real FIFO open interrupted by a signal does.
func (g *dguest) openFifo(gp string, flags int64) int64 {
	acc := flags & lxOAccmod
	nonblock := flags&lxONonblock != 0
	rv := g.dfs.fifo(gp)
	rv.mu.Lock()

	if acc == lxOWronly {
		// Write-only needs a reader: block for one, or fail ENXIO if non-blocking.
		for rv.realReads == 0 {
			if nonblock {
				rv.mu.Unlock()
				return sErr(lxENXIO)
			}
			if !g.condWaitIntr(rv.cond) {
				rv.mu.Unlock()
				return sErr(errRestart)
			}
		}
	}

	of, e := g.openFifoHost(gp, flags)
	if e != 0 {
		rv.mu.Unlock()
		return sErr(e)
	}
	if acc != lxOWronly {
		rv.realReads++
	}
	if acc != lxORdonly {
		rv.realWrites++
		rv.writeGen++
	}
	rv.cond.Broadcast()

	// A blocking read-only open completes only once a writer has opened too, so
	// the first read waits for data instead of seeing the writerless FIFO as
	// end-of-file. writeGen counts a writer that already came and went, so a read
	// that raced one is not stranded.
	if acc == lxORdonly && !nonblock {
		gen := rv.writeGen
		for rv.realWrites == 0 && rv.writeGen == gen {
			if !g.condWaitIntr(rv.cond) {
				rv.realReads--
				rv.cond.Broadcast()
				rv.mu.Unlock()
				of.Close()
				return sErr(errRestart)
			}
		}
	}
	rv.mu.Unlock()
	return g.installD(&dfile{f: of, gp: gp, stub: -1, fifo: rv}, flags)
}

// openFifoHost opens the FIFO's backing node non-blocking, so the open never
// blocks while rv.mu is held (the counts ensure the peer is present, so the
// open returns at once). The host fd stays non-blocking; the guest keeps its
// own flag, and its blocking reads and writes block in the interruptible IO
// path (hostInterruptibleRead/Write poll the fd), not on the host open.
func (g *dguest) openFifoHost(gp string, flags int64) (*os.File, lxErrno) {
	hf := goOpenFlags(flags)&^(os.O_CREATE|os.O_EXCL|os.O_TRUNC) | hostfs.HostONonblock
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return nil, osErrno(err)
	}
	nf, err := loc.Node.Open(hf)
	if err != nil {
		return nil, osErrno(err)
	}
	of, ok := hostDupOf(nf, gp)
	nf.Close()
	if !ok {
		return nil, lxEINVAL
	}
	return of, 0
}
