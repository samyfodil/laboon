//go:build darwin || linux || windows

package sandbox

import (
	"os"
	"sync"

	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// FIFOs (named pipes) block on open the way the kernel does: a read-only open
// waits for a writer, a write-only open waits for a reader. Doing that wait as
// a blocking host open() would park it on the serve goroutine where nothing can
// reach it — a guest signal cannot interrupt it and teardown cannot cancel it,
// so the run wedges (CoreCLR's debug pipe does exactly this). laboon instead
// runs the rendezvous here, against a per-run table keyed by the FIFO's path,
// waiting with condWaitIntr so a signal or teardown ends it. Each end then opens
// the real backend node non-blocking — which succeeds at once, the peer being
// present — and all data flows through that node with its own end-of-file and
// SIGPIPE behaviour, so the vfs still owns the pipe.
//
// Only the run's own guest opens count toward the rendezvous. A FIFO shared with
// a process outside the sandbox (e.g. a bind-mounted one the host also opens)
// will not match that outside end; such cross-sandbox FIFO sharing is not
// supported.
type fifoRv struct {
	mu         sync.Mutex
	cond       *sync.Cond
	realReads  int // read ends currently open on the backend
	realWrites int // write ends currently open on the backend
	writeGen   int // write ends ever opened; a writer that opens and closes still counts, so a read open that raced it is not stranded
}

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
	if !hostfs.FifoRendezvous {
		return g.openFifoDirect(gp, flags)
	}
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
	of, ok := hostOf(nf)
	if !ok {
		nf.Close()
		return nil, lxEINVAL
	}
	return of, 0
}

// openFifoDirect opens a FIFO node straight through the backend, with no
// rendezvous. It is the path for a backend without real FIFOs (Windows), where
// a named-pipe node is metadata only and carries no pipe semantics to wait on.
func (g *dguest) openFifoDirect(gp string, flags int64) int64 {
	hf := goOpenFlags(flags) &^ (os.O_CREATE | os.O_EXCL | os.O_TRUNC)
	if flags&lxONonblock != 0 {
		hf |= hostfs.HostONonblock
	}
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return sErr(osErrno(err))
	}
	nf, err := loc.Node.Open(hf)
	if err != nil {
		return sErr(osErrno(err))
	}
	of, ok := hostOf(nf)
	if !ok {
		nf.Close()
		return sErr(lxEINVAL)
	}
	return g.installD(&dfile{f: of, gp: gp, stub: -1}, flags)
}

// drop releases a closed description's ends, so a reader sees end-of-file once
// the writers are gone and a peer that opens later rendezvouses afresh.
func (rv *fifoRv) drop(acc int64) {
	rv.mu.Lock()
	if acc != lxOWronly {
		rv.realReads--
	}
	if acc != lxORdonly {
		rv.realWrites--
	}
	rv.cond.Broadcast()
	rv.mu.Unlock()
}
