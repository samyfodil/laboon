package sandbox

import "sync"

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
