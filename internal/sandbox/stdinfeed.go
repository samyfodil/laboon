package sandbox

import (
	"io"
	"os"
	"slices"
	"sync"
)

// stdinFeed copies a stdin reader that is not a file into the pipe the guest
// reads as its fd 0. A Read on an arbitrary io.Reader cannot be interrupted,
// and whatever it returns once the run is over is lost to the caller, so the
// feed reads only when the guest asks: while a read(2) of fd 0 waits on the
// pipe and the pipe is empty, it makes one Read of at most the smallest count
// a waiting read asked for. Any use of the description that can wait on the
// pipe without saying how much it wants (poll, epoll, splice, ...) turns it
// into a plain copier that streams the reader into the pipe. When the run
// ends the feed stops and closes its end of the pipe; only a Read the guest
// asked for and was still waiting on can be left outstanding, and what it
// returns is dropped.
type stdinFeed struct {
	r                  io.Reader
	in                 *os.File // the pipe's read end, the guest's stdin
	w                  *os.File // its write end
	mu                 sync.Mutex
	cond               sync.Cond
	waits              []int // the counts of the reads waiting on the pipe
	changed            bool  // a read began or ended, or a Read gave nothing, since the feed last looked
	streaming, stopped bool
	reading            bool // in a Read of r
	exited             chan struct{}
}

// newStdinFeed feeds r to the pipe pr, pw.
func newStdinFeed(r io.Reader, pr, pw *os.File) *stdinFeed {
	f := &stdinFeed{r: r, in: pr, w: pw, exited: make(chan struct{})}
	f.cond.L = &f.mu
	go f.copy()
	return f
}

func (f *stdinFeed) copy() {
	defer close(f.exited)
	defer f.w.Close()
	buf := make([]byte, 32<<10)
	for {
		f.mu.Lock()
		n := f.next(len(buf))
		if n == 0 {
			f.mu.Unlock()
			return
		}
		f.reading = true
		f.mu.Unlock()
		m, err := f.r.Read(buf[:n])
		f.mu.Lock()
		f.reading = false
		f.changed = f.changed || m == 0 && err == nil
		stopped := f.stopped
		f.mu.Unlock()
		if stopped {
			return
		}
		if m > 0 {
			if _, werr := f.w.Write(buf[:m]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// next waits, with f.mu held, until the feed should Read, and returns how
// much, at most limit; 0 once it is stopped. Without streaming it reads only
// when a read waits on an empty pipe, and looks again only once a read began
// or ended: a read that took everything leaves the others still waiting.
func (f *stdinFeed) next(limit int) int {
	for !f.stopped {
		if f.streaming {
			return limit
		}
		if f.changed && len(f.waits) > 0 {
			f.changed = false
			if held, err := pipeHeld(f.in); err == nil && held == 0 {
				return min(limit, slices.Min(f.waits))
			}
		}
		f.cond.Wait()
	}
	return 0
}

// want is a read of up to n bytes about to wait on the pipe.
func (f *stdinFeed) want(n int) {
	f.mu.Lock()
	f.waits = append(f.waits, n)
	f.changed = true
	f.mu.Unlock()
	f.cond.Broadcast()
}

// done ends a read that asked with want(n).
func (f *stdinFeed) done(n int) {
	f.mu.Lock()
	if i := slices.Index(f.waits, n); i >= 0 {
		f.waits = slices.Delete(f.waits, i, i+1)
	}
	f.changed = true
	f.mu.Unlock()
	f.cond.Broadcast()
}

// held is how much of what the feed copied the pipe still holds.
func (f *stdinFeed) held() int {
	n, err := pipeHeld(f.in)
	if err != nil {
		return 0
	}
	return n
}

// stream makes the feed copy the reader into the pipe from now on.
func (f *stdinFeed) stream() {
	f.mu.Lock()
	if !f.streaming {
		f.streaming = true
		f.cond.Broadcast()
	}
	f.mu.Unlock()
}

// stop ends the feed with the run and closes its end of the pipe. Unless it
// is in a Read, which nothing can interrupt, the copier is gone when stop
// returns; one in a Read ends as that Read returns.
func (f *stdinFeed) stop() {
	f.mu.Lock()
	f.stopped = true
	reading := f.reading
	f.mu.Unlock()
	f.cond.Broadcast()
	f.w.Close()
	if !reading {
		<-f.exited
	}
}
