package sandbox

import (
	"io"
	"os"
	"sync"
)

// stdinFeed copies a stdin reader that is not a file into the pipe the guest
// reads as its fd 0. A Read on an arbitrary io.Reader cannot be interrupted,
// and whatever it returns once the run is over is lost to the caller, so the
// feed reads only when the guest asks: one Read of at most the guest's count
// for each read(2) of fd 0 that waits on the pipe. Any other use of the
// description (poll, epoll, splice, an ioctl, ...) turns it into a plain
// copier that streams the reader into the pipe, since those can wait on the
// pipe without saying how much they want. When the run ends the feed stops
// and closes its end of the pipe; only a Read the guest asked for and was
// still waiting on can be left outstanding, and what it returns is dropped.
type stdinFeed struct {
	r                  io.Reader
	in                 *os.File // the pipe's read end, the guest's stdin
	w                  *os.File // its write end
	mu                 sync.Mutex
	cond               sync.Cond
	asks               int // reads waiting for the feed to make one Read each
	size               int // at most this much per Read while not streaming
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
		for !f.stopped && !f.streaming && f.asks == 0 {
			f.cond.Wait()
		}
		if f.stopped {
			f.mu.Unlock()
			return
		}
		n := len(buf)
		if !f.streaming {
			f.asks--
			n = min(n, f.size)
		}
		f.reading = true
		f.mu.Unlock()
		m, err := f.r.Read(buf[:n])
		f.mu.Lock()
		f.reading = false
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

// want is a read of up to n bytes about to wait on the pipe.
func (f *stdinFeed) want(n int) {
	f.mu.Lock()
	f.asks++
	f.size = n
	f.mu.Unlock()
	f.cond.Broadcast()
}

// done ends a read that asked with want: one that got nothing (EAGAIN, a
// signal) takes back its ask if the feed has not acted on it yet.
func (f *stdinFeed) done(got bool) {
	if got {
		return
	}
	f.mu.Lock()
	if f.asks > 0 {
		f.asks--
	}
	f.mu.Unlock()
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
