//go:build windows

package sandbox

import (
	"bytes"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Host pipe ends on Windows: the caller's stdio, or the pipes laboon copies a
// non-file stdio through. The guest sees each as a pipe whose transport is its
// pipeEnd, and its description's file is a placeholder, so nothing but the
// pipeEnd ever does I/O on the host handle. The handle is synchronous and
// someone else's: a request on its file object waits for any other in flight,
// so a stray query behind a pending read or write would hang, and the handle
// cannot be made overlapped.
//
// Reads. A zero-byte ReadFile, which consumes nothing and reserves no quota,
// waits for data or end of file on a thread of the end's own (the watcher),
// only while someone waits for data. A reader reads only what the pipe then
// holds, so its read never waits in the kernel.
//
// Writes. The pipe's free space is not observable: a read the reader has
// pending counts against the writer's quota, so an empty pipe whose reader
// waits with a buffer as large as the pipe reports no room at all. A write
// that does not visibly fit is issued as a blocking WriteFile on a helper
// thread, and a signal or the writer's death cancels it. That is exact for a
// chunk no larger than the pipe's buffer: the pipe takes the whole chunk into
// its queue and holds the request only until enough of the data ahead of it is
// read, before any of the chunk can be, so a cancel delivers none of it and a
// completion all of it. A larger write's cancel would lose the count of what
// was already read. A non-blocking write that does not visibly fit is accepted
// and finishes in the background, and the end's next writes wait for it:
// POLLOUT is set exactly when no write is in flight, EAGAIN comes exactly
// when one is, and the run's end waits for what was accepted.
//
// A second synchronous request on the same file object waits in the I/O
// manager where no cancel reaches, so the end's requests take its lock first,
// in a wait a signal ends. cmd's 2>&1 gives stdout and stderr one object under
// two handles; CompareObjectHandles finds it, so they share an end.

var (
	procCancelSynchronousIo  = modKernel32.NewProc("CancelSynchronousIo")
	procCompareObjectHandles = windows.NewLazySystemDLL("kernelbase.dll").NewProc("CompareObjectHandles")
)

// pipeBuf is Linux's PIPE_BUF: a write of up to this many bytes is not split.
const pipeBuf = 4096

// pipeEnd is one host pipe end, shared by the descriptions of every run that
// uses it. Lock order: pipeEnd.mu, then dnet.mu.
type pipeEnd struct {
	h    windows.Handle // a duplicate, which also names the end
	out  bool           // the end the guest writes
	lock windows.Handle // auto-reset event, set while no request of ours is in flight
	size int            // the end's buffer: the largest chunk a cancel is exact for
	refs int            // descriptions and requests holding it, under pipeEnds.mu

	mu       sync.Mutex
	cond     *sync.Cond     // the watcher waits here to be armed or closed
	busy     bool           // write end: a write is in flight
	ready    bool           // read end: data or end of file is there
	eof      bool           // read end: every writer is gone
	armed    bool           // read end: someone waits for data
	watching bool           // read end: the watcher's zero-byte read is in flight
	peeking  int            // FIONREAD peeks in flight: the watcher is not armed meanwhile
	closing  bool           // the last reference is gone
	handed   bool           // shutdown left closing the end to the watcher's read in flight
	started  bool           // the watcher's goroutine has started
	stopped  bool           // and has ended
	watchTh  windows.Handle // the watcher's thread, which a cancel names
	data     windows.Handle // read end: manual-reset, set while ready
	stamp    uint64
	buses    map[*dnet]struct{} // the runs that polled it, woken on a change
	bg       sync.WaitGroup     // background writes in flight
}

var pipeEnds struct {
	mu   sync.Mutex
	ends []*pipeEnd
}

// hostPipeFile is the guest's description of the run's stdio file h when it
// is a pipe, or nil: a pipe whose transport is its end's pipeEnd. It runs as
// the run's stdio is set up, before any request of ours could leave the file
// object busy, since the query here would wait for it.
func hostPipeFile(h windows.Handle, write bool) *dfile {
	if t, _ := windows.GetFileType(h); t != windows.FILE_TYPE_PIPE {
		return nil
	}
	p := openPipeEnd(h, write)
	if p == nil {
		return nil
	}
	ph, e := hostless("pipe:")
	if e != 0 {
		p.release()
		return nil
	}
	po := &pipeObj{io: p}
	d := &dfile{f: ph, gp: "pipe:", stub: -1, pipe: po}
	d.fx.oflags, d.fx.hasFlags = lxORdonly, true
	po.ends[0] = d
	if write {
		d.fx.oflags = lxOWronly
		po.ends = [2]*dfile{nil, d}
	}
	return d
}

func openPipeEnd(h windows.Handle, write bool) *pipeEnd {
	pipeEnds.mu.Lock()
	defer pipeEnds.mu.Unlock()
	for _, p := range pipeEnds.ends {
		if p.out == write && sameObject(p.h, h) {
			p.refs++
			return p
		}
	}
	var info pipeLocalInfo
	var iosb windows.IO_STATUS_BLOCK
	if windows.NtQueryInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), filePipeLocalInformation) != nil {
		return nil
	}
	size := info.inboundQuota // a client end writes to the server's inbound queue
	if info.end == filePipeServerEnd {
		size = info.outboundQuota
	}
	p := &pipeEnd{out: write, size: max(int(size), 1), refs: 1, buses: map[*dnet]struct{}{}}
	p.cond = sync.NewCond(&p.mu)
	self := windows.CurrentProcess()
	if windows.DuplicateHandle(self, h, self, &p.h, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return nil
	}
	var err error
	if p.lock, err = windows.CreateEvent(nil, 0, 1, nil); err == nil {
		p.data, err = windows.CreateEvent(nil, 1, 0, nil)
	}
	if err != nil {
		p.closeHandles()
		return nil
	}
	pipeEnds.ends = append(pipeEnds.ends, p)
	return p
}

func sameObject(a, b windows.Handle) bool {
	if procCompareObjectHandles.Find() != nil {
		return a == b
	}
	r, _, _ := procCompareObjectHandles.Call(uintptr(a), uintptr(b))
	return r != 0
}

func (p *pipeEnd) hold() {
	pipeEnds.mu.Lock()
	p.refs++
	pipeEnds.mu.Unlock()
}

func (p *pipeEnd) release() {
	pipeEnds.mu.Lock()
	p.refs--
	last := p.refs == 0
	if last {
		for i, q := range pipeEnds.ends {
			if q == p {
				pipeEnds.ends = append(pipeEnds.ends[:i], pipeEnds.ends[i+1:]...)
				break
			}
		}
	}
	pipeEnds.mu.Unlock()
	if last {
		p.shutdown()
	}
}

// shutdown stops the watcher and closes the end. A watcher read in flight is
// cancelled and left to close the end as it returns: no cancel reaches a read
// still waiting behind another process's request on the file object (a shell
// reading the stdin it shares with us), so nothing can wait for it to leave.
func (p *pipeEnd) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closing = true
	p.cond.Broadcast()
	for p.started && !p.stopped && !p.watching {
		p.cond.Wait()
	}
	if p.started && !p.stopped {
		p.handed = true
		procCancelSynchronousIo.Call(uintptr(p.watchTh)) // under p.mu: the watcher closes its thread handle only with it held
		return
	}
	p.closeHandles()
}

func (p *pipeEnd) closeHandles() {
	for _, h := range []windows.Handle{p.h, p.lock, p.data} {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}
}

// changed marks a readiness change and wakes the runs that polled the end.
// p.mu is held.
func (p *pipeEnd) changed() {
	p.stamp++
	for n := range p.buses {
		n.mu.Lock()
		n.notify()
		n.mu.Unlock()
	}
}

// arm starts the watcher's wait for data, unless data is there. p.mu is held.
func (p *pipeEnd) arm() {
	if p.ready || p.armed || p.closing {
		return
	}
	p.armed = true
	if !p.started {
		p.started = true
		go p.watcher()
		return
	}
	p.cond.Broadcast()
}

// watcher waits for data on the read end with zero-byte reads while armed.
func (p *pipeEnd) watcher() {
	// Never unlocked: the thread ends with this goroutine, so no cancel meant
	// for the watcher reaches another goroutine's I/O.
	runtime.LockOSThread()
	var th windows.Handle
	self := windows.CurrentProcess()
	err := windows.DuplicateHandle(self, windows.CurrentThread(), self, &th, 0, false, windows.DUPLICATE_SAME_ACCESS)
	p.mu.Lock()
	defer func() {
		if th != 0 {
			windows.CloseHandle(th)
		}
		if p.handed {
			p.closeHandles()
		}
		p.stopped = true
		p.cond.Broadcast()
		p.mu.Unlock()
	}()
	if err != nil {
		p.ready, p.eof = true, true // a wait no one could end: report end of file
		windows.SetEvent(p.data)
		p.changed()
		return
	}
	p.watchTh = th
	for {
		for (!p.armed || p.peeking > 0) && !p.closing {
			p.cond.Wait()
		}
		if p.closing {
			return
		}
		p.watching = true
		p.mu.Unlock()
		var n uint32
		err := windows.ReadFile(p.h, nil, &n, nil)
		p.mu.Lock()
		p.watching = false
		if p.closing {
			return
		}
		if err == windows.ERROR_OPERATION_ABORTED {
			continue
		}
		p.armed = false
		p.ready, p.eof = true, err != nil
		windows.SetEvent(p.data)
		p.changed()
	}
}

// acquire takes the end's lock: at once or not at all when nonblocking, else
// waiting until a signal or the writer's death.
func (p *pipeEnd) acquire(g *dguest, wake windows.Handle, nb bool) bool {
	if nb {
		e, _ := windows.WaitForSingleObject(p.lock, 0)
		return e == windows.WAIT_OBJECT_0
	}
	ev, err := windows.WaitForMultipleObjects([]windows.Handle{p.lock, wake, g.ch.ioDeath, g.ch.proc}, false, windows.INFINITE)
	return err == nil && ev == windows.WAIT_OBJECT_0
}

func (p *pipeEnd) peek() (uint32, error) {
	var avail uint32
	if r, _, err := procPeekNamedPipe.Call(uintptr(p.h), 0, 0, 0, uintptr(unsafe.Pointer(&avail)), 0); r == 0 {
		return 0, err
	}
	return avail, nil
}

func (p *pipeEnd) read(g *dguest, d *dfile, b []byte, nb, whole bool) (int, error) {
	if !holdPipe(d) {
		return 0, lxErr(lxEBADF)
	}
	defer d.unref()
	if p.out || d.fx.oflags&lxOAccmod == lxOWronly {
		return 0, lxErr(lxEBADF)
	}
	if len(b) == 0 && !whole {
		return 0, nil
	}
	var wake windows.Handle
	if !nb {
		w, err := g.hostWake()
		if err != nil {
			return 0, err
		}
		defer windows.CloseHandle(w)
		if g.sigIntr() || g.ch.dead() {
			return 0, errSigIntr
		}
		wake = w
	}
	if !p.acquire(g, wake, nb) {
		if nb {
			return 0, lxErr(lxEAGAIN) // another reader waits: the pipe is empty
		}
		return 0, errSigIntr
	}
	defer windows.SetEvent(p.lock)
	for {
		p.mu.Lock()
		if !p.ready {
			p.arm()
			p.mu.Unlock()
			if nb {
				return 0, lxErr(lxEAGAIN)
			}
			ev, err := windows.WaitForMultipleObjects([]windows.Handle{p.data, wake, g.ch.ioDeath, g.ch.proc}, false, windows.INFINITE)
			if err != nil {
				return 0, err
			}
			if ev != windows.WAIT_OBJECT_0 {
				return 0, errSigIntr
			}
			continue
		}
		eof := p.eof
		p.mu.Unlock()
		// Ready: the watcher's read is over and none is armed, so these
		// requests do not wait.
		avail, err := p.peek()
		if err != nil || eof && avail == 0 {
			p.mu.Lock()
			p.eof = true // a broken pipe: what is left is end of file
			p.mu.Unlock()
			return 0, nil
		}
		if avail == 0 { // another process read it: wait again
			p.mu.Lock()
			p.ready = false
			windows.ResetEvent(p.data)
			p.mu.Unlock()
			continue
		}
		if whole && int(avail) > len(b) {
			return 0, errFaultRead
		}
		var n uint32
		rerr := windows.ReadFile(p.h, b[:min(len(b), int(avail))], &n, nil)
		left, perr := p.peek()
		p.mu.Lock()
		switch {
		case perr != nil:
			p.eof = true
		case left == 0 && !p.eof:
			p.ready = false
			windows.ResetEvent(p.data)
		}
		p.mu.Unlock()
		if n == 0 && rerr != nil {
			if rerr == windows.ERROR_BROKEN_PIPE {
				return 0, nil
			}
			return 0, &os.PathError{Op: "read", Path: "pipe", Err: rerr}
		}
		return int(n), nil
	}
}

// room is the write quota left, which pending reads only undercount (a write
// of at most room bytes completes at once), and whether the reader is there.
func (p *pipeEnd) room() (int, bool) {
	var info pipeLocalInfo
	var iosb windows.IO_STATUS_BLOCK
	if windows.NtQueryInformationFile(p.h, &iosb, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), filePipeLocalInformation) != nil {
		return 0, true
	}
	return int(info.writeQuotaAvailable), info.state == filePipeConnectedState
}

func (p *pipeEnd) setBusy(busy bool) {
	p.mu.Lock()
	p.busy = busy
	if !busy {
		p.changed()
	}
	p.mu.Unlock()
}

// write writes b as a write to a Linux pipe does: blocking, all of it, in one
// piece if it is at most pipeBuf bytes, unless a signal or the writer's death
// ends the wait (then what was written, or errSigIntr).
func (p *pipeEnd) write(g *dguest, d *dfile, b []byte, nb bool) (int, error) {
	if !holdPipe(d) {
		return 0, lxErr(lxEBADF)
	}
	defer d.unref()
	if !p.out || d.fx.oflags&lxOAccmod == lxORdonly {
		return 0, lxErr(lxEBADF)
	}
	if len(b) == 0 {
		return 0, nil
	}
	if nb {
		return p.writeNonblock(b)
	}
	wake, err := g.hostWake()
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(wake)
	if g.sigIntr() || g.ch.dead() {
		return 0, errSigIntr
	}
	if !p.acquire(g, wake, false) {
		return 0, errSigIntr
	}
	p.setBusy(true)
	defer windows.SetEvent(p.lock)
	defer p.setBusy(false)
	n := 0
	for n < len(b) {
		c := b[n:min(len(b), n+p.size)]
		room, open := p.room()
		var m int
		switch {
		case !open || room >= len(c):
			m, err = pipeWrite(p.h, c) // a reader gone fails at once
		case room > 0 && len(b) > pipeBuf:
			m, err = pipeWrite(p.h, c[:room])
		default:
			m, err = g.pipeWriteWait(p, c, wake)
		}
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// writeNonblock writes what fits at once, or accepts a chunk to finish in the
// background, or fails with EAGAIN while a write is in flight.
func (p *pipeEnd) writeNonblock(b []byte) (int, error) {
	if e, _ := windows.WaitForSingleObject(p.lock, 0); e != windows.WAIT_OBJECT_0 {
		return 0, lxErr(lxEAGAIN)
	}
	c := b[:min(len(b), p.size)]
	room, open := p.room()
	if !open || room >= len(c) || room > 0 && len(b) > pipeBuf {
		if open && room < len(c) {
			c = c[:room]
		}
		n, err := pipeWrite(p.h, c)
		windows.SetEvent(p.lock)
		return n, err
	}
	data := bytes.Clone(c)
	p.setBusy(true)
	p.hold()
	p.bg.Add(1)
	go func() {
		pipeWrite(p.h, data) // accepted already: a reader gone is the next write's EPIPE
		p.setBusy(false)
		windows.SetEvent(p.lock)
		p.bg.Done()
		p.release()
	}()
	return len(c), nil
}

func pipeWrite(h windows.Handle, b []byte) (int, error) {
	var n uint32
	if err := windows.WriteFile(h, b, &n, nil); err != nil {
		return int(n), &os.PathError{Op: "write", Path: "pipe", Err: err}
	}
	return int(n), nil
}

// pipeWriteWait writes c, at most the pipe's buffer, on a helper thread, and
// cancels the write if a signal or the writer's death comes first.
func (g *dguest) pipeWriteWait(p *pipeEnd, c []byte, wake windows.Handle) (int, error) {
	type result struct {
		n   int
		err error
	}
	done, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(done)
	thread := make(chan windows.Handle, 1)
	res := make(chan result, 1)
	free := make(chan struct{})
	go func() {
		// The thread is this write's alone until the canceller is done with
		// it: a late cancel must not reach another goroutine's I/O.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var h windows.Handle
		self := windows.CurrentProcess()
		if err := windows.DuplicateHandle(self, windows.CurrentThread(), self, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			thread <- 0
			res <- result{0, err}
			return
		}
		thread <- h
		n, err := pipeWrite(p.h, c)
		res <- result{n, err}
		windows.SetEvent(done)
		<-free
	}()
	th := <-thread
	if th == 0 {
		return 0, (<-res).err
	}
	defer windows.CloseHandle(th)
	defer close(free)
	ev, err := windows.WaitForMultipleObjects([]windows.Handle{done, wake, g.ch.ioDeath, g.ch.proc}, false, windows.INFINITE)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		// Cancel until the write is cancelled or done. Before the helper's
		// request is pending a cancel finds nothing; it is retried, not timed.
		for {
			if r, _, _ := procCancelSynchronousIo.Call(uintptr(th)); r != 0 {
				break
			}
			if e, _ := windows.WaitForSingleObject(done, 0); e == windows.WAIT_OBJECT_0 {
				break
			}
			runtime.Gosched()
		}
	}
	r := <-res
	if err != nil {
		return r.n, err
	}
	if ev != windows.WAIT_OBJECT_0 {
		return r.n, errSigIntr
	}
	return r.n, r.err
}

func (p *pipeEnd) open(int64)  { p.hold() }
func (p *pipeEnd) close(int64) { p.release() }

// resize keeps the host pipe's capacity, which laboon cannot change.
func (p *pipeEnd) resize(int32) lxErrno { return 0 }

// poll is the end's readiness, arming the watcher when there is no data yet.
func (p *pipeEnd) poll(n *dnet) pollState {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buses[n] = struct{}{}
	st := pollState{stamp: p.stamp}
	switch {
	case p.out:
		if !p.busy {
			st.mask = pollOutSet
		}
	case p.ready:
		st.mask = pollInSet
		if p.eof {
			st.mask |= lxPollHup
		}
	default:
		p.arm()
	}
	return st
}

// avail is FIONREAD: what a read end holds.
func (p *pipeEnd) avail() int {
	p.mu.Lock()
	if p.out || !p.ready {
		p.mu.Unlock()
		return 0 // nothing there, and the watcher may be waiting: no request
	}
	p.peeking++
	p.mu.Unlock()
	a, _ := p.peek()
	p.mu.Lock()
	if p.peeking--; p.peeking == 0 {
		p.cond.Broadcast()
	}
	p.mu.Unlock()
	return int(a)
}

// flushPipeEnds waits for the background writes to the ends of the run's
// stdio files: what a guest wrote stays written after it is gone.
func flushPipeEnds(files []*os.File) {
	for _, f := range files {
		if f == nil {
			continue
		}
		var wait []*pipeEnd
		pipeEnds.mu.Lock()
		for _, p := range pipeEnds.ends {
			if p.out && sameObject(p.h, windows.Handle(f.Fd())) {
				wait = append(wait, p)
			}
		}
		pipeEnds.mu.Unlock()
		for _, p := range wait {
			p.bg.Wait()
		}
	}
}

// forgetPipeBus stops waking run n's waiters on pipe end changes.
func forgetPipeBus(n *dnet) {
	pipeEnds.mu.Lock()
	ends := append([]*pipeEnd(nil), pipeEnds.ends...)
	pipeEnds.mu.Unlock()
	for _, p := range ends {
		p.mu.Lock()
		delete(p.buses, n)
		p.mu.Unlock()
	}
}

// pipeLocalInfo is FILE_PIPE_LOCAL_INFORMATION.
type pipeLocalInfo struct {
	pipeType, configuration, maxInstances, curInstances uint32
	inboundQuota, readDataAvailable                     uint32
	outboundQuota, writeQuotaAvailable                  uint32
	state, end                                          uint32
}

const (
	filePipeLocalInformation = 24
	filePipeConnectedState   = 3
	filePipeServerEnd        = 1
)
