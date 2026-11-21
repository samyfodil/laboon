//go:build darwin

package sandbox

import (
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// A guest pipe on darwin is the supervisor's, as on windows: a host pipe has
// no capacity the guest can set (F_SETPIPE_SZ), and its atomicity and
// readiness follow Darwin's buffer sizing, not Linux's. ringPipe holds the
// bytes. Its readiness is mirrored on two host pipes, as a terminal's is
// (tty_unix.go), so the host poll and kqueue behind a guest's wait see it: in
// holds bytes while the read end is readable or its writers are gone, out is
// filled while the write end has no room. A read end's description is a dup
// of in's read end, a write end's of out's write end.
type ringPipe struct {
	mu               sync.Mutex
	bus              chan struct{}
	buf              []byte
	head, used       int
	readers, writers int
	inR, inW         *os.File
	outR, outW       *os.File
	in, full         bool
	edges            int // bytes in inR: one more for each write, so each is an edge
}

// ringEdgeMax bounds the bytes in inR: past it, they are drained to one.
const ringEdgeMax = 512

func (g *dguest) pipeFiles() (*os.File, *os.File, pipeIO, error) {
	p := &ringPipe{bus: make(chan struct{}), buf: make([]byte, lxPipeDefSize), readers: 1, writers: 1}
	var err error
	if p.inR, p.inW, err = os.Pipe(); err == nil {
		p.outR, p.outW, err = os.Pipe()
	}
	if err != nil {
		p.free()
		return nil, nil, nil, err
	}
	r, e := p.file(lxORdonly)
	if e != 0 {
		p.free()
		return nil, nil, nil, lxErr(e)
	}
	w, e := p.file(lxOWronly)
	if e != 0 {
		r.Close()
		p.free()
		return nil, nil, nil, lxErr(e)
	}
	return r, w, p, nil
}

func (g *dguest) pollNote() pollNote { return pollNote{} }

// file is the host file behind a new description of the pipe opened mode.
func (p *ringPipe) file(mode int64) (*os.File, lxErrno) {
	src := p.inR
	if mode == lxOWronly {
		src = p.outW
	}
	fd, err := unix.Dup(hostFd(src))
	if err != nil {
		return nil, osErrno(err)
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "pipe:"), 0
}

func (p *ringPipe) free() {
	for _, f := range []*os.File{p.inR, p.inW, p.outR, p.outW} {
		if f != nil {
			f.Close()
		}
	}
}

// touch wakes the waiters and mirrors the readiness now; wrote is whether
// bytes went in, which is a new read edge. Called with p.mu held.
func (p *ringPipe) touch(wrote bool) {
	close(p.bus)
	p.bus = make(chan struct{})
	in := p.used > 0 || p.writers == 0
	full := p.used == len(p.buf) && p.readers > 0
	switch {
	case in && (!p.in || wrote):
		if p.edges >= ringEdgeMax {
			drainPipe(p.inR)
			p.edges = 0
		}
		if n, _ := p.inW.Write([]byte{1}); n == 1 {
			p.edges++
		}
	case !in && p.in:
		drainPipe(p.inR)
		p.edges = 0
	}
	p.in = in
	if full != p.full {
		if full {
			fillPipe(p.outW)
		} else {
			drainPipe(p.outR)
		}
		p.full = full
	}
}

func (p *ringPipe) wait(g *dguest) lxErrno {
	ch := p.bus
	p.mu.Unlock()
	e := g.waitOn(ch, time.Time{})
	p.mu.Lock()
	return e
}

func (p *ringPipe) open(mode int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if mode != lxOWronly {
		p.readers++
	}
	if mode != lxORdonly {
		p.writers++
	}
	p.touch(false)
}

func (p *ringPipe) close(mode int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if mode != lxOWronly {
		p.readers--
	}
	if mode != lxORdonly {
		p.writers--
	}
	if p.readers == 0 && p.writers == 0 {
		p.free()
		return
	}
	p.touch(false)
}

func (p *ringPipe) resize(size int32) lxErrno {
	p.mu.Lock()
	defer p.mu.Unlock()
	if int(size) < p.used {
		return lxEBUSY
	}
	b := make([]byte, size)
	k := copy(b, p.buf[p.head:min(p.head+p.used, len(p.buf))])
	copy(b[k:], p.buf[:p.used-k])
	p.buf, p.head = b, 0
	p.touch(false)
	return 0
}

func (p *ringPipe) read(g *dguest, d *dfile, b []byte, nb, whole bool) (int, error) {
	if !holdPipe(d) {
		return 0, lxErr(lxEBADF)
	}
	defer d.unref()
	if d.fx.oflags&lxOAccmod == lxOWronly {
		return 0, lxErr(lxEBADF)
	}
	if len(b) == 0 && !whole {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.used == 0 {
		if p.writers == 0 {
			return 0, nil
		}
		if nb {
			return 0, lxErr(lxEAGAIN)
		}
		if e := p.wait(g); e != 0 {
			return 0, pipeWaitError(e)
		}
	}
	if whole && p.used > len(b) {
		return 0, errFaultRead
	}
	take := min(len(b), p.used)
	k := copy(b[:take], p.buf[p.head:min(p.head+take, len(p.buf))])
	copy(b[k:take], p.buf[:take-k])
	p.head = (p.head + take) % len(p.buf)
	p.used -= take
	p.touch(false)
	return take, nil
}

// write takes all of b or, past PIPE_BUF, what fits, as Linux does; a write
// of PIPE_BUF or less waits for room for all of it.
func (p *ringPipe) write(g *dguest, d *dfile, b []byte, nb bool) (int, error) {
	if !holdPipe(d) {
		return 0, lxErr(lxEBADF)
	}
	defer d.unref()
	if d.fx.oflags&lxOAccmod == lxORdonly {
		return 0, lxErr(lxEBADF)
	}
	if len(b) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if p.readers == 0 {
			return 0, lxErr(lxEPIPE)
		}
		room := len(p.buf) - p.used
		if room >= len(b) || len(b) > lxPipeBuf && room > 0 {
			take := min(room, len(b))
			tail := (p.head + p.used) % len(p.buf)
			k := copy(p.buf[tail:], b[:take])
			copy(p.buf, b[k:take])
			p.used += take
			p.touch(true)
			return take, nil
		}
		if nb {
			return 0, lxErr(lxEAGAIN)
		}
		if e := p.wait(g); e != 0 {
			return 0, pipeWaitError(e)
		}
	}
}

func (p *ringPipe) poll(mode int64) pollState {
	p.mu.Lock()
	defer p.mu.Unlock()
	var st pollState
	if mode != lxOWronly {
		if p.used > 0 || p.writers == 0 {
			st.mask |= pollInSet
		}
		if p.writers == 0 {
			st.mask |= lxPollHup
		}
	}
	if mode != lxORdonly {
		if p.used < len(p.buf) || p.readers == 0 {
			st.mask |= pollOutSet
		}
		if p.readers == 0 {
			st.mask |= lxPollErr
		}
	}
	return st
}

func ringOf(d *dfile) (*ringPipe, bool) {
	if d.pipe == nil {
		return nil, false
	}
	p, ok := d.pipe.io.(*ringPipe)
	return p, ok
}

// ringPollState is a supervisor pipe end's poll mask.
func ringPollState(d *dfile) (pollState, bool) {
	p, ok := ringOf(d)
	if !ok {
		return pollState{}, false
	}
	return p.poll(d.fx.oflags & lxOAccmod), true
}

// ringFds are the host fds whose readiness mirrors a supervisor pipe end's.
func ringFds(d *dfile) (rfd, wfd int, ok bool) {
	p, ok := ringOf(d)
	if !ok {
		return 0, 0, false
	}
	fd := hostFd(d.f)
	if d.fx.oflags&lxOAccmod == lxORdwr {
		return fd, hostFd(p.outW), true
	}
	return fd, fd, true
}

// ringQueued is what a supervisor pipe holds (FIONREAD).
func ringQueued(d *dfile) (int, bool) {
	p, ok := ringOf(d)
	if !ok {
		return 0, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.used, true
}
