//go:build windows

package sandbox

import (
	"os"
	"time"
)

// bufferPipe belongs to the supervisor, including across fork/exec and
// SCM_RIGHTS. n.mu protects the ring, endpoint counts and readiness stamps.
// No guest ever receives the placeholder NUL handles.
type bufferPipe struct {
	n                *dnet
	buf              []byte
	head, used       int
	readers, writers int
	wgen             uint64 // write ends ever opened, so a FIFO's read open that raced a writer is not stranded
	stamp            [2]uint64
}

func (g *dguest) pipeFiles() (*os.File, *os.File, pipeIO, error) {
	r, e := hostless("pipe:")
	if e != 0 {
		return nil, nil, nil, lxErr(e)
	}
	w, e := dupFile(r)
	if e != 0 {
		r.Close()
		return nil, nil, nil, lxErr(e)
	}
	p := &bufferPipe{n: g.netState(), buf: make([]byte, lxPipeDefSize), readers: 1, writers: 1}
	return r, w, p, nil
}

// touch is called under n.mu. Reads only change write readiness; writes only
// change read readiness. Separate stamps avoid spurious EPOLLET on drains.
func (p *bufferPipe) touch(end int) {
	p.n.seq++
	p.stamp[end] = p.n.seq
	p.n.notify()
}

func (p *bufferPipe) open(mode int64) {
	p.n.mu.Lock()
	defer p.n.mu.Unlock()
	if mode != lxOWronly {
		p.readers++
		p.touch(1)
	}
	if mode != lxORdonly {
		p.writers++
		p.wgen++
		p.touch(0)
	}
}

func (p *bufferPipe) close(mode int64) {
	p.n.mu.Lock()
	defer p.n.mu.Unlock()
	if mode != lxOWronly {
		p.readers--
		if p.readers == 0 {
			p.touch(1)
		}
	}
	if mode != lxORdonly {
		p.writers--
		if p.writers == 0 {
			p.touch(0)
		}
	}
}

func (p *bufferPipe) resize(size int32) lxErrno {
	p.n.mu.Lock()
	defer p.n.mu.Unlock()
	if int(size) < p.used {
		return lxEBUSY
	}
	b := make([]byte, size)
	k := copy(b, p.buf[p.head:min(p.head+p.used, len(p.buf))])
	copy(b[k:], p.buf[:p.used-k])
	p.buf, p.head = b, 0
	p.touch(1)
	return 0
}

func (p *bufferPipe) read(g *dguest, d *dfile, b []byte, nb, whole bool) (int, error) {
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
	p.n.mu.Lock()
	defer p.n.mu.Unlock()
	for p.used == 0 {
		if p.writers == 0 {
			return 0, nil
		}
		if nb {
			return 0, lxErr(lxEAGAIN)
		}
		if e := g.wait(p.n, time.Time{}); e != 0 {
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
	p.touch(1)
	return take, nil
}

func (p *bufferPipe) write(g *dguest, d *dfile, b []byte, nb bool) (int, error) {
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
	p.n.mu.Lock()
	defer p.n.mu.Unlock()
	for {
		if p.readers == 0 {
			return 0, lxErr(lxEPIPE) // stub raises SIGPIPE
		}
		room := len(p.buf) - p.used
		if room >= len(b) || len(b) > 4096 && room > 0 {
			take := min(room, len(b))
			tail := (p.head + p.used) % len(p.buf)
			k := copy(p.buf[tail:], b[:take])
			copy(p.buf, b[k:take])
			p.used += take
			p.touch(0)
			return take, nil // large writes may be partial; never restart these bytes
		}
		if nb {
			return 0, lxErr(lxEAGAIN)
		}
		if e := g.wait(p.n, time.Time{}); e != 0 {
			return 0, pipeWaitError(e)
		}
	}
}

func (p *bufferPipe) poll(mode int64) pollState {
	p.n.mu.Lock()
	defer p.n.mu.Unlock()
	var st pollState
	if mode != lxOWronly {
		st.stamp += p.stamp[0]
		if p.used > 0 || p.writers == 0 {
			st.mask |= pollInSet
		}
		if p.writers == 0 {
			st.mask |= lxPollHup
		}
	}
	if mode != lxORdonly {
		st.stamp += p.stamp[1]
		if p.used < len(p.buf) || p.readers == 0 {
			st.mask |= pollOutSet
		}
		if p.readers == 0 {
			st.mask |= lxPollErr
		}
	}
	return st
}

func (g *dguest) pollNote() pollNote {
	n := g.netState()
	return pollNote{notify: func() { n.mu.Lock(); n.notify(); n.mu.Unlock() }}
}
