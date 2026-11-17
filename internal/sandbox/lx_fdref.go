//go:build darwin || linux || windows

package sandbox

import "sync"

// unref drops one reference to the open-file description and closes its host
// resources with the last one.
func (d *dfile) unref() {
	if d.refs.Add(-1) != 0 {
		return
	}
	d.epollRelease()
	if d.pipe != nil && d.pipe.io != nil {
		d.pipe.io.close(d.fx.oflags & lxOAccmod)
	}
	if d.fifo != nil {
		d.fifo.drop(d.fx.oflags & lxOAccmod)
	}
	stubFiles.closed(d)
	d.releaseFx()
	if d.f != nil {
		d.f.Close()
	}
	if d.mem != nil && d.mem.vf != nil {
		d.mem.vf.Close() // an in-memory backend file's content handle (tmpfs, WithFS)
	}
	if d.pathFD != nil {
		d.pathFD.Close()
	}
	if d.ev != nil {
		d.ev.w.Close()
	}
	if d.ep != nil {
		d.ep.close()
	}
	if d.tfd != nil {
		d.tfd.close()
	}
	if d.pty != nil {
		d.pty.close()
	}
	if d.sk != nil {
		d.sk.close()
	}
	if d.sf != nil {
		d.sf.close()
	}
}

func (g *dguest) ioctl(fd int64, req, arg uint64) int64 {
	d, ok := g.ft.get(int(fd))
	if !ok {
		return sErr(lxEBADF)
	}
	switch req {
	case lxFionbio:
		b, err := g.readMem(arg, 4)
		if err != nil {
			return sErr(lxEFAULT)
		}
		d.nonblock.Store(le32(b) != 0)
		if d.stub >= 0 {
			syncStdio()
		}
		return 0
	case lxFioclex, lxFionclex:
		g.ft.setCloexec(int(fd), req == lxFioclex)
		return 0
	case lxFioasync:
		// O_ASYNC, as F_SETFL sets it.
		b, err := g.readMem(arg, 4)
		if err != nil {
			return sErr(lxEFAULT)
		}
		if d.fx.hasFlags {
			d.fx.oflags &^= lxOAsync
			if le32(b) != 0 {
				d.fx.oflags |= lxOAsync
			}
		}
		return 0
	}
	if r, ok := g.sockIoctl(d, req, arg); ok {
		return r
	}
	return g.ttyIoctl(d, req, arg)
}

// Linux ioctl requests on a descriptor's flags.
const (
	lxFionbio  = 0x5421
	lxFionclex = 0x5450
	lxFioclex  = 0x5451
	lxFioasync = 0x5452
)

// epWatch is the epolls a description is registered in, with how many
// registrations each, so that its release can remove it from them.
type epWatch struct {
	mu  sync.Mutex
	eps map[*epoll]int
}

func (w *epWatch) add(ep *epoll) {
	w.mu.Lock()
	if w.eps == nil {
		w.eps = map[*epoll]int{}
	}
	w.eps[ep]++
	w.mu.Unlock()
}

func (w *epWatch) done(ep *epoll) {
	w.mu.Lock()
	if w.eps[ep]--; w.eps[ep] <= 0 {
		delete(w.eps, ep)
	}
	w.mu.Unlock()
}

// epollRelease removes the description from every epoll it is registered in,
// as the kernel does when the last reference to a file goes. It runs before
// the host fds close, while the registrations still name them.
func (d *dfile) epollRelease() {
	d.epw.mu.Lock()
	eps := make([]*epoll, 0, len(d.epw.eps))
	for ep := range d.epw.eps {
		eps = append(eps, ep)
	}
	d.epw.mu.Unlock()
	for _, ep := range eps {
		ep.forget(d)
	}
}
