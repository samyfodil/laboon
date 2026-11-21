package sandbox

import (
	"os"
	"time"

	"github.com/samyfodil/laboon/core"
)

// A FIFO node on Windows holds no pipe of its own, so the run keeps one for it:
// every open of the node joins the same supervisor pipe, which carries the data,
// the end-of-file once the writers are gone, and the blocking open rendezvous,
// as pipe(7) has them. It lives for the run; the bytes left in it are dropped
// when its last end closes, as a FIFO's are.

func (n *dnet) fifo(id core.NodeID) *pipeObj {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fifos == nil {
		n.fifos = map[core.NodeID]*pipeObj{}
	}
	po := n.fifos[id]
	if po == nil {
		po = &pipeObj{io: &bufferPipe{n: n, buf: make([]byte, lxPipeDefSize)}}
		n.fifos[id] = po
	}
	return po
}

// openFifo opens the FIFO at gp: a write-only open waits for a reader (ENXIO if
// non-blocking), a blocking read-only open for a writer. A signal ends either
// wait. The description keeps a handle on the node for fstat.
func (g *dguest) openFifo(gp string, flags int64) int64 {
	loc, err := g.vns().Resolve(gp, false)
	if err != nil {
		return sErr(osErrno(err))
	}
	nf, err := loc.Node.Open(os.O_RDONLY)
	if err != nil {
		return sErr(osErrno(err))
	}
	of, ok := hostDupOf(nf, gp)
	nf.Close()
	if !ok {
		return sErr(lxEINVAL)
	}
	n := g.netState()
	po := n.fifo(loc.Node.ID())
	p := po.io.(*bufferPipe)
	acc := flags & lxOAccmod
	nonblock := flags&lxONonblock != 0
	n.mu.Lock()
	if p.readers == 0 && p.writers == 0 {
		p.head, p.used = 0, 0
	}
	if acc == lxOWronly && nonblock && p.readers == 0 {
		n.mu.Unlock()
		of.Close()
		return sErr(lxENXIO)
	}
	if acc != lxOWronly {
		p.readers++
		p.touch(1)
	}
	if acc != lxORdonly {
		p.writers++
		p.wgen++
		p.touch(0)
	}
	var e lxErrno
	switch {
	case acc == lxOWronly:
		for p.readers == 0 && e == 0 {
			e = g.wait(n, time.Time{})
		}
	case acc == lxORdonly && !nonblock:
		for gen := p.wgen; p.writers == 0 && p.wgen == gen && e == 0; {
			e = g.wait(n, time.Time{})
		}
	}
	n.mu.Unlock()
	if e != 0 {
		p.close(acc)
		of.Close()
		return sErr(e)
	}
	return g.installD(&dfile{f: of, gp: gp, stub: -1, pipe: po}, flags)
}
