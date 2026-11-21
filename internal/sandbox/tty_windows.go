//go:build windows

package sandbox

import (
	"os"
	"slices"
	"strconv"
	"sync"
	"time"
)

// A Windows terminal's hub is the run's socket state: its lock and readiness
// bus, so reads, writes, poll, select and epoll on a terminal wait as they do
// on a socket.
type ttyHub struct{ n *dnet }

func (h *ttyHub) mutex() *sync.Mutex { return &h.n.mu }

// termState is a run's terminals by index.
type termState struct {
	mu   sync.Mutex
	devs map[int]*ttyDev
}

// touch records a readiness change and wakes every waiter. d.mu is held.
func (d *ttyDev) touch() {
	d.n.seq++
	d.stamp = d.n.seq
	d.n.notify()
}

func (d *ttyDev) free() {}

// ttyWait parks until the next change on d, a signal, the deadline or
// teardown. It is called and returns with d.mu held. 0 means look again.
func (g *dguest) ttyWait(d *ttyDev, deadline time.Time) lxErrno {
	return g.wait(d.n, deadline)
}

func (g *dguest) newTTY() (*ttyDev, lxErrno) {
	return g.term.newDev(g.dfs, &ttyHub{n: g.netState()}, -1), 0
}

// sideFile is the host file behind a terminal description: a placeholder,
// since the device is served from the supervisor.
func (d *ttyDev) sideFile(master bool, gp string) (*os.File, lxErrno) {
	return hostless(gp)
}

// openTTY opens the guest terminal device gp, told by the device the path
// resolves to (the pty multiplexor, the controlling terminal, or a pty slave),
// reporting false when gp is not one of them.
func (g *dguest) openTTY(gp string, flags int64) (int64, bool) {
	n, e, ok := g.pseudo(gp)
	if !ok || e != 0 || n.kind != pDev {
		return 0, false
	}
	switch major, minor := lxMajor(n.rdev), lxMinor(n.rdev); {
	case major == 5 && minor == 2:
		return g.openPtmx(flags), true
	case major == 5 && minor == 0:
		d := g.term.cttyOf(g.mySid())
		if d == nil {
			return sErr(lxENXIO), true
		}
		return g.openSlave(d, "/dev/tty", flags|lxONoctty), true
	case major == 136:
		d := g.term.dev(int(minor))
		if d == nil {
			return sErr(lxENOENT), true
		}
		return g.openSlave(d, "/dev/pts/"+strconv.Itoa(int(minor)), flags), true
	}
	return 0, false
}

// ptsDir is a devpts instance: ptmx and the run's terminals.
func (g *dguest) ptsDir() *pnode {
	ts := &g.term
	node := func(i int) *pnode {
		return &pnode{kind: pDev, perm: 0o620, host: "/dev/pts/" + strconv.Itoa(i), rdev: lxMakedev(136, uint64(i))}
	}
	return &pnode{
		kind: pDir, perm: 0o755,
		kids: func() []pchild {
			ts.mu.Lock()
			ns := make([]int, 0, len(ts.devs))
			for i := range ts.devs {
				ns = append(ns, i)
			}
			ts.mu.Unlock()
			slices.Sort(ns)
			out := []pchild{{"ptmx", devNode("ptmx")}}
			for _, i := range ns {
				out = append(out, pchild{strconv.Itoa(i), node(i)})
			}
			return out
		},
		look: func(name string) *pnode {
			if name == "ptmx" {
				return devNode("ptmx")
			}
			if d := g.ptsDev(name); d != nil {
				return node(d.idx)
			}
			return nil
		},
	}
}

func (g *dguest) ttyLstat(gp string) (os.FileInfo, lxErrno, bool) { return nil, 0, false }

func ttyRdev(fi os.FileInfo) (uint64, bool) { return 0, false }

func (g *dguest) ttyIoctl(df *dfile, req, arg uint64) int64 {
	if df.pty == nil {
		return sErr(lxENOTTY)
	}
	return g.ptyIoctl(df, req, arg)
}
