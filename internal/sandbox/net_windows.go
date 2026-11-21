//go:build windows

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/samyfodil/laboon/core"
	"golang.org/x/sys/windows"
)

// Sockets for the Windows backend. The stub has no network (the LPAC refuses
// Winsock), so every guest socket is a supervisor object and its data moves
// through queues here:
//   - AF_UNIX sockets and socketpairs live entirely in the supervisor, which
//     serves every guest process of a run. A connection is the two sockets'
//     receive queues; SCM_RIGHTS moves open-file descriptions between them.
//     A path name is a socket node in the overlay, an abstract name a key.
//   - AF_INET and AF_INET6 sockets are Winsock sockets through Go's net
//     package. A goroutine fills a socket's receive queue from the host
//     socket and another drains its send queue into it, so O_NONBLOCK,
//     timeouts, signals and readiness all apply to the queues.
// One lock per run (dnet.mu) guards every socket. A change bumps the
// socket's stamp and wakes whoever waits on the run's bus: blocked calls,
// poll, select and epoll (poll_windows.go).
//
// UDP datagrams and TCP connections to port 53 are answered by the egress DNS
// policy; other destinations are checked against the egress allowlist.

// served reports whether d's IO is the supervisor's own (a socket or a
// terminal) with a placeholder host file (NUL), which sendfile and splice
// refuse.
func (d *dfile) served() bool { return d.sk != nil || d.pty != nil }

const (
	sockRcvBuf    = 256 << 10 // receive queue bound, bytes
	sockSndBuf    = 256 << 10 // a TCP socket's send queue bound
	udpMax        = 65507
	lxMsgNosignal = 0x4000
)

// Socket states.
const (
	skNew = iota
	skListening
	skConnecting
	skConnected
)

// sockSeg is one write's worth of queued data: a datagram, or a piece of a
// stream that may carry descriptors (which bound a stream read).
type sockSeg struct {
	b      []byte
	from   []byte   // the sender's guest sockaddr, for datagrams
	rights []*dfile // SCM_RIGHTS: one reference each while queued
}

// sockQ is a receive queue. eof is set once nothing more will arrive; err is
// reported once, after the queued data (a reset connection).
type sockQ struct {
	segs []sockSeg
	n    int
	eof  bool
	err  lxErrno
}

func (q *sockQ) push(s sockSeg) {
	q.segs = append(q.segs, s)
	q.n += len(s.b)
}

// drop empties the queue, returning the descriptors it held for the caller to
// release once the run lock is dropped.
func (q *sockQ) drop() []*dfile {
	var rel []*dfile
	for _, s := range q.segs {
		rel = append(rel, s.rights...)
	}
	q.segs, q.n = nil, 0
	return rel
}

type ucred struct{ pid, uid, gid uint32 }

// dsock is the socket of an open-file description (dfile.sk). Every field
// past n is guarded by n.mu.
type dsock struct {
	family, typ, proto int
	n                  *dnet
	ino                uint64

	state    int
	closed   bool
	virt     bool   // always false: the virtual network (vnet) is not realized on windows
	loop     bool   // an INET socket of a run without networking, or of a run's own loopback (loopnet_windows.go)
	lo       bool   // a host INET socket bound to a wildcard, its port held on the run's own loopback too (loopClaim)
	netns    int32  // a loop socket's network namespace
	name     []byte // guest sockaddr it is bound to (AF_UNIX), nil if none
	peer     []byte // guest sockaddr of the peer, nil if none
	key      any    // its entry in dnet.names (a bound AF_UNIX name)
	rx       sockQ
	pair     *dsock // AF_UNIX: the connected peer (a datagram socket: where sends go)
	peerGone bool   // AF_UNIX: the peer closed
	shutRd   bool
	shutWr   bool
	soErr    lxErrno
	backlog  []*dsock
	maxBack  int
	acceptE  lxErrno // the host's accept failed: the guest's next accept takes the error
	stamp    uint64
	opts     map[[2]int][]byte
	rcvTimeo time.Duration
	sndTimeo time.Duration
	cred     ucred // the creator, what a peer's SO_PEERCRED reports
	peerCred ucred
	dns      bool    // a datagram socket connected to :53, answered here
	nl       *nlDump // a netlink socket's running dump

	laddr   netip.AddrPort // an inet socket's bound address before it has a host socket
	raddr   netip.AddrPort // a connected UDP socket's peer
	conn    net.Conn
	ln      net.Listener
	pc      *net.UDPConn
	pcConn  bool // pc is connected to raddr (connect made it)
	tx      []byte
	txErr   lxErrno
	wrDone  bool
	linger0 bool
	v6only  bool

	mcast    []mcMember  // a loop socket's IPv4 multicast groups (vmcast_windows.go)
	mcast6   []mc6Member // its IPv6 groups
	mcIf     int32       // IP_MULTICAST_IF's interface, 0 for the route's
	mcIfAddr uint32      // the address IP_MULTICAST_IF named it by
}

func (s *dsock) inet() bool { return s.family == lxAFInet || s.family == lxAFInet6 }

// local reports whether s is served entirely here, over queues and pairs: an
// AF_UNIX socket, or an INET one on loopback without networking.
// A unix socket connected to a host socket moves its bytes over a host
// connection, as a TCP one does.
func (s *dsock) local() bool { return s.family == lxAFUnix && s.conn == nil || s.loop }

// sockKey is a pathname-bound AF_UNIX socket node's host file identity (volume
// plus file id), the key the names table uses for it.
type sockKey struct {
	vol uint32
	id  uint64
}

// absKey is an abstract AF_UNIX name's key in the names table: the names are
// per network namespace, as on Linux.
type absKey struct {
	netns int32
	name  string
}

// dnet is a run's socket state: the lock and bus of every socket, the egress
// policy, and the bound AF_UNIX names.
type dnet struct {
	mu    sync.Mutex
	cond  *sync.Cond // the pumps wait here
	bus   chan struct{}
	seq   uint64
	eg    *egress
	names map[any]*dsock           // sockKey of a socket node, or the absKey of an abstract name
	fifos map[core.NodeID]*pipeObj // the pipe of each FIFO node the run opened (fifo_windows.go)
	ino   uint64
	auto  uint32

	loops map[loopPort][]*dsock // bound loopback sockets of a run without networking
	ephem uint16                // the last ephemeral port given out

	nets  map[int32]*netModel // per-netns interface/address/route model (routing netlink)
	mcDev map[mcDevKey]int    // the multicast groups each interface took in, with how many loop sockets joined each there
	nftns map[int32]*nftState // per-netns nftables ruleset (netfilter netlink)
}

func (g *dguest) netState() *dnet {
	g.dfs.netOnce.Do(func() {
		n := &dnet{eg: newEgress(g.cfg), bus: make(chan struct{}), names: map[any]*dsock{}}
		n.cond = sync.NewCond(&n.mu)
		g.dfs.net = n
	})
	return g.dfs.net
}

// close ends the run's networking; each socket closes with its description.
func (n *dnet) close() {}

// syncIPNetns is a no-op on Windows, which has no virtual network.
func (n *dnet) syncIPNetns(netns int32, m *netModel) {}

// reconcilePublish is a no-op on Windows, which has no virtual network to
// publish into.
func (n *dnet) reconcilePublish(netns int32) {}

// changed records a change of s's readiness (s may be nil) and wakes every
// waiter. Called with n.mu held.
func (n *dnet) changed(s *dsock) {
	n.seq++
	if s != nil {
		s.stamp = n.seq
	}
	n.notify()
}

// notify wakes the waiters without marking any readiness change. Called with
// n.mu held.
func (n *dnet) notify() {
	close(n.bus)
	n.bus = make(chan struct{})
	n.cond.Broadcast()
}

// watch returns the channel the next change closes.
func (n *dnet) watch() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.bus
}

// wait parks until the next change, a signal, the deadline or teardown. It is
// called and returns with n.mu held. 0 means look again.
func (g *dguest) wait(n *dnet, deadline time.Time) lxErrno {
	ch := n.bus
	n.mu.Unlock()
	e := g.waitOn(ch, deadline)
	n.mu.Lock()
	return e
}

// waitOn parks until ch closes, a signal is pending (errRestart), deadline
// passes (lxEAGAIN; zero is none) or the guest is torn down (lxEINTR). A
// signal or teardown after the checks below kicks the thread, and the kick
// channel holds it.
func (g *dguest) waitOn(ch <-chan struct{}, deadline time.Time) lxErrno {
	var kick chan struct{}
	if t := g.sigs().thread(g.pid); t != nil {
		kick = t.kick()
	}
	if g.sigIntr() {
		return errRestart
	}
	if g.ch.dead() {
		return lxEINTR
	}
	var expired <-chan time.Time
	if !deadline.IsZero() {
		left := time.Until(deadline)
		if left <= 0 {
			return lxEAGAIN
		}
		tm := time.NewTimer(left)
		defer tm.Stop()
		expired = tm.C
	}
	select {
	case <-ch:
	case <-kick:
	case <-expired:
	case <-g.ch.ioGone:
		return lxEINTR
	case <-g.ch.done:
		return lxEINTR
	case <-g.ch.stop:
		return lxEINTR
	}
	if g.ch.dead() {
		return lxEINTR
	}
	if g.sigIntr() {
		return errRestart
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return lxEAGAIN
	}
	return 0
}

// deadlineOf is the end of a wait bounded by a socket timeout (0: none).
func deadlineOf(t time.Duration) time.Time {
	if t <= 0 {
		return time.Time{}
	}
	return time.Now().Add(t)
}

// hostless returns a placeholder host file for an object that has none (a
// socket, eventfd or epoll instance), so the shared code's checks for an open
// file hold. It is the NUL device; hostfs.FileStat reports a socket for "socket:".
func hostless(name string) (*os.File, lxErrno) {
	p, err := windows.UTF16PtrFromString("NUL")
	if err != nil {
		return nil, lxEINVAL
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, osErrno(err)
	}
	return os.NewFile(uintptr(h), name), 0
}

func (g *dguest) creds() ucred {
	var c ucred
	g.withCreds(func(cr *creds) int64 {
		c = ucred{pid: uint32(g.tgid), uid: cr.euid, gid: cr.egid}
		return 0
	})
	return c
}

// newSock makes a socket of the network namespace netns.
func (n *dnet) newSock(family, typ, proto int, cred ucred, netns int32) *dsock {
	n.mu.Lock()
	n.ino++
	ino := n.ino
	n.mu.Unlock()
	return &dsock{family: family, typ: typ, proto: proto, n: n, ino: ino, cred: cred, maxBack: 128, netns: netns}
}

func sockDfile(s *dsock) (*dfile, lxErrno) {
	name := fmt.Sprintf("socket:[%d]", s.ino)
	f, e := hostless(name)
	if e != 0 {
		return nil, e
	}
	return &dfile{f: f, gp: name, stub: -1, sk: s}, 0
}

func (g *dguest) installSock(s *dsock, flags int) int64 {
	d, e := sockDfile(s)
	if e != 0 {
		s.close()
		return sErr(e)
	}
	d.nonblock.Store(flags&lxSockNonblock != 0)
	fd := g.ft.add(d, 0)
	if fd >= 0 && flags&lxSockCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	return int64(fd)
}

func (g *dguest) socket(family, typ, proto int) int64 {
	flags := typ &^ 0xf
	typ &= 0xf
	if flags&^(lxSockNonblock|lxSockCloexec) != 0 {
		return sErr(lxEINVAL)
	}
	switch family {
	case lxAFUnix:
		if typ != lxSockStream && typ != lxSockDgram && typ != lxSockSeqpacket {
			return sErr(lxESOCKTNOSUPPORT)
		}
		if proto != 0 {
			return sErr(lxEPROTONOSUPPORT)
		}
	case lxAFNetlink:
		if typ != lxSockRaw && typ != lxSockDgram {
			return sErr(lxESOCKTNOSUPPORT)
		}
		if proto != 0 { // NETLINK_ROUTE only
			return sErr(lxEPROTONOSUPPORT)
		}
	case lxAFInet, lxAFInet6:
		if !g.hostNet() && g.cfg.NoNet && !g.cfg.Net {
			return sErr(lxEAFNOSUPPORT) // no network at all, not even loopback
		}
		switch {
		case typ == lxSockStream && (proto == 0 || proto == 6):
			proto = 6
		case typ == lxSockDgram && (proto == 0 || proto == 17):
			proto = 17
		case typ == lxSockStream || typ == lxSockDgram:
			return sErr(lxEPROTONOSUPPORT)
		default:
			return sErr(lxESOCKTNOSUPPORT)
		}
	default:
		return sErr(lxEAFNOSUPPORT)
	}
	s := g.netState().newSock(family, typ, proto, g.creds(), g.ps.netns.Load())
	if family == lxAFNetlink {
		s.nl = newNlDump(g.guestPageSize())
	}
	if s.inet() && !g.hostNet() {
		s.loop = true
	}
	return g.installSock(s, flags)
}

func (g *dguest) socketpair(family, typ, proto int, svAddr uint64) int64 {
	if family != lxAFUnix {
		if family == lxAFInet || family == lxAFInet6 {
			return sErr(lxEOPNOTSUPP)
		}
		return sErr(lxEAFNOSUPPORT)
	}
	flags := typ &^ 0xf
	typ &= 0xf
	if flags&^(lxSockNonblock|lxSockCloexec) != 0 {
		return sErr(lxEINVAL)
	}
	if typ != lxSockStream && typ != lxSockDgram && typ != lxSockSeqpacket {
		return sErr(lxESOCKTNOSUPPORT)
	}
	if proto != 0 {
		return sErr(lxEPROTONOSUPPORT)
	}
	n := g.netState()
	cr := g.creds()
	ns := g.ps.netns.Load()
	a, b := n.newSock(family, typ, 0, cr, ns), n.newSock(family, typ, 0, cr, ns)
	a.pair, b.pair = b, a
	a.state, b.state = skConnected, skConnected
	a.peerCred, b.peerCred = cr, cr
	fa := g.installSock(a, flags)
	if fa < 0 {
		b.close()
		return fa
	}
	fb := g.installSock(b, flags)
	if fb < 0 {
		g.ft.remove(int(fa))
		return fb
	}
	var out [8]byte
	put32(out[:], uint32(fa))
	put32(out[4:], uint32(fb))
	if err := g.writeMem(svAddr, out[:]); err != nil {
		g.ft.remove(int(fa))
		g.ft.remove(int(fb))
		return sErr(lxEFAULT)
	}
	return 0
}

// close is the socket's end with its last description.
func (s *dsock) close() {
	n := s.n
	n.mu.Lock()
	if s.closed {
		n.mu.Unlock()
		return
	}
	s.closed = true
	rel := s.rx.drop()
	if s.key != nil && n.names[s.key] == s {
		delete(n.names, s.key)
	}
	if s.loop || s.lo {
		n.loopUnbind(s)
	}
	n.loopLeaveAll(s)
	for _, c := range s.backlog {
		rel = append(rel, c.abortLocked()...)
	}
	s.backlog = nil
	if p := s.pair; p != nil && p.pair == s {
		p.peerGone = true
		p.rx.eof = true
		n.changed(p)
	}
	ln, pc, conn := s.ln, s.pc, s.conn
	abort := s.linger0
	n.changed(s)
	n.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	if pc != nil {
		pc.Close()
	}
	if conn != nil && abort {
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		conn.Close()
	}
	for _, d := range rel {
		d.unref()
	}
}

// abortLocked ends a connection no one accepted: the client sees it reset.
func (s *dsock) abortLocked() []*dfile {
	s.closed = true
	rel := s.rx.drop()
	if p := s.pair; p != nil && p.pair == s {
		p.peerGone = true
		p.rx.eof = true
		p.rx.err = lxECONNRESET
		s.n.changed(p)
	}
	if s.conn != nil {
		go s.conn.Close()
	}
	return rel
}

// ---- addresses ------------------------------------------------------------------

// inetAddr reads a guest AF_INET/AF_INET6 sockaddr for a socket of the given
// family. An IPv4 address on an IPv6 socket is taken (v4-mapped) only where
// Linux takes one: a datagram destination (v4ok).
func inetAddr(raw []byte, family int, v4ok bool) (netip.AddrPort, lxErrno) {
	switch saFamily(raw) {
	case lxAFInet:
		if family == lxAFInet6 && !v4ok {
			if len(raw) < 24 {
				return netip.AddrPort{}, lxEINVAL
			}
			return netip.AddrPort{}, lxEAFNOSUPPORT
		}
		if len(raw) < 16 {
			return netip.AddrPort{}, lxEINVAL
		}
		a := netip.AddrFrom4([4]byte(raw[4:8]))
		if family == lxAFInet6 {
			a = netip.AddrFrom16(a.As16())
		}
		return netip.AddrPortFrom(a, uint16(raw[2])<<8|uint16(raw[3])), 0
	case lxAFInet6:
		if len(raw) < 24 {
			return netip.AddrPort{}, lxEINVAL
		}
		if family != lxAFInet6 {
			return netip.AddrPort{}, lxEAFNOSUPPORT
		}
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(raw[8:24])), uint16(raw[2])<<8|uint16(raw[3])), 0
	}
	return netip.AddrPort{}, lxEAFNOSUPPORT
}

// linuxAddr renders ap as a sockaddr of the socket's family: an IPv4 address
// on an IPv6 socket is v4-mapped.
func linuxAddr(ap netip.AddrPort, family int) []byte {
	a := ap.Addr()
	if family == lxAFInet {
		b := make([]byte, 16)
		b[0] = lxAFInet
		b[2], b[3] = byte(ap.Port()>>8), byte(ap.Port())
		if a.Is4In6() || a.Is4() {
			v := a.Unmap().As4()
			copy(b[4:8], v[:])
		}
		return b
	}
	b := make([]byte, 28)
	b[0] = lxAFInet6
	b[2], b[3] = byte(ap.Port()>>8), byte(ap.Port())
	if a.IsValid() {
		v := a.As16()
		copy(b[8:24], v[:])
	}
	return b
}

// addrPortOf is a host net.Addr as an AddrPort.
func addrPortOf(a net.Addr) netip.AddrPort {
	switch a := a.(type) {
	case *net.TCPAddr:
		return a.AddrPort()
	case *net.UDPAddr:
		return a.AddrPort()
	}
	return netip.AddrPort{}
}

// wildcard is the unspecified address of a family.
func wildcard(family int) netip.Addr {
	if family == lxAFInet6 {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

// hostNet is the Go network for an inet socket's host side: an IPv6 socket is
// dual-stack unless IPV6_V6ONLY.
func (s *dsock) hostNet() string {
	base := "tcp"
	if s.typ == lxSockDgram {
		base = "udp"
	}
	switch {
	case s.family == lxAFInet:
		return base + "4"
	case s.v6only:
		return base + "6"
	}
	return base
}

// sockErrno maps a host network error to a Linux errno.
func sockErrno(err error) lxErrno {
	var e windows.Errno
	if errors.As(err, &e) {
		return winErrno(e)
	}
	var se syscall.Errno
	if errors.As(err, &se) {
		return winErrno(windows.Errno(se))
	}
	switch {
	case errors.Is(err, net.ErrClosed):
		return lxEBADF
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return lxETIMEDOUT
	case errors.Is(err, io.EOF):
		return lxECONNRESET
	}
	var ae *net.AddrError
	if errors.As(err, &ae) {
		return lxEINVAL
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return lxEADDRNOTAVAIL
	}
	return lxEIO
}

func (g *dguest) egressOK(ap netip.AddrPort) bool {
	a := ap.Addr().Unmap()
	return g.netState().eg.connectAllowed(net.IP(a.AsSlice()), int(ap.Port()))
}

// ---- AF_UNIX names --------------------------------------------------------------

// unixKey resolves a guest AF_UNIX address for the socket s to its key in dnet.names: its absKey
// for an abstract one, the socket node's file id for a path. bind creates the
// node.
func (g *dguest) unixKey(s *dsock, raw []byte, create bool) (key any, canon []byte, e lxErrno) {
	name, abstract, canon, e := unixName(raw)
	if e != 0 {
		return nil, nil, e
	}
	if abstract {
		return absKey{s.netns, name}, canon, 0
	}
	gp, e := g.walkAt(lxAtFdcwd, name, !create)
	if e != 0 {
		return nil, nil, e
	}
	if create {
		if e := g.mkSockNode(gp); e != 0 {
			return nil, nil, e
		}
	}
	fi, e := g.lstatGuest(gp)
	if e != 0 {
		return nil, nil, e
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return nil, nil, lxECONNREFUSED
	}
	dev, ino := HostDevIno(fi)
	if ino == 0 && dev == 0 {
		return nil, nil, lxECONNREFUSED
	}
	return sockKey{uint32(dev), ino}, canon, 0
}

// mkSockNode creates the socket node a bind names, as mknod would: the parent
// must exist and the name must not.
func (g *dguest) mkSockNode(gp string) lxErrno {
	if fi, e := g.lstatGuest(path.Dir(gp)); e != 0 {
		return e
	} else if !fi.IsDir() {
		return lxENOTDIR
	}
	if _, e := g.lstatGuest(gp); e == 0 {
		return lxEADDRINUSE
	} else if e != lxENOENT {
		return e
	}
	if e := g.dacCreate(gp); e != 0 {
		return e
	}
	// Create the socket node through the overlay backend, which copies up the
	// parents and makes the typed node in the writable top.
	ploc, err := g.vns().Resolve(path.Dir(gp), true)
	if err != nil {
		return osErrno(err)
	}
	if _, err := g.create(ploc, gp, core.CreateSpec{Kind: core.Socket, Mode: g.createPerm(0o777)}); err != nil {
		return osErrno(err)
	}
	g.notify(gp, inCreate, 0)
	return 0
}

// ---- bind / listen / accept / connect -------------------------------------------

func (g *dguest) bind(fd int64, addr, addrlen uint64) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	raw, e := g.readSockaddr(addr, addrlen)
	if e != 0 {
		return sErr(e)
	}
	s := d.sk
	n := s.n
	if s.family == lxAFNetlink {
		return 0 // the port id is the process's, as unbound
	}
	if s.family == lxAFUnix {
		var key any
		var canon []byte
		if len(raw) == 2 && saFamily(raw) == lxAFUnix {
			n.mu.Lock()
			n.auto++
			name := fmt.Sprintf("%05x", n.auto&0xfffff)
			n.mu.Unlock()
			key, canon = absKey{s.netns, name}, append([]byte{lxAFUnix, 0, 0}, name...)
		} else {
			n.mu.Lock()
			bound := s.name != nil
			n.mu.Unlock()
			if bound {
				return sErr(lxEINVAL)
			}
			if key, canon, e = g.unixKey(s, raw, true); e != 0 {
				return sErr(e)
			}
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if s.name != nil {
			return sErr(lxEINVAL)
		}
		if old, ok := n.names[key]; ok && !old.closed {
			return sErr(lxEADDRINUSE)
		}
		n.names[key] = s
		s.key, s.name = key, canon
		return 0
	}
	if s.loop {
		return g.loopBind(s, raw)
	}
	ap, e := inetAddr(raw, s.family, false)
	if e != 0 {
		return sErr(e)
	}
	n.mu.Lock()
	bound := s.laddr.IsValid() || s.pc != nil || s.ln != nil || s.conn != nil
	n.mu.Unlock()
	if bound {
		return sErr(lxEINVAL)
	}
	if ap.Addr().Unmap().IsLoopback() { // the run's own loopback (loopnet_windows.go)
		n.mu.Lock()
		s.loop, s.netns = true, g.ps.netns.Load()
		n.mu.Unlock()
		return g.loopBind(s, raw)
	}
	own := ap.Addr().Unmap().IsUnspecified()
	// A port the host chooses that the run's own loopback holds is chosen
	// again; one the guest named is taken.
	for range 16 {
		if s.typ == lxSockDgram {
			pc, err := net.ListenUDP(s.hostNet(), net.UDPAddrFromAddrPort(ap))
			if err != nil {
				return sErr(sockErrno(err))
			}
			n.mu.Lock()
			s.laddr = addrPortOf(pc.LocalAddr())
			if own && n.loopClaim(s) != 0 {
				s.laddr = netip.AddrPort{}
				n.mu.Unlock()
				pc.Close()
				if ap.Port() != 0 {
					return sErr(lxEADDRINUSE)
				}
				continue
			}
			n.startUDP(s, pc)
			n.mu.Unlock()
			return 0
		}
		// A stream socket gets its host socket at listen or connect; the
		// address is checked (and an ephemeral port chosen) now.
		l, err := net.Listen(s.hostNet(), ap.String())
		if err != nil {
			return sErr(sockErrno(err))
		}
		port := addrPortOf(l.Addr()).Port()
		l.Close()
		n.mu.Lock()
		s.laddr = netip.AddrPortFrom(ap.Addr(), port)
		if own && n.loopClaim(s) != 0 {
			s.laddr = netip.AddrPort{}
			n.mu.Unlock()
			if ap.Port() != 0 {
				return sErr(lxEADDRINUSE)
			}
			continue
		}
		n.mu.Unlock()
		return 0
	}
	return sErr(lxEADDRINUSE)
}

func (g *dguest) listen(fd int64, backlog int) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	s := d.sk
	n := s.n
	if s.typ == lxSockDgram {
		return sErr(lxEOPNOTSUPP)
	}
	backlog = min(max(backlog, 0), 4096) + 1
	n.mu.Lock()
	defer n.mu.Unlock()
	switch s.state {
	case skListening:
		s.maxBack = backlog
		return 0
	case skNew:
	default:
		return sErr(lxEINVAL)
	}
	if s.family == lxAFUnix {
		if s.name == nil {
			return sErr(lxEINVAL)
		}
		s.state, s.maxBack = skListening, backlog
		return 0
	}
	if s.loop {
		if !s.laddr.IsValid() {
			if e := n.loopBindLocked(s, netip.AddrPortFrom(wildcard(s.family), 0)); e != 0 {
				return sErr(e)
			}
		}
		if n.loopListenTaken(s) {
			return sErr(lxEADDRINUSE)
		}
		s.state, s.maxBack = skListening, backlog
		return 0
	}
	at := s.laddr
	claim := !at.IsValid() // an unbound socket listens on a wildcard
	if !at.IsValid() {
		at = netip.AddrPortFrom(wildcard(s.family), 0)
	}
	for range 16 {
		n.mu.Unlock()
		ln, err := net.Listen(s.hostNet(), at.String())
		n.mu.Lock()
		if err != nil {
			return sErr(sockErrno(err))
		}
		if s.closed {
			ln.Close()
			return sErr(lxEBADF)
		}
		s.laddr = addrPortOf(ln.Addr())
		if claim && n.loopClaim(s) != 0 {
			ln.Close()
			continue // a port the run's own loopback holds: choose again
		}
		s.ln, s.state, s.maxBack = ln, skListening, backlog
		go n.acceptLoop(s, ln)
		return 0
	}
	s.laddr = netip.AddrPort{}
	return sErr(lxEADDRINUSE)
}

// acceptLoop moves the host's accepted connections into s's backlog, up to
// its length. An accept the host fails (out of handles or memory: Go retries
// an aborted connection itself) goes to the guest's next accept, as Linux
// fails it, and the loop accepts again once that has taken the error.
func (n *dnet) acceptLoop(s *dsock, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			n.mu.Lock()
			if !s.closed && !errors.Is(err, net.ErrClosed) {
				s.acceptE = sockErrno(err)
				n.changed(s)
				for !s.closed && s.acceptE != 0 {
					n.cond.Wait()
				}
			}
			closed := s.closed
			n.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		n.mu.Lock()
		for !s.closed && len(s.backlog) >= s.maxBack {
			n.cond.Wait()
		}
		if s.closed {
			n.mu.Unlock()
			c.Close()
			return
		}
		cs := &dsock{family: s.family, typ: s.typ, proto: s.proto, n: n, cred: s.cred, maxBack: 128}
		n.ino++
		cs.ino = n.ino
		cs.peer = linuxAddr(addrPortOf(c.RemoteAddr()), s.family)
		n.startTCP(cs, c)
		s.backlog = append(s.backlog, cs)
		n.changed(s)
		n.mu.Unlock()
	}
}

func (g *dguest) accept4(fd int64, addr, lenAddr uint64, flags int) int64 {
	if flags&^(lxSockNonblock|lxSockCloexec) != 0 {
		return sErr(lxEINVAL)
	}
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	s := d.sk
	n := s.n
	if s.typ == lxSockDgram {
		return sErr(lxEOPNOTSUPP)
	}
	n.mu.Lock()
	end := deadlineOf(s.rcvTimeo)
	var c *dsock
	for {
		if s.state != skListening || s.closed {
			n.mu.Unlock()
			return sErr(lxEINVAL)
		}
		if len(s.backlog) > 0 {
			c = s.backlog[0]
			s.backlog = s.backlog[1:]
			n.changed(s)
			break
		}
		if e := s.acceptE; e != 0 {
			s.acceptE = 0
			n.cond.Broadcast()
			n.mu.Unlock()
			return sErr(e)
		}
		if d.nonblock.Load() {
			n.mu.Unlock()
			return sErr(lxEAGAIN)
		}
		if e := g.wait(n, end); e != 0 {
			n.mu.Unlock()
			return sErr(e)
		}
	}
	peer := c.peer
	n.mu.Unlock()
	if peer == nil {
		peer = []byte{lxAFUnix, 0}
	}
	nfd := g.installSock(c, flags)
	if nfd < 0 {
		return nfd
	}
	if e := g.putSockaddr(peer, addr, lenAddr); e != 0 {
		return sErr(e)
	}
	return nfd
}

func (g *dguest) connect(fd int64, addr, addrlen uint64) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	raw, e := g.readSockaddr(addr, addrlen)
	if e != 0 {
		return sErr(e)
	}
	s := d.sk
	if s.family == lxAFNetlink {
		return 0 // every request goes to the kernel
	}
	if s.family == lxAFUnix {
		return g.unixConnect(d, raw)
	}
	if s.loop {
		return g.loopConnect(d, raw)
	}
	n := s.n
	if saFamily(raw) != 0 {
		// The run's own loopback: served in-process, never the host's. A
		// nameserver there is the supervisor's resolver all the same.
		if ap, e := inetAddr(raw, s.family, s.typ == lxSockDgram); e == 0 && loopLocal(ap.Addr()) && ap.Port() != 53 {
			n.mu.Lock()
			if st := s.state; s.typ == lxSockStream && st != skNew {
				n.mu.Unlock()
				switch st {
				case skConnected:
					return sErr(lxEISCONN)
				case skConnecting:
					return sErr(lxEALREADY)
				}
				return sErr(lxEINVAL)
			}
			e := n.toLoop(s, g.ps.netns.Load(), ap.Addr())
			n.mu.Unlock()
			if e != 0 {
				return sErr(e)
			}
			return g.loopConnect(d, raw)
		}
	}
	if saFamily(raw) == 0 {
		// AF_UNSPEC: a datagram socket drops its peer; a stream ends its
		// connection.
		n.mu.Lock()
		defer n.mu.Unlock()
		if s.typ == lxSockDgram {
			s.dns, s.peer, s.raddr = false, nil, netip.AddrPort{}
			return 0
		}
		if s.state == skConnected {
			s.shutRd, s.shutWr = true, true
			s.rx.eof = true
			n.changed(s)
		}
		return 0
	}
	ap, e := inetAddr(raw, s.family, s.typ == lxSockDgram)
	if e != 0 {
		return sErr(e)
	}
	if s.typ == lxSockDgram {
		dns := ap.Port() == 53
		if !dns && !g.egressOK(ap) {
			return sErr(lxECONNREFUSED)
		}
		if dns {
			if e := n.autobindUDP(s); e != 0 {
				return sErr(e)
			}
		} else if e := n.connectUDP(s, ap); e != 0 {
			return sErr(e)
		}
		n.mu.Lock()
		s.dns = dns
		s.raddr = ap
		s.peer = normSockaddr(raw)
		if !dns {
			s.peer = linuxAddr(ap, s.family)
		}
		n.mu.Unlock()
		return 0
	}
	n.mu.Lock()
	switch s.state {
	case skConnected:
		n.mu.Unlock()
		return sErr(lxEISCONN)
	case skConnecting:
		n.mu.Unlock()
		if d.nonblock.Load() {
			return sErr(lxEALREADY)
		}
		return g.awaitConnect(d)
	case skListening:
		n.mu.Unlock()
		return sErr(lxEINVAL)
	}
	if ap.Port() == 53 {
		// DNS over TCP goes to the supervisor's resolver.
		c1, c2 := net.Pipe()
		go n.eg.serveStream(c2)
		s.peer = normSockaddr(raw)
		n.startTCP(s, c1)
		n.changed(s)
		n.mu.Unlock()
		return 0
	}
	if !g.egressOK(ap) {
		n.mu.Unlock()
		return sErr(lxECONNREFUSED)
	}
	s.state, s.soErr = skConnecting, 0
	s.peer = linuxAddr(ap, s.family)
	local := s.laddr
	network := s.hostNet()
	n.changed(s)
	n.mu.Unlock()
	go n.dial(s, network, ap, local)
	if d.nonblock.Load() {
		return sErr(lxEINPROGRESS)
	}
	return g.awaitConnect(d)
}

// dial makes s's host connection, leaving s connected or failed with its
// error pending.
func (n *dnet) dial(s *dsock, network string, ap, local netip.AddrPort) {
	dl := net.Dialer{Timeout: 75 * time.Second}
	if local.IsValid() {
		dl.LocalAddr = net.TCPAddrFromAddrPort(local)
	}
	to := ap
	if a := ap.Addr(); a.Is4In6() {
		to = netip.AddrPortFrom(a.Unmap(), ap.Port())
		if network == "tcp" {
			network = "tcp4"
		}
	}
	c, err := dl.Dial(network, to.String())
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.closed || s.state != skConnecting {
		if c != nil {
			c.Close()
		}
		return
	}
	if err != nil {
		s.state, s.soErr, s.peer = skNew, sockErrno(err), nil
		n.changed(s)
		return
	}
	n.startTCP(s, c)
	n.changed(s)
}

// awaitConnect parks a blocking connect until the handshake ends. A signal
// ends the wait with EINTR and the connection goes on; SO_SNDTIMEO leaves it
// in progress, as on Linux.
func (g *dguest) awaitConnect(d *dfile) int64 {
	s := d.sk
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	end := deadlineOf(s.sndTimeo)
	for s.state == skConnecting {
		switch e := g.wait(n, end); e {
		case 0:
		case errRestart:
			return sErr(lxEINTR)
		case lxEAGAIN:
			return sErr(lxEINPROGRESS)
		default:
			return sErr(e)
		}
	}
	if s.state == skConnected {
		return 0
	}
	e := s.soErr
	s.soErr = 0
	if e == 0 {
		e = lxECONNREFUSED
	}
	return sErr(e)
}

func (g *dguest) unixConnect(d *dfile, raw []byte) int64 {
	s := d.sk
	n := s.n
	if saFamily(raw) == 0 && s.typ == lxSockDgram {
		n.mu.Lock()
		s.pair, s.peer = nil, nil
		n.mu.Unlock()
		return 0
	}
	key, canon, e := g.unixKey(s, raw, false)
	if e != 0 {
		return sErr(e)
	}
	if _, path := key.(sockKey); path && s.typ == lxSockStream {
		n.mu.Lock()
		l, ok := n.names[key]
		n.mu.Unlock()
		if !ok || l.closed {
			return g.hostUnixConnect(d, raw, canon)
		}
	}
	cr := g.creds()
	n.mu.Lock()
	defer n.mu.Unlock()
	l, ok := n.names[key]
	if !ok || l.closed {
		return sErr(lxECONNREFUSED)
	}
	if l.typ != s.typ {
		return sErr(lxEPROTOTYPE)
	}
	if s.typ == lxSockDgram {
		s.pair, s.peer = l, canon
		return 0
	}
	switch s.state {
	case skConnected:
		return sErr(lxEISCONN)
	case skListening:
		return sErr(lxEINVAL)
	}
	if l.state != skListening {
		return sErr(lxECONNREFUSED)
	}
	end := deadlineOf(s.sndTimeo)
	for len(l.backlog) >= l.maxBack {
		if d.nonblock.Load() {
			return sErr(lxEAGAIN)
		}
		if e := g.wait(n, end); e != 0 {
			return sErr(e)
		}
		if l.closed || l.state != skListening {
			return sErr(lxECONNREFUSED)
		}
	}
	n.ino++
	srv := &dsock{family: lxAFUnix, typ: s.typ, n: n, ino: n.ino, cred: l.cred, maxBack: 128}
	srv.name, srv.peer = l.name, s.name
	srv.pair, s.pair = s, srv
	srv.state, s.state = skConnected, skConnected
	s.peerCred, srv.peerCred = l.cred, cr
	s.peer = canon
	l.backlog = append(l.backlog, srv)
	n.changed(l)
	n.changed(s)
	return 0
}

// hostUnixConnect connects s to the host socket a path names, which a
// backend holding host sockets (a bind of a host directory) reaches.
func (g *dguest) hostUnixConnect(d *dfile, raw, canon []byte) int64 {
	s := d.sk
	n := s.n
	name, _, _, e := unixName(raw)
	if e != 0 {
		return sErr(e)
	}
	gp, e := g.walkAt(lxAtFdcwd, name, true)
	if e != 0 {
		return sErr(e)
	}
	loc, err := g.vns().Resolve(gp, true)
	if err != nil {
		return sErr(osErrno(err))
	}
	sfs, ok := loc.FS.(core.SocketFS)
	if !ok {
		return sErr(lxECONNREFUSED)
	}
	n.mu.Lock()
	switch s.state {
	case skConnected:
		n.mu.Unlock()
		return sErr(lxEISCONN)
	case skListening:
		n.mu.Unlock()
		return sErr(lxEINVAL)
	}
	n.mu.Unlock()
	var c net.Conn
	err = sfs.ReachSocket(loc.Node, func(addr string) error {
		var err error
		c, err = net.Dial("unix", addr)
		return err
	})
	switch {
	case errors.Is(err, core.ErrSocketUnsupported):
		return sErr(lxECONNREFUSED)
	case err != nil:
		var ce core.Errno
		if errors.As(err, &ce) {
			return sErr(osErrno(err))
		}
		return sErr(sockErrno(err))
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	switch {
	case s.closed:
		c.Close()
		return sErr(lxEBADF)
	case s.state == skConnected || s.state == skListening:
		c.Close()
		return sErr(lxEISCONN)
	}
	s.peer = canon
	n.startTCP(s, c)
	n.changed(s)
	return 0
}

func (g *dguest) sockname(fd int64, addr, lenAddr uint64, peer bool) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	s := d.sk
	n := s.n
	n.mu.Lock()
	var out []byte
	switch {
	case s.family == lxAFNetlink && peer:
		out = sockaddrNl(0)
	case s.family == lxAFNetlink:
		out = sockaddrNl(g.tgid)
	case peer && s.loop:
		connected := s.state == skConnected || s.typ == lxSockDgram && s.peer != nil
		if !connected || s.peer == nil {
			n.mu.Unlock()
			return sErr(lxENOTCONN)
		}
		out = s.peer
	case s.loop:
		out = s.name
		if out == nil {
			out = linuxAddr(netip.AddrPortFrom(wildcard(s.family), 0), s.family)
		}
	case peer && s.family == lxAFUnix:
		if s.state != skConnected && s.pair == nil {
			n.mu.Unlock()
			return sErr(lxENOTCONN)
		}
		out = s.peer
		if out == nil {
			out = []byte{lxAFUnix, 0}
		}
	case peer:
		connected := s.state == skConnected || s.typ == lxSockDgram && s.peer != nil
		if !connected || s.peer == nil {
			n.mu.Unlock()
			return sErr(lxENOTCONN)
		}
		out = s.peer
	case s.family == lxAFUnix:
		out = s.name
		if out == nil {
			out = []byte{lxAFUnix, 0}
		}
	default:
		ap := s.laddr
		switch {
		case s.pc != nil:
			ap = addrPortOf(s.pc.LocalAddr())
		case s.ln != nil:
			ap = addrPortOf(s.ln.Addr())
		case s.conn != nil:
			if a := addrPortOf(s.conn.LocalAddr()); a.IsValid() {
				ap = a
			} else {
				ap = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)
			}
		}
		if !ap.IsValid() {
			ap = netip.AddrPortFrom(wildcard(s.family), 0)
		}
		out = linuxAddr(ap, s.family)
	}
	n.mu.Unlock()
	if e := g.putSockaddr(out, addr, lenAddr); e != 0 {
		return sErr(e)
	}
	return 0
}

func (g *dguest) shutdown(fd int64, how int) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	if how < 0 || how > 2 {
		return sErr(lxEINVAL)
	}
	s := d.sk
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.typ == lxSockDgram {
		if s.peer == nil && s.pair == nil {
			return sErr(lxENOTCONN)
		}
		return 0
	}
	if s.state != skConnected {
		return sErr(lxENOTCONN)
	}
	if how != 1 {
		s.shutRd = true
		s.rx.eof = true
	}
	if how != 0 && !s.shutWr {
		s.shutWr = true
		if p := s.pair; p != nil {
			p.rx.eof = true
			n.changed(p)
		}
	}
	n.changed(s)
	return 0
}
