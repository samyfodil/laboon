//go:build windows

package sandbox

import "net/netip"

// The run's own loopback. A run without Net has, as Linux has with no
// network, only the loopback interface: INET sockets on 127.0.0.0/8 and ::1
// reach each other inside the run and nothing else. A run with Net has the
// host's network but, as a network namespace has, its own loopback: what goes
// to 127.0.0.0/8, ::1 or 0.0.0.0 stays in the run, and a socket bound to a
// wildcard takes connections and datagrams from both (loopClaim). Such a socket (loop) is
// served here like an AF_UNIX one, over the same queues and pairs; only its
// names differ. A name is a bound address and port, in a table per network
// namespace, socket type and port; a wildcard address binds all of its
// family's addresses (an IPv6 one IPv4's too unless IPV6_V6ONLY), and a
// datagram to a port no one bound is dropped, as one the kernel answers with
// an ICMP unreachable.

// The virtual network is served the same way: an address a network namespace
// configured through routing netlink (vnetaddr.go) is reached from every
// namespace of the run, so a socket bound to one is named in a run-wide table
// (scope vnetGlobal) while loopback and wildcard binds stay per namespace. A
// wildcard bind also receives on its namespace's virtual-network addresses.

// loopPort is a bucket of the loopback name table.
type loopPort struct {
	netns int32
	typ   int
	port  uint16
}

// The kernel's default ephemeral range (net.ipv4.ip_local_port_range).
const (
	loopEphemLo = 32768
	loopEphemHi = 60999
)

// loopCover is the set of local addresses a bound socket receives on.
type loopCover struct {
	v4all, v6all bool
	ip           netip.Addr // a single address, v4-mapped ones unmapped
}

func coverOf(s *dsock, a netip.Addr) loopCover {
	a = a.Unmap()
	switch {
	case a.IsUnspecified() && a.Is4():
		return loopCover{v4all: true}
	case a.IsUnspecified():
		return loopCover{v6all: true, v4all: !s.v6only}
	}
	return loopCover{ip: a}
}

func (c loopCover) has(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is4() {
		return c.v4all || c.ip == a
	}
	return c.v6all || c.ip == a
}

func (c loopCover) overlaps(d loopCover) bool {
	switch {
	case c.ip.IsValid() && d.ip.IsValid():
		return c.ip == d.ip
	case c.ip.IsValid():
		return d.has(c.ip)
	case d.ip.IsValid():
		return c.has(d.ip)
	}
	return c.v4all && d.v4all || c.v6all && d.v6all
}

// loopLocal reports whether a is an address of the loopback interface: in
// 127.0.0.0/8 or ::1, or unspecified (a connect to it reaches the host itself).
func loopLocal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsUnspecified()
}

// loopSelf is the address a socket of the family sends from to dest: its
// family's loopback address, v4-mapped on an IPv6 socket sending to IPv4.
func loopSelf(family int, dest netip.Addr) netip.Addr {
	if dest.Unmap().Is4() {
		if family == lxAFInet6 {
			return netip.AddrFrom16(netip.AddrFrom4([4]byte{127, 0, 0, 1}).As16())
		}
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return netip.IPv6Loopback()
}

// loopAs renders ap for a socket of the family: an IPv4 address on an IPv6
// socket is v4-mapped.
func loopAs(ap netip.AddrPort, family int) []byte {
	a := ap.Addr().Unmap()
	if family == lxAFInet6 && a.Is4() {
		a = netip.AddrFrom16(a.As16())
	}
	return linuxAddr(netip.AddrPortFrom(a, ap.Port()), family)
}

// vnetOwner is the namespace holding a, an address of the run's virtual
// network. n.mu is held.
func (n *dnet) vnetOwner(a netip.Addr) (int32, bool) {
	a = a.Unmap()
	if !a.Is4() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
		return 0, false
	}
	b := a.As4()
	ns, ok := n.ipNetns[beIP(b[:])]
	return ns, ok
}

// vnetDest reports whether a socket of netns reaches a on the virtual network.
// n.mu is held.
func (n *dnet) vnetDest(netns int32, a netip.Addr) bool {
	a = a.Unmap()
	if netns == 0 || !a.Is4() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
		return false
	}
	b := a.As4()
	return n.onVirtualNet(netns, beIP(b[:]))
}

// loopKey is the bucket s is named in.
func loopKey(s *dsock) loopPort {
	if s.vscope {
		return loopPort{vnetGlobal, s.typ, s.laddr.Port()}
	}
	return loopPort{s.netns, s.typ, s.laddr.Port()}
}

// loopRivals are the sockets a bind of s covering c at port may collide with:
// those of its own bucket, and those of the other scope sharing addresses with
// it (a virtual-network address's holder's wildcards, or a namespace's own
// virtual-network addresses). n.mu is held.
func (n *dnet) loopRivals(s *dsock, c loopCover, port uint16) []*dsock {
	if c.ip.IsValid() {
		if ns, ok := n.vnetOwner(c.ip); ok {
			out := append([]*dsock(nil), n.loops[loopPort{vnetGlobal, s.typ, port}]...)
			return append(out, n.loops[loopPort{ns, s.typ, port}]...)
		}
	}
	out := append([]*dsock(nil), n.loops[loopPort{s.netns, s.typ, port}]...)
	for _, o := range n.loops[loopPort{vnetGlobal, s.typ, port}] {
		if ns, ok := n.vnetOwner(o.laddr.Addr()); ok && ns == s.netns {
			out = append(out, o)
		}
	}
	return out
}

// loopBindLocked binds s to ap, choosing an ephemeral port for port 0. n.mu
// is held.
func (n *dnet) loopBindLocked(s *dsock, ap netip.AddrPort) lxErrno {
	c := coverOf(s, ap.Addr())
	port := ap.Port()
	if port == 0 {
		for range loopEphemHi - loopEphemLo + 1 {
			n.ephem++
			if n.ephem < loopEphemLo || n.ephem > loopEphemHi {
				n.ephem = loopEphemLo
			}
			if !n.loopTaken(s, c, n.ephem, false) {
				port = n.ephem
				break
			}
		}
		if port == 0 {
			return lxEADDRINUSE
		}
	} else if n.loopTaken(s, c, port, true) {
		return lxEADDRINUSE
	}
	if n.loops == nil {
		n.loops = map[loopPort][]*dsock{}
	}
	_, s.vscope = n.vnetOwner(ap.Addr())
	s.laddr = netip.AddrPortFrom(ap.Addr(), port)
	s.name = loopAs(s.laddr, s.family)
	k := loopKey(s)
	n.loops[k] = append(n.loops[k], s)
	return 0
}

// loopTaken reports whether s, covering c, may not bind port: a socket
// there covers an address it does, and (with share) does not let it share
// (loopShares). A free port is chosen without sharing. n.mu is held.
func (n *dnet) loopTaken(s *dsock, c loopCover, port uint16, share bool) bool {
	for _, o := range n.loopRivals(s, c, port) {
		if !o.closed && o != s && coverOf(o, o.laddr.Addr()).overlaps(c) && !(share && loopShares(s, o)) {
			return true
		}
	}
	return false
}

// loopShares reports whether s may bind over o, whose addresses on the port
// overlap its own, as Linux lets them share it: both by SO_REUSEPORT as one
// uid, or both by SO_REUSEADDR, a stream socket only while o does not listen.
// n.mu is held.
func loopShares(s, o *dsock) bool {
	if optVal(s, lxSolSocket, 15) != 0 && optVal(o, lxSolSocket, 15) != 0 && s.cred.uid == o.cred.uid {
		return true
	}
	return optVal(s, lxSolSocket, 2) != 0 && optVal(o, lxSolSocket, 2) != 0 && (s.typ != lxSockStream || o.state != skListening)
}

// loopListenTaken reports whether s may not listen: a socket sharing its
// port and an address otherwise than by SO_REUSEPORT already listens there,
// which Linux checks for again at listen. n.mu is held.
func (n *dnet) loopListenTaken(s *dsock) bool {
	c := coverOf(s, s.laddr.Addr())
	for _, o := range n.loopRivals(s, c, s.laddr.Port()) {
		if o == s || o.closed || o.state != skListening || !coverOf(o, o.laddr.Addr()).overlaps(c) {
			continue
		}
		if !(optVal(s, lxSolSocket, 15) != 0 && optVal(o, lxSolSocket, 15) != 0 && s.cred.uid == o.cred.uid) {
			return true
		}
	}
	return false
}

// loopUnbind takes s out of the name table. n.mu is held.
func (n *dnet) loopUnbind(s *dsock) {
	if !s.laddr.IsValid() {
		return
	}
	k := loopKey(s)
	l := n.loops[k]
	for i, o := range l {
		if o == s {
			l = append(l[:i], l[i+1:]...)
			break
		}
	}
	if len(l) == 0 {
		delete(n.loops, k)
	} else {
		n.loops[k] = l
	}
}

// loopClaim holds the port of s, a host socket bound to a wildcard address in
// a run with networking, on the run's own loopback too: connections and
// datagrams to the loopback reach it there, as a wildcard bind receives on
// lo. n.mu is held.
func (n *dnet) loopClaim(s *dsock) lxErrno {
	if n.loopTaken(s, coverOf(s, s.laddr.Addr()), s.laddr.Port(), true) {
		return lxEADDRINUSE
	}
	if n.loops == nil {
		n.loops = map[loopPort][]*dsock{}
	}
	k := loopKey(s)
	n.loops[k] = append(n.loops[k], s)
	s.lo = true
	return 0
}

// toLoop makes s, a socket of a run with networking about to reach the
// loopback, a socket of the run's own loopback only: one bound to a wildcard
// gives its host side up and keeps its port, on the loopback address it
// reaches dest from. n.mu is held.
func (n *dnet) toLoop(s *dsock, netns int32, dest netip.Addr) lxErrno {
	port := s.laddr.Port()
	if s.lo {
		n.loopUnbind(s)
		s.lo = false
	}
	if s.pc != nil {
		s.pc.Close()
		s.pc = nil
	}
	s.loop, s.netns, s.laddr = true, netns, netip.AddrPort{}
	if port == 0 {
		return 0
	}
	return n.loopBindLocked(s, netip.AddrPortFrom(loopSelf(s.family, dest), port))
}

// loopTarget is the socket of type typ a connection or datagram from from to
// dest reaches: of those bound to that address, else to a wildcard covering
// it, newest first, the one loopPick chooses. n.mu is held.
func (n *dnet) loopTarget(netns int32, typ int, dest, from netip.AddrPort) *dsock {
	a := loopDst(dest.Addr())
	var exact, wild []*dsock
	ks := []loopPort{{netns, typ, dest.Port()}}
	if ns, ok := n.vnetOwner(a); ok {
		// A virtual-network address: bound by name run-wide, or by a wildcard
		// of the namespace holding it.
		ks = []loopPort{{vnetGlobal, typ, dest.Port()}, {ns, typ, dest.Port()}}
	}
	for _, k := range ks {
		l := n.loops[k]
		for i := len(l) - 1; i >= 0; i-- {
			o := l[i]
			if o.closed {
				continue
			}
			switch c := coverOf(o, o.laddr.Addr()); {
			case c.ip.IsValid() && c.ip == a:
				exact = append(exact, o)
			case c.has(a):
				wild = append(wild, o)
			}
		}
	}
	if o := loopPick(exact, typ, from); o != nil {
		return o
	}
	return loopPick(wild, typ, from)
}

// loopDst is the loopback address a connection or datagram to a reaches: a
// itself, or its family's loopback for the wildcard.
func loopDst(a netip.Addr) netip.Addr {
	switch {
	case !a.Unmap().IsUnspecified():
		return a.Unmap()
	case a.Is6() && !a.Is4In6():
		return netip.IPv6Loopback()
	}
	return netip.AddrFrom4([4]byte{127, 0, 0, 1})
}

// loopPick is the socket of os, newest first, that a datagram or connection
// from from goes to: a datagram to one connected to from, else to one
// connected to none; a connection to a listener. Of sockets sharing by
// SO_REUSEPORT it picks one by a hash of from, as Linux spreads a port's
// flows; else the newest. n.mu is held.
func loopPick(os []*dsock, typ int, from netip.AddrPort) *dsock {
	var free []*dsock
	for _, o := range os {
		switch {
		case typ == lxSockStream:
			if o.state == skListening {
				free = append(free, o)
			}
		case !o.raddr.IsValid():
			free = append(free, o)
		case unmapAP(o.raddr) == unmapAP(from):
			return o
		}
	}
	if len(free) == 0 {
		if typ == lxSockStream && len(os) > 0 {
			return os[0] // no listener: the connection is refused
		}
		return nil
	}
	if optVal(free[0], lxSolSocket, 15) == 0 {
		return free[0]
	}
	var group []*dsock
	for _, o := range free {
		if optVal(o, lxSolSocket, 15) != 0 {
			group = append(group, o)
		}
	}
	b := from.Addr().Unmap().As16()
	h := (uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])) * 2654435761
	h ^= uint32(from.Port()) * 40503
	return group[h%uint32(len(group))]
}

func (g *dguest) loopBind(s *dsock, raw []byte) int64 {
	ap, e := inetAddr(raw, s.family, false)
	if e != 0 {
		return sErr(e)
	}
	if a := ap.Addr(); a.Is6() && !a.Is4In6() && a.IsMulticast() {
		return g.loopBindGroup6(s, raw)
	}
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if a := ap.Addr().Unmap(); !a.IsLoopback() && !a.IsUnspecified() && !(a.Is4() && a.IsMulticast()) {
		if ns, ok := n.vnetOwner(a); !ok || ns != s.netns {
			return sErr(lxEADDRNOTAVAIL) // no interface of its namespace has it, and it is no group
		}
	}
	if s.laddr.IsValid() {
		return sErr(lxEINVAL)
	}
	if e := n.loopBindLocked(s, ap); e != 0 {
		return sErr(e)
	}
	return 0
}

// loopAutobind gives an unbound s an ephemeral port, as the kernel binds it
// on a connect or send: a datagram socket's on the wildcard, a stream's on
// the address it connects to dest from. n.mu is held.
func (n *dnet) loopAutobind(s *dsock, dest netip.Addr) lxErrno {
	if s.laddr.IsValid() {
		return 0
	}
	at := n.loopSrc(s, dest)
	if s.typ == lxSockDgram {
		at = wildcard(s.family)
	}
	return n.loopBindLocked(s, netip.AddrPortFrom(at, 0))
}

// loopNarrow puts s, bound to a wildcard and connecting, at src, the address
// its route picked, as Linux sets a connected socket's local address. n.mu
// is held.
func (n *dnet) loopNarrow(s *dsock, src netip.Addr) {
	if !s.laddr.Addr().Unmap().IsUnspecified() {
		return
	}
	if s.family == lxAFInet6 && src.Is4() {
		src = netip.AddrFrom16(src.As16())
	}
	s.laddr = netip.AddrPortFrom(src, s.laddr.Port())
	s.name = loopAs(s.laddr, s.family)
}

// loopSrc is the address a socket s bound to none reaches dest from, as
// Linux's route lookup picks it: its namespace's own address on the virtual
// network for an address there, else the loopback's. n.mu is held.
func (n *dnet) loopSrc(s *dsock, dest netip.Addr) netip.Addr {
	if n.vnetDest(s.netns, dest) {
		if ip, ok := n.netnsAddr(s.netns); ok {
			a := netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)})
			if s.family == lxAFInet6 {
				a = netip.AddrFrom16(a.As16())
			}
			return a
		}
	}
	return loopSelf(s.family, dest)
}

// loopFrom is the address a datagram from s to dest comes from: its own, or,
// bound to a wildcard or a group, the address it reaches dest from. n.mu is
// held.
func (n *dnet) loopFrom(s *dsock, dest netip.Addr) netip.AddrPort {
	src := s.laddr.Addr()
	if a := src.Unmap(); a.IsUnspecified() || a.IsMulticast() {
		src = n.loopSrc(s, dest).Unmap()
	}
	return netip.AddrPortFrom(src, s.laddr.Port())
}

// loopDest reads a datagram or connection destination for s, which must be on
// the loopback interface or, from a namespace of its own, the virtual network.
func loopDest(s *dsock, raw []byte) (netip.AddrPort, lxErrno) {
	ap, e := inetAddr(raw, s.family, s.typ == lxSockDgram)
	if e != 0 {
		return ap, e
	}
	if loopLocal(ap.Addr()) {
		return ap, 0
	}
	n := s.n
	n.mu.Lock()
	on := n.vnetDest(s.netns, ap.Addr())
	n.mu.Unlock()
	if !on {
		return ap, lxENETUNREACH
	}
	return ap, 0
}

func (g *dguest) loopConnect(d *dfile, raw []byte) int64 {
	s := d.sk
	n := s.n
	if saFamily(raw) == 0 {
		n.mu.Lock()
		defer n.mu.Unlock()
		if s.typ == lxSockDgram {
			s.peer, s.raddr = nil, netip.AddrPort{}
			return 0
		}
		if s.state == skConnected {
			s.shutRd, s.shutWr = true, true
			s.rx.eof = true
			if p := s.pair; p != nil && p.pair == s {
				p.peerGone, p.rx.eof = true, true
				n.changed(p)
			}
			n.changed(s)
		}
		return 0
	}
	if s.typ == lxSockDgram {
		if ap, e := inetAddr(raw, s.family, true); e == 0 && ap.Addr().Unmap().Is4() && ap.Addr().Unmap().IsMulticast() {
			// A group is a datagram socket's peer like any address.
			n.mu.Lock()
			defer n.mu.Unlock()
			ga := ap.Addr().Unmap().As4()
			link, _, src := n.vmcOut(s.netns, s.mcIf, beIP(ga[:]))
			if link == 0 {
				return sErr(lxENETUNREACH)
			}
			if e := n.loopAutobind(s, ap.Addr()); e != 0 {
				return sErr(e)
			}
			n.loopNarrow(s, netip.AddrFrom4([4]byte{byte(src >> 24), byte(src >> 16), byte(src >> 8), byte(src)}))
			s.raddr, s.peer = ap, loopAs(ap, s.family)
			return 0
		}
	}
	ap, e := loopDest(s, raw)
	if e != 0 {
		return sErr(e)
	}
	cr := g.creds()
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.typ == lxSockDgram {
		if e := n.loopAutobind(s, ap.Addr()); e != 0 {
			return sErr(e)
		}
		n.loopNarrow(s, n.loopSrc(s, ap.Addr()))
		s.raddr, s.peer = ap, loopAs(ap, s.family)
		return 0
	}
	switch s.state {
	case skConnected:
		return sErr(lxEISCONN)
	case skListening:
		return sErr(lxEINVAL)
	}
	if e := n.loopAutobind(s, ap.Addr()); e != 0 {
		return sErr(e)
	}
	n.loopNarrow(s, n.loopSrc(s, ap.Addr()))
	l := n.loopTarget(s.netns, s.typ, ap, s.laddr)
	if l == nil || l.state != skListening {
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
	srv := &dsock{family: l.family, typ: s.typ, proto: s.proto, n: n, ino: n.ino, cred: l.cred, maxBack: 128, loop: true, netns: l.netns}
	srv.laddr = netip.AddrPortFrom(loopDst(ap.Addr()), ap.Port())
	srv.name, srv.peer = loopAs(srv.laddr, l.family), loopAs(s.laddr, l.family)
	srv.pair, s.pair = s, srv
	srv.state, s.state = skConnected, skConnected
	s.peerCred, srv.peerCred = l.cred, cr
	s.raddr, s.peer = ap, loopAs(ap, s.family)
	l.backlog = append(l.backlog, srv)
	n.changed(l)
	n.changed(s)
	return 0
}

// loopSend sends one datagram, to dest or the connected peer. One to a port no
// one bound, or past a full receive queue, is dropped, as the kernel drops it.
func (g *dguest) loopSend(s *dsock, iovs [][2]uint64, total int, dest []byte) int64 {
	if total > udpMax {
		return sErr(lxEMSGSIZE)
	}
	var ap netip.AddrPort
	group := false
	if dest != nil {
		var e lxErrno
		if ap, e = inetAddr(dest, s.family, true); e == 0 && ap.Addr().Unmap().Is4() && ap.Addr().Unmap().IsMulticast() {
			group = true
		} else if ap, e = loopDest(s, dest); e != 0 {
			return sErr(e)
		}
	}
	buf, e := g.gather(iovs, 0, total)
	if e != 0 {
		return sErr(e)
	}
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if dest == nil {
		if s.peer == nil {
			return sErr(lxEDESTADDRREQ)
		}
		ap = s.raddr
		group = ap.Addr().Unmap().Is4() && ap.Addr().Unmap().IsMulticast()
	}
	if s.shutWr {
		return sErr(lxEPIPE)
	}
	if group {
		if e := n.loopMcSend(s, buf, ap); e != 0 {
			return sErr(e)
		}
		return int64(total)
	}
	if e := n.loopAutobind(s, ap.Addr()); e != 0 {
		return sErr(e)
	}
	from := n.loopFrom(s, ap.Addr())
	to := n.loopTarget(s.netns, s.typ, ap, from)
	if to == nil || to.shutRd || to.rx.n+len(buf) > sockRcvBuf {
		return int64(total)
	}
	to.rx.push(sockSeg{b: buf, from: loopAs(from, to.family)})
	n.changed(to)
	return int64(total)
}
