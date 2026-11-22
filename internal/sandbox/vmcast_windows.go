package sandbox

import (
	"net/netip"
	"strconv"
)

// Multicast on the run's in-process loopback (lx_vmcast.go): a loop socket's
// memberships, and the delivery of what it sends to a group. Windows joins no
// namespaces with a data plane, so a datagram reaches its own namespace's
// sockets alone.

// loopMembership joins (or, drop, leaves) the IPv4 group an ip_mreq or
// ip_mreqn b names, for s, a loop socket.
func (g *dguest) loopMembership(s *dsock, b []byte, drop bool) int64 {
	if s.typ == lxSockStream {
		return sErr(lxEPROTO)
	}
	group, addr, index, e := mcReq(b)
	if e != 0 {
		return sErr(e)
	}
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	link := n.vmcFind(s.netns, index, addr, group)
	if link == 0 && (!drop || (index == 0 && addr == 0)) {
		return sErr(lxENODEV)
	}
	list, e := mcEdit(s.mcast, mcMember{link, group}, drop)
	if e != 0 {
		return sErr(e)
	}
	s.mcast = list
	delta := 1
	if drop {
		delta = -1
	}
	n.mcDevAdd(mcDevKey{s.netns, link, group}, delta)
	return 0
}

// loopMembership6 joins (or, drop, leaves) the IPv6 group an ipv6_mreq b
// names, for s, a loop socket.
func (g *dguest) loopMembership6(s *dsock, b []byte, drop bool) int64 {
	if len(b) < 20 {
		return sErr(lxEINVAL)
	}
	if s.typ == lxSockStream {
		return sErr(lxEPROTO)
	}
	var m mc6Member
	copy(m.group[:], b[:16])
	if m.group[0] != 0xff {
		return sErr(lxEINVAL)
	}
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if m.link = n.vmcLink6(s.netns, int32(le32(b[16:20]))); m.link == 0 {
		return sErr(lxENODEV)
	}
	list, e := mc6Edit(s.mcast6, m, drop)
	if e != 0 {
		return sErr(e)
	}
	s.mcast6 = list
	return 0
}

// loopSetIf sets IP_MULTICAST_IF for s, a loop socket (mcIfReq).
func (g *dguest) loopSetIf(s *dsock, b []byte) int64 {
	addr, index, e := mcIfReq(b)
	if e != 0 {
		return sErr(e)
	}
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	var link int32
	if index != 0 || addr != 0 {
		if link = n.vmcFind(s.netns, index, addr, 0); link == 0 {
			return sErr(lxEADDRNOTAVAIL)
		}
	}
	s.mcIf, s.mcIfAddr = link, addr
	return 0
}

// loopSetIf6 sets IPV6_MULTICAST_IF for s, a loop socket: an interface that
// exists, or 0 for none, as Linux's do_ipv6_setsockopt takes it.
func (g *dguest) loopSetIf6(s *dsock, b []byte) int64 {
	if s.typ == lxSockStream {
		return sErr(lxENOPROTOOPT)
	}
	if len(b) < 4 {
		return sErr(lxEINVAL)
	}
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if v := int32(le32(b)); v != 0 && !n.vmcHasLink(s.netns, v) {
		return sErr(lxENODEV)
	}
	if s.opts == nil {
		s.opts = map[[2]int][]byte{}
	}
	s.opts[[2]int{lxSolIPv6, 17}] = append([]byte(nil), b[:4]...)
	return 0
}

// loopBindGroup6 binds s, a loop socket, to the IPv6 group raw names, as
// Linux's inet6_bind takes a multicast address: with an interface that
// exists (its scope id) when its scope needs one. Each interface's is an
// address of its own (its zone).
func (g *dguest) loopBindGroup6(s *dsock, raw []byte) int64 {
	if len(raw) < 28 {
		return sErr(lxEINVAL)
	}
	a := [16]byte(raw[8:24])
	link := le32(raw[24:28])
	if !v6Scoped(a[:]) {
		link = 0
	} else if link == 0 {
		return sErr(lxEINVAL)
	}
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if link != 0 && !n.vmcHasLink(s.netns, int32(link)) {
		return sErr(lxENODEV)
	}
	if s.laddr.IsValid() {
		return sErr(lxEINVAL)
	}
	ga := netip.AddrFrom16(a)
	if link != 0 {
		ga = ga.WithZone(strconv.FormatUint(uint64(link), 10))
	}
	if e := n.loopBindLocked(s, netip.AddrPortFrom(ga, uint16(raw[2])<<8|uint16(raw[3]))); e != 0 {
		return sErr(e)
	}
	s.name = group6Sockaddr(a, s.laddr.Port(), link)
	return 0
}

// loopLeaveAll drops what s, closing, joined. n.mu is held.
func (n *dnet) loopLeaveAll(s *dsock) {
	for _, m := range s.mcast {
		n.mcDevAdd(mcDevKey{s.netns, m.link, m.group}, -1)
	}
	s.mcast = nil
}

// optVal is s's value of an option it keeps, Linux's default when it was
// never set (keptDefault). n.mu is held.
func optVal(s *dsock, level, name int) int32 {
	v, ok := s.opts[[2]int{level, name}]
	switch {
	case !ok:
		return keptDefault[[2]int{level, name}]
	case len(v) >= 4:
		return int32(le32(v))
	case len(v) >= 1:
		return int32(v[0])
	}
	return 0
}

// loopMcSend sends buf from s, a loop socket, to group (lx_vmcast.go). n.mu
// is held.
func (n *dnet) loopMcSend(s *dsock, buf []byte, group netip.AddrPort) lxErrno {
	ga := group.Addr().Unmap().As4()
	g4 := beIP(ga[:])
	link, lo, src := n.vmcOut(s.netns, s.mcIf, g4)
	if link == 0 {
		return lxENETUNREACH
	}
	if !s.laddr.IsValid() {
		if e := n.loopBindLocked(s, netip.AddrPortFrom(wildcard(s.family), 0)); e != 0 {
			return e
		}
	}
	from := s.laddr
	if a := from.Addr().Unmap(); a.IsUnspecified() || a.IsMulticast() {
		from = netip.AddrPortFrom(netip.AddrFrom4([4]byte{byte(src >> 24), byte(src >> 16), byte(src >> 8), byte(src)}), from.Port())
	}
	if !lo && optVal(s, lxSolIP, 34) == 0 {
		return 0 // IP_MULTICAST_LOOP off, and no namespace beyond its own to reach
	}
	if n.mcDev[mcDevKey{s.netns, link, g4}] == 0 {
		return 0 // the interface did not take the group in
	}
	ga4 := netip.AddrFrom4(ga)
	for _, o := range n.loops[loopPort{s.netns, lxSockDgram, group.Port()}] {
		if o.closed || o.shutRd || !coverOf(o, o.laddr.Addr()).has(ga4) {
			continue
		}
		if o.raddr.IsValid() && unmapAP(o.raddr) != unmapAP(from) {
			continue
		}
		joined := optVal(o, lxSolIP, lxIPMulticastAll) != 0
		for _, m := range o.mcast {
			joined = joined || m == mcMember{link, g4}
		}
		if !joined || o.rx.n+len(buf) > sockRcvBuf {
			continue
		}
		o.rx.push(sockSeg{b: append([]byte(nil), buf...), from: loopAs(from, o.family)})
		n.changed(o)
	}
	return 0
}

func unmapAP(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
