//go:build windows

package sandbox

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The socket data path on Windows: send and receive over the queues of
// net_windows.go, the host pumps behind inet sockets, DNS answers, and
// SCM_RIGHTS.

// recvResult is one received message, ready for the guest.
type recvResult struct {
	data  []byte
	full  int    // the datagram's real length (== len(data) for a stream)
	from  []byte // guest sockaddr of the sender, nil if none
	oob   []*dfile
	cred  ucred // the AF_UNIX sender's
	flags uint32
}

// recvOobCap is how much control data a receive takes: AF_UNIX sockets carry
// SCM_RIGHTS, nothing else carries any.
func recvOobCap(sk *dsock) int {
	if sk.family == lxAFUnix {
		return 1024
	}
	return 0
}

// ---- host pumps -----------------------------------------------------------------

// startTCP makes c s's connection and starts its pumps. n.mu is held.
func (n *dnet) startTCP(s *dsock, c net.Conn) {
	s.conn, s.state = c, skConnected
	go n.readLoop(s, c)
	go n.writeLoop(s, c)
}

// readLoop fills s's receive queue from c, pausing while the queue is full.
func (n *dnet) readLoop(s *dsock, c net.Conn) {
	buf := make([]byte, 64<<10)
	for {
		m, err := c.Read(buf)
		n.mu.Lock()
		if m > 0 && !s.shutRd && !s.closed {
			s.rx.push(sockSeg{b: append([]byte(nil), buf[:m]...)})
		}
		if err != nil {
			s.rx.eof = true
			if !errors.Is(err, io.EOF) && !s.closed {
				if e := sockErrno(err); e == lxECONNRESET || e == lxECONNABORTED {
					s.rx.err = lxECONNRESET
					if s.txErr == 0 {
						s.txErr = lxECONNRESET
					}
				}
			}
			n.changed(s)
			n.mu.Unlock()
			return
		}
		n.changed(s)
		for !s.closed && s.rx.n >= sockRcvBuf {
			n.cond.Wait()
		}
		closed := s.closed
		n.mu.Unlock()
		if closed {
			return
		}
	}
}

// writeLoop drains s's send queue into c. After shutdown(SHUT_WR) it sends
// FIN once the queue is empty; after close it flushes what is queued and
// closes c.
func (n *dnet) writeLoop(s *dsock, c net.Conn) {
	n.mu.Lock()
	for {
		for len(s.tx) == 0 && !s.closed && !(s.shutWr && !s.wrDone) {
			n.cond.Wait()
		}
		if len(s.tx) == 0 {
			if s.closed {
				break
			}
			s.wrDone = true
			n.mu.Unlock()
			if tc, ok := c.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
			n.mu.Lock()
			continue
		}
		chunk := append([]byte(nil), s.tx[:min(len(s.tx), 64<<10)]...)
		if s.closed {
			c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		}
		n.mu.Unlock()
		m, err := c.Write(chunk)
		n.mu.Lock()
		s.tx = s.tx[m:]
		if err != nil {
			if s.txErr == 0 {
				s.txErr = lxEPIPE
			}
			s.tx = nil
			n.changed(s)
			for !s.closed {
				n.cond.Wait()
			}
			break
		}
		n.changed(s)
	}
	n.mu.Unlock()
	c.Close()
}

// startUDP makes pc s's host socket and starts its receive pump. n.mu is
// held.
func (n *dnet) startUDP(s *dsock, pc *net.UDPConn) {
	s.pc = pc
	go n.udpLoop(s, pc)
}

func (n *dnet) udpLoop(s *dsock, pc *net.UDPConn) {
	buf := make([]byte, 65536)
	for {
		m, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			n.mu.Lock()
			closed := s.closed
			n.mu.Unlock()
			if closed {
				return
			}
			continue // an ICMP error for an earlier send
		}
		n.mu.Lock()
		if s.closed {
			n.mu.Unlock()
			return
		}
		keep := !s.raddr.IsValid() || s.dns || sameHost(s.raddr, from)
		if keep && s.rx.n+m <= sockRcvBuf {
			s.rx.push(sockSeg{b: append([]byte(nil), buf[:m]...), from: linuxAddr(from, s.family)})
			n.changed(s)
		}
		n.mu.Unlock()
	}
}

func sameHost(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
}

// autobindUDP gives a datagram socket its host socket on an ephemeral port,
// as a send or connect does on Linux.
func (n *dnet) autobindUDP(s *dsock) lxErrno {
	n.mu.Lock()
	has := s.pc != nil
	n.mu.Unlock()
	if has {
		return 0
	}
	pc, err := net.ListenUDP(s.hostNet(), net.UDPAddrFromAddrPort(netip.AddrPortFrom(wildcard(s.family), 0)))
	if err != nil {
		return sockErrno(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.pc != nil || s.closed {
		pc.Close()
		return 0
	}
	s.laddr = addrPortOf(pc.LocalAddr())
	n.startUDP(s, pc)
	return 0
}

// connectUDP connects a datagram socket's host side to ap, so the host's
// routing answers as Linux's would (ENETUNREACH; getsockname then names the
// source address). A socket the guest bound keeps its host socket and only
// checks the route.
func (n *dnet) connectUDP(s *dsock, ap netip.AddrPort) lxErrno {
	to := net.UDPAddrFromAddrPort(ap)
	network := s.hostNet()
	if a := ap.Addr(); a.Is4In6() {
		to = net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.Unmap(), ap.Port()))
		network = "udp4"
	}
	n.mu.Lock()
	bound := s.pc != nil && !s.pcConn
	n.mu.Unlock()
	if bound {
		probe, err := net.DialUDP(network, nil, to)
		if err != nil {
			return sockErrno(err)
		}
		probe.Close()
		return 0
	}
	pc, err := net.DialUDP(network, nil, to)
	if err != nil {
		return sockErrno(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.closed {
		pc.Close()
		return lxEBADF
	}
	if old := s.pc; old != nil {
		old.Close()
	}
	s.laddr = addrPortOf(pc.LocalAddr())
	n.startUDP(s, pc)
	s.pcConn = true
	return 0
}

// dnsSend answers a DNS query the guest sent to the server ns: the egress
// policy resolves it off the guest's thread and the reply is queued on s as
// a datagram from ns.
func (n *dnet) dnsSend(s *dsock, q, ns []byte) {
	q = append([]byte(nil), q...) // the thread's next send reuses q's buffer
	go func() {
		reply := n.eg.answer(q, hostLookup)
		if reply == nil {
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if s.closed || s.rx.n+len(reply) > sockRcvBuf {
			return
		}
		s.rx.push(sockSeg{b: reply, from: ns})
		n.changed(s)
	}()
}

// netlinkSend answers the guest's netlink requests: each reply datagram is
// queued on s as from the kernel before the send returns.
func (g *dguest) netlinkSend(s *dsock, iovs [][2]uint64, total int) int64 {
	req, e := g.gather(iovs, 0, min(total, 65536))
	if e != 0 {
		return sErr(e)
	}
	replies := s.nl.queue(g.nlReplies(req, g.ps.netns.Load()), uint32(g.tgid))
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, dg := range replies {
		s.rx.push(sockSeg{b: dg, from: sockaddrNl(0)})
	}
	n.changed(s)
	return int64(total)
}

// netlinkReceived follows a receive with an n-byte buffer: the running dump,
// if any, queues its next datagram.
func (g *dguest) netlinkReceived(s *dsock, n int) {
	dg := s.nl.received(n)
	if dg == nil {
		return
	}
	s.n.mu.Lock()
	defer s.n.mu.Unlock()
	s.rx.push(sockSeg{b: dg, from: sockaddrNl(0)})
	s.n.changed(s)
}

// ---- send -----------------------------------------------------------------------

// sendIov sends the iovec list on a socket: to dest (a guest sockaddr) when
// given, with the guest's control messages ctl (SCM_RIGHTS on AF_UNIX).
func (g *dguest) sendIov(d *dfile, iovs [][2]uint64, dest, ctl []byte, flags uint32) int64 {
	s := d.sk
	total := iovTotal(iovs)
	nb := d.nonblock.Load() || flags&lxMsgDontwait != 0
	if s.family == lxAFNetlink {
		return g.netlinkSend(s, iovs, total)
	}
	if !s.local() {
		if s.typ == lxSockDgram {
			if dest != nil {
				// To the run's own loopback: in-process, from the wildcard
				// port a socket holds there, or as a socket of it.
				if ap, e := inetAddr(dest, s.family, true); e == 0 && loopLocal(ap.Addr()) && ap.Port() != 53 {
					n := s.n
					n.mu.Lock()
					var e lxErrno
					if !s.lo && !s.laddr.IsValid() {
						e = n.toLoop(s, g.ps.netns.Load(), ap.Addr())
					}
					n.mu.Unlock()
					if e != 0 {
						return sErr(e)
					}
					return g.loopSend(s, iovs, total, dest)
				}
			}
			return g.udpSend(s, iovs, total, dest)
		}
		return g.tcpSend(s, iovs, total, nb)
	}
	if s.loop && s.typ == lxSockDgram {
		return g.loopSend(s, iovs, total, dest)
	}
	if s.loop {
		dest = nil // TCP ignores a send's address
	}
	var rights []*dfile
	if len(ctl) > 0 {
		var e lxErrno
		if rights, e = g.sendRights(ctl); e != 0 {
			return sErr(e)
		}
	}
	r := g.unixSend(s, iovs, total, dest, rights, g.sentCred(ctl), nb)
	if r < 0 {
		for _, f := range rights {
			f.unref()
		}
	}
	return r
}

// sendRights takes a reference to each description an SCM_RIGHTS message
// names.
func (g *dguest) sendRights(ctl []byte) ([]*dfile, lxErrno) {
	var out []*dfile
	fail := func(e lxErrno) ([]*dfile, lxErrno) {
		for _, f := range out {
			f.unref()
		}
		return nil, e
	}
	for off := 0; off+16 <= len(ctl); {
		l := int(le64(ctl[off:]))
		if l < 16 || off+l > len(ctl) {
			return fail(lxEINVAL)
		}
		level, typ := int32(le32(ctl[off+8:])), int32(le32(ctl[off+12:]))
		if level == lxSolSocket && typ == lxScmRights {
			data := ctl[off+16 : off+l]
			for i := 0; i+4 <= len(data); i += 4 {
				f, ok := g.ft.get(int(int32(le32(data[i:]))))
				if !ok {
					return fail(lxEBADF)
				}
				if len(out) >= 253 {
					return fail(lxETOOMANYREFS)
				}
				f.refs.Add(1)
				out = append(out, f)
			}
		}
		off += (l + 7) &^ 7
	}
	return out, 0
}

// unixSend queues data on the peer: a connected stream's or seqpacket's pair,
// or a datagram socket's destination.
func (g *dguest) unixSend(s *dsock, iovs [][2]uint64, total int, dest []byte, rights []*dfile, cred ucred, nb bool) int64 {
	n := s.n
	var to *dsock
	if dest != nil {
		if s.typ != lxSockDgram {
			n.mu.Lock()
			connected := s.state == skConnected
			n.mu.Unlock()
			if connected {
				return sErr(lxEISCONN)
			}
			return sErr(lxEOPNOTSUPP)
		}
		key, _, e := g.unixKey(s, dest, false)
		if e != 0 {
			return sErr(e)
		}
		n.mu.Lock()
		to = n.names[key]
		n.mu.Unlock()
		if to == nil {
			return sErr(lxECONNREFUSED)
		}
		if to.typ != lxSockDgram {
			return sErr(lxEPROTOTYPE)
		}
	}
	stream := s.typ == lxSockStream
	if !stream && total > sockRcvBuf {
		return sErr(lxEMSGSIZE)
	}
	end := deadlineOf(s.sndTimeo)
	sent := 0
	for first := true; first || sent < total; first = false {
		buf, e := g.gather(iovs, sent, min(total-sent, sockRcvBuf))
		if e != 0 {
			return partial(sent, e)
		}
		n.mu.Lock()
		for {
			p := to
			if p == nil {
				p = s.pair
			}
			switch {
			case s.shutWr:
				n.mu.Unlock()
				return partial(sent, lxEPIPE)
			case p == nil && s.peerGone:
				n.mu.Unlock()
				return partial(sent, lxEPIPE)
			case p == nil && s.typ == lxSockDgram && s.peer == nil:
				n.mu.Unlock()
				return sErr(lxENOTCONN)
			case p == nil || p.closed:
				n.mu.Unlock()
				if s.typ == lxSockDgram {
					return sErr(lxECONNREFUSED)
				}
				return partial(sent, lxEPIPE)
			case p.shutRd && !stream:
				n.mu.Unlock()
				return sErr(lxEPIPE)
			}
			room := sockRcvBuf - p.rx.n
			if stream && room > 0 && len(buf) > 0 || !stream && (room >= len(buf) || p.rx.n == 0) {
				take := len(buf)
				if stream {
					take = min(room, len(buf))
				}
				seg := sockSeg{b: append([]byte(nil), buf[:take]...), rights: rights, cred: cred}
				if s.typ == lxSockDgram {
					seg.from = s.name
				}
				rights = nil
				if !p.shutRd {
					p.rx.push(seg)
				} else {
					for _, f := range seg.rights {
						defer f.unref()
					}
				}
				n.changed(p)
				sent += take
				buf = buf[take:]
				if len(buf) == 0 {
					break
				}
				continue
			}
			if len(buf) == 0 {
				break
			}
			if nb {
				n.mu.Unlock()
				return partial(sent, lxEAGAIN)
			}
			if e := g.wait(n, end); e != 0 {
				n.mu.Unlock()
				return partial(sent, e)
			}
		}
		n.mu.Unlock()
		if total == 0 {
			break
		}
	}
	return int64(sent)
}

// partial is a send's result: what it moved, or e when nothing.
func partial(sent int, e lxErrno) int64 {
	if sent > 0 {
		return int64(sent)
	}
	return sErr(e)
}

func (g *dguest) tcpSend(s *dsock, iovs [][2]uint64, total int, nb bool) int64 {
	n := s.n
	end := deadlineOf(s.sndTimeo)
	sent := 0
	for sent < total || total == 0 {
		buf, e := g.gather(iovs, sent, min(total-sent, sockSndBuf))
		if e != 0 {
			return partial(sent, e)
		}
		n.mu.Lock()
		for {
			if s.txErr != 0 {
				e := s.txErr
				s.txErr = lxEPIPE
				n.mu.Unlock()
				return partial(sent, e)
			}
			if s.shutWr {
				n.mu.Unlock()
				return partial(sent, lxEPIPE)
			}
			if s.state != skConnected && s.state != skConnecting {
				n.mu.Unlock()
				return partial(sent, lxENOTCONN)
			}
			if total == 0 {
				n.mu.Unlock()
				return 0
			}
			if room := sockSndBuf - len(s.tx); s.state == skConnected && room > 0 {
				take := min(room, len(buf))
				s.tx = append(s.tx, buf[:take]...)
				sent += take
				buf = buf[take:]
				n.notify()
				if len(buf) == 0 {
					break
				}
				continue
			}
			if nb {
				n.mu.Unlock()
				return partial(sent, lxEAGAIN)
			}
			if e := g.wait(n, end); e != 0 {
				n.mu.Unlock()
				return partial(sent, e)
			}
		}
		n.mu.Unlock()
	}
	return int64(sent)
}

func (g *dguest) udpSend(s *dsock, iovs [][2]uint64, total int, dest []byte) int64 {
	n := s.n
	var ap netip.AddrPort
	var ns []byte
	if dest != nil {
		var e lxErrno
		if ap, e = inetAddr(dest, s.family, true); e != 0 {
			return sErr(e)
		}
		ns = normSockaddr(dest)
	} else {
		n.mu.Lock()
		ap, ns = s.raddr, s.peer
		n.mu.Unlock()
		if !ap.IsValid() {
			return sErr(lxEDESTADDRREQ)
		}
	}
	if total > udpMax {
		return sErr(lxEMSGSIZE)
	}
	data, e := g.gather(iovs, 0, total)
	if e != 0 {
		return sErr(e)
	}
	if ap.Port() == 53 {
		if e := n.autobindUDP(s); e != 0 {
			return sErr(e)
		}
		n.dnsSend(s, data, ns)
		return int64(total)
	}
	if !g.egressOK(ap) {
		return sErr(lxEPERM)
	}
	if e := n.autobindUDP(s); e != 0 {
		return sErr(e)
	}
	n.mu.Lock()
	pc := s.pc
	n.mu.Unlock()
	n.mu.Lock()
	pcConn, raddr := s.pcConn, s.raddr
	n.mu.Unlock()
	var err error
	switch {
	case pcConn && sameHost(ap, raddr):
		_, err = pc.Write(data)
	case pcConn:
		return sErr(lxEISCONN)
	default:
		to := ap
		if s.family == lxAFInet || s.hostNet() == "udp4" {
			to = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		}
		_, err = pc.WriteToUDPAddrPort(data, to)
	}
	if err != nil {
		return sErr(sockErrno(err))
	}
	return int64(total)
}

// ---- receive --------------------------------------------------------------------

// recv takes up to want bytes from the receive queue: a stream's bytes (up to
// and including a piece that carries descriptors) or one datagram.
func (g *dguest) recv(d *dfile, want, oobCap int, flags uint32) (recvResult, lxErrno) {
	s := d.sk
	n := s.n
	var r recvResult
	if flags&lxMsgOob != 0 {
		return r, lxEINVAL
	}
	nb := d.nonblock.Load() || flags&lxMsgDontwait != 0
	peek := flags&lxMsgPeek != 0
	stream := s.typ == lxSockStream
	waitall := stream && flags&lxMsgWaitall != 0 && !peek && !nb
	var rel []*dfile
	defer func() {
		for _, f := range rel {
			f.unref()
		}
	}()
	n.mu.Lock()
	defer n.mu.Unlock()
	pc := s.opts[[2]int{lxSolSocket, lxSoPasscred}]
	passcred := s.family == lxAFUnix && len(pc) >= 4 && le32(pc) != 0
	credSet := false
	end := deadlineOf(s.rcvTimeo)
	// consumed wakes what waits for room: the reader pump, a unix peer.
	consumed := func() {
		n.notify()
		if p := s.pair; p != nil {
			n.changed(p)
		}
	}
	for {
		if stream && want == 0 {
			return r, 0
		}
		if len(s.rx.segs) > 0 {
			if !stream {
				seg := s.rx.segs[0]
				r.full = len(seg.b)
				r.data = append([]byte(nil), seg.b[:min(want, len(seg.b))]...)
				if r.full > len(r.data) {
					r.flags |= lxMsgTrunc
				}
				r.from = seg.from
				r.oob = seg.rights
				r.cred = seg.cred
				if peek {
					for _, f := range r.oob {
						f.refs.Add(1)
					}
				} else {
					s.rx.segs = s.rx.segs[1:]
					s.rx.n -= len(seg.b)
					consumed()
				}
				break
			}
			stop := false
			for i := 0; i < len(s.rx.segs) && len(r.data) < want && !stop; i++ {
				seg := &s.rx.segs[i]
				if passcred {
					// Never glue messages from different writers.
					if credSet && seg.cred != r.cred {
						stop = true
						break
					}
					r.cred, credSet = seg.cred, true
				}
				k := min(want-len(r.data), len(seg.b))
				r.data = append(r.data, seg.b[:k]...)
				if len(seg.rights) > 0 {
					stop = true
					if peek {
						for _, f := range seg.rights {
							f.refs.Add(1)
						}
						r.oob = append(r.oob, seg.rights...)
					} else {
						r.oob = append(r.oob, seg.rights...)
						seg.rights = nil
					}
				}
				if !peek {
					seg.b = seg.b[k:]
					s.rx.n -= k
				}
			}
			if !peek {
				for len(s.rx.segs) > 0 && len(s.rx.segs[0].b) == 0 && len(s.rx.segs[0].rights) == 0 {
					s.rx.segs = s.rx.segs[1:]
				}
				consumed()
			}
			if !waitall || len(r.data) >= want || stop {
				break
			}
		}
		if len(r.data) > 0 && (s.rx.eof || s.rx.err != 0) {
			break
		}
		if s.rx.err != 0 {
			e := s.rx.err
			s.rx.err = 0
			return r, e
		}
		if s.rx.eof || s.shutRd || s.peerGone {
			break
		}
		if stream && s.state != skConnected && s.state != skConnecting {
			return r, lxENOTCONN
		}
		if nb {
			if len(r.data) > 0 {
				break
			}
			return r, lxEAGAIN
		}
		if e := g.wait(n, end); e != 0 {
			if len(r.data) > 0 {
				break
			}
			return r, e
		}
	}
	if stream {
		r.full = len(r.data)
	}
	if oobCap == 0 && len(r.oob) > 0 {
		rel, r.oob = r.oob, nil
	}
	return r, 0
}

// recvInto receives into the iovec list, returning the message and the byte
// count delivered.
func (g *dguest) recvInto(d *dfile, iovs [][2]uint64, oobCap int, flags uint32) (recvResult, int, lxErrno) {
	r, e := g.recv(d, iovTotal(iovs), oobCap, flags)
	if e != 0 {
		return r, 0, e
	}
	if d.sk.nl != nil {
		g.netlinkReceived(d.sk, iovTotal(iovs))
	}
	if e := g.scatter(iovs, 0, r.data); e != 0 {
		for _, f := range r.oob {
			f.unref()
		}
		r.oob = nil
		return r, 0, e
	}
	return r, len(r.data), 0
}

// guestControl installs received descriptors in the caller's table and
// renders them as one SCM_RIGHTS message in room bytes; those that do not fit
// are closed, with MSG_CTRUNC.
func (g *dguest) guestControl(oob []*dfile, room int, cloexec, peek bool) ([]byte, uint32) {
	fit := 0
	if room >= 20 {
		fit = (room - 16) / 4
	}
	var data []byte
	var flags uint32
	for i, f := range oob {
		if i >= fit {
			f.unref()
			flags |= lxMsgCtrunc
			continue
		}
		fd := g.ft.add(f, 0)
		f.unref()
		if fd < 0 {
			flags |= lxMsgCtrunc
			continue
		}
		if cloexec {
			g.ft.setCloexec(fd, true)
		}
		data = append(data, i32bytes(fd)...)
	}
	if len(data) == 0 {
		return nil, flags
	}
	out, f := putCmsg(nil, room, lxSolSocket, lxScmRights, data)
	return out, flags | f
}

// ---- ioctl ----------------------------------------------------------------------

const (
	lxFionread = 0x541b
	lxSiocoutq = 0x5411
)

// sockIoctl serves FIONREAD on sockets and pipes and SIOCOUTQ on sockets. ok
// is false for a request it does not handle.
func (g *dguest) sockIoctl(d *dfile, req, arg uint64) (int64, bool) {
	var v int
	switch {
	case req == lxFionread && d.pipe != nil && d.pipe.io != nil:
		switch p := d.pipe.io.(type) {
		case *bufferPipe:
			p.n.mu.Lock()
			v = p.used
			p.n.mu.Unlock()
		case *pipeEnd:
			v = p.avail()
		}
	case d.sk != nil && (req == lxFionread || req == lxSiocoutq):
		s := d.sk
		s.n.mu.Lock()
		switch {
		case req == lxSiocoutq:
			v = len(s.tx)
		case s.state == skListening:
			s.n.mu.Unlock()
			return sErr(lxEINVAL), true
		case s.typ == lxSockStream:
			v = s.rx.n
		case len(s.rx.segs) > 0:
			v = len(s.rx.segs[0].b)
		}
		s.n.mu.Unlock()
	case req == lxFionread && d.f != nil && d.sk == nil && d.ev == nil && d.ep == nil:
		avail, ok := pipeAvail(d.f)
		if !ok {
			return 0, false
		}
		v = int(avail)
	case d.sk != nil:
		return g.ifIoctl(req, arg)
	default:
		return 0, false
	}
	if err := g.writeMem(arg, i32bytes(v)); err != nil {
		return sErr(lxEFAULT), true
	}
	return 0, true
}

// pipeAvail is the byte count waiting in a pipe; ok is false for anything
// else.
func pipeAvail(f *os.File) (uint32, bool) {
	h := windows.Handle(f.Fd())
	if t, _ := windows.GetFileType(h); t != windows.FILE_TYPE_PIPE {
		return 0, false
	}
	var avail uint32
	r, _, _ := procPeekNamedPipe.Call(uintptr(h), 0, 0, 0, uintptr(unsafe.Pointer(&avail)), 0)
	return avail, r != 0
}
