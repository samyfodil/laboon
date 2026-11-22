//go:build darwin || linux

package sandbox

import (
	"net"
	"os"
	"sort"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The socket data path: send/recv, msghdr and control messages (SCM_RIGHTS),
// the mmsg batches, plain read/write/readv/writev on a socket, and the
// in-supervisor DNS answers.

func dwSendFlags(lx uint32) int {
	var dw int
	if lx&lxMsgOob != 0 {
		dw |= unix.MSG_OOB
	}
	if lx&lxMsgDontroute != 0 {
		dw |= unix.MSG_DONTROUTE
	}
	if lx&lxMsgEor != 0 {
		dw |= unix.MSG_EOR
	}
	return dw
}

func dwRecvFlags(lx uint32) int {
	var dw int
	if lx&lxMsgOob != 0 {
		dw |= unix.MSG_OOB
	}
	if lx&lxMsgPeek != 0 {
		dw |= unix.MSG_PEEK
	}
	return dw
}

func lxRecvFlagsOut(dw int) uint32 {
	var lx uint32
	if dw&unix.MSG_OOB != 0 {
		lx |= lxMsgOob
	}
	if dw&unix.MSG_EOR != 0 {
		lx |= lxMsgEor
	}
	if dw&unix.MSG_TRUNC != 0 {
		lx |= lxMsgTrunc
	}
	if dw&unix.MSG_CTRUNC != 0 {
		lx |= lxMsgCtrunc
	}
	return lx
}

// ---- guest buffers -------------------------------------------------------------

// ---- send ----------------------------------------------------------------------

// sendIov sends the iovec list on a socket: to dest (a guest sockaddr) when
// given, with the guest's Linux control messages ctl.
func (g *dguest) sendIov(d *dfile, iovs [][2]uint64, dest, ctl []byte, flags uint32) int64 {
	sk := d.sk
	if sk.nl != nil {
		return g.netlinkSend(d, iovs)
	}
	if sk.virt && sk.typ != lxSockStream {
		// A datagram on a virtual socket (DNS); a connected virtual stream writes
		// through the normal path to its paired backing.
		return g.virtSend(d, iovs, dest)
	}
	if sk.sp != nil && sk.sp.peerClosed(sk.side) {
		return sErr(lxEPIPE)
	}
	total := iovTotal(iovs)
	var to unix.Sockaddr
	var unixDest unixReach
	sk.mu.Lock()
	dnsPeer := sk.dns
	peer := sk.peer
	sk.mu.Unlock()
	switch {
	case dest != nil && sk.typ == lxSockStream:
		if sk.family == lxAFUnix {
			return sErr(lxEISCONN)
		}
	case dest != nil && sk.family == lxAFUnix:
		reach, _, e := g.unixTarget(dest)
		if e != 0 {
			return sErr(e)
		}
		unixDest = reach
	case dest != nil:
		sa, e := inetSockaddr(dest, sk.family, true)
		if e != 0 {
			return sErr(e)
		}
		if saPortOf(sa) == 53 {
			return g.dnsSend(d, iovs, normSockaddr(dest))
		}
		if g.hostNet() && sk.inet() {
			// To the run's own loopback (vlo_unix.go).
			if ip, port, v6, loop, any := vloIP(dest); loop || any {
				if !g.vloSide(d) {
					return sErr(lxEPERM)
				}
				return g.vloSend(d, iovs, ip, port, v6)
			}
		}
		if !g.egressOK(sa) {
			return sErr(lxEPERM)
		}
		to = sa
	case dnsPeer:
		return g.dnsSend(d, iovs, peer)
	}
	if total > dgramMax && sk.typ != lxSockStream {
		return sErr(lxEMSGSIZE)
	}
	// Record the sender's credentials for the connected peer before the data is
	// deliverable, so a peer that wakes on this message never finds none.
	if sk.cl != nil {
		g.sendCreds(d, ctl)
	}
	var oob []byte
	if len(ctl) > 0 {
		var tokens []int
		var e lxErrno
		if oob, tokens, e = g.hostControl(ctl); e != 0 {
			g.netState().sweep()
			return sErr(e)
		}
		defer closeAll(tokens)
	}
	nb := d.nonblock.Load() || flags&lxMsgDontwait != 0
	dwFlags := dwSendFlags(flags)
	sent := 0
	for {
		chunk := total - sent
		if sk.typ == lxSockStream && chunk > sendChunk {
			chunk = sendChunk
		}
		buf, e := g.gather(iovs, sent, chunk)
		if e != 0 {
			return sErr(e)
		}
		for off := 0; ; {
			var n int
			err := g.sockIO(d, true, nb, sk.timeout(true), func(h int) error {
				var err error
				if unixDest != nil {
					err = unixDest(func(sa *unix.SockaddrUnix) error {
						n, err = unix.SendmsgN(h, buf[off:], oob, sa, dwFlags)
						return err
					})
					return err
				}
				n, err = unix.SendmsgN(h, buf[off:], oob, to, dwFlags)
				return err
			})
			if err != nil {
				if sent+off > 0 {
					return int64(sent + off)
				}
				if unixDest != nil && err == unix.ENOTSOCK {
					err = unix.ECONNREFUSED // the name is not a socket
				}
				return sErr(osErrno(err))
			}
			oob = nil
			off += n
			if off >= len(buf) || sk.typ != lxSockStream {
				sent += off
				break
			}
			if nb {
				return int64(sent + off)
			}
		}
		if sent >= total || sk.typ != lxSockStream {
			return int64(sent)
		}
	}
}

// ---- descriptor passing ----------------------------------------------------------

// An fd sent over SCM_RIGHTS travels as a token: the read end of a fresh host
// pipe, whose inode names the sender's open-file description in dnet.lent
// (which holds a reference to it). The receiver trades the token back for
// that same description, so every kind of fd crosses (stdio served in the
// stub, eventfd, epoll, a directory with its guest path) and the description
// is shared as on Linux, O_NONBLOCK and offset included. The supervisor keeps
// the write end to notice a token that dies unreceived (its socket closed
// with the message queued): a write then fails with EPIPE.
type lent struct {
	d *dfile
	w int
}

func fdKey(fd int) ([2]uint64, bool) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return [2]uint64{}, false
	}
	return [2]uint64{uint64(st.Dev), st.Ino}, true
}

// lend registers d for sending and returns the token fd to send; the caller
// closes it once the message is sent (or not).
func (n *dnet) lend(d *dfile) (int, lxErrno) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked()
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		return -1, osErrno(err)
	}
	unix.CloseOnExec(p[0])
	unix.CloseOnExec(p[1])
	unix.SetNonblock(p[1], true)
	pipeNoSigpipe(p[1])
	k, _ := fdKey(p[0])
	d.refs.Add(1)
	n.lent[k] = lent{d: d, w: p[1]}
	return p[0], 0
}

// sweepLocked releases the descriptions whose tokens no longer exist.
func (n *dnet) sweepLocked() {
	for k, l := range n.lent {
		if _, err := unix.Write(l.w, []byte{0}); err == unix.EPIPE {
			l.d.unref()
			unix.Close(l.w)
			delete(n.lent, k)
		}
	}
}

func (n *dnet) sweep() {
	n.mu.Lock()
	n.sweepLocked()
	n.mu.Unlock()
}

// claim trades a received token for the description it names, with one
// reference for the caller. A peek leaves the token valid for the real
// receive. nil means fd is not a token (a host fd from outside the sandbox).
func (n *dnet) claim(fd int, peek bool) *dfile {
	k, ok := fdKey(fd)
	if !ok {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	l, ok := n.lent[k]
	if !ok {
		return nil
	}
	if peek {
		l.d.refs.Add(1)
		return l.d
	}
	delete(n.lent, k)
	unix.Close(l.w)
	return l.d
}

// received turns a host fd from SCM_RIGHTS into a description with one
// reference for the caller, consuming fd.
func (g *dguest) received(fd int, peek bool) *dfile {
	if d := g.netState().claim(fd, peek); d != nil {
		unix.Close(fd)
		return d
	}
	d := adoptHostFd(fd)
	d.refs.Add(1)
	return d
}

// hostControl converts the guest's Linux control messages to the host's:
// SCM_RIGHTS, each guest fd as a token from lend (the caller closes the
// returned fds after sending), and the IP options of cmsgTypes;
// SCM_CREDENTIALS is dropped, as Darwin has no equivalent to attach.
func (g *dguest) hostControl(ctl []byte) ([]byte, []int, lxErrno) {
	var fds []int
	var extra []byte
	for off := 0; off+16 <= len(ctl); {
		clen := int(le64(ctl[off:]))
		level, typ := int32(le32(ctl[off+8:])), int32(le32(ctl[off+12:]))
		if clen < 16 || off+clen > len(ctl) {
			closeAll(fds)
			return nil, nil, lxEINVAL
		}
		if dl, dt, ok := hostCmsgType(level, typ); ok {
			extra = append(extra, hostCmsg(dl, dt, ctl[off+16:off+clen])...)
		}
		if level == 1 && typ == lxScmRights {
			data := ctl[off+16 : off+clen]
			for i := 0; i+4 <= len(data); i += 4 {
				d, ok := g.ft.get(int(int32(le32(data[i:]))))
				if !ok {
					closeAll(fds)
					return nil, nil, lxEBADF
				}
				t, e := g.netState().lend(d)
				if e != 0 {
					closeAll(fds)
					return nil, nil, e
				}
				fds = append(fds, t)
			}
		}
		off += (clen + 7) &^ 7
	}
	if len(fds) == 0 {
		return extra, nil, 0
	}
	return append(unix.UnixRights(fds...), extra...), fds, 0
}

// Linux ancillary (level, type) pairs and the host ones they travel as (the
// same on Linux). On
// receive Darwin reports IP_RECVTTL and IP_RECVTOS under the option's own
// name, with a one-byte value.
var cmsgTypes = []struct{ lxLevel, lxType, dwLevel, dwType int32 }{
	{lxSolIP, 8, unix.IPPROTO_IP, unix.IP_PKTINFO},
	{lxSolIP, 2, unix.IPPROTO_IP, unix.IP_RECVTTL},
	{lxSolIP, 1, unix.IPPROTO_IP, unix.IP_RECVTOS},
	{lxSolIPv6, 50, unix.IPPROTO_IPV6, unix.IPV6_PKTINFO},
	{lxSolIPv6, 52, unix.IPPROTO_IPV6, unix.IPV6_HOPLIMIT},
	{lxSolIPv6, 67, unix.IPPROTO_IPV6, unix.IPV6_TCLASS},
}

// hostCmsgType maps a Linux ancillary message the host can send to the host's.
func hostCmsgType(level, typ int32) (int32, int32, bool) {
	if level == lxSolIP && typ != 8 {
		return 0, 0, false
	}
	for _, c := range cmsgTypes {
		if c.lxLevel == level && c.lxType == typ {
			return c.dwLevel, c.dwType, true
		}
	}
	return 0, 0, false
}

// hostCmsg lays out one host control message (a 32-bit length on Darwin, a
// 64-bit one on Linux).
func hostCmsg(level, typ int32, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = level, typ
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

// lxCmsg converts one received Darwin control message to Linux's level, type
// and data, in Linux's order (rank); ok is false for one with no Linux form.
func lxCmsg(m *unix.SocketControlMessage) (level, typ int32, data []byte, rank int, ok bool) {
	for i, c := range cmsgTypes {
		if c.dwLevel != m.Header.Level || c.dwType != m.Header.Type {
			continue
		}
		data = m.Data
		switch {
		case c.lxType == 2 && c.lxLevel == lxSolIP && len(data) >= 1:
			data = i32bytes(int(data[0])) // IP_TTL is an int on Linux
		case c.lxType == 1 && c.lxLevel == lxSolIP && len(data) >= 1:
			data = data[:1]
		}
		return c.lxLevel, c.lxType, data, i, true
	}
	return 0, 0, nil, 0, false
}

// closeAll closes the token fds of a message: sent ones live on in flight,
// unsent ones die, and the next sweep releases their descriptions.
func closeAll(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

// ---- receive -------------------------------------------------------------------

// recvResult is one received message, ready for the guest.
type recvResult struct {
	data  []byte // at most what the guest asked for
	full  int    // the datagram's real length (== len(data) for a stream)
	from  []byte // guest sockaddr of the sender, nil if none
	oob   []byte // Darwin control messages
	flags uint32 // Linux msg_flags
}

// recv receives up to n bytes (n at most sendChunk for a stream). A datagram
// is read whole into a buffer large enough to learn its true length
// (MSG_TRUNC), then cut to n.
func (g *dguest) recv(d *dfile, n, oobCap int, flags uint32) (recvResult, lxErrno) {
	sk := d.sk
	var r recvResult
	if n == 0 && sk.typ == lxSockStream {
		return r, 0
	}
	if sk.nl != nil && sk.nl.overrun.Swap(false) {
		return r, lxENOBUFS
	}
	size := min(n, sendChunk)
	if sk.typ != lxSockStream {
		floor := 65536
		if sk.family == lxAFUnix {
			floor = 256 << 10
		}
		size = min(max(n, floor), dgramMax)
	}
	buf := g.rbufOf(size) // reused per-thread; the data is scattered to the guest before return
	var oob []byte
	if oobCap > 0 {
		oob = make([]byte, oobCap)
	}
	nb := d.nonblock.Load() || flags&lxMsgDontwait != 0
	waitall := flags&lxMsgWaitall != 0 && flags&lxMsgPeek == 0 && sk.typ == lxSockStream && !nb
	dwFlags := dwRecvFlags(flags)
	got := 0
	for {
		var m, oobn, rflags int
		var from unix.Sockaddr
		op := func(h int) error {
			var err error
			m, oobn, rflags, from, err = unix.Recvmsg(h, buf[got:], oob, dwFlags)
			if err != nil && m > 0 && from == nil {
				err = nil // an unparseable sender address; keep the data
			}
			return err
		}
		var err error
		if sk.vlo != nil {
			err = g.dualIO(d, nb, sk.timeout(false), op) // from the network or the run's own loopback
		} else {
			err = g.sockIO(d, false, nb, sk.timeout(false), op)
		}
		if err != nil {
			if got > 0 {
				break
			}
			if sk.sp != nil && err == unix.EAGAIN && sk.sp.peerEnded(sk.side) {
				sk.sp.received(sk.side, false) // the end is owed: send it, and read it next
				return r, 0
			}
			return r, osErrno(err)
		}
		if r.from == nil && (from != nil || sk.nl != nil) {
			r.from = g.guestFrom(sk, from) // a netlink reply has no host sender: it is the kernel's
		}
		if oobn > 0 {
			r.oob = oob[:oobn]
			oob = nil
		}
		r.flags |= lxRecvFlagsOut(rflags)
		got += m
		if !waitall || m == 0 || got >= size {
			break
		}
	}
	r.full = got
	if sk.sp != nil && flags&lxMsgPeek == 0 {
		sk.sp.received(sk.side, got == 0)
	}
	if got > n {
		r.flags |= lxMsgTrunc
		got = n
	}
	r.data = buf[:got]
	return r, 0
}

// recvInto receives into the iovec list. MSG_WAITALL on a blocking stream
// keeps receiving, a chunk at a time, until the whole list is filled or the
// stream ends, fails or times out. It returns the first chunk's result and the
// byte count delivered.
func (g *dguest) recvInto(d *dfile, iovs [][2]uint64, oobCap int, flags uint32) (recvResult, int, lxErrno) {
	n := iovTotal(iovs)
	r, e := g.recv(d, n, oobCap, flags)
	if e != 0 {
		return r, 0, e
	}
	if d.sk.nl != nil {
		g.netlinkReceived(d, n)
	}
	if d.sk.virt && r.from == nil {
		// A reply the UDP egress relay delivered comes from no named sender;
		// report it as from the server the guest queried.
		d.sk.mu.Lock()
		r.from = d.sk.vdnsServer
		d.sk.mu.Unlock()
	}
	if e := g.scatter(iovs, 0, r.data); e != 0 {
		return r, 0, e
	}
	got := len(r.data)
	if d.sk.typ != lxSockStream || flags&lxMsgWaitall == 0 || flags&(lxMsgPeek|lxMsgDontwait) != 0 || d.nonblock.Load() {
		return r, got, 0
	}
	// A chunk that came back short means EOF, an error or a timeout.
	for want, last := min(n, sendChunk), got; got < n && last == want; {
		want = min(n-got, sendChunk)
		more, e := g.recv(d, want, 0, flags)
		if e != 0 {
			break
		}
		if e := g.scatter(iovs, got, more.data); e != 0 {
			break
		}
		last = len(more.data)
		got += last
	}
	return r, got, 0
}

// guestFrom renders a sender address for the guest: a unix sender by its guest
// name, and a DNS answer as coming from the server the guest asked.
func (g *dguest) guestFrom(sk *dsock, sa unix.Sockaddr) []byte {
	if sk.nl != nil {
		return sockaddrNl(0)
	}
	if sk.family == lxAFUnix {
		if su, ok := sa.(*unix.SockaddrUnix); ok && su.Name != "" {
			if c := g.netState().guestName(su.Name); c != nil {
				return c
			}
		}
		return []byte{lxAFUnix, 0}
	}
	if su, ok := sa.(*unix.SockaddrUnix); ok && (sk.virt || sk.vlo != nil) {
		// A datagram from another virtual socket is named by its backing's
		// path; a DNS reply the proxy self-delivered, by this socket's own,
		// and comes from the server the guest queried.
		sk.mu.Lock()
		own, srv := sk.unlink, sk.vdnsServer
		sk.mu.Unlock()
		if su.Name != "" && su.Name != own {
			if from := g.netState().vudpFrom(sk, su.Name); from != nil {
				return from
			}
		}
		return srv
	}
	if sk.typ == lxSockDgram {
		if ns := g.netState().dnsServer(sa); ns != nil {
			return ns
		}
	}
	return linuxSockaddr(sa)
}

// guestControl converts received Darwin control messages to the guest's
// layout within room bytes. SCM_RIGHTS fds become guest fds; ones that do
// not fit are dropped and reported with MSG_CTRUNC.
func (g *dguest) guestControl(oob []byte, room int, cloexec, peek bool) ([]byte, uint32) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, 0
	}
	var out []byte
	var flags uint32
	sort.SliceStable(msgs, func(i, j int) bool {
		_, _, _, ri, _ := lxCmsg(&msgs[i])
		_, _, _, rj, _ := lxCmsg(&msgs[j])
		return ri < rj
	})
	for i := range msgs {
		if level, typ, data, _, ok := lxCmsg(&msgs[i]); ok {
			var f uint32
			out, f = putCmsg(out, room, level, typ, data)
			flags |= f
			continue
		}
		fds, err := unix.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		fit := 0
		if left := room - len(out) - 16; left >= 4 {
			fit = min(len(fds), left/4)
		}
		for _, fd := range fds[fit:] {
			g.received(fd, peek).unref()
		}
		if fit < len(fds) {
			flags |= lxMsgCtrunc
		}
		if fit == 0 {
			continue
		}
		c := make([]byte, 16+4*fit)
		put64(c, uint64(16+4*fit))
		put32(c[8:], 1)
		put32(c[12:], lxScmRights)
		for j, fd := range fds[:fit] {
			d := g.received(fd, peek)
			gfd := g.ft.add(d, 0)
			d.unref()
			if cloexec {
				g.ft.setCloexec(gfd, true)
			}
			put32(c[16+4*j:], uint32(gfd))
		}
		for len(c)%8 != 0 && len(out)+len(c) < room {
			c = append(c, 0)
		}
		out = append(out, c...)
	}
	return out, flags
}

// adoptHostFd wraps a host fd received over SCM_RIGHTS as a new open-file
// description of the right kind.
func adoptHostFd(fd int) *dfile {
	var st unix.Stat_t
	unix.Fstat(fd, &st)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFSOCK:
		typ, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		fam := lxAFUnix
		if sa, err := unix.Getsockname(fd); err == nil {
			switch sa.(type) {
			case *unix.SockaddrInet4:
				fam = lxAFInet
			case *unix.SockaddrInet6:
				fam = lxAFInet6
			}
		}
		d := newSockFile(fd, fam, typ, 0)
		if v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err == nil && v != 0 {
			d.sk.listening = true
		}
		return d
	case unix.S_IFIFO:
		unix.CloseOnExec(fd)
		unix.SetNonblock(fd, true)
		return &dfile{f: os.NewFile(uintptr(fd), "pipe:"), gp: "pipe:", stub: -1}
	}
	unix.CloseOnExec(fd)
	return &dfile{f: os.NewFile(uintptr(fd), "file:"), gp: "/", isDir: st.Mode&unix.S_IFMT == unix.S_IFDIR, stub: -1}
}

// ---- syscalls ------------------------------------------------------------------

// ---- DNS -----------------------------------------------------------------------

// dnsBind gives a datagram socket a local port (any address) if it has none,
// so a DNS answer has somewhere to arrive.
func (g *dguest) dnsBind(d *dfile) lxErrno {
	h := hostFd(d.f)
	sa, err := unix.Getsockname(h)
	if err == nil && saPortOf(sa) != 0 {
		return 0
	}
	var any unix.Sockaddr = &unix.SockaddrInet4{}
	if d.sk.family == lxAFInet6 {
		any = &unix.SockaddrInet6{}
	}
	if err := unix.Bind(h, any); err != nil {
		return osErrno(err)
	}
	return 0
}

// dnsSend answers a DNS query the guest sent to the server ns. The answer is
// resolved off the guest's thread and delivered as a real datagram from a
// supervisor loopback socket dedicated to ns, so readiness (poll, epoll) and
// recv work unchanged; recv reports that socket as ns.
func (g *dguest) dnsSend(d *dfile, iovs [][2]uint64, ns []byte) int64 {
	total := iovTotal(iovs)
	q, e := g.gather(iovs, 0, min(total, 65536))
	if e != 0 {
		return sErr(e)
	}
	if e := g.dnsBind(d); e != 0 {
		return sErr(e)
	}
	local, err := unix.Getsockname(hostFd(d.f))
	if err != nil {
		return sErr(osErrno(err))
	}
	var dst unix.Sockaddr
	switch sa := local.(type) {
	case *unix.SockaddrInet4:
		dst = &unix.SockaddrInet4{Port: sa.Port, Addr: [4]byte{127, 0, 0, 1}}
	case *unix.SockaddrInet6:
		v6 := &unix.SockaddrInet6{Port: sa.Port}
		copy(v6.Addr[:], net.IPv6loopback)
		dst = v6
	default:
		return sErr(lxEINVAL)
	}
	n := g.netState()
	from, e := n.dnsSender(d.sk.family, ns)
	if e != 0 {
		return sErr(e)
	}
	q = append([]byte(nil), q...) // the thread's next send reuses q's buffer
	go func() {
		if reply := n.eg.answer(q, hostLookup); reply != nil {
			unix.Sendto(from, reply, 0, dst)
		}
	}()
	return int64(total)
}

// dnsSender returns the loopback UDP socket answers from server ns are sent
// from, creating it on first use.
func (n *dnet) dnsSender(family int, ns []byte) (int, lxErrno) {
	key := string(rune(family)) + string(ns)
	n.mu.Lock()
	defer n.mu.Unlock()
	if fd, ok := n.dnsFrom[key]; ok {
		return fd, 0
	}
	var bindTo unix.Sockaddr = &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	dw := unix.AF_INET
	if family == lxAFInet6 {
		v6 := &unix.SockaddrInet6{}
		copy(v6.Addr[:], net.IPv6loopback)
		bindTo, dw = v6, unix.AF_INET6
	}
	fd, err := unix.Socket(dw, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, osErrno(err)
	}
	unix.CloseOnExec(fd)
	if err := unix.Bind(fd, bindTo); err != nil {
		unix.Close(fd)
		return -1, osErrno(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return -1, osErrno(err)
	}
	n.dnsFrom[key] = fd
	n.dnsPort[[2]int{family, saPortOf(sa)}] = ns
	return fd, 0
}

// dnsServer maps the source of a received datagram back to the DNS server
// the guest queried, when it is one of the answer sockets; nil otherwise.
func (n *dnet) dnsServer(sa unix.Sockaddr) []byte {
	var key [2]int
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		if sa.Addr != [4]byte{127, 0, 0, 1} {
			return nil
		}
		key = [2]int{lxAFInet, sa.Port}
	case *unix.SockaddrInet6:
		if !net.IP(sa.Addr[:]).Equal(net.IPv6loopback) {
			return nil
		}
		key = [2]int{lxAFInet6, sa.Port}
	default:
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dnsPort[key]
}

// dnsStream returns the address of the supervisor's DNS-over-TCP resolver,
// as a guest socket of the given family reaches it, starting it on first use.
// Each connection is a stream of 2-byte length-framed queries, each answered
// by the egress policy in the same framing.
func (n *dnet) dnsStream(family int) (unix.Sockaddr, lxErrno) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.dnsTCP == nil {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, osErrno(err)
		}
		n.dnsTCP = l
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go n.eg.serveStream(c)
			}
		}()
	}
	port := n.dnsTCP.Addr().(*net.TCPAddr).Port
	if family == lxAFInet6 {
		sa := &unix.SockaddrInet6{Port: port}
		copy(sa.Addr[:], net.IPv4(127, 0, 0, 1).To16())
		return sa, 0
	}
	return &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}, 0
}

// recvOobCap is the control buffer a receive on sk takes from the host.
func recvOobCap(sk *dsock) int {
	switch {
	case sk.family == lxAFUnix:
		return unix.CmsgSpace(4 * 253)
	case sk.inet():
		return 512
	}
	return 0
}
