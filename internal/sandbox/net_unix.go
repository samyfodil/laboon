//go:build darwin || linux

package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/samyfodil/laboon/core"
	"golang.org/x/sys/unix"
)

// Sockets for the macOS backend. Each guest socket is a host socket the
// supervisor owns, non-blocking and on Go's poller; the guest's blocking
// semantics (O_NONBLOCK, MSG_DONTWAIT, SO_RCVTIMEO/SO_SNDTIMEO) are applied
// here. Addresses, flags, options and control messages are translated between
// the Linux arm64 layouts the guest speaks and Darwin's. AF_UNIX paths live in
// the guest's overlay filesystem; abstract names in a supervisor directory.
// UDP datagrams to port 53 are answered by the egress DNS policy.

// served reports whether d's IO is the supervisor's own rather than its host
// file's; on darwin every description's f is the real host object.
func (d *dfile) served() bool { return false }

const dwSunPathMax = 104

// dsock is the socket state of an open-file description (dfile.sk).
type dsock struct {
	family int // Linux AF_*
	typ    int // Linux SOCK_* base type
	proto  int

	virt   bool   // a virtual INET socket in a non-host netns (vnet; no host network)
	netns  int32  // the network namespace this socket belongs to, captured at socket()
	vbound bool   // vnet: this socket holds a port reservation (sk.vk)
	vudp   bool   // vnet: the reservation is a datagram endpoint (dnet.vudps)
	vk     vkey   // vnet: the endpoint reservation key
	vp     *vport // vnet: its own reservation at vk, among the sockets sharing it
	vn     *dnet  // vnet: the registry holding the reservation

	mu         sync.Mutex
	name       []byte // AF_UNIX: the guest sockaddr it is bound to
	peer       []byte // AF_UNIX: the guest sockaddr it connected to; DNS mode: the :53 server
	dns        bool   // "connected" to a DNS server answered in-supervisor (host socket unconnected)
	vdnsServer []byte // vnet: DNS/UDP-egress peer a virtual datagram socket is connected to; replies are self-delivered and read back with this as the source
	udpEg      int    // vnet: host UDP socket a virtual datagram socket egresses through (0 = none, DNS proxy instead)
	vpeer      []byte // vnet: the loopback or virtual-network peer a virtual datagram socket is connected to
	unlink     string // host file of an abstract name, removed with the socket
	listening  bool
	wrShut     bool // its write side is shut down
	rcvTimeo   time.Duration
	sndTimeo   time.Duration
	opts       map[[2]int]int32 // Linux-only options kept for getsockopt
	nl         *netlinkState    // set for an AF_NETLINK socket
	cl         *credLink        // AF_UNIX: credential passing with the connected peer
	side       int              // which end of cl (and sp) this is (0 or 1)
	sp         *seqPair         // a SOCK_SEQPACKET pair the host has no such socket for
	vlo        *os.File         // a host INET socket bound to a wildcard: its side of the run's own loopback (vlo_unix.go), whose port reservation is vk
	vsrcs      map[vkey]vsrc    // vnet: a datagram socket bound to a wildcard: what it sends from, by source address (vsrcFd)
	mcast      []mcMember       // vnet: the IPv4 multicast groups it joined (vmcast_unix.go)
	mcast6     []mc6Member      // vnet: the IPv6 groups it joined
	mcIf       int32            // vnet: IP_MULTICAST_IF's interface, 0 for the route's
	mcIfAddr   uint32           // vnet: the address IP_MULTICAST_IF named it by
	mcNet      *dnet            // vnet: the run whose interfaces took its groups in
}

// vsrc is a unix datagram socket a vnet socket bound to a wildcard sends
// from, bound to the path naming one source address.
type vsrc struct {
	f    *os.File
	path string
}

func (s *dsock) close() {
	if s.vlo != nil {
		s.vlo.Close()
	}
	s.vmcLeaveAll()
	for _, v := range s.vsrcs {
		v.f.Close()
		os.Remove(v.path)
	}
	if s.vn != nil && s.unlink != "" {
		s.vn.mu.Lock()
		delete(s.vn.vconns, s.unlink)
		s.vn.mu.Unlock()
	}
	if s.sp != nil {
		s.sp.release(s.side)
	}
	if s.unlink != "" {
		os.Remove(s.unlink)
	}
	if s.udpEg > 0 {
		unix.Close(s.udpEg) // stops the UDP egress relay goroutine
	}
	if s.vn != nil && s.vbound {
		s.vn.mu.Lock()
		if s.vudp {
			vremove(s.vn.vudps, s.vk, s.vp)
		} else {
			vremove(s.vn.vports, s.vk, s.vp)
		}
		s.vn.mu.Unlock()
	}
	if s.nl != nil {
		unix.Close(s.nl.peer)
	}
}

// timeout is SO_SNDTIMEO (write) or SO_RCVTIMEO; 0 is none, negative never
// waits.
func (s *dsock) timeout(write bool) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if write {
		return s.sndTimeo
	}
	return s.rcvTimeo
}

func (s *dsock) inet() bool { return s.family == lxAFInet || s.family == lxAFInet6 }

// dnet is a run's shared networking state: the egress policy, a short host
// directory for abstract unix names and over-long paths, the guest names of
// bound unix sockets by host path, and the loopback sockets DNS answers are
// sent from.
type dnet struct {
	eg  *egress
	dir string

	mu        sync.Mutex
	seq       int
	names     map[string][]byte      // host socket path -> guest sockaddr
	conns     map[string]*credLink   // a connecting socket's hidden host name -> its connection's creds
	nodeSocks map[core.NodeID]string // socket node -> the supervisor socket bound for it (bindPath)
	dnsFrom   map[string]int         // family + server sockaddr -> sender fd
	dnsPort   map[[2]int][]byte      // {family, sender port} -> server sockaddr
	dnsTCP    net.Listener           // DNS over TCP, started on first use
	lent      map[[2]uint64]lent     // descriptions in flight over SCM_RIGHTS, by token

	vports  map[vkey]*vport              // vnet: stream endpoint reservations by (scope, ip, port)
	vudps   map[vkey]*vport              // vnet: datagram endpoint reservations
	vconns  map[string]vconn             // vnet: a connecting stream's addresses, by its backing path (vpeer)
	mcDev   map[mcDevKey]int             // vnet: the multicast groups each interface took in, with how many sockets joined each there
	group6  map[[20]byte]uint32          // vnet: the key ip standing for an IPv6 group bound to, by group and interface (vgroup6)
	vEphem  uint16                       // vnet: next ephemeral port to try
	vseq    uint64                       // vnet: the last reservation's sequence number (vport.seq)
	ipNetns map[uint32]int32             // vnet: virtual-network address -> the namespace it is assigned to
	pubs    map[int32]map[uint16]hostPub // vnet: realized -p publications per namespace, by host port

	nets  map[int32]*netModel // per-netns interface/address/route model (routing netlink)
	nftns map[int32]*nftState // per-netns nftables ruleset (netfilter netlink)
}

func (g *dguest) netState() *dnet {
	g.dfs.netOnce.Do(func() {
		n := &dnet{eg: newEgress(g.cfg), names: map[string][]byte{}, conns: map[string]*credLink{}, dnsFrom: map[string]int{}, dnsPort: map[[2]int][]byte{}, lent: map[[2]uint64]lent{}, vports: map[vkey]*vport{}, vudps: map[vkey]*vport{}, vconns: map[string]vconn{}, vEphem: 32768, ipNetns: map[uint32]int32{}}
		if dir, err := os.MkdirTemp("/tmp", netTmpPrefix()); err == nil {
			n.dir = dir
		}
		g.dfs.net = n
	})
	return g.dfs.net
}

func (n *dnet) close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, fd := range n.dnsFrom {
		unix.Close(fd)
	}
	if n.dnsTCP != nil {
		n.dnsTCP.Close()
	}
	for k, l := range n.lent {
		l.d.unref()
		unix.Close(l.w)
		delete(n.lent, k)
	}
	for _, m := range n.pubs {
		for _, pub := range m {
			unix.Close(pub.fd)
		}
	}
	if n.dir != "" {
		os.RemoveAll(n.dir)
	}
}

// tmpName returns a fresh short host path in the supervisor directory.
func (n *dnet) tmpName() string {
	n.mu.Lock()
	n.seq++
	s := n.seq
	n.mu.Unlock()
	return filepath.Join(n.dir, fmt.Sprintf("t%d", s))
}

func (n *dnet) guestName(host string) []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.names[host]
}

// ---- socket file descriptions -------------------------------------------------

// newSockFile wraps a host socket as a guest open-file description. The host
// side is always non-blocking (so it joins Go's poller), close-on-exec and
// SIGPIPE-free; the guest's O_NONBLOCK is the dfile's flag.
func newSockFile(fd, family, typ, proto int) *dfile {
	unix.CloseOnExec(fd)
	unix.SetNonblock(fd, true)
	sockNoSigpipe(fd)
	if family == lxAFUnix && typ != lxSockStream {
		// Darwin caps a unix datagram at the send buffer (2 KiB by default);
		// Linux allows far larger ones.
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 256<<10)
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 256<<10)
	}
	if proto == 0 && (family == lxAFInet || family == lxAFInet6) {
		switch typ {
		case lxSockStream:
			proto = unix.IPPROTO_TCP
		case lxSockDgram:
			proto = unix.IPPROTO_UDP
		}
	}
	return &dfile{f: os.NewFile(uintptr(fd), "socket"), gp: "socket:", stub: -1, sk: &dsock{family: family, typ: typ, proto: proto}}
}

func (g *dguest) installSock(d *dfile, flags int) int64 {
	d.nonblock.Store(flags&lxSockNonblock != 0)
	fd := g.ft.add(d, 0)
	if flags&lxSockCloexec != 0 {
		g.ft.setCloexec(fd, true)
	}
	return int64(fd)
}

func dwFamily(lx int) (int, bool) {
	switch lx {
	case lxAFUnix:
		return unix.AF_UNIX, true
	case lxAFInet:
		return unix.AF_INET, true
	case lxAFInet6:
		return unix.AF_INET6, true
	}
	return 0, false
}

func (g *dguest) socket(family, typ, proto int) int64 {
	if family == lxAFNetlink {
		if typ&^0xf&^(lxSockNonblock|lxSockCloexec) != 0 {
			return sErr(lxEINVAL)
		}
		return g.netlinkSocket(typ&0xf, proto, typ&^0xf)
	}
	dw, ok := dwFamily(family)
	if !ok {
		return sErr(lxEAFNOSUPPORT)
	}
	flags := typ &^ 0xf
	base := typ & 0xf
	if flags&^(lxSockNonblock|lxSockCloexec) != 0 {
		return sErr(lxEINVAL)
	}
	if family != lxAFUnix && !g.hostNet() {
		// A non-host network namespace, or a run without networking, has no
		// host networking (vnet owns it). An INET socket here is virtual:
		// backed by a disconnected host unix socket so the descriptor, ioctls,
		// poll and close work, but no network op reaches the host (gated
		// below). A runtime creates such a socket just to bring lo up via ioctl.
		if g.cfg.NoNet && !g.cfg.Net || (family != lxAFInet && family != lxAFInet6) {
			return sErr(lxEAFNOSUPPORT) // no network at all for the run, or an unsupported family
		}
		fd, err := unix.Socket(unix.AF_UNIX, base, 0)
		if err != nil {
			return sErr(osErrno(err))
		}
		if base == lxSockStream {
			vnetStreamBufs(fd)
		}
		d := newSockFile(fd, family, base, proto)
		d.sk.virt = true
		d.sk.netns = g.ps.netns.Load()
		return g.installSock(d, flags)
	}
	fd, err := unix.Socket(dw, base, proto)
	if err != nil {
		return sErr(osErrno(err))
	}
	return g.installSock(newSockFile(fd, family, base, proto), flags)
}

func (g *dguest) socketpair(family, typ, proto int, svAddr uint64) int64 {
	if family != lxAFUnix {
		if _, ok := dwFamily(family); ok {
			return sErr(lxEOPNOTSUPP)
		}
		return sErr(lxEAFNOSUPPORT)
	}
	flags := typ &^ 0xf
	typ &= 0xf
	if flags&^(lxSockNonblock|lxSockCloexec) != 0 {
		return sErr(lxEINVAL)
	}
	var sp *seqPair
	var fds [2]int
	var err error
	if typ == lxSockSeqpacket && !hostSeqpacket {
		sp, fds, err = newSeqPair()
	} else {
		fds, err = unix.Socketpair(unix.AF_UNIX, typ, proto)
	}
	if err != nil {
		return sErr(osErrno(err))
	}
	da := newSockFile(fds[0], family, typ, proto)
	db := newSockFile(fds[1], family, typ, proto)
	cl := newCredLink(g.curCred())
	da.sk.cl, da.sk.side, da.sk.sp = cl, 0, sp
	db.sk.cl, db.sk.side, db.sk.sp = cl, 1, sp
	a := g.installSock(da, flags)
	b := g.installSock(db, flags)
	var out [8]byte
	put32(out[:], uint32(a))
	put32(out[4:], uint32(b))
	if err := g.writeMem(svAddr, out[:]); err != nil {
		g.ft.remove(int(a))
		g.ft.remove(int(b))
		return sErr(lxEFAULT)
	}
	return 0
}

// ---- sockaddr translation ----------------------------------------------------

// inetSockaddr converts a guest AF_INET/AF_INET6 sockaddr for a socket of the
// given Linux family. An IPv4 address on an IPv6 socket is v4-mapped where
// Linux takes one (v4ok: a datagram destination); bind and a stream connect
// insist on a sockaddr_in6.
func inetSockaddr(raw []byte, family int, v4ok bool) (unix.Sockaddr, lxErrno) {
	switch saFamily(raw) {
	case lxAFInet:
		if family == lxAFInet6 && !v4ok {
			if len(raw) < 24 {
				return nil, lxEINVAL
			}
			return nil, lxEAFNOSUPPORT
		}
		if len(raw) < 16 {
			return nil, lxEINVAL
		}
		port := int(raw[2])<<8 | int(raw[3])
		if family == lxAFInet6 {
			sa := &unix.SockaddrInet6{Port: port}
			copy(sa.Addr[:], net.IPv4(raw[4], raw[5], raw[6], raw[7]).To16())
			return sa, 0
		}
		sa := &unix.SockaddrInet4{Port: port}
		copy(sa.Addr[:], raw[4:8])
		return sa, 0
	case lxAFInet6:
		if len(raw) < 24 {
			return nil, lxEINVAL
		}
		if family != lxAFInet6 {
			return nil, lxEAFNOSUPPORT
		}
		sa := &unix.SockaddrInet6{Port: int(raw[2])<<8 | int(raw[3])}
		copy(sa.Addr[:], raw[8:24])
		if len(raw) >= 28 {
			sa.ZoneId = le32(raw[24:])
		}
		return sa, 0
	}
	return nil, lxEAFNOSUPPORT
}

// linuxSockaddr renders a host address in the guest's layout.
func linuxSockaddr(sa unix.Sockaddr) []byte {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		b := make([]byte, 16)
		b[0] = lxAFInet
		b[2], b[3] = byte(sa.Port>>8), byte(sa.Port)
		copy(b[4:8], sa.Addr[:])
		return b
	case *unix.SockaddrInet6:
		b := make([]byte, 28)
		b[0] = lxAFInet6
		b[2], b[3] = byte(sa.Port>>8), byte(sa.Port)
		copy(b[8:24], sa.Addr[:])
		put32(b[24:], sa.ZoneId)
		return b
	}
	return []byte{lxAFUnix, 0}
}

// abstractPath maps an abstract AF_UNIX name to a supervisor file. The name is
// scoped to the network namespace: a process in a new one has a separate
// abstract namespace, as on Linux, so its names never collide with the host
// namespace's.
func (n *dnet) abstractPath(netns int32, name string) string {
	h := sha256.Sum256([]byte(name))
	p := "a" + hex.EncodeToString(h[:8])
	if netns != 0 {
		p = "n" + hex.EncodeToString(binID(netns)) + p
	}
	return filepath.Join(n.dir, p)
}

func binID(v int32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }

// unixReach runs op with a host address reaching a guest AF_UNIX name.
type unixReach func(op func(sa *unix.SockaddrUnix) error) error

// unixTarget resolves what an AF_UNIX connect/sendto reaches: an abstract
// name's supervisor socket, or the socket node at the guest path, reached
// through the filesystem holding it (which gives a host socket's address
// itself) or else at the supervisor socket a bind there made for the node.
func (g *dguest) unixTarget(raw []byte) (unixReach, []byte, lxErrno) {
	name, abstract, canon, e := unixName(raw)
	if e != 0 {
		return nil, nil, e
	}
	n := g.netState()
	if abstract {
		p := n.abstractPath(g.ps.netns.Load(), name)
		return func(op func(*unix.SockaddrUnix) error) error { return n.viaShort(p, op) }, canon, 0
	}
	gp, e := g.walkAt(lxAtFdcwd, name, true)
	if e != 0 {
		return nil, nil, e
	}
	loc, err := g.vns().Resolve(gp, true)
	if err != nil {
		return nil, nil, osErrno(err)
	}
	return func(op func(*unix.SockaddrUnix) error) error {
		if s, ok := loc.FS.(core.SocketFS); ok {
			err := s.ReachSocket(loc.Node, func(addr string) error { return op(&unix.SockaddrUnix{Name: addr}) })
			if !errors.Is(err, core.ErrSocketUnsupported) {
				return err
			}
		}
		p, ok := n.nodeSock(loc.Node.ID())
		if !ok {
			return unix.ECONNREFUSED
		}
		return n.viaShort(p, op)
	}, canon, 0
}

// nodeSock is the supervisor socket bound for a socket node of a filesystem
// that holds no host sockets (bindNode).
func (n *dnet) nodeSock(id core.NodeID) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p, ok := n.nodeSocks[id]
	return p, ok
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
	if d.sk.virt {
		if vnetStream(d) {
			return g.vbind(d, raw)
		}
		return g.virtBind(d, raw)
	}
	hfd := hostFd(d.f)
	if d.sk.nl != nil {
		return 0
	}
	if d.sk.family != lxAFUnix {
		sa, e := inetSockaddr(raw, d.sk.family, false)
		if e != 0 {
			return sErr(e)
		}
		if g.hostNet() && d.sk.inet() {
			// The run's own loopback (vlo_unix.go).
			switch _, port, _, loop, any := vloIP(raw); {
			case loop && hostPort(d) != 0:
				return sErr(lxEINVAL)
			case loop:
				if e := g.toVlo(d); e != 0 {
					return sErr(e)
				}
				if vnetStream(d) {
					return g.vbind(d, raw)
				}
				return g.virtBind(d, raw)
			case any && hostPort(d) != 0:
				return sErr(lxEINVAL)
			case any:
				return g.vloBindAny(d, raw, port)
			}
		}
		if err := unix.Bind(hfd, sa); err != nil {
			return sErr(osErrno(err))
		}
		return 0
	}
	n := g.netState()
	var host, sockPath string
	var canon []byte
	abstract := false
	if len(raw) == 2 {
		// Autobind: Linux picks a five-hex-digit abstract name.
		n.mu.Lock()
		n.seq++
		name := fmt.Sprintf("%05x", n.seq&0xfffff)
		n.mu.Unlock()
		canon = append([]byte{lxAFUnix, 0, 0}, name...)
		host, abstract = n.abstractPath(g.ps.netns.Load(), name), true
	} else {
		name, abs, c, e := unixName(raw)
		if e != 0 {
			return sErr(e)
		}
		canon, abstract = c, abs
		if abs {
			host = n.abstractPath(g.ps.netns.Load(), name)
		} else {
			sockPath = name
		}
	}
	d.sk.mu.Lock()
	defer d.sk.mu.Unlock()
	if d.sk.name != nil {
		return sErr(lxEINVAL)
	}
	if abstract {
		if err := n.bindUnix(hfd, host); err != nil {
			return sErr(osErrno(err))
		}
	} else {
		var e lxErrno
		host, e = g.bindPath(hfd, sockPath)
		g.upperChanged()
		if e != 0 {
			return sErr(e)
		}
	}
	d.sk.name = canon
	if abstract {
		d.sk.unlink = host
	}
	n.mu.Lock()
	n.names[host] = canon
	if sa, err := unix.Getsockname(hfd); err == nil {
		if su, ok := sa.(*unix.SockaddrUnix); ok && su.Name != "" {
			n.names[su.Name] = canon // the short name a long path was bound at
		}
	}
	n.mu.Unlock()
	return 0
}

// bindPath binds the host socket hfd at guest path name, as bind(2) makes the
// socket file: its parent must exist, the name must not. A filesystem that
// holds host sockets binds it there; any other gets a Socket node, and hfd is
// bound at a supervisor path the node's identity finds (nodeSock). It returns
// the address hfd was bound at, which the kernel reports for it.
func (g *dguest) bindPath(hfd int, name string) (string, lxErrno) {
	gp, e := g.walkAt(lxAtFdcwd, name, false)
	if e != 0 {
		return "", e
	}
	if fi, e := g.lstatGuest(path.Dir(gp)); e != 0 {
		return "", e
	} else if !fi.IsDir() {
		return "", lxENOTDIR
	}
	if _, e := g.lstatGuest(gp); e == 0 {
		return "", lxEADDRINUSE
	} else if e != lxENOENT {
		return "", e
	}
	if e := g.dacCreate(gp); e != 0 {
		return "", e
	}
	ploc, err := g.vns().Resolve(path.Dir(gp), true)
	if err != nil {
		return "", osErrno(err)
	}
	n := g.netState()
	var bound string
	if s, ok := ploc.FS.(core.SocketFS); ok {
		_, err = s.BindSocket(ploc.Node, path.Base(gp), func(addr string) error {
			bound = addr
			return unix.Bind(hfd, &unix.SockaddrUnix{Name: addr})
		})
		if err == nil {
			g.setWhite(gp, false)
			g.notify(gp, inCreate, 0)
			return bound, 0
		}
		if !errors.Is(err, core.ErrSocketUnsupported) {
			return "", osErrno(err)
		}
	}
	node, err := g.create(ploc, gp, core.CreateSpec{Kind: core.Socket, Mode: g.createPerm(0o777)})
	if err != nil {
		return "", osErrno(err)
	}
	bound = n.tmpName()
	if err := n.bindUnix(hfd, bound); err != nil {
		ploc.FS.Remove(ploc.Node, path.Base(gp), false)
		return "", osErrno(err)
	}
	n.mu.Lock()
	if n.nodeSocks == nil {
		n.nodeSocks = map[core.NodeID]string{}
	}
	n.nodeSocks[node.ID()] = bound
	n.mu.Unlock()
	g.notify(gp, inCreate, 0)
	return bound, 0
}

func (g *dguest) listen(fd int64, backlog int) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	if d.sk.virt {
		if vnetStream(d) {
			return g.vlisten(d, backlog)
		}
		return sErr(lxEOPNOTSUPP)
	}
	if d.sk.typ == lxSockDgram {
		return sErr(lxEOPNOTSUPP)
	}
	if backlog < 0 || backlog > 4096 {
		backlog = 4096
	}
	if g.hostNet() && d.sk.inet() && hostPort(d) == 0 {
		// An unbound socket listens on a wildcard, on the run's own loopback too.
		if r := g.vloBindAny(d, vSockaddr(d.sk.family, 0, 0), 0); r != 0 {
			return r
		}
	}
	if err := unix.Listen(hostFd(d.f), backlog); err != nil {
		return sErr(osErrno(err))
	}
	if d.sk.vlo != nil {
		if err := unix.Listen(vloFd(d), backlog); err != nil {
			return sErr(osErrno(err))
		}
		if e := g.netState().vlistenOn(d.sk.vk, d.sk.vp); e != 0 {
			return sErr(e)
		}
	}
	d.sk.mu.Lock()
	d.sk.listening = true
	d.sk.mu.Unlock()
	return 0
}

func (g *dguest) accept4(fd int64, addr, lenAddr uint64, flags int) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	if flags&^(lxSockNonblock|lxSockCloexec) != 0 {
		return sErr(lxEINVAL)
	}
	d.sk.mu.Lock()
	listening := d.sk.listening
	d.sk.mu.Unlock()
	if !listening {
		return sErr(lxEINVAL)
	}
	var nfd, from int
	var sa unix.Sockaddr
	accept := func(h int) error {
		var err error
		nfd, sa, err = unix.Accept(h)
		if err == unix.ECONNABORTED {
			return unix.EAGAIN
		}
		from = h
		return err
	}
	var err error
	if d.sk.vlo != nil {
		err = g.dualIO(d, d.nonblock.Load(), d.sk.timeout(false), accept)
	} else {
		err = g.sockIO(d, false, d.nonblock.Load(), d.sk.timeout(false), accept)
	}
	if err != nil {
		return sErr(osErrno(err))
	}
	var nd *dfile
	var peer []byte
	if d.sk.vlo != nil && from == vloFd(d) {
		nd = g.vloAccepted(d, nfd)
		peer = nd.sk.peer
	} else if d.sk.virt {
		nd = g.vaccept(d, nfd)
		peer = nd.sk.peer
	} else {
		nd = newSockFile(nfd, d.sk.family, d.sk.typ, d.sk.proto)
		if d.sk.family == lxAFUnix {
			peer = []byte{lxAFUnix, 0}
			if su, ok := sa.(*unix.SockaddrUnix); ok && su.Name != "" {
				if c := g.netState().guestName(su.Name); c != nil {
					peer = c
				}
				if cl := g.netState().takeConn(su.Name); cl != nil {
					cl.setOwner(1, g.curCred())
					nd.sk.cl, nd.sk.side = cl, 1
				}
			}
			d.sk.mu.Lock()
			nd.sk.name = d.sk.name
			d.sk.mu.Unlock()
		} else {
			peer = linuxSockaddr(sa)
		}
	}
	if e := g.putSockaddr(peer, addr, lenAddr); e != 0 {
		nd.refs.Add(1)
		nd.unref()
		return sErr(e)
	}
	return g.installSock(nd, flags)
}

// egressOK applies the egress policy to an IP destination. The host's
// loopback is out of reach: the run's is its own (vlo_unix.go).
func (g *dguest) egressOK(sa unix.Sockaddr) bool {
	var ip net.IP
	var port int
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		ip, port = net.IP(sa.Addr[:]), sa.Port
	case *unix.SockaddrInet6:
		ip, port = net.IP(sa.Addr[:]), sa.Port
	default:
		return true
	}
	return g.netState().eg.connectAllowed(ip, port)
}

func saPortOf(sa unix.Sockaddr) int {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return sa.Port
	case *unix.SockaddrInet6:
		return sa.Port
	}
	return 0
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
	if d.sk.virt {
		if vnetStream(d) && saFamily(raw) == 0 {
			unix.Shutdown(hostFd(d.f), unix.SHUT_RDWR) // AF_UNSPEC disconnects, as on the host path below
			return 0
		}
		if vnetStream(d) {
			return g.vconnect(d, raw)
		}
		return g.virtConnect(d, raw)
	}
	sk := d.sk
	hfd := hostFd(d.f)
	if sk.nl != nil {
		return 0
	}
	if sk.family == lxAFUnix {
		reach, canon, e := g.unixTarget(raw)
		if e != 0 {
			return sErr(e)
		}
		if e := g.connCreds(d); e != 0 {
			return sErr(e)
		}
		err := reach(func(sa *unix.SockaddrUnix) error { return unix.Connect(hfd, sa) })
		if err == unix.EINPROGRESS || err == unix.EAGAIN {
			err = g.awaitConnect(d)
		}
		if err == unix.ENOTSOCK {
			err = unix.ECONNREFUSED // the name is not a socket
		}
		if err != nil {
			return sErr(osErrno(err))
		}
		sk.mu.Lock()
		sk.peer = canon
		sk.mu.Unlock()
		return 0
	}
	if saFamily(raw) == 0 && sk.typ == lxSockStream {
		// AF_UNSPEC disconnects; Darwin cannot reuse the socket afterwards,
		// so the best match is to end the connection.
		unix.Shutdown(hfd, unix.SHUT_RDWR)
		return 0
	}
	if saFamily(raw) == 0 && sk.typ == lxSockDgram {
		// AF_UNSPEC dissolves a datagram socket's association.
		sk.mu.Lock()
		sk.dns, sk.peer = false, nil
		sk.mu.Unlock()
		unix.Connect(hfd, &unix.SockaddrInet4{})
		return 0
	}
	sa, e := inetSockaddr(raw, sk.family, sk.typ == lxSockDgram)
	if e != 0 {
		return sErr(e)
	}
	if g.hostNet() && sk.inet() && saPortOf(sa) != 53 {
		// The run's own loopback (vlo_unix.go), or the network alone.
		if _, _, _, loop, any := vloIP(raw); loop || any {
			return g.vloConnect(d, raw)
		}
		d.vloRelease()
	}
	if sk.typ == lxSockDgram && saPortOf(sa) == 53 {
		if e := g.dnsBind(d); e != 0 {
			return sErr(e)
		}
		sk.mu.Lock()
		sk.dns, sk.peer = true, normSockaddr(raw)
		sk.mu.Unlock()
		return 0
	}
	var peer []byte
	if sk.typ == lxSockStream && saPortOf(sa) == 53 {
		// DNS over TCP goes to the supervisor's resolver instead.
		lsa, e := g.netState().dnsStream(sk.family)
		if e != 0 {
			return sErr(e)
		}
		sa, peer = lsa, normSockaddr(raw)
	} else if !g.egressOK(sa) {
		return sErr(lxECONNREFUSED)
	}
	sk.mu.Lock()
	sk.dns, sk.peer = false, peer
	sk.mu.Unlock()
	err := unix.Connect(hfd, sa)
	if err == unix.EINPROGRESS {
		if d.nonblock.Load() {
			return sErr(lxEINPROGRESS)
		}
		err = g.awaitConnect(d)
	}
	if err != nil {
		return sErr(osErrno(err))
	}
	return 0
}

// connCreds gives an unnamed AF_UNIX stream socket about to connect a hidden
// host name in the run's socket directory, under which its credentials wait
// for the accept: the host stamps the supervisor on both ends, so the name is
// how the accepted end learns its peer (SO_PEERCRED, SCM_CREDENTIALS). The
// guest never sees it; its own name stays unnamed.
func (g *dguest) connCreds(d *dfile) lxErrno {
	sk := d.sk
	sk.mu.Lock()
	skip := sk.typ == lxSockDgram || sk.name != nil || sk.cl != nil || sk.unlink != ""
	sk.mu.Unlock()
	if skip {
		return 0
	}
	n := g.netState()
	n.mu.Lock()
	n.seq++
	host := filepath.Join(n.dir, fmt.Sprintf("c%x", n.seq))
	n.mu.Unlock()
	hfd := hostFd(d.f)
	if err := n.bindUnix(hfd, host); err != nil {
		return osErrno(err)
	}
	cl := newCredLink(g.curCred())
	n.mu.Lock()
	n.conns[host] = cl
	if sa, err := unix.Getsockname(hfd); err == nil {
		if su, ok := sa.(*unix.SockaddrUnix); ok && su.Name != "" {
			n.conns[su.Name] = cl
		}
	}
	n.mu.Unlock()
	sk.mu.Lock()
	sk.cl, sk.side, sk.unlink = cl, 0, host
	sk.mu.Unlock()
	return 0
}

// takeConn returns the credentials a connection from the socket bound at host
// name carries, once: the accept that receives it.
func (n *dnet) takeConn(name string) *credLink {
	n.mu.Lock()
	defer n.mu.Unlock()
	cl := n.conns[name]
	for k, v := range n.conns {
		if v == cl {
			delete(n.conns, k)
		}
	}
	return cl
}

// awaitConnect parks a blocking connect until the handshake finishes, then
// reports its outcome from SO_ERROR (the shape of Go's net package). A
// SO_SNDTIMEO expiry leaves it in progress, as on Linux.
func (g *dguest) awaitConnect(d *dfile) error {
	err := g.sockIO(d, true, false, d.sk.timeout(true), func(h int) error {
		v, err := unix.GetsockoptInt(h, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if v != 0 {
			return unix.Errno(v)
		}
		if _, err := unix.Getpeername(h); err != nil {
			return unix.EAGAIN
		}
		return nil
	})
	if err == unix.EAGAIN {
		return unix.EINPROGRESS
	}
	return err
}

func (g *dguest) sockname(fd int64, addr, lenAddr uint64, peer bool) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	sk := d.sk
	hfd := hostFd(d.f)
	var out []byte
	sk.mu.Lock()
	switch {
	case sk.nl != nil && peer:
		out = sockaddrNl(0)
	case sk.nl != nil:
		out = sockaddrNl(g.tgid)
	case peer && sk.peer != nil:
		out = sk.peer
	case sk.virt && !peer:
		out = sk.name
		if out == nil {
			out = sockaddrIn4(0, 0) // unbound: 0.0.0.0:0
		}
	case sk.family == lxAFUnix && !peer:
		out = sk.name
		if out == nil {
			out = []byte{lxAFUnix, 0}
		}
	}
	sk.mu.Unlock()
	if out == nil {
		var sa unix.Sockaddr
		var err error
		if peer {
			sa, err = unix.Getpeername(hfd)
		} else {
			sa, err = unix.Getsockname(hfd)
		}
		if err != nil {
			return sErr(osErrno(err))
		}
		if sk.family == lxAFUnix {
			out = []byte{lxAFUnix, 0}
			if su, ok := sa.(*unix.SockaddrUnix); ok && su.Name != "" {
				if c := g.netState().guestName(su.Name); c != nil {
					out = c
				}
			}
		} else {
			out = linuxSockaddr(sa)
		}
	}
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
	d.sk.mu.Lock()
	dns := d.sk.dns
	vconn := vnetStream(d) && d.sk.peer != nil
	d.sk.mu.Unlock()
	if d.sk.sp != nil && how != unix.SHUT_RD {
		d.sk.sp.end(d.sk.side)
	}
	if err := unix.Shutdown(hostFd(d.f), how); err != nil && !(err == unix.ENOTCONN && (dns || vconn)) {
		// A DNS socket's host side is unconnected; a vnet stream whose peer
		// has gone is disconnected on Darwin, where TCP still shuts down.
		return sErr(osErrno(err))
	}
	if how != unix.SHUT_RD {
		d.sk.mu.Lock()
		d.sk.wrShut = true
		d.sk.mu.Unlock()
	}
	return 0
}

// ---- blocking ------------------------------------------------------------------

// sockIO runs op on the host socket. op returns EAGAIN when it would block;
// for a blocking guest socket the call then parks on Go's poller (the write
// side when write is set) and retries, until timeo (0 = none) runs out (EAGAIN,
// as Linux reports an expired SO_RCVTIMEO/SO_SNDTIMEO) or the guest is torn
// down. The first attempt never parks, so ready I/O costs no timer.
func (g *dguest) sockIO(d *dfile, write, nonblock bool, timeo time.Duration, op func(fd int) error) error {
	rc, err := d.f.SyscallConn()
	if err != nil {
		return unix.EBADF
	}
	var opErr error
	call := func(fd uintptr) bool {
		opErr = op(int(fd))
		return opErr != unix.EAGAIN
	}
	if err := rc.Control(func(fd uintptr) { call(fd) }); err != nil {
		return unix.EBADF
	}
	if opErr != unix.EAGAIN || nonblock || timeo < 0 {
		return opErr
	}
	var end time.Time
	if timeo > 0 {
		end = time.Now().Add(timeo)
	}
	for {
		// The deadline (the guest's, if any) is set before the file is
		// parked: a wake for a signal or the guest's teardown then moves it
		// to the past, which this call sees; one before the park is caught
		// by the checks after it.
		if write {
			d.f.SetWriteDeadline(end)
		} else {
			d.f.SetReadDeadline(end)
		}
		unpark := g.parkIO(d.f, write)
		if g.sigIntr() {
			unpark()
			return unix.Errno(errRestart)
		}
		if g.ch.dead() {
			unpark()
			return unix.EINTR
		}
		if write {
			err = rc.Write(call)
		} else {
			err = rc.Read(call)
		}
		unpark()
		if err == nil {
			return opErr
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return unix.EBADF
		}
		if !end.IsZero() && !time.Now().Before(end) {
			return unix.EAGAIN
		}
		if g.sigIntr() {
			return unix.Errno(errRestart)
		}
		if g.ch.dead() {
			return unix.EINTR
		}
	}
}

// sockIoctl serves the socket/pipe ioctls: FIONREAD (bytes waiting) and
// SIOCATMARK. ok is false for a request it does not handle.
func (g *dguest) sockIoctl(d *dfile, req, arg uint64) (int64, bool) {
	const (
		lxFionread   = 0x541b
		lxSiocatmark = 0x8905
	)
	var dw uint
	switch {
	case req == lxFionread && d.f != nil && d.ev == nil && d.ep == nil && d.pty == nil && !d.isDir:
		dw = hostFIONREAD
	case req == lxSiocatmark && d.sk != nil:
		dw = hostSIOCATMARK
	case d.sk != nil:
		return g.ifIoctl(req, arg)
	default:
		return 0, false
	}
	v, err := unix.IoctlGetInt(hostFd(d.f), dw)
	if err != nil {
		return sErr(osErrno(err)), true
	}
	if err := g.writeMem(arg, i32bytes(v)); err != nil {
		return sErr(lxEFAULT), true
	}
	return 0, true
}
