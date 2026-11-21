//go:build darwin || linux

package sandbox

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// vnet: IPv4 stream delivery for isolated network namespaces, without the host
// network. A virtual INET socket (net_unix.go socket(): non-host netns) is
// backed by a host unix socket; bind/listen/connect/accept go through a per-run
// registry and a private host unix path, while the guest keeps INET addresses
// (synthesized on getsockname/getpeername/accept).
//
// Two address scopes:
//   - loopback (127/8, INADDR_ANY): per-namespace, so each container has its own
//     127.0.0.1. Keyed by the namespace.
//   - the virtual network: addresses the guest configures through routing netlink
//     (an interface address, or one on-link with it), one network shared across
//     the run's namespaces so a server in one container is reachable by its
//     address from another. Keyed globally; membership comes from the model, not
//     a fixed subnet.
//
// IPv6 has its own loopback and wildcard, ::1 and ::, apart from IPv4's as
// Linux keeps them: a wildcard of either family binds its family's addresses,
// an IPv6 one IPv4's too unless IPV6_V6ONLY, and an IPv4-mapped address is the
// IPv4 one.
//
// Anything else (a real host address) is unreachable, so an isolated namespace
// never reaches the host network. Global IPv6, multiple named networks and
// cross-run networks are not modelled.

// vkey identifies a reserved endpoint: scope is a namespace id for loopback or
// vnetGlobal for the shared network; ip is the address within that scope (0 for
// the namespace's wildcard). v6 marks IPv6's own address, :: or ::1 (ip 0 or
// 127.0.0.1).
type vkey struct {
	scope int32
	ip    uint32
	port  uint16
	v6    bool
}

type vport struct {
	path      string // backing host unix socket path
	listening bool
	v6only    bool       // an IPv6 wildcard that does not bind IPv4's addresses too
	peer      vkey       // a connected datagram endpoint's peer (ip, port, v6), which alone it takes datagrams from; port 0 when unconnected
	mc        []mcMember // the multicast groups its socket joined (lx_vmcast.go)
	mcNoAll   bool       // IP_MULTICAST_ALL is off: it takes only the groups it joined
	share     vshare     // how its socket lets others bind over it
	seq       uint64     // unique to it among the run's, in its paths
	next      *vport     // the next socket sharing its endpoint, bound before it
}

// vshare is how a socket lets others bind over its endpoint: SO_REUSEADDR,
// SO_REUSEPORT, as uid.
type vshare struct {
	reuse, reusePort bool
	uid              uint32
}

// shares reports whether a socket sharing by s may bind over e, an endpoint
// whose addresses overlap its own, as Linux allows it: both by SO_REUSEPORT
// as one uid, or both by SO_REUSEADDR, a stream socket only while e does not
// listen.
func (s vshare) shares(e *vport, stream bool) bool {
	if s.reusePort && e.share.reusePort && s.uid == e.share.uid {
		return true
	}
	return s.reuse && e.share.reuse && (!stream || !e.listening)
}

// vshareOf is how sk, a vnet socket, shares what it binds, as euid. sk.mu
// held.
func vshareOf(sk *dsock, euid uint32) vshare {
	return vshare{reuse: sk.opts[[2]int{lxSolSocket, 2}] != 0, reusePort: sk.opts[[2]int{lxSolSocket, 15}] != 0, uid: euid}
}

// vcover is the set of its namespace's addresses an endpoint receives on.
type vcover struct {
	v4all, v6all bool
	one          bool // one address, ip (IPv6's own when v6)
	ip           uint32
	v6           bool
}

func vcoverOf(k vkey, v6only bool) vcover {
	switch {
	case k.ip != 0:
		return vcover{one: true, ip: k.ip, v6: k.v6}
	case k.v6:
		return vcover{v6all: true, v4all: !v6only}
	}
	return vcover{v4all: true}
}

func (c vcover) has(ip uint32, v6 bool) bool {
	if c.one {
		return c.ip == ip && c.v6 == v6
	}
	if v6 {
		return c.v6all
	}
	return c.v4all
}

func (c vcover) overlaps(d vcover) bool {
	switch {
	case c.one:
		return d.has(c.ip, c.v6)
	case d.one:
		return c.has(d.ip, d.v6)
	}
	return c.v4all && d.v4all || c.v6all && d.v6all
}

// vnsOf is the namespace whose address k is: its scope, or for an address on
// the virtual network the namespace that holds it. The caller holds n.mu.
func (n *dnet) vnsOf(k vkey) (int32, bool) {
	if k.scope != vnetGlobal {
		return k.scope, true
	}
	ns, ok := n.ipNetns[k.ip]
	return ns, ok
}

func vnetStream(d *dfile) bool {
	return d.sk != nil && d.sk.virt && (d.sk.family == lxAFInet || d.sk.family == lxAFInet6) && d.sk.typ == lxSockStream
}

// vsource is the address a socket of namespace netns, bound to none, sends to
// dst (IPv6's own when v6) from, as Linux's route lookup picks it: the
// loopback's for a loopback dst, the address itself for one the namespace
// holds, else the namespace's address on the virtual network. The caller
// holds n.mu.
func (n *dnet) vsource(netns int32, dst uint32, v6 bool) (uint32, bool) {
	if loopback4(dst) {
		return 127<<24 | 1, v6
	}
	if ns, ok := n.ipNetns[dst]; ok && ns == netns {
		return dst, false
	}
	if a, ok := n.netnsAddr(netns); ok {
		return a, false
	}
	return 127<<24 | 1, false
}

// vconn is what a connecting vnet stream records for its accept: the address
// it connects from and the one it connects to.
type vconn struct{ src, dst vkey }

// scopeOf maps a bind/connect address to its registry scope and key-ip, or
// ok=false if the address is off both loopback and the virtual network.
// Loopback keeps its address in the key so a 127/8 bind stays per-namespace and
// distinct from the 0.0.0.0 wildcard (which also answers at the namespace's
// assigned network address); a virtual-network address is keyed globally.
// Membership in the virtual network comes from the model, not a fixed subnet.
func (n *dnet) scopeOf(netns int32, ip uint32) (scope int32, keyIP uint32, ok bool) {
	if loopback4(ip) || multicast4(ip) { // a group is bound to within a namespace
		return netns, ip, true
	}
	n.mu.Lock()
	on := n.onVirtualNet(netns, ip)
	n.mu.Unlock()
	if on {
		return vnetGlobal, ip, true
	}
	return 0, 0, false
}

func vPath(dir string, k vkey) string {
	return filepath.Join(dir, vBase("vnet", k))
}

// vBase is the name of the backing path of endpoint k in table name ("vnet"
// or "vudp"), from which the endpoint is read back (vPathAddr).
func vBase(name string, k vkey) string {
	if k.v6 {
		name += "6"
	}
	return fmt.Sprintf("%s-%d-%d-%d", name, k.scope, k.ip, k.port)
}

// vPathAddr is the endpoint the backing path at path in table name holds.
func vPathAddr(path, name string) (k vkey, ok bool) {
	base := filepath.Base(path)
	if strings.HasPrefix(base, name+"6-") {
		name, k.v6 = name+"6", true
	}
	c, _ := fmt.Sscanf(base, name+"-%d-%d-%d", &k.scope, &k.ip, &k.port)
	return k, c == 3
}

// sockaddrIn4 encodes a Linux sockaddr_in (port and address network byte order).
func sockaddrIn4(ip uint32, port uint16) []byte {
	b := make([]byte, 16)
	b[0], b[1] = lxAFInet, 0
	b[2], b[3] = byte(port>>8), byte(port)
	b[4], b[5], b[6], b[7] = byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)
	return b
}

func parseIn4(raw []byte) (ip uint32, port uint16, ok bool) {
	if len(raw) < 8 || raw[0] != lxAFInet || raw[1] != 0 {
		return 0, 0, false
	}
	port = uint16(raw[2])<<8 | uint16(raw[3])
	ip = uint32(raw[4])<<24 | uint32(raw[5])<<16 | uint32(raw[6])<<8 | uint32(raw[7])
	return ip, port, true
}

func loopback4(ip uint32) bool { return ip>>24 == 127 || ip == 0 } // 127/8 or INADDR_ANY

// sockaddrIn6 encodes a Linux sockaddr_in6, mapping the vnet's IPv4 address into
// it: 0 is the unspecified wildcard (::), anything else an IPv4-mapped address
// (::ffff:a.b.c.d). Real global IPv6 is not modelled; vName gives ::1.
func sockaddrIn6(ip uint32, port uint16) []byte {
	b := make([]byte, 28)
	b[0], b[1] = lxAFInet6, 0
	b[2], b[3] = byte(port>>8), byte(port)
	if ip != 0 {
		b[18], b[19] = 0xff, 0xff
		b[20], b[21], b[22], b[23] = byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)
	}
	return b
}

// parseSock reads an IPv4 or IPv6 guest sockaddr as a vnet address: v6 for
// IPv6's own, :: (ip 0) or ::1 (ip 127.0.0.1); ::ffff:a.b.c.d is that IPv4
// address. A global IPv6 address is unsupported.
func parseSock(raw []byte) (ip uint32, port uint16, v6, ok bool) {
	switch saFamily(raw) {
	case lxAFInet:
		ip, port, ok = parseIn4(raw)
		return ip, port, false, ok
	case lxAFInet6:
		if len(raw) < 28 {
			return 0, 0, true, false
		}
		port = uint16(raw[2])<<8 | uint16(raw[3])
		a := raw[8:24]
		switch {
		case allZero(a): // :: (unspecified wildcard)
			return 0, port, true, true
		case allZero(a[:15]) && a[15] == 1: // ::1 (loopback)
			return 127<<24 | 1, port, true, true
		case allZero(a[:10]) && a[10] == 0xff && a[11] == 0xff: // ::ffff:a.b.c.d
			return uint32(a[12])<<24 | uint32(a[13])<<16 | uint32(a[14])<<8 | uint32(a[15]), port, false, true
		}
		return 0, 0, true, false // a global IPv6 address: not modelled
	}
	return 0, 0, false, false
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// vSockaddr synthesizes the guest-facing address of a virtual socket in its own
// family, so getsockname/getpeername match the socket the guest created.
func vSockaddr(family int, ip uint32, port uint16) []byte {
	if family == lxAFInet6 {
		return sockaddrIn6(ip, port)
	}
	return sockaddrIn4(ip, port)
}

// vName is the guest sockaddr of a family socket for vnet address ip:port,
// IPv6's own when v6.
func vName(family int, ip uint32, port uint16, v6 bool) []byte {
	b := vSockaddr(family, ip, port)
	if v6 && ip != 0 {
		b = sockaddrIn6(0, port)
		b[23] = 1 // ::1
	}
	return b
}

// v6only reports whether s, an IPv6 socket, binds IPv6's addresses alone
// (IPV6_V6ONLY, which a vnet socket keeps itself). s.mu held.
func (s *dsock) v6onlyLocked() bool {
	return s.family == lxAFInet6 && s.opts[[2]int{lxSolIPv6, lxIPv6V6only}] != 0
}

// vaddrOf reads the address a family socket binds or connects to: the
// sockaddr's checks as the host's (inetSockaddr), then the vnet address. A
// mapped IPv4 address is EINVAL to bind and ENETUNREACH to connect to on an
// IPv6 socket that binds IPv6's addresses alone.
func vaddrOf(raw []byte, sk *dsock, connect bool) (ip uint32, port uint16, v6 bool, e lxErrno) {
	if _, e := inetSockaddr(raw, sk.family, false); e != 0 {
		return 0, 0, false, e
	}
	ip, port, v6, ok := parseSock(raw)
	switch {
	case !ok && connect:
		return 0, 0, false, lxENETUNREACH // a global IPv6 address laboon does not model
	case !ok:
		return 0, 0, false, lxEADDRNOTAVAIL
	case !v6 && saFamily(raw) == lxAFInet6 && sk.v6onlyLocked() && connect:
		return 0, 0, false, lxENETUNREACH
	case !v6 && saFamily(raw) == lxAFInet6 && sk.v6onlyLocked():
		return 0, 0, false, lxEINVAL
	}
	return ip, port, v6, 0
}

// vreserve claims endpoint k in tab (the stream or the datagram ports, as
// stream says), backed at the path name gives it, assigning a free ephemeral
// port when k.port is 0; v6only for an IPv6 wildcard that binds IPv6's
// addresses alone, sharing by sh with the sockets over whose endpoints it
// binds. A socket sharing k itself goes first in its chain: the newest takes
// a datagram they would both take, as on Linux. The caller holds n.mu.
func (n *dnet) vreserve(tab map[vkey]*vport, name string, k vkey, v6only bool, sh vshare, stream bool) (vkey, *vport, lxErrno) {
	if k.port == 0 {
		for p := n.vEphem; ; {
			if k.port = p; !n.vtaken(tab, k, v6only, vshare{}, stream) {
				n.vEphem = nextEphem(p + 1)
				break
			}
			if p = nextEphem(p + 1); p == n.vEphem {
				return vkey{}, nil, lxEADDRINUSE
			}
		}
	} else if n.vtaken(tab, k, v6only, sh, stream) {
		return vkey{}, nil, lxEADDRINUSE
	}
	n.vseq++
	vp := &vport{path: filepath.Join(n.dir, fmt.Sprintf("%s-%d", vBase(name, k), n.vseq)), v6only: v6only, share: sh, seq: n.vseq, next: tab[k]}
	tab[k] = vp
	return k, vp, 0
}

// vremove takes vp out of endpoint k in tab. The caller holds n.mu.
func vremove(tab map[vkey]*vport, k vkey, vp *vport) {
	if tab[k] == vp {
		if vp.next == nil {
			delete(tab, k)
		} else {
			tab[k] = vp.next
		}
		return
	}
	for e := tab[k]; e != nil; e = e.next {
		if e.next == vp {
			e.next = vp.next
			return
		}
	}
}

// vtaken reports whether endpoint k, sharing by sh, would share deliveries
// with one in tab that does not let it: one namespace's endpoints on a port
// whose addresses overlap (vcover). The caller holds n.mu.
func (n *dnet) vtaken(tab map[vkey]*vport, k vkey, v6only bool, sh vshare, stream bool) bool {
	ns, owned := n.vnsOf(k)
	c := vcoverOf(k, v6only)
	for ek, head := range tab {
		if ek.port != k.port {
			continue
		}
		if ek != k {
			if ens, ok := n.vnsOf(ek); !owned || !ok || ens != ns {
				continue
			}
		}
		for e := head; e != nil; e = e.next {
			if (ek == k || c.overlaps(vcoverOf(ek, e.v6only))) && !sh.shares(e, stream) {
				return true
			}
		}
	}
	return false
}

// vlistenTaken reports whether vp, endpoint k's, may not listen: a socket it
// shares an overlapping endpoint with otherwise than by SO_REUSEPORT already
// listens there, which Linux checks for again at listen. The caller holds
// n.mu.
func (n *dnet) vlistenTaken(k vkey, vp *vport) bool {
	ns, owned := n.vnsOf(k)
	c := vcoverOf(k, vp.v6only)
	for ek, head := range n.vports {
		if ek.port != k.port {
			continue
		}
		if ek != k {
			if ens, ok := n.vnsOf(ek); !owned || !ok || ens != ns {
				continue
			}
		}
		for e := head; e != nil; e = e.next {
			if e == vp || !e.listening || !(ek == k || c.overlaps(vcoverOf(ek, e.v6only))) {
				continue
			}
			if !(vp.share.reusePort && e.share.reusePort && vp.share.uid == e.share.uid) {
				return true
			}
		}
	}
	return false
}

// vdeliver is the endpoint in tab that a delivery to k reaches: of the
// sockets bound to the address itself, else to its namespace's wildcard of
// its family, else for IPv4 to an IPv6 wildcard that binds IPv4's addresses
// too (dual), the one pick chooses from that chain. The caller holds n.mu.
func (n *dnet) vdeliver(tab map[vkey]*vport, k vkey, pick func(chain *vport, dual bool) *vport) *vport {
	if vp := pick(tab[k], false); vp != nil {
		return vp
	}
	ns, owned := n.vnsOf(k)
	if !owned {
		return nil
	}
	if vp := pick(tab[vkey{ns, 0, k.port, k.v6}], false); vp != nil {
		return vp
	}
	if !k.v6 {
		return pick(tab[vkey{ns, 0, k.port, true}], true)
	}
	return nil
}

// vreusePick is the one of vs, newest first, that a datagram or connection
// from src goes to: of sockets sharing by SO_REUSEPORT, one by a hash of
// src, as Linux spreads a port's flows across them; else the newest.
func vreusePick(vs []*vport, src vkey) *vport {
	if len(vs) == 0 {
		return nil
	}
	if !vs[0].share.reusePort {
		return vs[0]
	}
	var group []*vport
	for _, v := range vs {
		if v.share.reusePort {
			group = append(group, v)
		}
	}
	h := src.ip*2654435761 ^ uint32(src.port)*40503
	return group[h%uint32(len(group))]
}

// vudpPick is the socket of chain a datagram from src goes to: one connected
// to src, else one connected to none (vreusePick); dual for an IPv4 datagram
// to IPv6 wildcards, which an IPv6-only one does not take.
func vudpPick(chain *vport, src vkey, dual bool) *vport {
	var free []*vport
	for v := chain; v != nil; v = v.next {
		switch {
		case dual && v.v6only:
		case v.peer.port == 0:
			free = append(free, v)
		case v.peer == src:
			return v
		}
	}
	return vreusePick(free, src)
}

// vtcpPick is the listener of chain a connection from src goes to
// (vreusePick); dual as for vudpPick.
func vtcpPick(chain *vport, src vkey, dual bool) *vport {
	var ls []*vport
	for v := chain; v != nil; v = v.next {
		if v.listening && !(dual && v.v6only) {
			ls = append(ls, v)
		}
	}
	return vreusePick(ls, src)
}

// nextEphem is p within the kernel's default ephemeral port range
// (net.ipv4.ip_local_port_range, 32768-60999), wrapping to its start.
func nextEphem(p uint16) uint16 {
	if p < 32768 || p > 60999 {
		return 32768
	}
	return p
}

// vbind binds a virtual IPv4 stream socket to ip:port (loopback or the virtual
// network).
func (g *dguest) vbind(d *dfile, raw []byte) int64 {
	sk := d.sk
	sk.mu.Lock()
	defer sk.mu.Unlock()
	ip, port, v6, e := vaddrOf(raw, sk, false)
	if e != 0 {
		return sErr(e)
	}
	n := g.netState()
	scope, keyIP, ok := n.scopeOf(sk.netns, ip)
	if !ok {
		return sErr(lxEADDRNOTAVAIL) // not an address this namespace holds
	}
	if sk.name != nil {
		return sErr(lxEINVAL) // already bound
	}
	n.mu.Lock()
	k, vp, e := n.vreserve(n.vports, "vnet", vkey{scope, keyIP, port, v6}, sk.v6onlyLocked(), vshareOf(sk, g.ps.cred.euid), true)
	n.mu.Unlock()
	if e != 0 {
		return sErr(e)
	}
	if err := n.bindUnix(hostFd(d.f), vp.path); err != nil {
		n.mu.Lock()
		vremove(n.vports, k, vp)
		n.mu.Unlock()
		return sErr(osErrno(err))
	}
	sk.name = vName(sk.family, ip, k.port, v6)
	sk.vk, sk.vp, sk.vbound = k, vp, true
	sk.unlink = vp.path // removed with the socket (dsock.close)
	sk.vn = n
	return 0
}

func (g *dguest) vlisten(d *dfile, backlog int) int64 {
	sk := d.sk
	sk.mu.Lock()
	bound := sk.vbound
	sk.mu.Unlock()
	if !bound { // listen without bind: an ephemeral port on the wildcard
		if r := g.vbind(d, vSockaddr(sk.family, 0, 0)); r != 0 {
			return r
		}
	}
	if backlog < 0 || backlog > 4096 {
		backlog = 4096
	}
	sk.mu.Lock()
	k, vp := sk.vk, sk.vp
	sk.mu.Unlock()
	n := g.netState()
	if e := n.vlistenOn(k, vp); e != 0 {
		return sErr(e)
	}
	if err := unix.Listen(hostFd(d.f), backlog); err != nil {
		n.mu.Lock()
		vp.listening = false
		n.mu.Unlock()
		return sErr(osErrno(err))
	}
	sk.mu.Lock()
	sk.listening = true
	sk.mu.Unlock()
	return 0
}

// vlistenOn marks vp, endpoint k's, listening, unless another socket already
// listens over it (vlistenTaken).
func (n *dnet) vlistenOn(k vkey, vp *vport) lxErrno {
	n.mu.Lock()
	defer n.mu.Unlock()
	if vp == nil {
		return 0
	}
	if !vp.listening && n.vlistenTaken(k, vp) {
		return lxEADDRINUSE
	}
	vp.listening = true
	return 0
}

// vconnect connects a virtual IPv4 stream socket to a listener reachable from
// its namespace (same-namespace loopback, or the shared virtual network).
func (g *dguest) vconnect(d *dfile, raw []byte) int64 {
	sk := d.sk
	sk.mu.Lock()
	ip, port, v6, e := vaddrOf(raw, sk, true)
	sk.mu.Unlock()
	if e != 0 {
		return sErr(e)
	}
	dst := ip
	if dst == 0 {
		dst = 127<<24 | 1 // connecting to the wildcard means the loopback: 127.0.0.1, or ::1
	}
	if port == 0 || multicast4(dst) {
		return sErr(lxENETUNREACH)
	}
	n := g.netState()
	scope, keyIP, ok := n.scopeOf(sk.netns, dst)
	if !ok {
		// Not loopback or the virtual network: an external address. A container on
		// a network may reach it through the egress proxy; an isolated one
		// (--network=none, no assigned address) cannot.
		return g.vegress(d, dst, port)
	}
	// Bind an unbound socket to an ephemeral port on the source address
	// before connecting; the reservation is released on socket close. The
	// accept learns both addresses from what the connect records (vpeer).
	n.mu.Lock()
	src, srcV6 := n.vsource(sk.netns, dst, v6)
	n.mu.Unlock()
	sk.mu.Lock()
	bound := sk.vbound
	sk.mu.Unlock()
	if !bound {
		if r := g.vbind(d, vName(sk.family, src, 0, srcV6)); r != 0 {
			return r
		}
	}
	sk.mu.Lock()
	k, own := sk.vk, sk.unlink
	if k.ip != 0 {
		src, srcV6 = k.ip, k.v6
	}
	sk.mu.Unlock()
	n.mu.Lock()
	path, reachable := n.vlistener(scope, keyIP, port, v6, vkey{ip: src, port: k.port, v6: srcV6})
	if reachable {
		n.vconns[own] = vconn{src: vkey{ip: src, port: k.port, v6: srcV6}, dst: vkey{ip: dst, port: port, v6: v6}}
	}
	n.mu.Unlock()
	if !reachable {
		return sErr(lxECONNREFUSED)
	}
	err := n.viaShort(path, func(sa *unix.SockaddrUnix) error { return unix.Connect(hostFd(d.f), sa) })
	if err == unix.EINPROGRESS || err == unix.EAGAIN {
		err = g.awaitConnect(d)
	}
	if err != nil {
		n.mu.Lock()
		delete(n.vconns, own)
		n.mu.Unlock()
		return sErr(osErrno(err))
	}
	sk.mu.Lock()
	sk.peer = vName(sk.family, dst, port, v6)
	sk.name = vName(sk.family, src, k.port, srcV6) // bound to a wildcard, it is now at the source its route picked
	sk.mu.Unlock()
	return 0
}

// virtBind handles bind on a non-stream virtual socket: a datagram socket
// binds a loopback or wildcard address, or one the namespace has on the
// virtual network (vudpBind). Binding any other address is refused.
func (g *dguest) virtBind(d *dfile, raw []byte) int64 {
	d.sk.mu.Lock()
	defer d.sk.mu.Unlock()
	if saFamily(raw) == lxAFInet6 && len(raw) >= 28 && raw[8] == 0xff {
		return g.vbindGroup6(d, raw)
	}
	ip, port, v6, e := vaddrOf(raw, d.sk, false)
	if e != 0 {
		return sErr(e)
	}
	scope, keyIP, ok := g.netState().scopeOf(d.sk.netns, ip)
	if !ok {
		return sErr(lxEADDRNOTAVAIL)
	}
	if e := g.vudpBind(d, vkey{scope, keyIP, port, v6}, ip); e != 0 {
		return sErr(e)
	}
	return 0
}

// vudpBind binds a virtual datagram socket to endpoint k, address ip (port 0:
// an ephemeral one). Its backing takes the endpoint's path, where a datagram
// to it is sent and which names it, as a datagram's sender, to the receiver
// (vudpFrom). d.sk.mu is held.
func (g *dguest) vudpBind(d *dfile, k vkey, ip uint32) lxErrno {
	sk := d.sk
	if sk.vbound || sk.unlink != "" {
		return lxEINVAL // already bound, or by its first send
	}
	n := g.netState()
	n.mu.Lock()
	k, vp, e := n.vreserve(n.vudps, "vudp", k, sk.v6onlyLocked(), vshareOf(sk, g.ps.cred.euid), false)
	n.mu.Unlock()
	if e != 0 {
		return e
	}
	if err := n.bindUnix(hostFd(d.f), vp.path); err != nil {
		n.mu.Lock()
		vremove(n.vudps, k, vp)
		n.mu.Unlock()
		return osErrno(err)
	}
	sk.vp = vp
	n.mu.Lock()
	vp.mc = append([]mcMember(nil), sk.mcast...)
	all, set := sk.opts[[2]int{lxSolIP, lxIPMulticastAll}]
	vp.mcNoAll = set && all == 0
	n.mu.Unlock()
	sk.name = vName(sk.family, ip, k.port, k.v6)
	sk.vk, sk.vbound, sk.vudp, sk.vn = k, true, true, n
	sk.unlink = vp.path // removed with the socket (dsock.close)
	return 0
}

// vudpAutobind binds an unbound virtual datagram socket to an ephemeral port
// on the address it sends to dst (IPv6's own when v6) from, as Linux binds one
// on its first send or connect: loopback for a loopback dst, else the
// namespace's address on the virtual network if it has one.
func (g *dguest) vudpAutobind(d *dfile, dst uint32, v6 bool) lxErrno {
	sk := d.sk
	sk.mu.Lock()
	defer sk.mu.Unlock()
	if sk.vbound || sk.unlink != "" {
		return 0
	}
	return g.vudpBind(d, vkey{sk.netns, 0, 0, sk.family == lxAFInet6}, 0)
}

// vsrcFd is the host fd a datagram from d, sent from fd, its backing, to dst
// (IPv6's own when v6) goes out of, and the address (ip, port, v6) it comes
// from. A socket bound to a wildcard sends each datagram from the address
// Linux's route picks for it (vsource).
func (g *dguest) vsrcFd(d *dfile, fd int, dst uint32, v6 bool) (int, vkey) {
	n := g.netState()
	n.mu.Lock()
	src, srcV6 := n.vsource(d.sk.netns, dst, v6)
	n.mu.Unlock()
	return g.vsrcFdAt(d, fd, src, srcV6)
}

// vsrcFdAt is vsrcFd for a datagram a socket bound to a wildcard sends from
// src (IPv6's own when srcV6): it goes out of a socket bound to the path
// naming that address, which its receiver reads as the sender's (vudpFrom).
// No other socket holds that path: the wildcard's reservation covers it.
func (g *dguest) vsrcFdAt(d *dfile, fd int, src uint32, srcV6 bool) (int, vkey) {
	sk := d.sk
	sk.mu.Lock()
	k := sk.vk
	sk.mu.Unlock()
	if k.ip != 0 && !vgroupKey(k) {
		return fd, vkey{ip: k.ip, port: k.port, v6: k.v6}
	}
	n := g.netState()
	from := vkey{ip: src, port: k.port, v6: srcV6}
	scope, keyIP, _ := n.scopeOf(sk.netns, src)
	key := vkey{scope, keyIP, k.port, srcV6}
	sk.mu.Lock()
	defer sk.mu.Unlock()
	if v, ok := sk.vsrcs[key]; ok {
		return hostFd(v.f), from
	}
	f, err := vloFile(sk.typ)
	if err != nil {
		return fd, from
	}
	path := filepath.Join(n.dir, vBase("vudp", key))
	if sk.vp != nil {
		path = fmt.Sprintf("%s-%d", path, sk.vp.seq) // one per sharer of its endpoint
	}
	if n.bindUnix(hostFd(f), path) != nil {
		f.Close()
		return fd, from
	}
	if sk.vsrcs == nil {
		sk.vsrcs = map[vkey]vsrc{}
	}
	sk.vsrcs[key] = vsrc{f, path}
	return hostFd(f), from
}

// vudpTarget is the backing path of the datagram socket a datagram from src
// (ip, port, v6) to keyIP:port in scope (IPv6's own address when v6) reaches
// (vdeliver): a connected socket takes only its peer's, as Linux's lookup
// matches it. "" when none does. The caller holds n.mu.
func (n *dnet) vudpTarget(scope int32, keyIP uint32, port uint16, v6 bool, src vkey) string {
	if vp := n.vdeliver(n.vudps, vkey{scope, keyIP, port, v6}, func(c *vport, dual bool) *vport { return vudpPick(c, src, dual) }); vp != nil {
		return vp.path
	}
	return ""
}

// vudpFrom is the guest address of the sender whose backing is bound at path,
// as receiver sk sees it, or nil if path is no datagram endpoint. A sender on
// a wildcard sent from loopback within its namespace, else from its address
// on the virtual network.
func (n *dnet) vudpFrom(sk *dsock, path string) []byte {
	k, ok := vPathAddr(path, "vudp")
	if !ok {
		return nil
	}
	if k.ip == 0 {
		k.ip = 127<<24 | 1
		k.v6 = k.v6 && sk.family == lxAFInet6 // an IPv4 receiver was sent to from IPv4's loopback
		if k.scope != sk.netns {
			k.v6 = false
			n.mu.Lock()
			if a, has := n.netnsAddr(k.scope); has {
				k.ip = a
			}
			n.mu.Unlock()
		}
	}
	return vName(sk.family, k.ip, k.port, k.v6)
}

// vudpSend sends a datagram to dst:port on loopback or the virtual network.
// One to a port no socket is bound on, or that its receiver has no room for,
// is dropped, as the kernel drops it.
func (g *dguest) vudpSend(d *dfile, iovs [][2]uint64, dst uint32, port uint16, v6 bool) int64 {
	total := iovTotal(iovs)
	if total > 65507 {
		return sErr(lxEMSGSIZE)
	}
	if e := g.vudpAutobind(d, dst, v6); e != 0 {
		return sErr(e)
	}
	data, e := g.gather(iovs, 0, total)
	if e != 0 {
		return sErr(e)
	}
	n := g.netState()
	scope, keyIP, _ := n.scopeOf(d.sk.netns, dst)
	fd, src := g.vsrcFd(d, hostFd(d.f), dst, v6)
	n.mu.Lock()
	path := n.vudpTarget(scope, keyIP, port, v6, src)
	n.mu.Unlock()
	if path != "" {
		n.viaShort(path, func(sa *unix.SockaddrUnix) error { return unix.Sendto(fd, data, unix.MSG_DONTWAIT, sa) })
	}
	return int64(total)
}

// virtConnect handles connect on a non-stream virtual socket. A datagram socket
// may "connect" to a :53 server (how a resolver associates its socket before
// send/recv); it is recorded so the connected send and recv resolve through the
// DNS proxy. Anything else off the virtual network is unreachable.
func (g *dguest) virtConnect(d *dfile, raw []byte) int64 {
	if saFamily(raw) == 0 && d.sk.typ == lxSockDgram { // AF_UNSPEC: no peer
		d.sk.mu.Lock()
		d.sk.vdnsServer, d.sk.vpeer = nil, nil
		vp := d.sk.vp
		d.sk.mu.Unlock()
		n := g.netState()
		n.mu.Lock()
		if vp != nil {
			vp.peer = vkey{}
		}
		n.mu.Unlock()
		return 0
	}
	if d.sk.typ != lxSockDgram {
		return sErr(lxENETUNREACH)
	}
	d.sk.mu.Lock()
	ip, port, v6, e := vaddrOf(raw, d.sk, true)
	d.sk.mu.Unlock()
	if e != 0 {
		return sErr(e)
	}
	dst := ip
	if dst == 0 {
		dst = 127<<24 | 1
	}
	if multicast4(dst) || g.vudpLocal(d, dst, port) {
		if e := g.vudpAutobind(d, dst, v6); e != 0 {
			return sErr(e)
		}
		n := g.netState()
		n.mu.Lock()
		src, srcV6 := n.vsource(d.sk.netns, dst, v6)
		n.mu.Unlock()
		d.sk.mu.Lock()
		d.sk.vpeer = vName(d.sk.family, dst, port, v6)
		if d.sk.vk.ip == 0 {
			d.sk.name = vName(d.sk.family, src, d.sk.vk.port, srcV6) // connected, it is at the source its route picked
		}
		vp := d.sk.vp
		d.sk.mu.Unlock()
		n.mu.Lock()
		if vp != nil {
			vp.peer = vkey{ip: dst, port: port, v6: v6}
		}
		n.mu.Unlock()
		return 0
	}
	if port == 53 && g.cfg.Net { // the resolver: answered by the DNS proxy
		if e := g.vdnsBind(d, ip); e != 0 {
			return sErr(e)
		}
		d.sk.mu.Lock()
		d.sk.vdnsServer = sockaddrIn4(ip, port)
		d.sk.mu.Unlock()
		return 0
	}
	return g.vudpConnect(d, ip, port)
}

// vudpLocal reports whether a datagram to dst:port stays among the run's
// sockets: on loopback, or on the virtual network except to a :53 server,
// which the DNS proxy answers when the run has networking.
func (g *dguest) vudpLocal(d *dfile, dst uint32, port uint16) bool {
	scope, _, in := g.netState().scopeOf(d.sk.netns, dst)
	return in && !(scope == vnetGlobal && port == 53 && g.cfg.Net)
}

// vudpConnect connects a virtual datagram socket to an external host through a
// real host UDP socket, under the egress policy. Replies from the host socket
// are self-delivered into the socket's backing so recv/poll see them.
func (g *dguest) vudpConnect(d *dfile, ip uint32, port uint16) int64 {
	n := g.netState()
	n.mu.Lock()
	networked := g.cfg.Net && n.netnsNetworked(d.sk.netns)
	n.mu.Unlock()
	if !networked {
		return sErr(lxENETUNREACH) // not attached to a network (e.g. --network=none)
	}
	dip := net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
	if !n.eg.connectAllowed(dip, int(port)) {
		return sErr(lxECONNREFUSED)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return sErr(osErrno(err))
	}
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dip.To4())
	sa.Port = int(port)
	if err := unix.Connect(fd, &sa); err != nil {
		unix.Close(fd)
		return sErr(osErrno(err))
	}
	if e := g.vdnsBind(d, ip); e != 0 { // bind the backing so a reply has somewhere to arrive
		unix.Close(fd)
		return sErr(e)
	}
	d.sk.mu.Lock()
	d.sk.udpEg = fd
	d.sk.vdnsServer = sockaddrIn4(ip, port)
	path := d.sk.unlink
	d.sk.mu.Unlock()
	go g.vudpRelay(d, fd, path)
	return 0
}

// vudpRelay carries datagrams the external peer sends back into the socket's
// backing, until the host socket is closed (socket close).
func (g *dguest) vudpRelay(d *dfile, fd int, path string) {
	n := g.netState()
	// Deliver through a dedicated sender, not the guest's socket: a client that
	// shut down its write side (nc does, after sending) would make a self-send
	// fail while its read side is still open.
	sfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	defer unix.Close(sfd)
	buf := make([]byte, 65535)
	for {
		m, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return // the host socket was closed
		}
		reply := append([]byte(nil), buf[:m]...)
		n.viaShort(path, func(sa *unix.SockaddrUnix) error { return unix.Sendto(sfd, reply, 0, sa) })
	}
}

// virtSend handles a send on a virtual socket (sendto/sendmsg/write funnel
// here). A datagram to :53 (or a connected DNS socket's send) is answered by the
// supervisor's DNS proxy, so an isolated container resolves names under the
// egress policy; anything else off the virtual network is unreachable.
func (g *dguest) virtSend(d *dfile, iovs [][2]uint64, dest []byte) int64 {
	if len(dest) == 0 { // a connected datagram socket
		d.sk.mu.Lock()
		udp, srv, peer := d.sk.udpEg, d.sk.vdnsServer, d.sk.vpeer
		d.sk.mu.Unlock()
		if udp > 0 { // UDP egress: forward out through the host socket
			return g.vudpWrite(udp, iovs)
		}
		if peer != nil {
			ip, port, v6, _ := parseSock(peer)
			if multicast4(ip) {
				return g.vmcSend(d, iovs, ip, port)
			}
			return g.vudpSend(d, iovs, ip, port, v6)
		}
		if srv == nil {
			return sErr(lxEDESTADDRREQ)
		}
		ip, port, _, _ := parseSock(srv)
		return g.vdnsSend(d, iovs, ip, port)
	}
	d.sk.mu.Lock()
	ip, port, v6, e := vaddrOf(dest, d.sk, true)
	d.sk.mu.Unlock()
	if e != 0 {
		return sErr(e)
	}
	dst := ip
	if dst == 0 {
		dst = 127<<24 | 1
	}
	if multicast4(dst) {
		return g.vmcSend(d, iovs, dst, port)
	}
	if g.vudpLocal(d, dst, port) {
		return g.vudpSend(d, iovs, dst, port, v6)
	}
	if port == 53 && g.cfg.Net {
		return g.vdnsSend(d, iovs, ip, port)
	}
	return sErr(lxENETUNREACH)
}

// vudpWrite forwards a datagram out through a connected host UDP egress socket.
func (g *dguest) vudpWrite(fd int, iovs [][2]uint64) int64 {
	data := make([]byte, 0, iovTotal(iovs))
	for _, iov := range iovs {
		b, err := g.readMem(iov[0], int(iov[1]))
		if err != nil {
			return sErr(lxEFAULT)
		}
		data = append(data, b...)
	}
	if err := unix.Send(fd, data, 0); err != nil {
		return sErr(osErrno(err))
	}
	return int64(len(data))
}

// vdnsOnlyV4 resolves like the host does but hides IPv6 (AAAA) results, because
// the virtual network only carries IPv4 egress: a container that learned an
// IPv6 address would try to reach it and fail, so leaving AAAA empty makes the
// resolver fall back to the IPv4 (A) record it can actually use.
func vdnsOnlyV4(network, name string) ([]net.IP, dnsmessage.RCode) {
	if network != "ip4" {
		// Hide AAAA as a successful empty answer so the resolver falls back to the
		// A record; the paired A query still carries the host's real result code.
		return nil, dnsmessage.RCodeSuccess
	}
	return hostLookup(network, name)
}

// vdnsSend answers a DNS query a virtual datagram socket sent to a :53 server.
// The reply is produced by the supervisor's DNS proxy (which resolves on the
// host, enforces the domain allowlist and pins the addresses it returns so a
// later egress to them is permitted) and delivered into the socket's own
// backing, so poll and recvfrom see it as an ordinary incoming datagram.
func (g *dguest) vdnsSend(d *dfile, iovs [][2]uint64, ip uint32, port uint16) int64 {
	query := make([]byte, 0, iovTotal(iovs))
	for _, iov := range iovs {
		b, err := g.readMem(iov[0], int(iov[1]))
		if err != nil {
			return sErr(lxEFAULT)
		}
		query = append(query, b...)
	}
	n := g.netState()
	if e := g.vdnsBind(d, ip); e != 0 {
		return sErr(e)
	}
	if reply := n.eg.answer(query, vdnsOnlyV4); reply != nil {
		d.sk.mu.Lock()
		path := d.sk.unlink
		d.sk.mu.Unlock()
		n.viaShort(path, func(sa *unix.SockaddrUnix) error { return unix.Sendto(hostFd(d.f), reply, 0, sa) })
	}
	d.sk.mu.Lock()
	d.sk.vdnsServer = sockaddrIn4(ip, port)
	d.sk.mu.Unlock()
	return int64(len(query))
}

// vdnsBind binds a virtual datagram socket that queries dst (the DNS proxy,
// or an egress peer) as its first send would, so a self-delivered reply has
// somewhere to arrive.
func (g *dguest) vdnsBind(d *dfile, dst uint32) lxErrno {
	return g.vudpAutobind(d, dst, false)
}

// netnsNetworked reports whether a namespace was given an address on the virtual
// network (so it may egress); an isolated --network=none namespace was not. The
// caller holds n.mu.
func (n *dnet) netnsNetworked(netns int32) bool {
	for _, ns := range n.ipNetns {
		if ns == netns {
			return true
		}
	}
	return false
}

// vegress proxies a virtual socket's connection to an external host out through
// a real host socket, under the egress policy. Only a container on a network may
// egress; traffic is relayed between the guest's socket and the host connection,
// so the guest never holds a host socket itself.
func (g *dguest) vegress(d *dfile, ip uint32, port uint16) int64 {
	n := g.netState()
	dip := net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
	n.mu.Lock()
	networked := g.cfg.Net && n.netnsNetworked(d.sk.netns)
	n.mu.Unlock()
	if !networked {
		return sErr(lxENETUNREACH) // not attached to a network (e.g. --network=none), or the run has none
	}
	if !n.eg.connectAllowed(dip, int(port)) {
		return sErr(lxECONNREFUSED) // the egress policy forbids this destination
	}
	// Connect the real host socket first, so a failure reaches the guest as the
	// connect error rather than a half-open relay.
	tfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return sErr(osErrno(err))
	}
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dip.To4())
	sa.Port = int(port)
	if err := unix.Connect(tfd, &sa); err != nil {
		unix.Close(tfd)
		return sErr(osErrno(err))
	}
	// Join the guest's socket to a private relay endpoint and hand both ends to
	// the relay.
	sconn, e := g.vpipe(d)
	if e != 0 {
		unix.Close(tfd)
		return sErr(e)
	}
	go relayStream(sconn, tfd)
	d.sk.mu.Lock()
	d.sk.peer = vSockaddr(d.sk.family, ip, port)
	d.sk.mu.Unlock()
	return 0
}

// vpipe connects the guest's virtual socket to a fresh private listener and
// returns the supervisor's accepted end, the other side of the guest's socket.
func (g *dguest) vpipe(d *dfile) (int, lxErrno) {
	n := g.netState()
	lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, osErrno(err)
	}
	defer unix.Close(lfd)
	n.mu.Lock()
	n.seq++
	path := filepath.Join(n.dir, fmt.Sprintf("eg-%d", n.seq))
	n.mu.Unlock()
	if err := n.bindUnix(lfd, path); err != nil {
		return -1, osErrno(err)
	}
	defer unix.Unlink(path)
	if err := unix.Listen(lfd, 1); err != nil {
		return -1, osErrno(err)
	}
	err = n.viaShort(path, func(sa *unix.SockaddrUnix) error { return unix.Connect(hostFd(d.f), sa) })
	if err == unix.EINPROGRESS || err == unix.EAGAIN {
		err = g.awaitConnect(d)
	}
	if err != nil {
		return -1, osErrno(err)
	}
	sconn, _, err := unix.Accept(lfd)
	if err != nil {
		return -1, osErrno(err)
	}
	return sconn, 0
}

// relayStream copies bytes both ways between two connected host sockets until
// each direction ends, half-closing the far side so the peer sees EOF, then
// closes both.
func relayStream(a, b int) {
	done := make(chan struct{}, 2)
	cp := func(dst, src int) {
		buf := make([]byte, 32*1024)
		for {
			nr, err := unix.Read(src, buf)
			if nr > 0 {
				for off := 0; off < nr; {
					nw, werr := unix.Write(dst, buf[off:nr])
					if nw > 0 {
						off += nw
					}
					if werr != nil || nw <= 0 {
						break
					}
				}
			}
			if nr <= 0 || err != nil {
				break
			}
		}
		unix.Shutdown(dst, unix.SHUT_WR) // signal EOF to the other side
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	unix.Close(a)
	unix.Close(b)
}

// vlisten4 finds a listener for a connect to (scope, keyIP, port), returning its
// backing path. Beyond an exact match it falls back to a wildcard (0.0.0.0)
// listener: in the same namespace for a loopback target, or in the address's
// owning namespace for a virtual-network target (so a container that bound
// 0.0.0.0 is reachable at its assigned address from another container). The
// caller holds n.mu.
func (n *dnet) vlistener(scope int32, keyIP uint32, port uint16, v6 bool, src vkey) (string, bool) {
	if vp := n.vdeliver(n.vports, vkey{scope, keyIP, port, v6}, func(c *vport, dual bool) *vport { return vtcpPick(c, src, dual) }); vp != nil {
		return vp.path, true
	}
	return "", false
}

// vaccept finishes an accept on a virtual listener: the new socket is virtual
// in the same namespace, with synthesized INET addresses.
func (g *dguest) vaccept(listener *dfile, nfd int) *dfile {
	vnetStreamBufs(nfd)
	fam := listener.sk.family
	nd := newSockFile(nfd, fam, lxSockStream, listener.sk.proto)
	nd.sk.virt = true
	nd.sk.netns = listener.sk.netns
	listener.sk.mu.Lock()
	nd.sk.name = listener.sk.name // the accepted side's local address is the listener's
	k := listener.sk.vk
	listener.sk.mu.Unlock()
	// Report the client's real address, carried by the backing unix socket's peer
	// path (a connecting socket binds its vnet address before it connects). If the
	// client bound no vnet path, fall back to a plausible peer on the same scope.
	c := vkey{ip: 127<<24 | 1, port: k.port}
	src, dst, ok := g.netState().vpeer(nfd, listener.sk.netns)
	if ok {
		c = src
	} else if k.scope == vnetGlobal {
		c.ip = 0 // an unidentified client on the virtual network
	}
	nd.sk.peer = vName(fam, c.ip, c.port, c.v6)
	if dst.port != 0 {
		nd.sk.name = vName(fam, dst.ip, dst.port, dst.v6) // the address the client connected to
	}
	return nd
}

// vpeer is what a vnet socket of namespace netns, accepted on nfd, knows of
// its client, by the backing path the client connected from: the address it
// connected from and the one it connected to, as its connect recorded them
// (vconns). For a client that recorded none, the address its path names, and
// no destination (dst.port 0); a client on a wildcard connected from the
// loopback in netns, else from its namespace's address on the virtual
// network. ok is false when the client bound no such path.
func (n *dnet) vpeer(nfd int, netns int32) (src, dst vkey, ok bool) {
	sa, err := unix.Getpeername(nfd)
	if err != nil {
		return vkey{}, vkey{}, false
	}
	ua, is := sa.(*unix.SockaddrUnix)
	if !is || ua.Name == "" {
		return vkey{}, vkey{}, false
	}
	n.mu.Lock()
	for path, c := range n.vconns {
		if filepath.Base(path) == filepath.Base(ua.Name) {
			delete(n.vconns, path)
			n.mu.Unlock()
			return c.src, c.dst, true
		}
	}
	n.mu.Unlock()
	k, ok := vPathAddr(ua.Name, "vnet")
	if ok && k.ip == 0 {
		k.ip = 127<<24 | 1
		if k.scope != netns {
			k.v6 = false
			n.mu.Lock()
			if a, has := n.netnsAddr(k.scope); has {
				k.ip = a
			}
			n.mu.Unlock()
		}
	}
	return k, vkey{}, ok
}
