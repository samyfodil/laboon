//go:build darwin || linux || windows

package sandbox

import "net"

// The run's virtual network as routing netlink configures it: which addresses
// it holds and which namespace holds each, shared by every host's data plane.

const vnetGlobal = int32(-1) // the registry scope for the shared network (never a real netns id)

// syncIPNetns feeds the vnet delivery map from a namespace's modelled addresses,
// so inter-container connectivity follows the interfaces the guest configures
// with routing netlink rather than the netavark shim: each non-loopback IPv4
// address maps to its namespace, exactly what the shim used to record from
// podman's allocation. Caller holds n.mu.
func (n *dnet) syncIPNetns(netns int32, m *netModel) {
	if n.ipNetns == nil {
		n.ipNetns = map[uint32]int32{}
	}
	for ip, ns := range n.ipNetns {
		if ns == netns {
			delete(n.ipNetns, ip)
		}
	}
	for _, l := range m.links {
		for _, a := range l.addrs {
			if a.family == lxAFInet && len(a.ip) == 4 && !net.IP(a.ip).IsLoopback() {
				n.ipNetns[uint32(a.ip[0])<<24|uint32(a.ip[1])<<16|uint32(a.ip[2])<<8|uint32(a.ip[3])] = netns
			}
		}
	}
}

// onVirtualNet reports whether ip is an address on the run's virtual network as
// the model describes it: an address assigned to some namespace, or one on-link
// with an interface of the connecting namespace. This replaces a hard-coded
// subnet, so any addressing a guest configures through routing netlink works.
// The caller holds n.mu.
func (n *dnet) onVirtualNet(netns int32, ip uint32) bool {
	if _, ok := n.ipNetns[ip]; ok {
		return true
	}
	m := n.nets[netns]
	if m == nil {
		return false
	}
	for _, l := range m.links {
		for _, a := range l.addrs {
			if a.family == lxAFInet && len(a.ip) == 4 && !net.IP(a.ip).IsLoopback() {
				if mask := prefixMask(a.prefix); mask != 0 && beIP(a.ip)&mask == ip&mask {
					return true
				}
			}
		}
	}
	return false
}

// netnsAddr returns a namespace's own virtual-network IPv4 address (the first
// the model carries), used as the local address when auto-binding a client so
// its peer learns a real source address. The caller holds n.mu.
func (n *dnet) netnsAddr(netns int32) (uint32, bool) {
	if m := n.nets[netns]; m != nil {
		for _, l := range m.links {
			for _, a := range l.addrs {
				if a.family == lxAFInet && len(a.ip) == 4 && !net.IP(a.ip).IsLoopback() {
					return beIP(a.ip), true
				}
			}
		}
	}
	for ip, ns := range n.ipNetns {
		if ns == netns {
			return ip, true
		}
	}
	return 0, false
}
