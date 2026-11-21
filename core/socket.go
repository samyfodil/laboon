package core

import "errors"

// ErrSocketUnsupported is returned by a SocketFS instance that holds no host
// sockets; the caller then keeps a socket's name as a Socket node of its own.
var ErrSocketUnsupported = errors.New("vfs: host sockets unsupported")

// SocketFS is the optional capability of a FileSystem that keeps AF_UNIX
// socket names as host sockets, so a socket bound there is reachable from the
// host and a host socket there is reachable from the guest (how an X server is
// shared). The caller's own socket descriptor does the bind or connect: the
// backend hands it a host address (a sun_path) valid only during the call, so
// no host path leaves the backend, and the address stays confined to the
// backend's tree and short enough for sun_path.
type SocketFS interface {
	// BindSocket creates name in dir by calling bind with an address naming
	// it, and returns the new node.
	BindSocket(dir Node, name string, bind func(addr string) error) (Node, error)
	// ReachSocket calls op with an address that reaches the socket node n.
	ReachSocket(n Node, op func(addr string) error) error
}
