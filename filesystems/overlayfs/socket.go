package overlayfs

import (
	"syscall"

	. "github.com/samyfodil/laboon/core"
)

// BindSocket binds name in the writable top, copying dir up first, when the
// top layer holds host sockets.
func (f *overlay) BindSocket(dir Node, name string, bind func(addr string) error) (Node, error) {
	s, ok := f.top().(SocketFS)
	if !ok {
		return nil, ErrSocketUnsupported
	}
	d := dir.(*overlayNode)
	defer f.changed(d.p)
	topDir, err := f.topDir(d.p)
	if err != nil {
		return nil, err
	}
	f.unwhiteout(topDir, name)
	p := join(d.p, name)
	l := f.makingLock(p)
	l.Lock()
	_, err = s.BindSocket(topDir, name, bind)
	l.Unlock()
	if err != nil {
		return nil, err
	}
	return f.resolve(p)
}

// ReachSocket reaches a socket in the writable top. One only a read-only layer
// holds is no socket a guest bound: whatever listened there, if anything, was
// the image builder's, so nothing answers.
func (f *overlay) ReachSocket(n Node, op func(addr string) error) error {
	o := n.(*overlayNode)
	if o.owner != len(f.layers)-1 {
		return syscall.ECONNREFUSED
	}
	s, ok := f.top().(SocketFS)
	if !ok {
		return ErrSocketUnsupported
	}
	return s.ReachSocket(o.nodes[o.owner], op)
}
