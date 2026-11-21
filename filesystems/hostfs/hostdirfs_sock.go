package hostfs

import (
	"path"

	"github.com/samyfodil/laboon/core"
)

// sockHost is a HostFS that binds and reaches host sockets by a short,
// confined address for a path in its tree.
type sockHost interface {
	hBindSock(p string, bind func(addr string) error) error
	hReachSock(p string, op func(addr string) error) error
}

func (f *HostDirFS) BindSocket(dir core.Node, name string, bind func(addr string) error) (core.Node, error) {
	s, ok := f.h.(sockHost)
	if !ok {
		return nil, core.ErrSocketUnsupported
	}
	p := path.Join(dir.(*HostNode).p, name)
	if err := s.hBindSock(f.hp(p), bind); err != nil {
		return nil, err
	}
	return f.node(p)
}

func (f *HostDirFS) ReachSocket(n core.Node, op func(addr string) error) error {
	s, ok := f.h.(sockHost)
	if !ok {
		return core.ErrSocketUnsupported
	}
	return s.hReachSock(f.hp(n.(*HostNode).p), op)
}
