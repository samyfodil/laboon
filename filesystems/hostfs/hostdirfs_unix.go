//go:build linux || darwin

package hostfs

import "github.com/samyfodil/laboon/core"

func (c *CachedFS) hBindSock(p string, bind func(addr string) error) error {
	s, ok := c.HostFS.(sockHost)
	if !ok {
		return core.ErrSocketUnsupported
	}
	defer c.Changed()
	return s.hBindSock(p, bind)
}

func (c *CachedFS) hReachSock(p string, op func(addr string) error) error {
	s, ok := c.HostFS.(sockHost)
	if !ok {
		return core.ErrSocketUnsupported
	}
	return s.hReachSock(p, op)
}
