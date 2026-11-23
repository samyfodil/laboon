//go:build linux || darwin

package hostfs

import (
	"path/filepath"
	"strings"

	"github.com/samyfodil/laboon/core"
)

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

// joinClean is filepath.Join(root, gp), without cleaning the whole of a long
// root again when both are clean already, as a node's path and its
// filesystem's root are.
func joinClean(root, gp string) string {
	switch {
	case root == "" || root[0] != '/' || !cleanRel(gp):
	case root == "/":
		return "/" + gp
	case cleanRel(root[1:]):
		if gp == "" {
			return root
		}
		return root + "/" + gp
	}
	return filepath.Join(root, gp)
}

// cleanRel reports whether p is "" or a relative path path.Clean leaves as it is.
func cleanRel(p string) bool {
	if p == "" {
		return true
	}
	if p[0] == '/' || p[len(p)-1] == '/' {
		return false
	}
	for len(p) > 0 {
		seg := p
		if i := strings.IndexByte(p, '/'); i >= 0 {
			seg, p = p[:i], p[i+1:]
		} else {
			p = ""
		}
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
