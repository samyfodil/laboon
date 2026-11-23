package overlayfs

import (
	"path"
	"strings"

	. "github.com/samyfodil/laboon/core"
)

func clean(p string) string         { return strings.Trim(path.Clean("/"+p), "/") }
func join(base, name string) string { return "/" + clean(base+"/"+name) }

// present reports whether L's directory dn contains name.
func present(L FileSystem, dn Node, name string) bool {
	_, err := L.Lookup(dn, name)
	return err == nil
}

// probe is present, and the error of a lookup that could not tell (nil when it
// could).
func probe(L FileSystem, dn Node, name string) (bool, error) {
	_, err := L.Lookup(dn, name)
	if err == nil || DefinitelyNotExist(err) {
		return err == nil, nil
	}
	return false, err
}

// layerNode resolves an overlay path within one layer, from its root.
func layerNode(L FileSystem, p string) (Node, bool) {
	n := L.Root()
	if p == "" {
		return n, true
	}
	for _, name := range strings.Split(p, "/") {
		c, err := L.Lookup(n, name)
		if err != nil {
			return nil, false
		}
		n = c
	}
	return n, true
}
