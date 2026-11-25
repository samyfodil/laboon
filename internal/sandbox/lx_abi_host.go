//go:build linux || windows

package sandbox

// On Linux and Windows a guest runs the supervisor's own architecture.
func (g *dguest) abi() *guestABI { return hostABI }
