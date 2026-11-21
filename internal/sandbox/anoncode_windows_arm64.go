//go:build windows

package sandbox

// anonTramps: an arm64 site branches to an island the stub builds itself
// (stub/windows/aarch64.zig, jitSiteWord), and the stub passes no area.
func (g *wguest) anonTramps(*dguest, uint64, int, uint64, uint64, func(uint64, []byte) error) {}
