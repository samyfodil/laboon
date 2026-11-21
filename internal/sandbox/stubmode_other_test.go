//go:build !linux

package sandbox

// trapModes are the ways into the stub a test takes a guest's syscalls; only
// the Linux stub has a trap fallback to choose.
var trapModes = []bool{false}

func useTraps(bool) func() { return func() {} }

// validateVMAs is a Linux stub check; elsewhere the mapping table has no host
// table to compare against.
func validateVMAs() func() { return func() {} }
