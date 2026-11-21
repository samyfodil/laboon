package sandbox

// trapModes are the ways into the stub a test takes a guest's syscalls: the
// trampolines and, on Linux, the trap fallback too.
var trapModes = []bool{false, true}

// useTraps sends every syscall site to the trap fallback, or none; the
// returned func restores the default.
func useTraps(traps bool) func() {
	was := fastTramp
	fastTramp = !traps
	return func() { fastTramp = was }
}

// validateVMAs checks the supervisor's mapping table against the host's on
// every change until the returned func runs.
func validateVMAs() func() {
	vmaValidate = true
	return func() { vmaValidate = false }
}
