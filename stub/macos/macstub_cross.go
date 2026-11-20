//go:build darwin

package macstub

import _ "embed"

// BinaryArm64 and BinaryAmd64 are the two guest-architecture stubs, both
// embedded regardless of the supervisor's own architecture, so a native
// supervisor can host a guest of the other architecture: a native arm64 build
// runs an x86-64 guest in the x86-64 stub under Rosetta. Binary (the per-arch
// file) still names the native one; these name each explicitly for the backend
// to pick by the guest ELF's machine.
//
//go:embed stub-arm64.bin
var BinaryArm64 []byte

//go:embed stub-amd64.bin
var BinaryAmd64 []byte
