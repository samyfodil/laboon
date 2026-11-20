//go:build arm64

package macstub

import _ "embed"

// Binary is the arm64 stub executable, built by build.sh.
//
//go:embed stub-arm64.bin
var Binary []byte

// HvfBinary is the HVF-backend stub, built by build-hvf.sh. It runs a non-PIE
// low-linked ET_EXEC guest in a VM (Hypervisor.framework) rather than mapping
// and rewriting it, so there is no __PAGEZERO wall and no Seatbelt allowlist
// (the VM is the boundary). The backend signs it with the hypervisor entitlement.
//
//go:embed hvf_stub.bin
var HvfBinary []byte
