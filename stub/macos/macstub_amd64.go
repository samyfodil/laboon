//go:build amd64

package macstub

import _ "embed"

// Binary is the x86-64 stub executable, built by build.sh. On Apple Silicon it
// runs under Rosetta.
//
//go:embed stub-amd64.bin
var Binary []byte

// HvfBinary has no x86-64 counterpart: the amd64 stub maps and rewrites the
// guest like the arm64 PIE path (static-PIE guests), with no Hypervisor.framework
// VM backend. It is nil so the shared darwin backend compiles; the HVF path is
// never selected on amd64.
var HvfBinary []byte
