// Package macstub embeds the macOS stub executable that a Linux guest runs in,
// one per guest architecture (stub-arm64.bin / stub-amd64.bin). See stub.zig for
// the protocol, the loader, the trampoline and the Seatbelt backstop; build.sh
// produces both. The darwin sandbox backend writes the matching one to a temp
// file, ad-hoc codesigns it and execs it per guest. Binary and HvfBinary are
// defined in the per-arch files (macstub_arm64.go / macstub_amd64.go).
package macstub

//go:generate ./build.sh
//go:generate ./build-hvf.sh
