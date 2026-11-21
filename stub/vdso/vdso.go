// Package vdso embeds the vDSO a guest gets on a host without a Linux kernel
// (macOS, Windows), one per guest architecture: an ELF shared object with the
// kernel's symbols and versions whose functions are system calls, rewritten
// like any image the guest runs. build.sh produces both from vdso.zig.
package vdso

import _ "embed"

//go:generate ./build.sh

// AMD64 is the x86-64 guest's vDSO (the __vdso_* symbols, LINUX_2.6).
//
//go:embed vdso-amd64.so
var AMD64 []byte

// ARM64 is the arm64 guest's vDSO (the __kernel_* symbols, LINUX_2.6.39).
//
//go:embed vdso-arm64.so
var ARM64 []byte
