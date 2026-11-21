//go:build linux || windows

package sandbox

import "debug/elf"

// elfMach is the ELF machine execve's checkELF requires. On linux and windows
// the guest's architecture is the build architecture (elfMachine), so the guest
// is unused.
func elfMach(*dguest) elf.Machine { return elfMachine }
