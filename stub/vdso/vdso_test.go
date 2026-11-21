package vdso

import (
	"bytes"
	"debug/elf"
	"testing"
)

// TestFits: each image is an ELF shared object of its machine, small enough
// for the room the stubs give it: a 4 KiB page on Windows, a 0xf00-byte
// record after a 72-byte header in the darwin channel.
func TestFits(t *testing.T) {
	for _, c := range []struct {
		img  []byte
		mach elf.Machine
	}{{AMD64, elf.EM_X86_64}, {ARM64, elf.EM_AARCH64}} {
		if len(c.img) > 0xf00-72 {
			t.Errorf("%v vDSO is %d bytes", c.mach, len(c.img))
		}
		f, err := elf.NewFile(bytes.NewReader(c.img))
		if err != nil || f.Machine != c.mach || f.Type != elf.ET_DYN {
			t.Errorf("%v vDSO: %v", c.mach, err)
		}
	}
}
