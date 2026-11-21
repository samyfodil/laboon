package sandbox

import (
	"errors"

	"github.com/samyfodil/laboon/internal/rewrite"
	"github.com/samyfodil/laboon/stub/vdso"
)

// The guest's vDSO (stub/vdso), which a stub maps at each exec. Each guest
// architecture's image sits in the run's shared region with the syscall sites
// the rewriter found in it, as stub/macos/stub.zig's vdsoImage reads them: the
// image's length, the site count, vdsoSites sites, then the image.
const (
	sigRunVdso = sigRunOff + 0x100
	vdsoRec    = 0xf00
	vdsoSites  = 16
)

// publishVdso writes the arm64 and the x86-64 guest's vDSO into the channel
// memory mem, before a stub maps anything.
func publishVdso(mem []byte, c *rewrite.Cache) error {
	for i, img := range [][]byte{vdso.ARM64, vdso.AMD64} {
		sites, err := computeSitesBytes(c, img)
		if err != nil {
			return err
		}
		at := 8 + 4*vdsoSites
		if len(sites) > vdsoSites || at+len(img) > vdsoRec {
			return errors.New("laboon: the vDSO does not fit its record")
		}
		r := mem[slotsLen+sigRunVdso+i*vdsoRec:][:vdsoRec]
		put32(r, uint32(len(img)))
		put32(r[4:], uint32(len(sites)))
		for j, s := range sites {
			put32(r[8+4*j:], s)
		}
		copy(r[at:], img)
	}
	return nil
}
