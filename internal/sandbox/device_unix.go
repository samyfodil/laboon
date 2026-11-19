//go:build linux || darwin

package sandbox

import (
	"os"
	"path"

	"github.com/samyfodil/laboon/core"
	"golang.org/x/sys/unix"
)

// ensureDevices creates each Config.Devices node under /dev once and wires its
// host backing, so a later open of the node routes through openVirtualDev to the
// host end. It runs after the overlay is ready and before the guest runs.
func (g *dguest) ensureDevices() {
	if len(g.cfg.Devices) == 0 {
		return
	}
	g.devs.once.Do(func() {
		for i, d := range g.cfg.Devices {
			if d.Kind != DeviceSerial {
				continue // other kinds are not wired yet
			}
			rdev := lxMakedev(lbDevMajor, uint64(i))
			if e := g.makeDeviceNode(d.Path, rdev); e != 0 {
				continue
			}
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if err != nil {
				continue
			}
			unix.CloseOnExec(fds[0])
			unix.CloseOnExec(fds[1])
			g.devs.mu.Lock()
			if g.devs.back == nil {
				g.devs.back = map[uint64]*os.File{}
			}
			g.devs.back[rdev] = os.NewFile(uintptr(fds[0]), "lbdev-guest")
			g.devs.devs = append(g.devs.devs, d)
			g.devs.mu.Unlock()
			d.publish(os.NewFile(uintptr(fds[1]), "lbdev-host"))
		}
	})
}

// makeDeviceNode creates gp as a character device numbered rdev in the overlay,
// the way a guest's mknod would, so it appears under /dev. Its parent (/dev)
// must already exist.
func (g *dguest) makeDeviceNode(gp string, rdev uint64) int64 {
	ploc, err := g.vns().Resolve(path.Dir(gp), true)
	if err != nil {
		return sErr(osErrno(err))
	}
	if _, err := g.create(ploc, gp, core.CreateSpec{Kind: core.Chardev, Mode: 0o600, Rdev: rdev}); err != nil {
		return sErr(osErrno(err))
	}
	return 0
}

// openDeviceBacking installs the open-file description for an attached Device
// whose node carries rdev, or reports false if rdev is not one. Each open dups
// the guest end so closing one fd does not close the backing.
func (g *dguest) openDeviceBacking(gp string, rdev uint64, flags int64) (int64, bool) {
	g.devs.mu.Lock()
	gf := g.devs.back[rdev]
	g.devs.mu.Unlock()
	if gf == nil {
		return 0, false
	}
	nfd, err := unix.Dup(int(gf.Fd()))
	if err != nil {
		return sErr(osErrno(err)), true
	}
	return g.installD(&dfile{f: os.NewFile(uintptr(nfd), gp), gp: gp, stub: -1}, flags), true
}
