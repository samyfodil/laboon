//go:build darwin || linux

package sandbox

import (
	"encoding/binary"
	"time"

	"golang.org/x/sys/unix"
)

// Terminal ioctls. A guest pty is a supervisor terminal (tty.go); the run's
// stdio terminal is a host one, whose line discipline, echo and window size
// are the host's, so for it this layer translates Linux's request numbers and
// struct termios to Darwin's. The two differ in nearly every bit: flag
// positions, the c_cc indices, the "disabled" char (0 vs 0xff), field widths
// (Darwin tcflag_t is 8 bytes) and the speed encoding (Linux Bxxx codes in
// c_cflag vs Darwin's numeric speeds).

// ttyCtl is the job-control state of a guest controlling terminal: the
// session it belongs to and its foreground process group. The host's own
// foreground group stays the supervisor's; these are the guest's ids.
type ttyCtl struct{ sid, pgrp int32 }

func hostRdev(fd int) (uint64, bool) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return 0, false
	}
	return uint64(st.Rdev), true
}

// adoptCtty makes the terminal at fd a guest controlling terminal of session
// sid with sid in the foreground, unless it already is one.
func (fs *dfs) adoptCtty(fd int, sid int32) {
	rdev, ok := hostRdev(fd)
	if !ok {
		return
	}
	fs.term.mu.Lock()
	if fs.term.ctl == nil {
		fs.term.ctl = map[uint64]*ttyCtl{}
	}
	if _, have := fs.term.ctl[rdev]; !have {
		fs.term.ctl[rdev] = &ttyCtl{sid: sid, pgrp: sid}
	}
	fs.term.mu.Unlock()
}

func (fs *dfs) cttyOf(fd int) *ttyCtl {
	rdev, ok := hostRdev(fd)
	if !ok {
		return nil
	}
	fs.term.mu.Lock()
	defer fs.term.mu.Unlock()
	return fs.term.ctl[rdev]
}

// ttyIoctl serves the terminal (and generic FIONREAD) requests ioctl does not
// handle itself. Anything else, and any request on a non-terminal, is ENOTTY,
// which is what isatty relies on.
func (g *dguest) ttyIoctl(d *dfile, req, arg uint64) int64 {
	req = uint64(uint32(req)) // the kernel takes an unsigned int; musl's sign-extends
	if d.vf != nil {          // a regular file: FIONREAD is what is left to read
		if req != lxFIONREAD {
			return sErr(lxENOTTY)
		}
		size, err := d.size0()
		if err != nil {
			return sErr(osErrno(err))
		}
		off, _ := d.tell()
		return g.ttyPutU32(arg, uint32(max(size-off, 0)))
	}
	if d.pty != nil {
		return g.ptyIoctl(d, req, arg)
	}
	if d.f == nil || d.ev != nil || d.ep != nil || d.tfd != nil {
		return sErr(lxENOTTY)
	}
	fd := hostFd(d.f)
	if req == lxFIONREAD {
		n, err := unix.IoctlGetInt(fd, hostFIONREAD)
		if err != nil {
			if mode, size, serr := d.hostStat(); serr == nil && mode.IsRegular() {
				off, _ := d.tell()
				n, err = int(max(size-off, 0)), nil
			}
		}
		if err != nil {
			return sErr(osErrno(err))
		}
		return g.ttyPutU32(arg, uint32(n))
	}
	cur, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return sErr(lxENOTTY)
	}
	switch req {
	case lxTCGETS, lxTCGETS2:
		two := req == lxTCGETS2
		if err := g.writeMem(arg, toLxTermios(cur).encode(two)); err != nil {
			return sErr(lxEFAULT)
		}
		return 0
	case lxTCSETS, lxTCSETSW, lxTCSETSF, lxTCSETS2, lxTCSETSW2, lxTCSETSF2:
		two := req >= lxTCSETS2
		n := 36
		if two {
			n = 44
		}
		b, err := g.readMem(arg, n)
		if err != nil {
			return sErr(lxEFAULT)
		}
		applyLxTermios(cur, decodeLxTermios(b), two)
		return ttyErr(hostSetTermios(fd, req, cur))
	case lxTIOCGWINSZ:
		ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
		if err != nil {
			return sErr(osErrno(err))
		}
		b := binary.LittleEndian.AppendUint16(nil, ws.Row)
		b = binary.LittleEndian.AppendUint16(b, ws.Col)
		b = binary.LittleEndian.AppendUint16(b, ws.Xpixel)
		b = binary.LittleEndian.AppendUint16(b, ws.Ypixel)
		if err := g.writeMem(arg, b); err != nil {
			return sErr(lxEFAULT)
		}
		return 0
	case lxTIOCSWINSZ:
		b, err := g.readMem(arg, 8)
		if err != nil {
			return sErr(lxEFAULT)
		}
		le := binary.LittleEndian
		ws := &unix.Winsize{Row: le.Uint16(b), Col: le.Uint16(b[2:]), Xpixel: le.Uint16(b[4:]), Ypixel: le.Uint16(b[6:])}
		return ttyErr(unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, ws))
	case lxTIOCOUTQ:
		n, err := unix.IoctlGetInt(fd, unix.TIOCOUTQ)
		if err != nil {
			return sErr(osErrno(err))
		}
		return g.ttyPutU32(arg, uint32(n))
	case lxTCFLSH:
		if arg > 2 { // TCIFLUSH, TCOFLUSH, TCIOFLUSH
			return sErr(lxEINVAL)
		}
		return ttyErr(hostFlush(fd, int(arg)))
	case lxTCXONC:
		switch arg {
		case 0: // TCOOFF
			return ttyErr(hostOutput(fd, false))
		case 1: // TCOON
			return ttyErr(hostOutput(fd, true))
		case 2, 3: // TCIOFF, TCION: send the STOP / START char
			c := cur.Cc[unix.VSTOP]
			if arg == 3 {
				c = cur.Cc[unix.VSTART]
			}
			if c != hostVDisable {
				if _, err := unix.Write(fd, []byte{c}); err != nil {
					return sErr(osErrno(err))
				}
			}
			return 0
		}
		return sErr(lxEINVAL)
	case lxTCSBRK, lxTCSBRKP:
		if arg != 0 && req == lxTCSBRK {
			return ttyErr(hostDrain(fd)) // tcdrain
		}
		if err := unix.IoctlSetInt(fd, unix.TIOCSBRK, 0); err != nil {
			return sErr(osErrno(err))
		}
		ttyBreak(arg, req == lxTCSBRKP)
		return ttyErr(unix.IoctlSetInt(fd, unix.TIOCCBRK, 0))
	case lxTIOCSBRK:
		return ttyErr(unix.IoctlSetInt(fd, unix.TIOCSBRK, 0))
	case lxTIOCCBRK:
		return ttyErr(unix.IoctlSetInt(fd, unix.TIOCCBRK, 0))
	case lxTIOCEXCL:
		return ttyErr(unix.IoctlSetInt(fd, unix.TIOCEXCL, 0))
	case lxTIOCNXCL:
		return ttyErr(unix.IoctlSetInt(fd, unix.TIOCNXCL, 0))
	case lxTIOCGEXCL:
		return g.ttyPutU32(arg, 0)
	case lxTIOCSTI:
		// Disabled, as on Linux with legacy_tiocsti=0: the host terminal is
		// the user's, and input pushed into it runs after the guest exits.
		return sErr(lxEIO)
	case lxTIOCGETD:
		return g.ttyPutU32(arg, 0) // N_TTY
	case lxTIOCSETD:
		b, err := g.readMem(arg, 4)
		if err != nil {
			return sErr(lxEFAULT)
		}
		if le32(b) != 0 {
			return sErr(lxEINVAL)
		}
		return 0
	case lxTIOCGPGRP, lxTIOCGSID:
		c := g.cttyOf(fd)
		if c == nil {
			return sErr(lxENOTTY)
		}
		v := c.pgrp
		if req == lxTIOCGSID {
			v = c.sid
		}
		return g.ttyPutU32(arg, uint32(v))
	case lxTIOCSPGRP:
		c := g.cttyOf(fd)
		if c == nil {
			return sErr(lxENOTTY)
		}
		b, err := g.readMem(arg, 4)
		if err != nil {
			return sErr(lxEFAULT)
		}
		if int32(le32(b)) < 0 {
			return sErr(lxEINVAL)
		}
		if len(g.pidsInPgrp(int(int32(le32(b))))) == 0 {
			return sErr(lxEPERM) // no such process group
		}
		g.term.mu.Lock()
		c.pgrp = int32(le32(b))
		g.term.mu.Unlock()
		return 0
	case lxTIOCSCTTY:
		g.adoptCtty(fd, int32(g.tgid))
		return 0
	case lxTIOCNOTTY:
		if g.cttyOf(fd) == nil {
			return sErr(lxENOTTY)
		}
		return 0
	case lxTIOCGPTN, lxTIOCSPTLCK, lxTIOCGPTLCK, lxTIOCGPTPEER:
		return sErr(lxENOTTY) // a slave, not a ptmx
	}
	return sErr(lxENOTTY)
}

func ttyBreak(arg uint64, deciseconds bool) {
	ms := 250
	if deciseconds && arg != 0 {
		ms = int(arg) * 100
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func ttyErr(err error) int64 {
	if err != nil {
		return sErr(osErrno(err))
	}
	return 0
}
