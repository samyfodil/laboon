package sandbox

// ucred is a Linux struct ucred: pid, uid, gid, each 32-bit.
type ucred struct{ pid, uid, gid uint32 }

func (c ucred) bytes() []byte {
	var b [12]byte
	put32(b[:], c.pid)
	put32(b[4:], c.uid)
	put32(b[8:], c.gid)
	return b[:]
}

// curCred is the calling process's credentials for a sent message. The
// automatic SCM_CREDENTIALS (no explicit cmsg) carry the real uid/gid, as
// Linux fills them.
func (g *dguest) curCred() ucred {
	c := ucred{pid: uint32(g.tgid)}
	if g.ps != nil {
		c.uid, c.gid = g.ps.cred.ruid, g.ps.cred.rgid
	}
	return c
}

// sentCred is the credentials a sent message carries: the caller's, or an
// explicit SCM_CREDENTIALS the guest attached. The guest names the pid in its
// own namespace and the message holds the global one; an unresolvable (forged)
// pid is not honoured.
func (g *dguest) sentCred(ctl []byte) ucred {
	c := g.curCred()
	if ec, ok := parseGuestCred(ctl); ok {
		if ec.pid != 0 {
			if gp, ok := g.nsToGlobal(int(ec.pid)); ok {
				c.pid = uint32(gp)
			}
		}
		c.uid, c.gid = ec.uid, ec.gid
	}
	return c
}

// credCmsg renders c as an SCM_CREDENTIALS message within room bytes, its
// global pid seen from the receiver's namespace (0 when the sender is in one it
// cannot see).
func (g *dguest) credCmsg(c ucred, room int) ([]byte, uint32) {
	if c.pid != 0 {
		c.pid = uint32(g.nsPid(int(c.pid)))
	}
	return putCmsg(nil, room, lxSolSocket, lxScmCredentials, c.bytes())
}

// parseGuestCred returns an explicit SCM_CREDENTIALS a guest attached to a sent
// message, if any (Linux cmsg layout: 64-bit len, then level and type).
func parseGuestCred(ctl []byte) (ucred, bool) {
	for off := 0; off+16 <= len(ctl); {
		clen := int(le64(ctl[off:]))
		if clen < 16 || off+clen > len(ctl) {
			break
		}
		level, typ := int32(le32(ctl[off+8:])), int32(le32(ctl[off+12:]))
		if level == lxSolSocket && typ == lxScmCredentials && off+16+12 <= off+clen {
			d := ctl[off+16:]
			return ucred{pid: le32(d), uid: le32(d[4:]), gid: le32(d[8:])}, true
		}
		off += (clen + 7) &^ 7
	}
	return ucred{}, false
}
