//go:build darwin || linux

package sandbox

import "sync"

// AF_UNIX credential passing (SO_PASSCRED / SCM_CREDENTIALS / SO_PEERCRED).
//
// Both ends of a guest AF_UNIX connection are host sockets the supervisor owns,
// so the host kernel stamps the supervisor's identity on a credential message,
// not the guest sender's. The sender's guest credentials travel beside the data
// on a credLink shared by the two ends instead. This is what Chromium's zygote
// "pid oracle" reads: it forks a child, the child sends on an inherited
// socketpair end, and the parent recovers the child's real pid from the
// SCM_CREDENTIALS of that message.

// ucred is a Linux struct ucred: pid, uid, gid, each 32-bit.
type ucred struct{ pid, uid, gid uint32 }

func (c ucred) bytes() []byte {
	var b [12]byte
	put32(b[:], c.pid)
	put32(b[4:], c.uid)
	put32(b[8:], c.gid)
	return b[:]
}

// credLink carries credentials across a connected AF_UNIX pair. q[side] holds
// the creds the endpoint on side has yet to receive; its peer appends on each
// send. owner[side] is the process that holds that end, the fallback reported
// when SO_PASSCRED is set but no send is pending, and the value SO_PEERCRED
// reads for the far end.
type credLink struct {
	mu    sync.Mutex
	last  [2]ucred // the last creds a send toward the endpoint on side carried
	has   [2]bool
	owner [2]ucred
}

func newCredLink(owner ucred) *credLink {
	return &credLink{owner: [2]ucred{owner, owner}}
}

// setOwner records the process that holds the end on side.
func (l *credLink) setOwner(side int, c ucred) {
	l.mu.Lock()
	l.owner[side] = c
	l.mu.Unlock()
}

// sent records that the endpoint on side sent a message carrying creds c, for
// its peer to receive. One slot per direction, not a queue: a connected pair's
// peer is a single process, so the last sender's creds stand (SO_PASSCRED
// delivers the peer's identity, which does not vary message to message). This
// keeps recv non-consuming, so MSG_PEEK and reads without SO_PASSCRED set never
// desynchronize it, and nothing accumulates.
func (l *credLink) sent(side int, c ucred) {
	p := 1 - side
	l.mu.Lock()
	l.last[p], l.has[p] = c, true
	l.mu.Unlock()
}

// recv returns the creds a message the endpoint on side receives carries: the
// last sender's, or the peer's owner when none has been sent.
func (l *credLink) recv(side int) ucred {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.has[side] {
		return l.last[side]
	}
	return l.owner[1-side]
}

// peer is the far end's owner creds, what SO_PEERCRED reports.
func (l *credLink) peer(side int) ucred {
	if l == nil {
		return ucred{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.owner[1-side]
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

// passcred reports whether SO_PASSCRED is set, so received messages carry the
// sender's SCM_CREDENTIALS.
func (s *dsock) passcred() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts[[2]int{lxSolSocket, lxSoPasscred}] != 0
}

// sendCreds records the calling process's credentials (or an explicit
// SCM_CREDENTIALS the guest attached) for the connected peer, before the data
// is sent so a peer that wakes on the message never finds none waiting.
func (g *dguest) sendCreds(d *dfile, ctl []byte) {
	if d.sk == nil || d.sk.cl == nil {
		return
	}
	c := g.curCred()
	if ec, ok := parseGuestCred(ctl); ok {
		// The guest names the pid in its own namespace; the link holds the
		// global one. An unresolvable (forged) pid is not honoured.
		if ec.pid != 0 {
			if gp, ok := g.nsToGlobal(int(ec.pid)); ok {
				c.pid = uint32(gp)
			}
		}
		c.uid, c.gid = ec.uid, ec.gid
	}
	d.sk.cl.sent(d.sk.side, c)
}

// recvCreds returns the SCM_CREDENTIALS control message to deliver with a
// received message when SO_PASSCRED is set, laid out within room bytes.
func (g *dguest) recvCreds(d *dfile, room int) ([]byte, uint32) {
	if d.sk == nil || d.sk.cl == nil || !d.sk.passcred() {
		return nil, 0
	}
	c := d.sk.cl.recv(d.sk.side)
	// The link holds the sender's global pid; the receiver sees it in its own
	// namespace (0 when the sender is in a namespace it cannot see).
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
