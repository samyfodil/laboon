//go:build darwin || linux || windows

package sandbox

import "time"

// hostNet reports whether the caller may use the host network: networking is
// enabled for the run and the process is in the host network namespace. A
// process that entered a new network namespace (clone/unshare CLONE_NEWNET, as
// a sandbox does for a renderer) sees an empty network — no host reach — even
// when -net is on.
func (g *dguest) hostNet() bool {
	return g.cfg.Net && g.ps.netns.Load() == 0
}

// The socket system calls as the guest makes them: numbers, flags, sockaddr
// and msghdr layouts, iovec gathering, and the send/recv family built on each
// host's sendIov and recvInto. A host supplies the socket itself (dsock),
// sendIov, recvInto, guestControl, recvOobCap and the per-call operations
// (socket, bind, connect, ...).

const (
	lxSocket      = 198
	lxSocketpair  = 199
	lxBind        = 200
	lxListen      = 201
	lxAccept      = 202
	lxConnect     = 203
	lxGetsockname = 204
	lxGetpeername = 205
	lxSendto      = 206
	lxRecvfrom    = 207
	lxSetsockopt  = 208
	lxGetsockopt  = 209
	lxShutdown    = 210
	lxSendmsg     = 211
	lxRecvmsg     = 212
	lxAccept4     = 242
	lxRecvmmsg    = 243
	lxSendmmsg    = 269

	lxSockStream    = 1
	lxSockDgram     = 2
	lxSockSeqpacket = 5
	lxSockNonblock  = 0x800
	lxSockCloexec   = 0x80000

	lxSunPathMax = 108 // Linux sun_path
)

// Linux MSG_* flags.
const (
	lxMsgOob         = 0x1
	lxMsgPeek        = 0x2
	lxMsgDontroute   = 0x4
	lxMsgCtrunc      = 0x8
	lxMsgTrunc       = 0x20
	lxMsgDontwait    = 0x40
	lxMsgEor         = 0x80
	lxMsgWaitall     = 0x100
	lxMsgWaitforone  = 0x10000
	lxMsgCmsgCloexec = 0x40000000

	lxScmRights      = 1
	lxScmCredentials = 2
	lxSoPasscred     = 16

	msghdrSize  = 56 // struct msghdr on arm64
	mmsghdrSize = 64 // struct mmsghdr: msghdr + u32 msg_len, padded

	sendChunk = 1 << 20
	dgramMax  = 1 << 20
	maxRW     = 0x7ffff000 // Linux MAX_RW_COUNT: one call moves at most this much
)

const (
	lxSolSocket = 1
	lxSolIP     = 0
	lxSolTCP    = 6
	lxSolIPv6   = 41

	lxIPv6V6only = 26

	lxSoType      = 3
	lxSoError     = 4
	lxSoLinger    = 13
	lxSoPeercred  = 17
	lxSoRcvtimeo  = 20
	lxSoSndtimeo  = 21
	lxSoAcceptcon = 30
	lxSoProtocol  = 38
	lxSoDomain    = 39
	lxSoRcvtimeoN = 66
	lxSoSndtimeoN = 67

	lxIPMulticastIf  = 32
	lxIPMulticastAll = 49
	lxIPAddMember    = 35
	lxIPDropMember   = 36
)

func init() {
	syscalls[lxSocket] = func(g *dguest, a [6]uint64) int64 {
		return g.socket(int(int32(a[0])), int(int32(a[1])), int(int32(a[2])))
	}
	syscalls[lxSocketpair] = func(g *dguest, a [6]uint64) int64 {
		return g.socketpair(int(int32(a[0])), int(int32(a[1])), int(int32(a[2])), a[3])
	}
	syscalls[lxBind] = func(g *dguest, a [6]uint64) int64 { return g.bind(int64(int32(a[0])), a[1], a[2]) }
	syscalls[lxListen] = func(g *dguest, a [6]uint64) int64 { return g.listen(int64(int32(a[0])), int(int32(a[1]))) }
	syscalls[lxAccept] = func(g *dguest, a [6]uint64) int64 { return g.accept4(int64(int32(a[0])), a[1], a[2], 0) }
	syscalls[lxAccept4] = func(g *dguest, a [6]uint64) int64 {
		return g.accept4(int64(int32(a[0])), a[1], a[2], int(int32(a[3])))
	}
	syscalls[lxConnect] = func(g *dguest, a [6]uint64) int64 { return g.connect(int64(int32(a[0])), a[1], a[2]) }
	syscalls[lxGetsockname] = func(g *dguest, a [6]uint64) int64 { return g.sockname(int64(int32(a[0])), a[1], a[2], false) }
	syscalls[lxGetpeername] = func(g *dguest, a [6]uint64) int64 { return g.sockname(int64(int32(a[0])), a[1], a[2], true) }
	syscalls[lxShutdown] = func(g *dguest, a [6]uint64) int64 { return g.shutdown(int64(int32(a[0])), int(int32(a[1]))) }
	syscalls[lxSendto] = func(g *dguest, a [6]uint64) int64 {
		return g.sendto(int64(int32(a[0])), a[1], a[2], uint32(a[3]), a[4], a[5])
	}
	syscalls[lxRecvfrom] = func(g *dguest, a [6]uint64) int64 {
		return g.recvfrom(int64(int32(a[0])), a[1], a[2], uint32(a[3]), a[4], a[5])
	}
}

// sock returns fd's socket description: EBADF for an unknown fd, ENOTSOCK
// for one that is not a socket.
func (g *dguest) sock(fd int64) (*dfile, lxErrno) {
	d, ok := g.ft.get(int(fd))
	if !ok {
		return nil, lxEBADF
	}
	if d.sk == nil {
		return nil, lxENOTSOCK
	}
	return d, 0
}

// readSockaddr copies a guest sockaddr of addrlen bytes.
func (g *dguest) readSockaddr(addr, addrlen uint64) ([]byte, lxErrno) {
	if int64(int32(addrlen)) < 0 || addrlen > 128 {
		return nil, lxEINVAL
	}
	if addrlen < 2 {
		return nil, lxEINVAL
	}
	b, err := g.argRead(addr, int(addrlen))
	if err != nil {
		return nil, lxEFAULT
	}
	return b, 0
}

func saFamily(raw []byte) int { return int(raw[0]) | int(raw[1])<<8 }

// unixName canonicalizes a guest AF_UNIX sockaddr: the path (or abstract
// name, which starts with a NUL) and the sockaddr bytes Linux reports for it.
func unixName(raw []byte) (name string, abstract bool, canon []byte, e lxErrno) {
	if saFamily(raw) != lxAFUnix {
		return "", false, nil, lxEINVAL
	}
	p := raw[2:]
	if len(p) > lxSunPathMax {
		return "", false, nil, lxEINVAL
	}
	if len(p) > 0 && p[0] == 0 {
		return string(p[1:]), true, append([]byte(nil), raw...), 0
	}
	if i := indexByte(p, 0); i >= 0 {
		p = p[:i]
	}
	if len(p) == 0 {
		return "", false, nil, lxEINVAL
	}
	canon = append([]byte{lxAFUnix, 0}, p...)
	return string(p), false, append(canon, 0), 0
}

// putSockaddr writes sa to the guest's (addr, *addrlen) out-parameters: up to
// the buffer's size, with the full length stored back, as Linux does.
func (g *dguest) putSockaddr(sa []byte, addr, lenAddr uint64) lxErrno {
	if addr == 0 || lenAddr == 0 {
		return 0
	}
	lb, err := g.argRead(lenAddr, 4)
	if err != nil {
		return lxEFAULT
	}
	room := int32(le32(lb))
	if room < 0 {
		return lxEINVAL
	}
	n := min(int(room), len(sa))
	if n > 0 {
		if err := g.putOut(addr, sa[:n]); err != nil {
			return lxEFAULT
		}
	}
	put32(lb, uint32(len(sa)))
	if err := g.putOut(lenAddr, lb); err != nil {
		return lxEFAULT
	}
	return 0
}

func init() {
	syscalls[lxSendmsg] = func(g *dguest, a [6]uint64) int64 { return g.sendmsg(int64(int32(a[0])), a[1], uint32(a[2])) }
	syscalls[lxRecvmsg] = func(g *dguest, a [6]uint64) int64 { return g.recvmsg(int64(int32(a[0])), a[1], uint32(a[2])) }
	syscalls[lxSendmmsg] = func(g *dguest, a [6]uint64) int64 {
		return g.sendmmsg(int64(int32(a[0])), a[1], uint32(a[2]), uint32(a[3]))
	}
	syscalls[lxRecvmmsg] = func(g *dguest, a [6]uint64) int64 {
		return g.recvmmsg(int64(int32(a[0])), a[1], uint32(a[2]), uint32(a[3]), a[4])
	}
}

// iovTotal is the byte count of the iovec list, capped at maxRW as Linux
// caps it.
func iovTotal(iovs [][2]uint64) int {
	var t uint64
	for _, v := range iovs {
		t += min(v[1], maxRW)
		if t >= maxRW {
			return maxRW
		}
	}
	return int(t)
}

// gather copies n bytes starting at byte off of the iovec list from guest
// memory.
func (g *dguest) gather(iovs [][2]uint64, off, n int) ([]byte, lxErrno) {
	out := g.gbuf(n)
	w := 0
	for _, v := range iovs {
		l := int(v[1])
		if off >= l {
			off -= l
			continue
		}
		take := min(l-off, n-w)
		if err := g.argGet(v[0]+uint64(off), out[w:w+take]); err != nil { // read straight into the reused buffer
			return nil, lxEFAULT
		}
		w += take
		off = 0
		if w == n {
			break
		}
	}
	return out[:w], 0
}

// scatter writes data across the iovec list in guest memory, starting at byte
// off of the list.
func (g *dguest) scatter(iovs [][2]uint64, off int, data []byte) lxErrno {
	for _, v := range iovs {
		if len(data) == 0 {
			break
		}
		if l := int(min(v[1], maxRW)); off >= l {
			off -= l
			continue
		}
		v[0] += uint64(off)
		v[1] -= uint64(off)
		off = 0
		take := min(int(min(v[1], maxRW)), len(data))
		if take == 0 {
			continue
		}
		if err := g.putOut(v[0], data[:take]); err != nil {
			return lxEFAULT
		}
		data = data[take:]
	}
	return 0
}

// putCmsg appends one Linux control message as put_cmsg does with room bytes
// left: one that does not fit is cut to the room (its cmsg_len says so) and
// reported with MSG_CTRUNC; under a header's worth of room it is dropped.
func putCmsg(out []byte, room int, level, typ int32, data []byte) ([]byte, uint32) {
	avail := room - len(out)
	if avail < 16 {
		return out, lxMsgCtrunc
	}
	var flags uint32
	cmlen := 16 + len(data)
	if cmlen > avail {
		flags = lxMsgCtrunc
		cmlen = avail
	}
	c := make([]byte, min(16+(len(data)+7)&^7, avail))
	put64(c, uint64(cmlen))
	put32(c[8:], uint32(level))
	put32(c[12:], uint32(typ))
	copy(c[16:cmlen], data)
	return append(out, c...), flags
}

func (g *dguest) sendto(fd int64, buf, n uint64, flags uint32, addr, addrlen uint64) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	var dest []byte
	if addr != 0 && addrlen != 0 {
		if dest, e = g.readSockaddr(addr, addrlen); e != 0 {
			return sErr(e)
		}
	}
	if int64(n) < 0 {
		return sErr(lxEINVAL)
	}
	return g.sendIov(d, [][2]uint64{{buf, n}}, dest, nil, flags)
}

func (g *dguest) recvfrom(fd int64, buf, n uint64, flags uint32, addr, lenAddr uint64) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	if int64(n) < 0 {
		return sErr(lxEINVAL)
	}
	r, got, e := g.recvInto(d, [][2]uint64{{buf, n}}, 0, flags)
	if e != 0 {
		return sErr(e)
	}
	from := r.from
	if from == nil {
		from = []byte{} // no address: *addrlen becomes 0
	}
	if e := g.putSockaddr(from, addr, lenAddr); e != 0 {
		return sErr(e)
	}
	if flags&lxMsgTrunc != 0 && d.sk.typ != lxSockStream {
		return int64(r.full)
	}
	return int64(got)
}

// sockRead and sockWrite serve read/write/readv/writev on a socket.
func (g *dguest) sockRead(d *dfile, iovs [][2]uint64) int64 {
	_, got, e := g.recvInto(d, iovs, 0, 0)
	if e != 0 {
		return sErr(e)
	}
	return int64(got)
}

func (g *dguest) sockWrite(d *dfile, iovs [][2]uint64) int64 {
	return g.sendIov(d, iovs, nil, nil, 0)
}

// msghdr is a decoded Linux struct msghdr.
type msghdr struct {
	name, namelen, iov, iovlen, control, controllen uint64
	flags                                           uint32
}

func (g *dguest) readMsghdr(addr uint64) (msghdr, lxErrno) {
	b, err := g.argRead(addr, msghdrSize)
	if err != nil {
		return msghdr{}, lxEFAULT
	}
	return msghdr{
		name: le64(b), namelen: uint64(le32(b[8:])), iov: le64(b[16:]), iovlen: le64(b[24:]),
		control: le64(b[32:]), controllen: le64(b[40:]), flags: le32(b[48:]),
	}, 0
}

func (g *dguest) sendOne(d *dfile, m msghdr, flags uint32) int64 {
	iovs, e := g.iovecs(m.iov, int64(m.iovlen))
	if e != 0 {
		return sErr(e)
	}
	var dest, ctl []byte
	if m.name != 0 && m.namelen != 0 {
		if dest, e = g.readSockaddr(m.name, m.namelen); e != 0 {
			return sErr(e)
		}
	}
	if m.control != 0 && m.controllen != 0 {
		if m.controllen > 1<<16 {
			return sErr(lxENOBUFS)
		}
		b, err := g.readMem(m.control, int(m.controllen))
		if err != nil {
			return sErr(lxEFAULT)
		}
		ctl = b
	}
	return g.sendIov(d, iovs, dest, ctl, flags)
}

// recvOne receives one message into the msghdr at addr, updating its
// namelen, controllen and flags.
func (g *dguest) recvOne(d *dfile, addr uint64, m msghdr, flags uint32) int64 {
	iovs, e := g.iovecs(m.iov, int64(m.iovlen))
	if e != 0 {
		return sErr(e)
	}
	// Control data is always taken, so what does not fit the guest's buffer
	// (even an absent one) is reported with MSG_CTRUNC, as on Linux.
	oobCap := recvOobCap(d.sk)
	r, got, e := g.recvInto(d, iovs, oobCap, flags)
	if e != 0 {
		return sErr(e)
	}
	var hdr [msghdrSize]byte
	b, err := g.argRead(addr, msghdrSize)
	if err != nil {
		return sErr(lxEFAULT)
	}
	copy(hdr[:], b)
	if m.name != 0 {
		from := r.from
		if from == nil {
			from = []byte{}
		}
		n := min(len(from), int(m.namelen))
		if n > 0 {
			if err := g.putOut(m.name, from[:n]); err != nil {
				return sErr(lxEFAULT)
			}
		}
		put32(hdr[8:], uint32(len(from)))
	}
	room := int(min(m.controllen, 1<<20))
	if m.control == 0 {
		room = 0
	}
	ctl, cf := g.recvCreds(d, &r, room)
	if len(r.oob) > 0 {
		rest := max(room-len(ctl), 0)
		dctl, df := g.guestControl(r.oob, rest, flags&lxMsgCmsgCloexec != 0, flags&lxMsgPeek != 0)
		ctl = append(ctl, dctl...)
		cf |= df
	}
	r.flags |= cf
	if len(ctl) > 0 {
		if err := g.putOut(m.control, ctl); err != nil {
			return sErr(lxEFAULT)
		}
	}
	put64(hdr[40:], uint64(len(ctl)))
	put32(hdr[48:], r.flags)
	if err := g.putOut(addr, hdr[:]); err != nil {
		return sErr(lxEFAULT)
	}
	if flags&lxMsgTrunc != 0 && d.sk.typ != lxSockStream {
		return int64(r.full)
	}
	return int64(got)
}

func (g *dguest) sendmsg(fd int64, addr uint64, flags uint32) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	m, e := g.readMsghdr(addr)
	if e != 0 {
		return sErr(e)
	}
	return g.sendOne(d, m, flags)
}

func (g *dguest) recvmsg(fd int64, addr uint64, flags uint32) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	m, e := g.readMsghdr(addr)
	if e != 0 {
		return sErr(e)
	}
	return g.recvOne(d, addr, m, flags)
}

func (g *dguest) sendmmsg(fd int64, vec uint64, vlen, flags uint32) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	vlen = min(vlen, 1024)
	var i uint32
	for ; i < vlen; i++ {
		at := vec + uint64(i)*mmsghdrSize
		m, e := g.readMsghdr(at)
		if e != 0 {
			return sErr(e)
		}
		r := g.sendOne(d, m, flags)
		if r < 0 {
			if i > 0 {
				break
			}
			return r
		}
		var b [4]byte
		put32(b[:], uint32(r))
		if err := g.writeMem(at+msghdrSize, b[:]); err != nil {
			return sErr(lxEFAULT)
		}
	}
	return int64(i)
}

// recvmmsg fills up to vlen messages. After the first, MSG_WAITFORONE makes
// the rest non-blocking. A timeout is checked, as Linux checks it, only after
// each message, and what is left of it is written back.
func (g *dguest) recvmmsg(fd int64, vec uint64, vlen, flags uint32, tsAddr uint64) int64 {
	d, e := g.sock(fd)
	if e != 0 {
		return sErr(e)
	}
	var end time.Time
	if tsAddr != 0 {
		b, err := g.readMem(tsAddr, 16)
		if err != nil {
			return sErr(lxEFAULT)
		}
		sec, nsec := int64(le64(b)), int64(le64(b[8:]))
		if sec < 0 || nsec < 0 || nsec >= 1e9 {
			return sErr(lxEINVAL)
		}
		end = time.Now().Add(time.Duration(sec)*time.Second + time.Duration(nsec))
		defer func() {
			left := max(time.Until(end), 0)
			var ts [16]byte
			put64(ts[:], uint64(left/time.Second))
			put64(ts[8:], uint64(left%time.Second))
			g.writeMem(tsAddr, ts[:])
		}()
	}
	vlen = min(vlen, 1024)
	var i uint32
	for ; i < vlen; i++ {
		at := vec + uint64(i)*mmsghdrSize
		m, e := g.readMsghdr(at)
		if e != 0 {
			return sErr(e)
		}
		f := flags
		if i > 0 && flags&lxMsgWaitforone != 0 {
			f |= lxMsgDontwait
		}
		r := g.recvOne(d, at, m, f)
		if r < 0 {
			if i > 0 {
				break
			}
			return r
		}
		var b [4]byte
		put32(b[:], uint32(r))
		if err := g.writeMem(at+msghdrSize, b[:]); err != nil {
			return sErr(lxEFAULT)
		}
		if !end.IsZero() && !time.Now().Before(end) {
			i++
			break
		}
	}
	return int64(i)
}

// normSockaddr pads an AF_INET/AF_INET6 sockaddr to its full Linux size, the
// form musl compares a reply's source against.
func normSockaddr(raw []byte) []byte {
	size := 16
	if saFamily(raw) == lxAFInet6 {
		size = 28
	}
	out := make([]byte, size)
	copy(out, raw)
	return out
}

func init() {
	syscalls[lxSetsockopt] = func(g *dguest, a [6]uint64) int64 {
		return g.setsockopt(int64(int32(a[0])), int(int32(a[1])), int(int32(a[2])), a[3], int64(int32(a[4])))
	}
	syscalls[lxGetsockopt] = func(g *dguest, a [6]uint64) int64 {
		return g.getsockopt(int64(int32(a[0])), int(int32(a[1])), int(int32(a[2])), a[3], a[4])
	}
}

func i32bytes(v int) []byte {
	var b [4]byte
	put32(b[:], uint32(int32(v)))
	return b[:]
}

func timevalBytes(t time.Duration) []byte {
	var b [16]byte
	put64(b[:], uint64(t/time.Second))
	put64(b[8:], uint64(t%time.Second/time.Microsecond))
	return b[:]
}
