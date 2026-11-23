//go:build darwin || linux || windows

package sandbox

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

//go:generate sh -c "go run ../cmd/sysnames \"$(go list -m -f '{{.Dir}}' golang.org/x/sys)\" /usr/src/linux-headers-$(uname -r)/include/linux/syscalls.h lx_sysnames.go"

// Config.Trace gets one line per guest syscall the supervisor serves, as strace
// prints it: the thread, the call's name and arguments (decoded by the kinds
// sysArgs gives them), and its result. Calls the stub serves in the guest
// (futex, thread control, the stdio fast path) never reach the supervisor and
// are not traced. An untraced run pays one nil check per call.

// traceWriter serializes a run's trace lines, written by many threads.
type traceWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (t *traceWriter) Write(b []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.w.Write(b)
}

// syncTrace makes w safe for a run's threads to trace to at once.
func syncTrace(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	if _, ok := w.(*traceWriter); ok {
		return w
	}
	return &traceWriter{w: w}
}

// serveTraced runs h, the handler of generic call nr, and traces it: the
// arguments are read before the call, what it read after. The serve loops call
// it only when the run traces, so an untraced call runs h as it always did.
func (g *dguest) serveTraced(h func(*dguest, [6]uint64) int64, nr uint64, a [6]uint64) int64 {
	if traceName(nr) == "" {
		return h(g, a)
	}
	call := g.traceArgs(nr, a)
	r := h(g, a)
	g.traceLine(call + " = " + g.traceRet(nr, a, r))
	return r
}

// traceEntry traces a call the serve loop answers itself (clone, execve, an
// exit): its result is what the guest sees next.
func (g *dguest) traceEntry(nr uint64, a [6]uint64) {
	if g.cfg.Trace != nil && traceName(nr) != "" {
		g.traceLine(g.traceArgs(nr, a) + " ...")
	}
}

// traceStart is call nr's "name(args)" for traceEnd, or "" when the run does
// not trace it.
func (g *dguest) traceStart(nr uint64, a [6]uint64) string {
	if g.cfg.Trace == nil || traceName(nr) == "" {
		return ""
	}
	return g.traceArgs(nr, a)
}

// traceEnd traces call, begun by traceStart, with its result r.
func (g *dguest) traceEnd(call string, r int64) {
	if call != "" {
		g.traceLine(call + " = " + traceResult(r))
	}
}

// traceNosys traces a call no handler serves.
func (g *dguest) traceNosys(nr uint64, a [6]uint64) {
	if g.cfg.Trace != nil && traceName(nr) != "" {
		g.traceLine(g.traceArgs(nr, a) + " = " + traceErrno(int64(lxENOSYS)))
	}
}

func (g *dguest) traceLine(s string) {
	io.WriteString(g.cfg.Trace, "[pid "+strconv.Itoa(g.pid)+"] "+s+"\n")
}

// traceName is the name of the guest call the supervisor keys nr: a Linux
// asm-generic number, or the private key of an x86-64 call with no generic
// form; "" for the stub's own requests.
func traceName(nr uint64) string {
	if isRealSyscall(nr) {
		if s := sysName(nr); s != "" {
			return s
		}
		return "syscall_" + strconv.FormatUint(nr, 10)
	}
	for _, base := range [...]uint64{0x4c431000, 0x4c43f000} {
		if nr-base < 0x1000 {
			switch nr - base {
			case 7:
				return "poll"
			case 23:
				return "select"
			case 34:
				return "pause"
			case 37:
				return "alarm"
			case 158:
				return "arch_prctl"
			case 201:
				return "time"
			}
		}
	}
	return ""
}

// traceKinds is the kind of each argument of call name (internal/cmd/sysnames):
// six in hex for a call syscalls.h does not declare.
func traceKinds(name string) string {
	if k := sysArgs(name); k != "" || name == "pause" {
		return k
	}
	return "xxxxxx"
}

// traceArgs is "name(arg, ...)" for call nr.
func (g *dguest) traceArgs(nr uint64, a [6]uint64) string {
	name := traceName(nr)
	kinds := traceKinds(name)
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('(')
	for i := range min(len(kinds), len(a)) {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(g.traceArg(kinds[i], a[i], a[min(i+1, len(a)-1)]))
	}
	b.WriteByte(')')
	return b.String()
}

// traceArg is argument v of kind k; next is the argument after it, a buffer's
// or an address's length.
func (g *dguest) traceArg(k byte, v, next uint64) string {
	switch k {
	case 'i':
		return strconv.Itoa(int(int32(v)))
	case 'l':
		return strconv.FormatInt(int64(v), 10)
	case 'o':
		return "0" + strconv.FormatUint(v, 8)
	case 'd':
		if int32(v) == lxAtFdcwd {
			return "AT_FDCWD"
		}
		return strconv.Itoa(int(int32(v)))
	case 's':
		if v != 0 {
			if s, err := g.readCStr(v); err == nil {
				return strconv.Quote(s)
			}
		}
	case 'w':
		if v != 0 {
			return g.traceData(v, next)
		}
	case 'a':
		if v != 0 {
			if s, ok := g.traceSockaddr(v, next); ok {
				return s
			}
		}
	}
	return traceHex(v)
}

// traceRet is call nr's result r: an errno by name, an address in hex, a
// count with the head of the data the call read.
func (g *dguest) traceRet(nr uint64, a [6]uint64, r int64) string {
	if r < 0 && r > -4096 {
		return traceErrno(-r)
	}
	name := traceName(nr)
	switch name {
	case "mmap", "mremap", "brk", "shmat":
		return traceHex(uint64(r))
	}
	if i := strings.IndexByte(sysArgs(name), 'r'); i >= 0 && r > 0 {
		g.flushOuts() // what was read may still wait to be copied to the guest
		return strconv.FormatInt(r, 10) + " " + g.traceData(a[i], uint64(r))
	}
	return strconv.FormatInt(r, 10)
}

// traceResult is r as a count, or an errno by name.
func traceResult(r int64) string {
	if r < 0 && r > -4096 {
		return traceErrno(-r)
	}
	return strconv.FormatInt(r, 10)
}

func traceErrno(e int64) string {
	name, desc := errnoName(e)
	if name == "" {
		return "-1 errno " + strconv.FormatInt(e, 10)
	}
	return "-1 " + name + " (" + desc + ")"
}

func traceHex(v uint64) string {
	if v < 10 {
		return strconv.FormatUint(v, 10)
	}
	return "0x" + strconv.FormatUint(v, 16)
}

// traceDataMax is how much of the data a call reads or writes a trace shows.
const traceDataMax = 32

// traceData quotes the head of the n bytes at addr.
func (g *dguest) traceData(addr, n uint64) string {
	m := min(n, traceDataMax)
	b, err := g.argRead(addr, int(m))
	if err != nil {
		return traceHex(addr)
	}
	s := strconv.Quote(string(b))
	if n > m {
		s += "..."
	}
	return s
}

// traceSockaddr decodes an AF_UNIX, AF_INET or AF_INET6 address.
func (g *dguest) traceSockaddr(addr, n uint64) (string, bool) {
	b, e := g.readSockaddr(addr, n)
	if e != 0 {
		return "", false
	}
	switch fam := int(b[0]) | int(b[1])<<8; {
	case fam == lxAFUnix:
		p := b[2:]
		if len(p) > 0 && p[0] == 0 {
			return fmt.Sprintf("{AF_UNIX, @%q}", strings.TrimRight(string(p[1:]), "\x00")), true
		}
		if i := strings.IndexByte(string(p), 0); i >= 0 {
			p = p[:i]
		}
		return fmt.Sprintf("{AF_UNIX, %q}", p), true
	case fam == lxAFInet && len(b) >= 8:
		return fmt.Sprintf("{AF_INET, %d.%d.%d.%d:%d}", b[4], b[5], b[6], b[7], int(b[2])<<8|int(b[3])), true
	case fam == lxAFInet6 && len(b) >= 24:
		var s strings.Builder
		for i := 0; i < 16; i += 2 {
			if i > 0 {
				s.WriteByte(':')
			}
			s.WriteString(strconv.FormatUint(uint64(b[8+i])<<8|uint64(b[9+i]), 16))
		}
		return fmt.Sprintf("{AF_INET6, [%s]:%d}", s.String(), int(b[2])<<8|int(b[3])), true
	}
	return "", false
}
