//go:build windows

package sandbox

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// Guest stdio on Windows. The stub has no stdio of its own: each guest fd 0-2
// is a description the supervisor serves on a host handle, the caller's file
// or a pipe to its reader or writer. A discarded stream (a nil reader, a nil
// or io.Discard writer) is the null device, and that one the stub serves
// itself: while a guest fd 0-2 refers to it, the slot's null_fds word (the
// alive field, unused on Windows) has bit i set and the stub answers read,
// write and writev on fd i with no supervisor round trip (stub/windows).

// hostNull is the host's null device, which stdioFiles opens for a discarded
// stream and stdioFile recognizes.
const hostNull = "NUL"

// stdioFiles gives the guest host files for its stdio: cfg's own *os.File, a
// pipe copied to or from a non-file reader or writer, or the null device.
// wait closes the supervisor's ends and copies out the rest of the guest's
// output. It runs once the guest is gone, every stub and serve loop with it,
// so no one writes to the output pipes any more and what they hold is all
// there is: each copier stops (a write end someone still holds would keep it
// from seeing end of file) and drains its pipe. The stdin copier, blocked on
// the caller's reader, is left to end with it.
func stdioFiles(cfg *Config) ([3]*os.File, func(), error) {
	var files [3]*os.File
	var wg sync.WaitGroup
	var mine []*os.File
	var outs []*outPipe
	closeAll := func() {
		for _, f := range mine {
			f.Close()
		}
	}
	for i, v := range []any{cfg.Stdin, cfg.Stdout, cfg.Stderr} {
		if f, ok := v.(*os.File); ok {
			files[i] = f
			continue
		}
		if v == nil || i > 0 && discarded(v.(io.Writer)) {
			f, err := os.OpenFile(hostNull, os.O_RDWR, 0)
			if err != nil {
				closeAll()
				return files, func() {}, err
			}
			files[i] = f
			mine = append(mine, f)
			continue
		}
		if i == 0 {
			r, w, err := hostPipe(copyPipeCap)
			if err != nil {
				closeAll()
				return files, func() {}, err
			}
			files[i] = r
			mine = append(mine, r)
			go func(src io.Reader) {
				io.Copy(w, src)
				w.Close()
			}(v.(io.Reader))
			continue
		}
		op, w, err := newOutPipe(copyPipeCap)
		if err != nil {
			closeAll()
			return files, func() {}, err
		}
		files[i] = w
		mine = append(mine, w)
		outs = append(outs, op)
		wg.Add(1)
		go func(dst io.Writer) {
			defer wg.Done()
			op.copyTo(dst)
		}(v.(io.Writer))
	}
	cfg.Stdin, cfg.Stdout, cfg.Stderr = files[0], files[1], files[2]
	return files, func() {
		closeAll()
		for _, op := range outs {
			windows.SetEvent(op.final)
		}
		wg.Wait()
	}, nil
}

// outPipe is a pipe the guest's output goes through to a copier: its write
// end an ordinary handle, its read end overlapped, so the copier waits for
// data or for final, which the end of the run sets.
type outPipe struct {
	r, ev, final windows.Handle
}

var outPipeSeq atomic.Uint64

// newOutPipe makes an outPipe of size bytes: a one-instance named pipe under
// a name no one can guess, whose one client is connected at once.
func newOutPipe(size uint32) (*outPipe, *os.File, error) {
	var nonce [8]byte
	rand.Read(nonce[:])
	name, err := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\pipe\laboon-%d-%d-%x`, os.Getpid(), outPipeSeq.Add(1), nonce))
	if err != nil {
		return nil, nil, err
	}
	r, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_INBOUND|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 0, size, 0, nil)
	if err != nil {
		return nil, nil, os.NewSyscallError("CreateNamedPipe", err)
	}
	w, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		windows.CloseHandle(r)
		return nil, nil, os.NewSyscallError("CreateFile", err)
	}
	op := &outPipe{r: r}
	if op.ev, err = windows.CreateEvent(nil, 1, 0, nil); err == nil {
		op.final, err = windows.CreateEvent(nil, 1, 0, nil)
	}
	if err != nil {
		op.close()
		windows.CloseHandle(w)
		return nil, nil, os.NewSyscallError("CreateEvent", err)
	}
	return op, os.NewFile(uintptr(w), "|1"), nil
}

func (op *outPipe) close() {
	for _, h := range []windows.Handle{op.r, op.ev, op.final} {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}
}

// copyTo copies the pipe to dst until every write end is closed, or until
// final is set: then what the pipe holds is copied and it stops.
func (op *outPipe) copyTo(dst io.Writer) {
	defer op.close()
	buf := make([]byte, 64<<10)
	final := false
	for {
		var n uint32
		ov := windows.Overlapped{HEvent: op.ev}
		windows.ResetEvent(op.ev)
		err := windows.ReadFile(op.r, buf, &n, &ov)
		if err == windows.ERROR_IO_PENDING {
			if final {
				// Nothing left: the pipe was empty.
				windows.CancelIoEx(op.r, &ov)
				windows.GetOverlappedResult(op.r, &ov, &n, true)
				if n > 0 {
					dst.Write(buf[:n])
				}
				return
			}
			ev, _ := windows.WaitForMultipleObjects([]windows.Handle{op.ev, op.final}, false, windows.INFINITE)
			if ev == windows.WAIT_OBJECT_0+1 {
				windows.CancelIoEx(op.r, &ov)
				final = true
			}
			err = windows.GetOverlappedResult(op.r, &ov, &n, true)
		}
		if n > 0 {
			dst.Write(buf[:n])
		}
		if err != nil && err != windows.ERROR_OPERATION_ABORTED && err != windows.ERROR_MORE_DATA {
			return // every write end closed (ERROR_BROKEN_PIPE)
		}
	}
}

// stdioFile is the guest's description of the supervisor's stdio file f: a
// duplicate of its handle, so a guest close leaves the supervisor's own. The
// null device is /dev/null to the guest; a pipe is a pipe whose transport is
// its pipeEnd.
func stdioFile(f *os.File, n int) *dfile {
	if f == nil {
		return &dfile{stub: -1}
	}
	self := windows.CurrentProcess()
	var h windows.Handle
	if err := windows.DuplicateHandle(self, windows.Handle(f.Fd()), self, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return &dfile{stub: -1}
	}
	if f.Name() == hostNull {
		return &dfile{f: os.NewFile(uintptr(h), hostNull), stub: -1, gp: "/dev/null", null: true}
	}
	if d := hostPipeFile(h, n > 0); d != nil {
		windows.CloseHandle(h)
		return d
	}
	return &dfile{f: os.NewFile(uintptr(h), f.Name()), stub: -1, gp: "/dev/stdio"}
}

// winTraced marks the slot's thread as ptrace-traced for the stub. The low
// bits of the alive word are the null-device fd mask; this is a free high bit.
// Unlike unix, the Windows stub publishes its frame unconditionally, but still
// needs this to gate reporting the syscalls it serves in-guest (MSG_TRACE_LOCAL)
// so an untraced thread posts nothing extra.
const winTraced uint32 = 1 << 31

// winSeccomp marks a slot whose process has a seccomp filter: the stub posts
// each call for the filters' verdict (msgSeccomp) before serving it.
const winSeccomp uint32 = 1 << 30

func (g *dguest) storeStdio(m uint64) {
	v := uint32(m)
	if g.traced.Load() {
		v |= winTraced
	}
	if g.ps != nil && g.ps.seccomp.Load() == secModeFilter {
		v |= winSeccomp
	}
	atomic.StoreUint32(&g.ch.page.alive, v)
}

// clearTraced drops the traced bit on detach so the stub stops reporting its
// in-guest-served syscalls; the null-device mask in the low bits is untouched.
func (g *dguest) clearTraced() { atomic.AndUint32(&g.ch.page.alive, ^winTraced) }

// stdioMask has bit i set while guest fd i is the run's null device.
func (g *dguest) stdioMask() uint64 {
	var m uint64
	g.ft.mu.Lock()
	defer g.ft.mu.Unlock()
	for i := 0; i < 3; i++ {
		if d := g.ft.fds[i]; d != nil && d.null {
			m |= 1 << i
		}
	}
	return m
}
