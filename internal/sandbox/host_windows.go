//go:build windows

package sandbox

import (
	"crypto/rand"
	"io"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hostFd(f *os.File) int { return int(f.Fd()) }

// readNonblock reads what a pipe holds without waiting (EAGAIN when it is
// empty); other files read as usual.
func readNonblock(f *os.File, buf []byte) (int, error) {
	if avail, ok := pipeAvail(f); ok && avail == 0 {
		var a uint32
		h := windows.Handle(f.Fd())
		if r, _, err := procPeekNamedPipe.Call(uintptr(h), 0, 0, 0, uintptr(unsafe.Pointer(&a)), 0); r == 0 && err == windows.ERROR_BROKEN_PIPE {
			return 0, nil
		}
		return 0, lxErr(lxEAGAIN)
	}
	n, err := f.Read(buf)
	if err == io.EOF {
		err = nil
	}
	return n, err
}

func writeNonblock(f *os.File, buf []byte) (int, error) { return f.Write(buf) }

func hostIsTTY(f *os.File) bool {
	var m uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &m) == nil
}

// hostAccMode reports f's access mode; Windows does not expose it on a handle,
// so the guest-side record is authoritative and this reports read-write.
func hostAccMode(f *os.File) (acc int64, appendMode bool, err error) {
	return lxORdwr, false, nil
}

func setHostAppend(int, bool) {}

// setHostPipeSize has nothing to size: a Windows pipe is a supervisor
// transport, which F_SETPIPE_SZ resizes through its pipeIO.
func setHostPipeSize(int, int) lxErrno { return 0 }

// hostHoles reports whether the host reports a file's holes: Windows does not
// here, so a file is one data extent, as on Linux without holes.
const hostHoles = false

func seekDataHole(int, int64, bool) (int64, lxErrno) { return 0, lxEINVAL }

var (
	procQPC = modKernel32.NewProc("QueryPerformanceCounter")
	procQPF = modKernel32.NewProc("QueryPerformanceFrequency")
	qpcFreq = sync.OnceValue(func() int64 {
		var f int64
		procQPF.Call(uintptr(unsafe.Pointer(&f)))
		return max(f, 1)
	})
)

// monoNow is CLOCK_MONOTONIC as the guest sees it: the performance counter
// (time since boot), which the stub reads too when it serves clock_gettime.
func monoNow() time.Duration {
	var c int64
	procQPC.Call(uintptr(unsafe.Pointer(&c)))
	f := qpcFreq()
	return time.Duration(c/f)*time.Second + time.Duration(c%f*int64(time.Second)/f)
}

// clockNow reads a guest clock: wall time for the realtime ones (0, 8), the
// monotonic clock otherwise.
func clockNow(clock int64) time.Duration {
	if clock == 0 || clock == 8 {
		return time.Duration(time.Now().UnixNano())
	}
	return monoNow()
}

// dupFile duplicates f's host handle into a new *os.File.
// dupFd is an owned duplicate of the host handle, named name.
func dupFd(fd int, name string) (*os.File, lxErrno) {
	p := windows.CurrentProcess()
	var h windows.Handle
	if err := windows.DuplicateHandle(p, windows.Handle(fd), p, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, osErrno(err)
	}
	return os.NewFile(uintptr(h), name), 0
}

func dupFile(f *os.File) (*os.File, lxErrno) {
	p := windows.CurrentProcess()
	var h windows.Handle
	if err := windows.DuplicateHandle(p, windows.Handle(f.Fd()), p, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, osErrno(err)
	}
	return os.NewFile(uintptr(h), f.Name()), 0
}

// hostErrnoOf is the Linux errno of a host error that carries one.
func hostErrnoOf(err error) (lxErrno, bool) {
	var e windows.Errno
	if !asErrno(err, &e) {
		return 0, false
	}
	return winErrno(e), true
}

// hostPipe is os.Pipe with a buffer of size bytes. Windows' default is a
// page, so a writer would wait for the reader to drain each page: a thread
// handoff per page, which costs hundreds of microseconds on a host where
// waking a thread is slow (a VM without Hyper-V enlightenments).
func hostPipe(size uint32) (r, w *os.File, err error) {
	var rh, wh windows.Handle
	if err := windows.CreatePipe(&rh, &wh, nil, size); err != nil {
		return nil, nil, os.NewSyscallError("pipe", err)
	}
	return os.NewFile(uintptr(rh), "|0"), os.NewFile(uintptr(wh), "|1"), nil
}

// copyPipeCap is the buffer of the pipes a supervisor goroutine copies
// through (captured stdio, /dev/zero): enough that the guest never waits for
// the copier to wake.
const copyPipeCap = 1 << 20

// hostDevOpen opens what stands in for a host device behind a synthetic /dev
// node: NUL for /dev/null; for /dev/zero and the random devices, a pipe a
// goroutine keeps full of zeros or random bytes until the reader closes it.
func hostDevOpen(name string, flag int) (*os.File, error) {
	switch name {
	case "/dev/null":
		return os.OpenFile("NUL", flag, 0)
	case "/dev/zero", "/dev/random", "/dev/urandom":
		if flag&(os.O_WRONLY|os.O_RDWR) != 0 {
			return os.OpenFile("NUL", flag, 0) // writes are discarded
		}
		r, w, err := hostPipe(copyPipeCap)
		if err != nil {
			return nil, err
		}
		go func() {
			defer w.Close()
			b := make([]byte, 64<<10)
			for {
				if name != "/dev/zero" {
					rand.Read(b)
				}
				if _, err := w.Write(b); err != nil {
					return
				}
			}
		}()
		return r, nil
	}
	return nil, os.ErrNotExist
}

// readNonblockKind is readNonblock: a Windows read has no kind to tell.
func readNonblockKind(f *os.File, buf []byte, k readKind) (int, error) { return readNonblock(f, buf) }

// readKind is unknown: nothing on Windows asks it.
func (d *dfile) readKind() readKind { return kindUnknown }
