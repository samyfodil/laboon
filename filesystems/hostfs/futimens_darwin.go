//go:build darwin

package hostfs

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/go-webgpu/goffi/ffi"
	"github.com/go-webgpu/goffi/types"
)

// libcFn is a libSystem function prepared for goffi.
type libcFn struct {
	cif types.CallInterface
	fn  unsafe.Pointer
}

func libcPrep(lib unsafe.Pointer, name string, ret *types.TypeDescriptor, args ...*types.TypeDescriptor) (*libcFn, error) {
	fn, err := ffi.GetSymbol(lib, name)
	if err != nil {
		return nil, err
	}
	c := &libcFn{fn: fn}
	if err := ffi.PrepareCallInterface(&c.cif, types.DefaultCall, ret, args); err != nil {
		return nil, err
	}
	return c, nil
}

// futimens sets a descriptor's times to the nanosecond. x/sys wraps only
// futimes on darwin, which holds microseconds.
var futimensFns = sync.OnceValues(func() ([2]*libcFn, error) {
	var fns [2]*libcFn
	lib, err := ffi.LoadLibrary("/usr/lib/libSystem.B.dylib")
	if err != nil {
		return fns, err
	}
	if fns[0], err = libcPrep(lib, "futimens", types.SInt32TypeDescriptor, types.SInt32TypeDescriptor, types.PointerTypeDescriptor); err != nil {
		return fns, err
	}
	fns[1], err = libcPrep(lib, "__error", types.PointerTypeDescriptor)
	return fns, err
})

func futimens(fd int, ts *[2]syscall.Timespec) error {
	fns, err := futimensFns()
	if err != nil {
		return err
	}
	// errno is the thread's: it is read on the thread the call ran on.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cfd, p := int32(fd), unsafe.Pointer(ts)
	var r int32
	if err := ffi.CallFunction(&fns[0].cif, fns[0].fn, unsafe.Pointer(&r), []unsafe.Pointer{unsafe.Pointer(&cfd), unsafe.Pointer(&p)}); err != nil {
		return err
	}
	runtime.KeepAlive(ts)
	if r == 0 {
		return nil
	}
	var errno *int32
	if err := ffi.CallFunction(&fns[1].cif, fns[1].fn, unsafe.Pointer(&errno), nil); err != nil {
		return err
	}
	return syscall.Errno(*errno)
}
