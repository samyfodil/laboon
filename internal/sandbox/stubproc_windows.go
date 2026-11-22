//go:build windows

package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	winstub "github.com/samyfodil/laboon/stub/windows"
)

// The stub runs in a less-privileged AppContainer (LPAC) with no
// capabilities: no filesystem, registry, network or cross-process handles of
// its own. It sees only the handles the supervisor lets it inherit, and a job
// object with kill-on-close ends it with the supervisor.

const appContainerName = "laboon.stub"

var (
	modUserenv  = windows.NewLazySystemDLL("userenv.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procCreateAppContainerProfile = modUserenv.NewProc("CreateAppContainerProfile")
	procDeriveAppContainerSid     = modUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	procVirtualAllocEx            = modKernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx             = modKernel32.NewProc("VirtualFreeEx")
	procFlushInstructionCache     = modKernel32.NewProc("FlushInstructionCache")
)

const (
	procThreadAttributeSecurityCapabilities = 0x00020009
	procThreadAttributeAllAppPackagesPolicy = 0x0002000F
	allAppPackagesOptOut                    = 1
	jobUILimitAll                           = 0xff // every JOB_OBJECT_UILIMIT_* bit
)

type securityCapabilities struct {
	sid      *windows.SID
	caps     uintptr
	ncaps    uint32
	reserved uint32
}

// appContainerSID creates the stub's AppContainer profile on first use.
// appContainerSID is the profile's SID, created once per supervisor.
var appContainerSID = sync.OnceValues(func() (*windows.SID, error) {
	name, err := windows.UTF16PtrFromString(appContainerName)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	hr, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(name)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if hr == 0 {
		return sid, nil
	}
	if hr, _, _ = procDeriveAppContainerSid.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&sid))); hr != 0 {
		return nil, fmt.Errorf("AppContainer SID: hresult %#x", hr)
	}
	return sid, nil
})

// stubPath writes the embedded stub to the user cache, named by content, so
// concurrent runs share one file. It is done once per supervisor.
var stubPath = sync.OnceValues(func() (string, error) {
	sum := sha256.Sum256(winstub.Binary)
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "laboon")
	p := filepath.Join(dir, "stub-"+hex.EncodeToString(sum[:8])+".exe")
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".stub-*")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(winstub.Binary); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	if err := os.Rename(f.Name(), p); err != nil {
		os.Remove(f.Name())
		if _, serr := os.Stat(p); serr == nil {
			return p, nil
		}
		return "", err
	}
	return p, nil
})

// stubProc is a running stub process. thread is its first thread, 0 for a
// fork child.
type stubProc struct {
	proc, thread windows.Handle
}

func (s *stubProc) close() {
	if s.thread != 0 {
		windows.CloseHandle(s.thread)
	}
	windows.CloseHandle(s.proc)
}

// stubMitigations are the process mitigations every stub runs under. The
// guest shares the stub's address space and can call into ntdll as the stub
// does, so what the stub's process may reach, the guest may. The stub reaches
// the kernel only through ntdll's memory, thread, event, section and
// exception calls, so it gives up the rest of the kernel's attack surface:
// win32k and file-system control calls, extension points (AppInit DLLs and
// the like), non-system fonts and image loads from anywhere but System32;
// misuse of a handle or of the heap is fatal.
var stubMitigations = [2]uint64{
	1<<12 | // heap corruption terminates
		1<<24 | // invalid handle references raise
		1<<28 | // no win32k system calls
		1<<32 | // no extension points
		1<<48 | // no non-system fonts
		1<<52 | 1<<56 | 1<<60, // images: none remote, none low-label, System32 first
	1 << 56, // no file-system control system calls
}

// startStub launches the stub in the LPAC with handles inherited (and only
// those), under stubMitigations, in the run's kill-on-close job. The handles'
// values, then extra, are on its command line in hex.
func startStub(job windows.Handle, handles []windows.Handle, extra ...uint64) (*stubProc, error) {
	exe, err := stubPath()
	if err != nil {
		return nil, err
	}
	sid, err := appContainerSID()
	if err != nil {
		return nil, err
	}
	cmd := syscall.EscapeArg(exe)
	for _, h := range handles {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return nil, err
		}
		cmd += fmt.Sprintf(" %x", uintptr(h))
	}
	for _, v := range extra {
		cmd += fmt.Sprintf(" %x", v)
	}
	attrs, err := windows.NewProcThreadAttributeList(4)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	caps := securityCapabilities{sid: sid}
	if err := attrs.Update(procThreadAttributeSecurityCapabilities, unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
		return nil, fmt.Errorf("security capabilities: %w", err)
	}
	optOut := uint32(allAppPackagesOptOut)
	if err := attrs.Update(procThreadAttributeAllAppPackagesPolicy, unsafe.Pointer(&optOut), unsafe.Sizeof(optOut)); err != nil {
		return nil, fmt.Errorf("LPAC policy: %w", err)
	}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, fmt.Errorf("handle list: %w", err)
	}
	mit := stubMitigations
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, unsafe.Pointer(&mit), unsafe.Sizeof(mit)); err != nil {
		return nil, fmt.Errorf("mitigation policy: %w", err)
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	cmdp, err := windows.UTF16PtrFromString(cmd)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_SUSPENDED | windows.DETACHED_PROCESS)
	var s *stubProc
	for try := 0; ; try++ {
		if err := windows.CreateProcess(nil, cmdp, nil, nil, true, flags, nil, nil, &si.StartupInfo, &pi); err != nil {
			return nil, fmt.Errorf("start stub: %w", err)
		}
		s = &stubProc{proc: pi.Process, thread: pi.Thread}
		if try == 7 || s.clearOfGuest() {
			break
		}
		windows.TerminateProcess(pi.Process, 1)
		s.close()
	}
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		s.close()
		return nil, fmt.Errorf("job: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// clearOfGuest reports whether the host's first allocations in the stub, its
// process and first thread's blocks and stack, are clear of where an
// unrandomized guest's layout goes: the brk area, the top of the address space
// and the legacy mmap base. Windows puts them anywhere in the low terabyte,
// which holds an arm64 guest's whole 39-bit space, and grows later threads up
// from there; a stub that is not clear is started again, so the layout is the
// same at each execve.
func (s *stubProc) clearOfGuest() bool {
	const lowTB, grow = 1 << 40, 64 << 20
	task, etDyn := winTask()
	spots := [][2]uint64{
		{etDyn, etDyn + brkGap + brkMax},
		{task - 2<<30, task},
		{task / unmappedDiv, task/unmappedDiv + mmapAreaRoom},
	}
	for _, sp := range spots {
		lo := (sp[0] - grow) &^ (allocGran - 1)
		if sp[1] <= lowTB && s.freeAt(lo, sp[1]-lo) < sp[1]-lo {
			return false
		}
	}
	return true
}

// newJob makes a run's job: closing it ends every stub in it, it grants no
// UI access, and it holds the memory its stubs commit to maxBytes (0: no
// limit), where an allocation past it fails as out of memory.
func newJob(maxBytes uint64) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var ext windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	ext.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if maxBytes > 0 {
		ext.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		ext.JobMemoryLimit = uintptr(maxBytes)
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&ext)), uint32(unsafe.Sizeof(ext))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: jobUILimitAll}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// Remote memory: the supervisor's process handle has full access, so it
// shapes and reads the guest's address space from outside.

func (s *stubProc) alloc(addr, size uint64, prot uint32) (uint64, error) {
	r, _, err := procVirtualAllocEx.Call(uintptr(s.proc), uintptr(addr), uintptr(size),
		windows.MEM_RESERVE|windows.MEM_COMMIT, uintptr(prot))
	if r == 0 {
		return 0, err
	}
	return uint64(r), nil
}

func (s *stubProc) reserve(addr, size uint64) (uint64, error) {
	r, _, err := procVirtualAllocEx.Call(uintptr(s.proc), uintptr(addr), uintptr(size),
		windows.MEM_RESERVE, windows.PAGE_NOACCESS)
	if r == 0 {
		return 0, err
	}
	return uint64(r), nil
}

func (s *stubProc) commit(addr, size uint64, prot uint32) (uint64, error) {
	r, _, err := procVirtualAllocEx.Call(uintptr(s.proc), uintptr(addr), uintptr(size),
		windows.MEM_COMMIT, uintptr(prot))
	if r == 0 {
		return 0, err
	}
	return uint64(r), nil
}

func (s *stubProc) free(addr, size uint64, release bool) error {
	typ := uintptr(windows.MEM_DECOMMIT)
	if release {
		typ, size = windows.MEM_RELEASE, 0
	}
	if r, _, err := procVirtualFreeEx.Call(uintptr(s.proc), uintptr(addr), uintptr(size), typ); r == 0 {
		return err
	}
	return nil
}

func (s *stubProc) protect(addr, size uint64, prot uint32) error {
	var old uint32
	return windows.VirtualProtectEx(s.proc, uintptr(addr), uintptr(size), prot, &old)
}

func (s *stubProc) writeMem(addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	var n uintptr
	if err := windows.WriteProcessMemory(s.proc, uintptr(addr), &b[0], uintptr(len(b)), &n); err != nil {
		return err
	}
	if n != uintptr(len(b)) {
		return errors.New("short guest write")
	}
	return nil
}

// flushCode makes code written into the stub visible to its instruction
// fetch (arm64 caches are not coherent with WriteProcessMemory's stores).
func (s *stubProc) flushCode(addr, size uint64) error {
	if r, _, err := procFlushInstructionCache.Call(uintptr(s.proc), uintptr(addr), uintptr(size)); r == 0 {
		return err
	}
	return nil
}

func (s *stubProc) readMem(addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	var n uintptr
	if err := windows.ReadProcessMemory(s.proc, uintptr(addr), &b[0], uintptr(len(b)), &n); err != nil {
		return err
	}
	if n != uintptr(len(b)) {
		return errors.New("short guest read")
	}
	return nil
}

// winProt maps Linux PROT_* bits to a Windows page protection.
func winProt(prot uint64) uint32 {
	const r, w, x = 1, 2, 4
	switch {
	case prot&x != 0 && prot&w != 0:
		return windows.PAGE_EXECUTE_READWRITE
	case prot&x != 0:
		return windows.PAGE_EXECUTE_READ
	case prot&w != 0:
		return windows.PAGE_READWRITE
	case prot&r != 0:
		return windows.PAGE_READONLY
	}
	return windows.PAGE_NOACCESS
}
