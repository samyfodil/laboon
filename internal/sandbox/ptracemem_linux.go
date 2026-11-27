//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"runtime"
)

// ptraceAccess reads or writes the tracee g's memory for ptrace. process_vm
// honours page permissions; /proc/<pid>/mem then forces access to read-only
// guest text (and on arm64 lets the kernel synchronise the instruction cache
// after a write). The stub-overlap guard is applied by the caller.
func ptraceAccess(g *dguest, addr uint64, b []byte, write bool) error {
	m := g.mp
	var err error
	if write {
		err = lxErr(lxEIO)
		if runtime.GOARCH != "arm64" {
			err = m.write(addr, b)
		}
	} else {
		err = m.read(addr, b)
	}
	if err == nil {
		return nil
	}
	mode := os.O_RDONLY
	if write {
		mode = os.O_WRONLY
	}
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", m.pid.Load()), mode, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if write {
		_, err = f.WriteAt(b, int64(addr))
	} else {
		_, err = f.ReadAt(b, int64(addr))
	}
	return err
}

// Stub-layout facts ptrace needs, as the Linux stub lays them out.
var (
	ptStubLo     = stubLo
	ptStubHi     = stubHi
	ptraceStepOK = true // x86 TF single-step is supported on Linux
)

// ptraceInternalPC reports whether pc is in the stub's own machinery -- a
// rewritten syscall site or a reserved range -- which single-step must not
// enter. Caller holds no lock; this takes the memProc lock.
func (m *memProc) ptraceInternalPC(pc uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sites.load().has(pc) {
		return true
	}
	for _, r := range m.reserved {
		if pc >= r.lo && pc < r.hi {
			return true
		}
	}
	return false
}

// ptraceSP is the guest stack pointer at the trapped syscall, from the stub's
// saved slot.
func ptraceSP(g *dguest) uint64 { return le64(g.mem[g.slot*slotSize+stubSp:]) }

// ptrace is wired on Linux.
const ptraceEnabled = true
