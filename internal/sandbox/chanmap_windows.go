package sandbox

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the shared region is a placeholder reservation, chanLen long, in
// the supervisor and in every stub, with a section per chunk of chunkSlots
// slots mapped into it as the chunk first comes into use. One section for the
// whole region is out: a section's prototype page tables are allocated whole
// when it is made, a gigabyte of kernel pool for each half terabyte. A
// chunk's section holds its slots' channel pages, signal records and windows,
// each part mapped where the region has it (chunkParts), so every process sees
// every chunk at the same offsets.
const (
	chunkSlots = 64
	chunkLen   = chunkSlots * (slotSize + sigStride + winSize)
	memMapped  = 0x40000 // MEM_MAPPED
)

// chunkPart is one of a chunk's three parts: at, its offset in the region;
// off, its offset in the chunk's section; size, its length.
type chunkPart struct{ at, off, size uintptr }

func chunkParts(c int) [3]chunkPart {
	s, g, w := uintptr(chunkSlots*slotSize), uintptr(chunkSlots*sigStride), uintptr(chunkSlots*winSize)
	k := uintptr(c)
	return [3]chunkPart{{k * s, 0, s}, {slotsLen + k*g, s, g}, {winOff + k*w, s + g, w}}
}

// chanMap is the run's shared region: the chunks made so far, and the stubs
// that have checked in, each given every chunk.
type chanMap struct {
	mu    sync.Mutex
	base  uintptr          // the region in the supervisor
	secs  []windows.Handle // each chunk's section
	stubs map[int]chanStub // by OS pid
}

type chanStub struct {
	proc windows.Handle // the map's own handle on the stub process
	base uintptr        // its region
}

func newChanMap() (*chanMap, error) {
	m := &chanMap{stubs: map[int]chanStub{}}
	size := uintptr(chanLen)
	if st, _, _ := procNtAllocateVirtualMemoryEx.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&m.base)), uintptr(unsafe.Pointer(&size)),
		windows.MEM_RESERVE|memReservePlaceholder, windows.PAGE_NOACCESS, 0, 0); st != 0 {
		return nil, ntErr("reserve channel", st)
	}
	if err := m.addChunk(); err != nil {
		m.close()
		return nil, err
	}
	return m, nil
}

// mem is the region as the supervisor sees it; only the chunks made so far
// are memory.
func (m *chanMap) mem() []byte {
	// base is memory outside the Go heap; read it as a pointer without a
	// uintptr conversion vet would flag.
	return unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&m.base))), chanLen)
}

// section is slot i's chunk's section, which a stub starting on slot i maps
// itself.
func (m *chanMap) section(i int) windows.Handle {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secs[i/chunkSlots]
}

// back has slot i's chunk made (dfs.takeSlot): a slot past the chunks so far
// is in the next one.
func (m *chanMap) back(i int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return i/chunkSlots < len(m.secs) || m.addChunk() == nil
}

// addChunk makes the next chunk and maps it into the supervisor and every
// stub. A live stub it cannot be mapped into is ended: it is out of memory,
// and would fault on the chunk's first slot it touched. m.mu held.
func (m *chanMap) addChunk() error {
	c := len(m.secs)
	sec, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, 0, chunkLen, nil)
	if err != nil {
		return err
	}
	if err := mapChunk(windows.CurrentProcess(), m.base, sec, c); err != nil {
		windows.CloseHandle(sec)
		return err
	}
	m.secs = append(m.secs, sec)
	for pid, s := range m.stubs {
		if m.prune(pid, s) {
			continue
		}
		if mapChunk(s.proc, s.base, sec, c) != nil {
			windows.TerminateProcess(s.proc, 128+9)
		}
	}
	return nil
}

// adopt gives a stub that has checked in, its region at base, every chunk: it
// maps those the region lacks (a fork child has its parent's), and each chunk
// made from now on.
func (m *chanMap) adopt(proc windows.Handle, pid int, base uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.stubs[pid]; ok {
		m.prune(pid, s)
	}
	s, ok := m.stubs[pid]
	if !ok {
		s.base = uintptr(base)
		cur := windows.CurrentProcess()
		if err := windows.DuplicateHandle(cur, proc, cur, &s.proc, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return err
		}
		m.stubs[pid] = s
	}
	for c, sec := range m.secs {
		if err := mapChunk(s.proc, s.base, sec, c); err != nil {
			return err
		}
	}
	return nil
}

// prune drops a stub that has ended, and reports whether it had.
// m.mu held.
func (m *chanMap) prune(pid int, s chanStub) bool {
	if ev, err := windows.WaitForSingleObject(s.proc, 0); err == nil && ev == uint32(windows.WAIT_TIMEOUT) {
		return false
	}
	windows.CloseHandle(s.proc)
	delete(m.stubs, pid)
	return true
}

// mapChunk maps chunk c's parts into proc's region at base, each where the
// region has a placeholder: one already mapped (inherited) stays.
func mapChunk(proc windows.Handle, base uintptr, sec windows.Handle, c int) error {
	for _, p := range chunkParts(c) {
		at := base + p.at
		var mbi windows.MemoryBasicInformation
		if windows.VirtualQueryEx(proc, at, &mbi, unsafe.Sizeof(mbi)) == nil && mbi.Type == memMapped {
			continue
		}
		// The part's own placeholder, split out of the reservation; it may be
		// one already, between parts mapped on both sides.
		lo, size := at, p.size
		procNtFreeVirtualMemory.Call(uintptr(proc), uintptr(unsafe.Pointer(&lo)), uintptr(unsafe.Pointer(&size)), windows.MEM_RELEASE|memPreservePlaceholder)
		lo, size = at, p.size
		off := int64(p.off)
		if st, _, _ := procNtMapViewOfSectionEx.Call(uintptr(sec), uintptr(proc), uintptr(unsafe.Pointer(&lo)), uintptr(unsafe.Pointer(&off)),
			uintptr(unsafe.Pointer(&size)), memReplacePlaceholder, windows.PAGE_READWRITE, 0, 0); st != 0 {
			return ntErr("map channel chunk", st)
		}
	}
	return nil
}

// close unmaps the region from the supervisor, releases its reservation and
// lets go of the sections and stubs.
func (m *chanMap) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for a := m.base; m.base != 0 && a < m.base+chanLen; {
		var mbi windows.MemoryBasicInformation
		if windows.VirtualQuery(a, &mbi, unsafe.Sizeof(mbi)) != nil || mbi.RegionSize == 0 {
			break
		}
		switch {
		case mbi.Type == memMapped:
			windows.UnmapViewOfFile(a)
		case mbi.State == windows.MEM_RESERVE:
			windows.VirtualFree(mbi.AllocationBase, 0, windows.MEM_RELEASE)
		}
		a += mbi.RegionSize
	}
	for _, sec := range m.secs {
		windows.CloseHandle(sec)
	}
	for pid, s := range m.stubs {
		windows.CloseHandle(s.proc)
		delete(m.stubs, pid)
	}
	m.secs = nil
}

// adoptStub gives the stub process proc, checked in with its region at base,
// the run's every chunk (chanMap.adopt).
func (r *procRun) adoptStub(proc windows.Handle, base uint64) error {
	pid, err := windows.GetProcessId(proc)
	if err != nil {
		return err
	}
	return r.chans.adopt(proc, int(pid), base)
}
