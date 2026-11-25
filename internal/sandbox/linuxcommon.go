//go:build linux

package sandbox

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/samyfodil/laboon/internal/rewrite"
)

// What both Linux backends (the guest one and the shared layer's) use.

const (
	stackSize = 8 << 20
	trampSize = 1 << 20
	minAddr   = 0x10000 // vm.mmap_min_addr
)

// pageSize is the host's: 4K on x86-64, but 16K or 64K on some arm64 kernels.
var pageSize = uint64(os.Getpagesize())

func alignUp(v uint64) uint64 { return (v + pageSize - 1) &^ (pageSize - 1) }

// layout is where an execve places a program: a position-independent one with
// an interpreter at exe (ELF_ET_DYN_BASE moved by a random offset of
// mmapRndBits pages), the stack's top at stack (moved down by stackRndBits
// pages), the break brkRnd, a random part of 1 GiB, past its base (brkBase),
// and mm, the mmap area below the stack, where the interpreter -- or a program
// with none -- loads first. Linux's ASLR draws each anew per execve;
// ADDR_NO_RANDOMIZE leaves them all at their bases.
type layout struct {
	exe, stack, brkRnd uint64
	mm                 mmapLayout // where mmap places what the guest leaves unplaced
}

// brkBase is where exe's break starts before brkRnd, as load_elf_binary puts
// it: at ELF_ET_DYN_BASE for a program with no interpreter, out of the mmap
// area it loads in -- rounded up, the base being two thirds of the address
// space, which a load bias rounds down (etDynBase) -- else past its end, a
// page past it when randomized.
func (l layout) brkBase(exe *image) uint64 {
	switch {
	case exe.dyn && exe.interp == "":
		return etDynBase + pageSize
	case l.mm.norand:
		return exe.hi
	}
	return exe.hi + pageSize
}

func (g *dguest) drawLayout() layout {
	g.dfs.mu.Lock()
	pers := g.ps.personality
	rlimStack := g.ps.rlim[rlimitStack].cur
	g.dfs.mu.Unlock()
	// The stack's top is STACK_TOP, the task size, as on Linux, and the mmap
	// area lies below it.
	stackBase := uint64(vmTaskSize)
	mm := drawMmapLayout(stackBase, rlimStack, pers)
	if pers&addrNoRandomize != 0 {
		return layout{exe: etDynBase, stack: stackBase, mm: mm}
	}
	return layout{
		exe:    etDynBase + randPages(1<<rndBits()),
		stack:  stackBase - randPages(1<<stackRndBits),
		brkRnd: randPages(1 << 30 / pageSize),
		mm:     mm,
	}
}

// rndBits is the host's vm.mmap_rnd_bits, which a Linux process on it is
// randomized by, when the supervisor may read it (root may), else the
// kernel's default for the architecture.
var rndBits = sync.OnceValue(func() uint64 {
	b, err := os.ReadFile("/proc/sys/vm/mmap_rnd_bits")
	if n, perr := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && perr == nil && n > 0 && n < 64 {
		return uint64(n)
	}
	return mmapRndBits
})

// vmRndBits is what /proc/sys/vm/mmap_rnd_bits reports: the host's.
func (g *dguest) vmRndBits() uint64 { return rndBits() }

// guestPageSize is the guest's page size, AT_PAGESZ: the host's.
func (g *dguest) guestPageSize() int { return int(pageSize) }

// randPages is a random page-aligned offset below n pages (a power of two).
func randPages(n uint64) uint64 {
	var b [8]byte
	rand.Read(b[:])
	return (binary.LittleEndian.Uint64(b[:]) & (n - 1)) * pageSize
}

// chunkSize is the trampoline area allocated per runtime code mapping.
const chunkSize = 64 << 10

// codeRewriter patches syscall sites and builds their trampolines:
// rewrite.Rewriter on x86-64, rewrite.A64Rewriter on arm64.
type codeRewriter interface {
	Trampolines() []byte
	Patched() *rewrite.Result
}

// stubEntries holds the offsets, from the stub's image base, of the stub entry
// points the rewriter calls. entry is lc_syscall_entry (every arch). entryGs
// and latekick are the %gs-anchor fast path's entry (lc_syscall_entry_gs) and
// late-kick delivery (lc_latekick); they exist only in the amd64 stub, so they
// are 0 on an arch that has no %gs anchor.
type stubEntries struct {
	entry    uint64
	entryGs  uint64
	latekick uint64
}

// stubEntry returns the stub's entry-point offsets. It also settles which stub
// binary and address window this process uses, so the entries match the binary
// a nested laboon will actually load. Offsets, not absolute values: the ET_EXEC
// is linked at a fixed base but the PIE is image-base 0 and placed at a window
// chosen at load, so each entry is resolved to base+offset once the stub
// reports its window (boot).
func stubEntry() (stubEntries, error) {
	f, err := elf.NewFile(bytes.NewReader(chooseStub()))
	if err != nil {
		return stubEntries{}, err
	}
	var base uint64
	if f.Type == elf.ET_EXEC {
		base = ^uint64(0)
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Vaddr < base {
				base = p.Vaddr
			}
		}
	}
	syms, err := f.Symbols()
	if err != nil {
		return stubEntries{}, err
	}
	var e stubEntries
	for _, s := range syms {
		switch s.Name {
		case "lc_syscall_entry":
			e.entry = s.Value - base
		case "lc_syscall_entry_gs":
			e.entryGs = s.Value - base
		case "lc_latekick":
			e.latekick = s.Value - base
		}
	}
	if e.entry == 0 {
		return stubEntries{}, errors.New("stub has no lc_syscall_entry")
	}
	return e, nil
}
