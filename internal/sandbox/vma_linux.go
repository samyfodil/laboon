package sandbox

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// The guest's address space as the supervisor maps it, and where a mapping
// the guest leaves unplaced goes. Linux places one with get_unmapped_area:
// at the hint if it is free, else top-down below mmap_base, a base drawn at
// each execve (bottom-up from TASK_UNMAPPED_BASE with the legacy layout), a
// private anonymous mapping a whole number of huge pages long padded so it
// can sit huge-page aligned. The supervisor makes the same choices and has
// the host map there with MAP_FIXED_NOREPLACE, so placement follows the
// guest's layout and personality -- re-randomized at each execve, fixed
// under ADDR_NO_RANDOMIZE -- rather than the stub process's own. The host
// stays the authority on what is free: a range it refuses (one of the stub
// process's own mappings) is remembered and the search goes on.

// vmaRun is a mapped range; anon marks private anonymous memory, which mremap
// places with the huge-page rule too.
type vmaRun struct {
	lo, hi uint64
	anon   bool
}

// vmaSet is the guest's mappings, sorted and disjoint, adjacent ones of a
// kind merged, and the foreign ranges the host refused.
type vmaSet struct {
	r       []vmaRun
	foreign []run
}

// mmapLayout is where a process's unplaced mappings go, drawn at execve.
type mmapLayout struct {
	base, legacyBase uint64 // mmap_base, and TASK_UNMAPPED_BASE plus the same offset
	legacy, norand   bool
}

// stackGuardGap is the gap Linux keeps below the stack (stack_guard_gap).
func stackGuardGap() uint64 { return 256 * pageSize }

// hugePage is the PMD size transparent huge pages align to.
func hugePage() uint64 { return pageSize * (pageSize / 8) }

// drawMmapLayout draws a process's mmap layout below the stack area whose
// top, unrandomized, is stackBase, as Linux's arch_pick_mmap_layout does.
func drawMmapLayout(stackBase, rlimStack uint64, personality uint32) mmapLayout {
	norand := personality&addrNoRandomize != 0
	l := mmapLayout{norand: norand, legacy: personality&addrCompatLayout != 0 || unlimitedStackLegacy && rlimStack == rlimInf}
	var rnd uint64
	pad := stackGuardGap()
	if !norand {
		rnd = randPages(1 << rndBits())
		pad += 1 << stackRndBits * pageSize
	}
	gap := rlimStack
	if gap+pad > gap {
		gap += pad
	}
	gap = min(max(gap, 128<<20), vmTaskSize/6*5)
	l.base = alignUp(stackBase - gap - rnd)
	l.legacyBase = alignUp(vmTaskSize/unmappedDiv) + rnd
	return l
}

func (s vmaSet) clone() vmaSet {
	return vmaSet{r: append([]vmaRun(nil), s.r...), foreign: append([]run(nil), s.foreign...)}
}

// add records [lo, hi) as mapped, replacing what was there, and returns how
// many bytes were not mapped before.
func (s *vmaSet) add(lo, hi uint64, anon bool) uint64 {
	if lo >= hi {
		return 0
	}
	removed := s.sub(lo, hi)
	i := sort.Search(len(s.r), func(i int) bool { return s.r[i].lo >= lo })
	nr := vmaRun{lo, hi, anon}
	if i > 0 && s.r[i-1].hi == lo && s.r[i-1].anon == anon {
		i--
		nr.lo = s.r[i].lo
		s.r = append(s.r[:i], s.r[i+1:]...)
	}
	if i < len(s.r) && s.r[i].lo == nr.hi && s.r[i].anon == anon {
		nr.hi = s.r[i].hi
		s.r = append(s.r[:i], s.r[i+1:]...)
	}
	s.r = append(s.r, vmaRun{})
	copy(s.r[i+1:], s.r[i:])
	s.r[i] = nr
	return hi - lo - removed
}

// sub takes [lo, hi) out and returns how many mapped bytes it held.
func (s *vmaSet) sub(lo, hi uint64) uint64 {
	if lo >= hi {
		return 0
	}
	i := sort.Search(len(s.r), func(i int) bool { return s.r[i].hi > lo })
	var removed uint64
	for i < len(s.r) && s.r[i].lo < hi {
		v := s.r[i]
		removed += min(v.hi, hi) - max(v.lo, lo)
		switch {
		case v.lo < lo && v.hi > hi:
			s.r[i].hi = lo
			s.r = append(s.r, vmaRun{})
			copy(s.r[i+2:], s.r[i+1:])
			s.r[i+1] = vmaRun{hi, v.hi, v.anon}
			return removed
		case v.lo < lo:
			s.r[i].hi = lo
			i++
		case v.hi > hi:
			s.r[i].lo = hi
			return removed
		default:
			s.r = append(s.r[:i], s.r[i+1:]...)
		}
	}
	return removed
}

// at is the run that holds addr, if one does.
func (s *vmaSet) at(addr uint64) (vmaRun, bool) {
	i := sort.Search(len(s.r), func(i int) bool { return s.r[i].hi > addr })
	if i < len(s.r) && s.r[i].lo <= addr {
		return s.r[i], true
	}
	return vmaRun{}, false
}

// total is the bytes mapped.
func (s *vmaSet) total() uint64 {
	var n uint64
	for _, v := range s.r {
		n += v.hi - v.lo
	}
	return n
}

// addForeign remembers [lo, hi) as the host's.
func (s *vmaSet) addForeign(lo, hi uint64) {
	s.foreign = append(s.foreign, run{lo: lo, hi: hi})
	sort.Slice(s.foreign, func(i, j int) bool { return s.foreign[i].lo < s.foreign[j].lo })
}

// obstacles is what a mapping may not overlap besides the guest's own: the
// stub's window and reserved ranges, the foreign ones and the stack's guard
// gap, sorted. m.mu held.
func (m *memProc) obstacles() []run {
	o := make([]run, 0, len(m.vm.foreign)+len(m.reserved)+2)
	o = append(o, run{lo: stubLo, hi: stubHi})
	o = append(o, m.vm.foreign...)
	o = append(o, m.reserved...)
	if m.stackLo != 0 {
		o = append(o, run{lo: m.stackLo - min(m.stackLo, stackGuardGap()), hi: m.stackLo})
	}
	sort.Slice(o, func(i, j int) bool { return o[i].lo < o[j].lo })
	return o
}

// clear reports whether [lo, hi) overlaps neither a guest mapping nor an
// obstacle.
func (m *memProc) clear(obs []run, lo, hi uint64) bool {
	i := sort.Search(len(m.vm.r), func(i int) bool { return m.vm.r[i].hi > lo })
	if i < len(m.vm.r) && m.vm.r[i].lo < hi {
		return false
	}
	for _, o := range obs {
		if o.lo < hi && lo < o.hi {
			return false
		}
	}
	return true
}

// topDown finds the highest aligned a in [low, high-n] with [a, a+n) clear,
// as unmapped_area_topdown does.
func (m *memProc) topDown(obs []run, n, low, high uint64) (uint64, bool) {
	end := high
	i := sort.Search(len(m.vm.r), func(i int) bool { return m.vm.r[i].lo >= end }) - 1
	j := sort.Search(len(obs), func(j int) bool { return obs[j].lo >= end }) - 1
	for {
		// The next obstacle down: of the two lists' next, the one reaching higher.
		var lo, hi uint64
		found := false
		if i >= 0 && (j < 0 || m.vm.r[i].hi >= obs[j].hi) {
			lo, hi, found = m.vm.r[i].lo, m.vm.r[i].hi, true
			i--
		} else if j >= 0 {
			lo, hi, found = obs[j].lo, obs[j].hi, true
			j--
		}
		gapLo := low
		if found {
			gapLo = max(hi, low)
		}
		if end >= n && end-n >= gapLo {
			return (end - n) &^ (pageSize - 1), true
		}
		if !found {
			return 0, false
		}
		end = min(end, lo)
		if end <= low {
			return 0, false
		}
	}
}

// bottomUp finds the lowest a in [low, high-n] with [a, a+n) clear, as
// unmapped_area does.
func (m *memProc) bottomUp(obs []run, n, low, high uint64) (uint64, bool) {
	start := alignUp(low)
	i := sort.Search(len(m.vm.r), func(i int) bool { return m.vm.r[i].hi > start })
	j := sort.Search(len(obs), func(j int) bool { return obs[j].hi > start })
	for {
		var lo, hi uint64
		found := false
		if i < len(m.vm.r) && (j >= len(obs) || m.vm.r[i].lo <= obs[j].lo) {
			lo, hi, found = m.vm.r[i].lo, m.vm.r[i].hi, true
			i++
		} else if j < len(obs) {
			lo, hi, found = obs[j].lo, obs[j].hi, true
			j++
		}
		limit := high
		if found {
			limit = min(lo, high)
		}
		if limit >= start && limit-start >= n {
			return start, true
		}
		if !found || hi >= high {
			return 0, false
		}
		start = max(start, alignUp(hi))
	}
}

// place picks where a mapping of n bytes the guest left unplaced goes, as
// get_unmapped_area does; anon marks a private anonymous one. m.mu held.
func (m *memProc) place(hint, n, flags uint64, anon bool) (uint64, bool) {
	if n == 0 || n > vmTaskSize-minAddr {
		return 0, false
	}
	obs := m.obstacles()
	if hint != 0 {
		if h := hint &^ (pageSize - 1); h >= minAddr && h <= vmTaskSize-n && m.clear(obs, h, h+n) {
			return h, true
		}
	}
	if flags&unix.MAP_HUGETLB != 0 {
		// hugetlb_get_unmapped_area: aligned to the huge page size the flags
		// name (MAP_HUGE_SHIFT), the default one when they name none.
		hs := hugePage()
		if sh := flags >> 26 & 0x3f; sh != 0 {
			hs = 1 << sh
		}
		n = (n + hs - 1) &^ (hs - 1)
		if a, ok := m.search(obs, n+hs); ok {
			return (a + hs - 1) &^ (hs - 1), true
		}
		return 0, false
	}
	if map32bit != 0 && flags&map32bit != 0 {
		lo := uint64(0x40000000)
		if !m.lay.norand {
			lo += randPages(0x02000000 / pageSize)
		}
		return m.bottomUp(obs, n, lo, 0x80000000)
	}
	if huge := hugePage(); anon && hint == 0 && n%huge == 0 {
		// thp_get_unmapped_area: room for the mapping and one more huge page,
		// the mapping placed at its first huge page boundary above the start,
		// or a page higher when the start is a boundary and the search went
		// top-down.
		if a, ok := m.search(obs, n+huge); ok {
			off := -a & (huge - 1)
			if off == 0 && !m.lay.legacy {
				return a + huge, true
			}
			return a + off, true
		}
	}
	return m.search(obs, n)
}

// placeFresh is where a fresh address space under layout l, one with nothing
// mapped but what the stub process holds, places n bytes first. m.mu held.
func (m *memProc) placeFresh(l mmapLayout, n uint64) (uint64, bool) {
	f := &memProc{vm: vmaSet{foreign: m.vm.foreign}, lay: l}
	return f.place(0, n, 0, false)
}

// search is the layout's own search, top-down below mmap_base falling back
// to bottom-up from the legacy base, or bottom-up alone with the legacy
// layout.
func (m *memProc) search(obs []run, n uint64) (uint64, bool) {
	if !m.lay.legacy {
		if a, ok := m.topDown(obs, n, max(minAddr, pageSize), m.lay.base); ok {
			return a, true
		}
	}
	return m.bottomUp(obs, n, m.lay.legacyBase, vmTaskSize)
}

// mapAt has the host map n bytes for a guest mapping and records it: at addr
// when the guest fixed it (MAP_FIXED or MAP_FIXED_NOREPLACE in flags), else
// where place puts it, the hint addr included. do makes the host call at an
// address with the fixed flag to use; it returns the address mapped or a
// negated errno. g.mp.mu held.
func (g *dguest) mapAt(addr, n, flags uint64, anon bool, do func(at, fixed uint64) int64) int64 {
	m := g.mp
	if fixed := flags & (unix.MAP_FIXED | unix.MAP_FIXED_NOREPLACE); fixed != 0 {
		r := do(addr, fixed)
		if r >= 0 {
			g.trackAs(uint64(r), n, anon)
		}
		return r
	}
	n = alignUp(n)
	for range 64 {
		at, ok := m.place(addr, n, flags, anon)
		if !ok {
			return sErr(lxENOMEM)
		}
		r := do(at, unix.MAP_FIXED_NOREPLACE)
		if r >= 0 && uint64(r) != at {
			// A host without MAP_FIXED_NOREPLACE took it as a hint.
			g.host(unix.SYS_MUNMAP, uint64(r), n)
			r = -int64(unix.EEXIST)
		}
		if r == -int64(unix.EEXIST) {
			m.vm.addForeign(at, at+n) // the host's own: place again
			addr = 0
			continue
		}
		if r >= 0 {
			g.trackAs(uint64(r), n, anon)
		}
		return r
	}
	return sErr(lxENOMEM)
}

// vmaValidate checks after a memory call that every range the set holds is
// mapped in the stub (LABOON_VMA_VALIDATE).
var vmaValidate = os.Getenv("LABOON_VMA_VALIDATE") != ""

func (g *dguest) checkVmas(what string) {
	if !vmaValidate {
		return
	}
	g.mp.mu.Lock()
	defer g.mp.mu.Unlock()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", g.mp.pid.Load()))
	if err != nil {
		return
	}
	var host []run
	for line := range strings.Lines(string(b)) {
		var lo, hi uint64
		if _, err := fmt.Sscanf(line, "%x-%x", &lo, &hi); err == nil {
			host = append(host, run{lo: lo, hi: hi})
		}
	}
	if len(host) == 0 || g.sigs().killedBy(g.tgid) != 0 {
		return // the process is going (killed), its mappings with it, mid-listing perhaps
	}
	for _, v := range g.mp.vm.r {
		for at := v.lo; at < v.hi; {
			i := sort.Search(len(host), func(i int) bool { return host[i].hi > at })
			if i == len(host) || host[i].lo > at {
				panic(fmt.Sprintf("laboon: after %s the guest mapping %#x-%#x is not mapped at %#x (pid %d, host %v)", what, v.lo, v.hi, at, g.mp.pid.Load(), host))
			}
			at = host[i].hi
		}
	}
}
