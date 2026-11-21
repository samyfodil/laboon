package rewrite

import (
	"bytes"
	"cmp"
	"slices"
)

// Descender finds syscalls by recursive-descent disassembly: it decodes only
// bytes reached as code, starting from entry points known to be real
// instruction boundaries (e.g. fault addresses) and following direct branches
// and fall-through. Unlike a linear sweep it never decodes data as code, so
// it does not drift on binaries that interleave code and data in their text
// (V8's builtins blob is the motivating case).
//
// A Descender is persistent for one code region: visited state accumulates
// across calls, so each new entry only explores code not seen before. Code
// reached only through an indirect branch (jump table, function pointer) is
// not followed; it is discovered when it is first executed and faults, which
// seeds a new entry.
type Descender struct {
	code    []byte
	visited []bool // byte decoded as part of an instruction
	queued  []bool // offset already enqueued as an entry
	queue   []int
	sites   []Site
	ends    []int // offsets just past the terminators decoded
	swept   int   // how many of ends Scavenge has swept from
	axAt    map[int]bool
	stealAt map[int]uint8 // the run before a syscall a sweep accepted, as the sweep decoded it
	exits   []int         // targets of direct branches out of code, as offsets from its start
	// FS, when set, also records the %fs-relative instructions decoded.
	FS      bool
	fsSites []FSSite
	// decode is the length/flow decoder trace uses; x86decode in production,
	// swapped for the disassembler oracle in the differential test.
	decode func([]byte) x86inst
}

// NewDescender returns a Descender over code (the whole region's bytes).
func NewDescender(code []byte) *Descender {
	return &Descender{
		code:    code,
		visited: make([]bool, len(code)),
		queued:  make([]bool, len(code)),
		decode:  x86decode,
	}
}

// AddEntry schedules off (an offset into code) as an instruction boundary;
// one outside code is recorded as an exit.
func (d *Descender) AddEntry(off int) {
	if off < 0 || off >= len(d.code) {
		d.exits = append(d.exits, off)
		return
	}
	if d.queued[off] {
		return
	}
	d.queued[off] = true
	d.queue = append(d.queue, off)
}

// Run explores all queued entries and returns the syscall sites discovered
// since the last call (so the caller can patch just the new ones).
func (d *Descender) Run() []Site {
	start := len(d.sites)
	for len(d.queue) > 0 {
		off := d.queue[len(d.queue)-1]
		d.queue = d.queue[:len(d.queue)-1]
		d.trace(off)
	}
	return d.sites[start:]
}

// trace decodes from off along fall-through until it leaves the region, hits
// an undecodable byte, revisits decoded code, or reaches a terminator,
// queuing the targets of direct branches as it goes.
func (d *Descender) trace(off int) {
	t := tail{long: -1}
	for off >= 0 && off < len(d.code) && !d.visited[off] {
		// endbr64/endbr32 (CET function prologues) are the 4-byte no-op
		// f3 0f 1e fa/fb; skip them whole (the 0f 1e form is easy to
		// mis-sync on). Handled before the decoder so it never sees them.
		if n := endbrLen(d.code[off:]); n > 0 {
			for i := 0; i < n && off+i < len(d.visited); i++ {
				d.visited[off+i] = true
			}
			t.long = -1
			off += n
			continue
		}
		in := d.decode(d.code[off:])
		if !in.ok {
			return
		}
		for i := 0; i < in.len && off+i < len(d.visited); i++ {
			d.visited[off+i] = true
		}
		if in.syscall {
			steal := t.steal(off)
			if steal == 0 {
				steal = d.stealAt[off] // reached from itself: the sweep saw what precedes it
			}
			d.sites = append(d.sites, Site{Off: uint32(off), Steal: steal})
		}
		if d.FS && in.fsMem {
			d.fsSites = append(d.fsSites, fsSite(off, in, &t))
		}
		if in.relOK {
			d.AddEntry(off + in.len + in.rel)
		}
		if in.terminates {
			d.ends = append(d.ends, off+in.len)
			return
		}
		t.add(in, off)
		off += in.len
	}
}

// AnalyzeEntries runs recursive descent over code from the given entry
// offsets (real instruction boundaries, e.g. function starts from .eh_frame)
// and returns the syscall sites. Every entry is known-good and only reachable
// code is decoded, so it does not drift through data. It then sweeps the
// parts of code scav lists, its executable sections (Scavenge), for the
// syscalls of functions no entry names.
func AnalyzeEntries(code []byte, entries []int, scav [][2]int) Plan {
	d := descendAll(code, entries, scav, false)
	assignCaves(d.sites, d.caves())
	return Plan{Sites: d.sites}
}

// AnonSites finds the syscall sites in code written at run time, one page of
// it: descent from roots, the instruction boundaries it is known to be
// entered at (where a thread was about to execute it, and the targets of
// other pages' branches into it), and a sweep of all of it. exits are the
// targets of the direct branches the code it decoded makes out of it, as
// offsets from its start: roots of the pages they land in.
func AnonSites(code []byte, roots []int) (sites, exits []int) {
	plan, exits := AnonPlan(code, roots)
	for _, s := range plan {
		sites = append(sites, int(s.Off))
	}
	return sites, exits
}

// AnonPlan is AnonSites with each site's run to steal, sorted by offset.
func AnonPlan(code []byte, roots []int) (sites []Site, exits []int) {
	d := descendAll(code, roots, [][2]int{{0, len(code)}}, false)
	sites = slices.Clone(d.sites)
	slices.SortFunc(sites, func(a, b Site) int { return int(a.Off) - int(b.Off) })
	return sites, d.exits
}

// descendAll descends from entries, then sweeps scav and descends from what
// the sweep accepts, until a sweep accepts nothing more.
func descendAll(code []byte, entries []int, scav [][2]int, fs bool) *Descender {
	d := NewDescender(code)
	d.FS = fs
	for _, e := range entries {
		d.AddEntry(e)
	}
	d.Run()
	for {
		added := 0
		for _, r := range scav {
			added += d.Scavenge(r[0], r[1])
		}
		d.swept = len(d.ends) // what the next round sweeps from is what Run ends anew
		if added == 0 {
			return d
		}
		d.Run()
	}
}

// caves are the offsets of five-byte slots in code no path reaches: the
// padding (nops, int3) right after a terminator, before the next instruction
// decoded. A site with no run to steal jumps through one (Site.Cave).
func (d *Descender) caves() []int {
	var out []int
	slices.Sort(d.ends)
	for i, e := range d.ends {
		if i > 0 && e == d.ends[i-1] {
			continue
		}
		n := 0
		for e+n < len(d.code) && !d.visited[e+n] {
			l := padLen(d.code[e+n:])
			if l == 0 || slices.Contains(d.visited[e+n:e+n+l], true) {
				break
			}
			n += l
		}
		for k := 0; k+5 <= n; k += 5 {
			out = append(out, e+k)
		}
	}
	return out
}

// assignCaves gives each site with no run to steal the nearest unused cave a
// two-byte jmp at its syscall reaches.
func assignCaves(sites []Site, caves []int) {
	used := make([]bool, len(caves))
	idx := make([]int, len(sites))
	for i := range idx {
		idx[i] = i
	}
	slices.SortFunc(idx, func(a, b int) int { return cmp.Compare(sites[a].Off, sites[b].Off) })
	for _, i := range idx {
		s := &sites[i]
		if s.Steal != 0 {
			continue
		}
		best := -1
		for j, c := range caves {
			if r := c - (int(s.Off) + 2); !used[j] && r >= -128 && r <= 127 && (best < 0 || abs(r) < abs(caves[best]-(int(s.Off)+2))) {
				best = j
			}
		}
		if best >= 0 {
			used[best] = true
			s.Cave = int16(caves[best] - int(s.Off))
		}
	}
}

// trapCaves are caves inside runs of int3, the padding compilers put after a
// call that does not return and between functions: five int3 bytes right after
// another, which a path reaches only by resuming from the trap that one raises.
// Descent decodes int3 as an instruction and walks on through them, so they
// are not caves to it.
func trapCaves(code []byte) []int {
	var out []int
	for i := 0; i < len(code); {
		j := bytes.IndexByte(code[i:], 0xcc)
		if j < 0 {
			break
		}
		lo := i + j
		hi := lo
		for hi < len(code) && code[hi] == 0xcc {
			hi++
		}
		for c := lo + 1; c+5 <= hi; c += 5 {
			out = append(out, c)
		}
		i = hi
	}
	return out
}

// assignFSCaves gives each %fs site too short for the jmp, with no run to
// steal, the nearest cave a two-byte jmp at it reaches that no syscall site
// or other %fs site took.
func assignFSCaves(fs []FSSite, sites []Site, caves []int) {
	slices.Sort(caves)
	caves = slices.Compact(caves)
	taken := map[int]bool{}
	take := func(c int) {
		for k := range 5 {
			taken[c+k] = true
		}
	}
	free := func(c int) bool {
		for k := range 5 {
			if taken[c+k] {
				return false
			}
		}
		return true
	}
	for _, s := range sites {
		if s.Cave != 0 {
			take(int(s.Off) + int(s.Cave))
		}
	}
	for i := range fs {
		s := &fs[i]
		if s.Len >= 5 || s.Steal != 0 {
			continue
		}
		from := int(s.Off) + 2
		best := -1
		j, _ := slices.BinarySearch(caves, from-128)
		for ; j < len(caves) && caves[j] <= from+127; j++ {
			if c := caves[j]; free(c) && (best < 0 || abs(c-from) < abs(best-from)) {
				best = c
			}
		}
		if best >= 0 {
			take(best)
			s.Cave = int16(best - int(s.Off))
		}
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// padLen is the length of the padding instruction at b (nop in any of its
// forms, int3), or 0 if b holds something else.
func padLen(b []byte) int {
	if len(b) > 0 && b[0] == 0xcc {
		return 1
	}
	in := x86decode(b)
	if !in.ok {
		return 0
	}
	i := 0
	for i < in.len && (b[i] == 0x66 || b[i] == 0x2e) {
		i++
	}
	switch {
	case i < in.len && b[i] == 0x90 && i+1 == in.len:
		return in.len
	case i+1 < in.len && b[i] == 0x0f && b[i+1] == 0x1f:
		return in.len
	}
	return 0
}

// AnalyzeEntriesFS is AnalyzeEntries that also finds the %fs-relative
// instructions descent decodes, in offset order (a sweep's are left alone:
// one it misses faults, which the host serves).
func AnalyzeEntriesFS(code []byte, entries []int, scav [][2]int) Plan {
	d := descendAll(code, entries, scav, true)
	p := Plan{Sites: d.sites, FS: d.fsSites}
	assignFSCaves(p.FS, p.Sites, append(d.caves(), trapCaves(code)...))
	slices.SortFunc(p.Sites, func(a, b Site) int { return cmp.Compare(a.Off, b.Off) })
	slices.SortFunc(p.FS, func(a, b FSSite) int { return cmp.Compare(a.Off, b.Off) })
	return p
}

// Visited reports whether off was decoded as part of an instruction.
func (d *Descender) Visited(off int) bool {
	return off >= 0 && off < len(d.visited) && d.visited[off]
}

// Scavenge finds the syscalls in [lo, hi) descent did not reach, in code that
// follows decoded code: real syscalls in functions reached only indirectly.
// From each point just past a terminator descent decoded (a jmp, ret, ud2...)
// and did not go on from, in address order, it decodes straight on (sweep).
// It queues each syscall it accepts as an entry and returns how many it
// added, so the caller can Run again, which can end more code and so open
// more to sweep.
func (d *Descender) Scavenge(lo, hi int) int {
	hi = min(hi, len(d.code))
	ends := slices.Clone(d.ends[d.swept:])
	slices.Sort(ends)
	if d.axAt == nil {
		d.axAt = map[int]bool{}
	}
	added := 0
	for _, e := range ends {
		if e >= lo && e < hi && !d.visited[e] {
			added += d.sweep(e, hi, d.axAt)
		}
	}
	return added
}

// sweep decodes straight on from off, the point just past a terminator. The
// bytes after a terminator are the compiler's alignment padding (nops, int3)
// and then the next function, so it skips the padding and takes what follows
// as a function's start, again after each terminator it decodes. A syscall it
// lands on exactly is code when eax, where the Linux ABI passes the syscall
// number, was written on a path to it that the sweep decoded: since that
// start, or before a forward branch to it (axAt carries those, by target). It
// stops at decoded code, at hi, or at a byte that decodes as no instruction:
// data, not code. Descent takes each syscall it accepts from there, with the
// run before it the sweep decoded, which a trampoline steals from.
func (d *Descender) sweep(off, hi int, axAt map[int]bool) int {
	added := 0
	ax := false
	t := tail{long: -1}
	off = skipPad(d.code, off, hi)
	for off < hi && !d.visited[off] {
		if k := endbrLen(d.code[off:]); k > 0 {
			t.long = -1
			off += k
			continue
		}
		in := d.decode(d.code[off:])
		if !in.ok || off+in.len > hi {
			break
		}
		ax = ax || axAt[off]
		if in.syscall && ax && !d.queued[off] {
			if s := t.steal(off); s != 0 {
				if d.stealAt == nil {
					d.stealAt = map[int]uint8{}
				}
				d.stealAt[off] = s
			}
			d.AddEntry(off)
			added++
		}
		ax = ax || in.destAX
		if t := off + in.len + in.rel; in.relOK && t > off {
			axAt[t] = axAt[t] || ax
		}
		t.add(in, off)
		off += in.len
		if in.terminates {
			ax = false
			t = tail{long: -1}
			off = skipPad(d.code, off, hi)
		}
	}
	return added
}

// skipPad returns the offset past the padding at off, before hi.
func skipPad(code []byte, off, hi int) int {
	for off < hi {
		n := padLen(code[off:hi])
		if n == 0 {
			break
		}
		off += n
	}
	return off
}

// endbrLen returns 4 if code starts with endbr64/endbr32 (f3 0f 1e fa/fb),
// else 0. These CET prologues are skipped whole so a scan never has to care
// how a decoder frames the f3 0f 1e form.
func endbrLen(code []byte) int {
	if len(code) >= 4 && code[0] == 0xf3 && code[1] == 0x0f && code[2] == 0x1e &&
		(code[3] == 0xfa || code[3] == 0xfb) {
		return 4
	}
	return 0
}
