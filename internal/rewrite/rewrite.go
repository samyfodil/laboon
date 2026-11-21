// Package rewrite redirects x86-64 syscall instructions into the stub, so a
// sandboxed guest never enters the host kernel directly.
//
// Every syscall becomes ud2 (same two bytes), which traps to the stub's
// SIGILL handler. Where the instructions before it are position-independent
// and the first of them is at least five bytes (typically `mov eax, N`), that
// one is also replaced by a jmp to a per-site trampoline that re-executes the
// run and calls the stub directly, skipping the signal. The rest of the run
// and the ud2 stay in place, so a branch into the run or straight to the old
// syscall address still works, just slower.
package rewrite

import (
	"bytes"
	"encoding/binary"
)

// MaxSteal bounds the bytes before a syscall that rewriting its site may
// change.
const MaxSteal = maxStolen

// SiteSpan bounds the bytes on either side of a syscall that rewriting its
// site may change: the run stolen before it, or the cave its two-byte jmp
// reaches (up to 126 bytes before it, or a five-byte slot ending 134 after).
const SiteSpan = 134

// Trampoline area layout: an 8-byte pointer to the stub's syscall entry,
// padding, then one trampoline per site.
const (
	headerSize = 16
	maxStolen  = 32
	// Largest trampoline: the %gs-anchor island -- stolen run (maxStolen) + lea
	// r11 (7) + the entry acquire (clear kicked 12, set busy 12) + save sp (9) +
	// load the service stack (9) + the service call (6) + restore sp (9) + the
	// exit (clear busy 12, read kicked 8, jrcxz 2, jmp to lc_latekick 6) + jmp
	// back (5).
	trampMax = maxStolen + 7 + 12 + 12 + 9 + 9 + 6 + 9 + 12 + 8 + 2 + 6 + 5
)

// Rewriter patches code regions and accumulates their trampolines.
type Rewriter struct {
	base  uint64 // address the trampoline area is mapped at
	limit uint64 // its size
	tramp []byte
	// Nonzero when the thread pointer lives at %gs:tpSlot; see SegmentSlot.
	tpSlot uint32
	// Nonzero when exit sites switch to the stack at %gs:exitSlot; see
	// ExitStack.
	exitSlot uint32
	// Nonzero when the stub owns %gs as a per-thread anchor: a syscall
	// trampoline saves the guest sp at %gs:spSlot and services on the stack
	// whose top is %gs:scratchSlot, never the guest's own stack. busySlot and
	// kickedSlot are the stub thread's busy and kicked flags, which the island
	// sets at entry and rechecks at exit so a kick cannot be delivered onto a
	// live service continuation. See GsAnchor.
	spSlot, scratchSlot, busySlot, kickedSlot uint32
	// NoStray skips the scan for stray syscall encodings in Apply.
	NoStray bool
	Result
}

// Result is what a rewriter patched.
type Result struct {
	// Sites are the addresses of syscalls turned into traps (ud2 on x86,
	// udf or a branch to an island on arm64).
	Sites []uint64
	// Restarts are the traps inside trampolines a restarted syscall resumes
	// at (afterTrampoline).
	Restarts []uint64
	// Fast counts sites that also got a trampoline.
	Fast int
	// FS counts %fs-relative instructions moved to islands (PatchFS).
	FS int
	// Stray are syscall encodings left after patching: on x86, 0f 05 pairs
	// not at a decoded instruction boundary; on arm64, svc words that were
	// not found as code. The stub's seccomp filter kills the process if one
	// is ever executed as a syscall.
	Stray []uint64
}

// Patched returns what was patched so far.
func (r *Result) Patched() *Result { return r }

// New returns a Rewriter whose trampolines live in [base, base+size), which
// must be within ±2GB of all patched code. entry is the stub's syscall entry.
// A size of 0 disables trampolines: every site uses the ud2 path.
func New(base, size, entry uint64) *Rewriter {
	t := make([]byte, headerSize)
	binary.LittleEndian.PutUint64(t, entry)
	return &Rewriter{base: base, limit: size, tramp: t}
}

// Trampolines returns the trampoline area contents.
func (w *Rewriter) Trampolines() []byte { return w.tramp }

// GsAnchor makes syscall trampolines service on a per-thread scratch stack
// rather than the guest's own stack: the stub owns %gs, sp is the offset of the
// guest-sp slot within it (the trampoline stores the guest rsp there), and
// scratch the offset of the service-stack-top slot (the trampoline loads rsp
// from it). This keeps a guest whose thread stacks are small and adjacently
// packed -- a nested laboon's Go goroutine stacks -- from being corrupted by a
// servicing frame underflowing into a neighbor.
// GsAnchor also records the busy and kicked flag offsets (so the island can
// hold off redirection across the service) and stores latekick, the stub's
// lc_latekick entry, in the area header (the slot ExitStack uses on Windows,
// unused under the %gs anchor): the island jumps there to deliver a kick it
// caught in its exit epilogue.
func (w *Rewriter) GsAnchor(sp, scratch, busy, kicked uint32, latekick uint64) {
	w.spSlot, w.scratchSlot, w.busySlot, w.kickedSlot = sp, scratch, busy, kicked
	binary.LittleEndian.PutUint64(w.tramp[8:], latekick)
}

// Plan is the result of analyzing a code region: what to patch, as offsets
// into it. It depends only on the code bytes, so it can be cached by content
// and applied at any load address.
type Plan struct {
	Sites []Site
	// FS are the %fs-relative instructions, for hosts that rewrite them
	// (SegmentSlot); only analyses that look for them fill it.
	FS []FSSite
}

// TrampBytes bounds the trampoline area p needs: a trampoline per syscall
// site and, on a host that rewrites them (SegmentSlot), an island per %fs
// site.
func (p Plan) TrampBytes() uint64 {
	return headerSize + uint64(len(p.Sites))*2*trampMax + uint64(len(p.FS))*(fsIslandMax+maxStolen)
}

// Site is a syscall instruction at Off. Steal is the length of the run of
// instructions just before it that can move into a trampoline, else 0. A
// site with none may have a Cave: the offset from Off of a five-byte slot of
// padding no path reaches, within a two-byte jmp of the syscall.
type Site struct {
	Off   uint32
	Steal uint8
	Cave  int16
}

// Analyze disassembles code and finds every syscall to patch. This is the
// expensive step; see Cache.
func Analyze(code []byte) Plan {
	var p Plan
	t := tail{long: -1}
	for off := 0; off < len(code); {
		in := x86decode(code[off:])
		if !in.ok {
			// Data or padding inside text: resynchronize a byte later.
			off++
			t.long = -1
			continue
		}
		if in.syscall {
			p.Sites = append(p.Sites, Site{Off: uint32(off), Steal: t.steal(off)})
		}
		t.add(in, off)
		off += in.len
	}
	return p
}

// Patch analyzes and rewrites code in place. vaddr is its load address.
func (w *Rewriter) Patch(code []byte, vaddr uint64) {
	w.Apply(Analyze(code), code, vaddr)
}

// Apply rewrites code in place following p, which must come from Analyze
// on these same bytes.
func (w *Rewriter) Apply(p Plan, code []byte, vaddr uint64) {
	for _, s := range p.Sites {
		off := int(s.Off)
		if off+2 > len(code) || code[off] != 0x0f || code[off+1] != 0x05 || int(s.Steal) > off {
			continue // not this code: never patch blindly
		}
		code[off], code[off+1] = 0x0f, 0x0b
		w.Sites = append(w.Sites, vaddr+uint64(off))
		if s.Steal == 0 && s.Cave != 0 && w.spSlot != 0 {
			w.caveTrampoline(code, vaddr, off, off+int(s.Cave))
			continue
		}
		if s.Steal == 0 && w.tpSlot != 0 {
			w.afterTrampoline(code, vaddr, off)
			continue
		}
		run := code[off-int(s.Steal) : off]
		if s.Steal == 0 || !runOK(run) || w.tpSlot != 0 && anyInst(run, hasFS) {
			continue
		}
		switch {
		case !anyInst(run, loadsExit):
			w.trampoline(code, vaddr, off-int(s.Steal), off)
		case w.exitSlot != 0:
			w.exitTrampoline(code, vaddr, off-int(s.Steal), off)
		}
	}
	if !w.NoStray {
		for _, i := range straySites(code) {
			w.Stray = append(w.Stray, vaddr+uint64(i))
		}
	}
}

// loadsExit reports whether ins loads exit's number into eax. A thread's
// exit must not write below the guest's stack pointer, as a trampoline
// call does: the stack may be free already (Go's exitThread says so before
// the syscall). It keeps the trap, which the Linux stub serves on its own
// stack, or takes an ExitStack trampoline.
func loadsExit(ins []byte) bool {
	return bytes.Equal(ins, []byte{0xb8, 0x3c, 0, 0, 0}) || bytes.Equal(ins, []byte{0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0})
}

// ExitStack makes exit sites jump to entry on the stack whose top the stub
// keeps at %gs:slot, without touching the guest's stack: a host whose
// exceptions are dispatched on the faulting stack (Windows) cannot serve the
// trap there either. entry is stored in the area header.
func (w *Rewriter) ExitStack(slot uint32, entry uint64) {
	w.exitSlot = slot
	binary.LittleEndian.PutUint64(w.tramp[8:], entry)
}

// exitTrampoline emits, for an exit site whose instruction at code[ins:sc]
// loads the number:
//
//	<instruction>
//	mov rsp, %gs:exitSlot
//	jmp [rip+header+8]
func (w *Rewriter) exitTrampoline(code []byte, vaddr uint64, ins, sc int) {
	at := uint64(len(w.tramp))
	if at+trampMax > w.limit {
		return
	}
	t := append(w.tramp, code[ins:sc]...)
	t = append(t, 0x65, 0x48, 0x8b, 0x24, 0x25)
	t = binary.LittleEndian.AppendUint32(t, w.exitSlot)
	t = append(t, 0xff, 0x25)
	t = binary.LittleEndian.AppendUint32(t, uint32(int32(8-(len(t)+4))))
	w.tramp = t
	jmpOver(code, ins, vaddr+uint64(ins), w.base+at)
	w.Fast++
}

// afterTrampoline gives a site whose preceding instruction cannot move a
// trampoline that takes the following one instead, when that is a compare of
// rax with an immediate (Go's Syscall6: SYSCALL; CMPQ AX, $-4095), which
// nothing branches to. On a host whose exceptions are dispatched on the
// faulting stack a trap costs kilobytes below the guest's stack pointer, more
// than a Go goroutine has:
//
//	lea rcx, [rip+R]            ; the resume address
//	jmp [rip+entry]             ; the stub resumes the guest at R
//	ud2                         ; R-2: where a restart resumes
//	R: <compare>
//	jmp <after the compare>
func (w *Rewriter) afterTrampoline(code []byte, vaddr uint64, sc int) {
	clen := cmpRAXImm(code[sc+2:])
	if clen == 0 {
		return
	}
	at := uint64(len(w.tramp))
	if at+trampMax+4 > w.limit {
		return
	}
	next := sc + 2 + clen
	t := w.tramp
	t = append(t, 0x48, 0x8d, 0x0d, 0, 0, 0, 0) // lea rcx, [rip+R], patched below
	lea := len(t)
	t = append(t, 0xff, 0x25)
	t = binary.LittleEndian.AppendUint32(t, uint32(int32(0-(len(t)+4))))
	t = append(t, 0x0f, 0x0b)
	r := len(t)
	w.Restarts = append(w.Restarts, w.base+uint64(r-2))
	binary.LittleEndian.PutUint32(t[lea-4:], uint32(r-lea))
	t = append(t, code[sc+2:next]...)
	t = append(t, 0xe9)
	t = binary.LittleEndian.AppendUint32(t, uint32(int32(vaddr+uint64(next)-(w.base+uint64(len(t))+4))))
	w.tramp = t

	src := vaddr + uint64(sc)
	code[sc] = 0xe9
	binary.LittleEndian.PutUint32(code[sc+1:], uint32(int32(w.base+at-(src+5))))
	for i := sc + 5; i < next; i++ {
		code[i] = 0xcc
	}
	w.Fast++
}

// cmpRAXImm returns the length of a `cmp rax, imm` at b (Go's Syscall6 emits
// SYSCALL; CMPQ AX, $-4095 right after, and nothing branches to the compare),
// or 0 if b is not one. The forms are REX.W 3D id, REX.W 81 /7 id and
// REX.W 83 /7 ib, all with rax as the first operand (3D implicit, else rm=rax).
func cmpRAXImm(b []byte) int {
	in := x86decode(b)
	if !in.ok || in.len < 3 || in.len > maxStolen {
		return 0
	}
	switch {
	case len(b) >= 2 && b[0] == 0x48 && b[1] == 0x3d:
		return in.len
	case len(b) >= 3 && b[0] == 0x48 && (b[1] == 0x81 || b[1] == 0x83) && b[2] == 0xf8:
		return in.len
	}
	return 0
}

// tail follows the instructions a scan decodes, for the run a trampoline
// can take before a syscall.
type tail struct {
	end  int // offset just past the last instruction decoded
	long int // start of the run's nearest instruction of five bytes or more, or -1
}

func (t *tail) add(in x86inst, off int) {
	switch {
	case !in.movable:
		t.long = -1
	case in.len >= 5:
		t.long = off
	case off != t.end:
		t.long = -1
	}
	t.end = off + in.len
}

// steal returns the length of the run to move for a syscall at sc: from an
// instruction long enough to hold the 5-byte jmp on its own through
// position-independent instructions up to sc. Only that first instruction
// is overwritten, so a branch to any later one, or to the old syscall, runs
// the original code into the ud2.
func (t *tail) steal(sc int) uint8 {
	if t.long < 0 || t.end != sc || sc-t.long > maxStolen {
		return 0
	}
	return uint8(sc - t.long)
}

// runOK reports whether b is a run tail.steal would take, so a plan that did
// not come from these bytes cannot make Apply move the wrong thing.
func runOK(b []byte) bool {
	t := tail{long: -1}
	for off := 0; off < len(b); {
		in := x86decode(b[off:])
		if !in.ok {
			return false
		}
		t.add(in, off)
		off += in.len
	}
	return t.long == 0 && t.end == len(b)
}

// anyInst reports whether f holds for an instruction of the run b.
func anyInst(b []byte, f func([]byte) bool) bool {
	for len(b) > 0 {
		in := x86decode(b)
		if !in.ok {
			return true
		}
		if f(b[:in.len]) {
			return true
		}
		b = b[in.len:]
	}
	return false
}

// jmpOver replaces the instruction at code[ins], loaded at src and at least
// five bytes long, with a jmp to dst. The instructions after it keep their
// bytes.
func jmpOver(code []byte, ins int, src, dst uint64) {
	in := x86decode(code[ins:])
	if !in.ok {
		return
	}
	code[ins] = 0xe9
	binary.LittleEndian.PutUint32(code[ins+1:], uint32(int32(dst-(src+5))))
	for i := ins + 5; i < ins+in.len; i++ {
		code[i] = 0xcc
	}
}

// trampoline emits, for the instruction at code[ins:sc] followed by a
// syscall at sc:
//
//	<instruction>
//	lea r11, [rip+after]        ; resume address for a possible clone child
//	lea rsp, [rsp-128]          ; step over the red zone
//	call [rip+entry]            ; stub saves registers and services the syscall
//	lea rsp, [rsp+128]
//	jmp after                   ; back past the original syscall
//
// and replaces the instruction with a jmp to it. r11 is clobbered, which is
// fine: a real syscall clobbers r11 too, so the guest never relies on it. The
// Linux stub reads the resume address straight from r11 (saved in the Frame),
// leaving %gs entirely to the guest so a guest may itself be a laboon stub. A
// SegmentSlot host (Windows) resumes the guest itself, so its trampoline
// pushes nothing below the guest's stack pointer, where Linux writes nothing
// (a Go goroutine at its deepest nosplit call has no room there). It passes
// the resume address in rcx, where the syscall instruction itself leaves it:
// a signal taken before the jump saves and restores it with the rest of the
// registers, which a per-thread slot would not survive (the handler's own
// syscalls overwrite it):
//
//	<instruction>
//	lea rcx, [rip+after]
//	jmp [rip+entry]
func (w *Rewriter) trampoline(code []byte, vaddr uint64, ins, sc int) {
	if at, ok := w.emit(code, vaddr, ins, sc); ok {
		jmpOver(code, ins, vaddr+uint64(ins), w.base+at)
		w.Fast++
	}
}

// caveTrampoline gives a syscall at sc with no run to steal a trampoline
// reached through the cave at code[cave:cave+5], padding no path reaches: the
// syscall becomes a two-byte jmp to the cave, which jumps to the trampoline.
// Only the syscall's own bytes change where code runs, so a branch anywhere
// else runs what it always did, and a restart, which resumes at the syscall,
// takes the trampoline again. The trampoline services on the per-thread
// stack (GsAnchor), never the guest's, so it is safe for a thread's exit,
// whose number it cannot see.
func (w *Rewriter) caveTrampoline(code []byte, vaddr uint64, sc, cave int) {
	r := cave - (sc + 2)
	if cave < 0 || cave+5 > len(code) || r < -128 || r > 127 {
		return
	}
	for n := 0; n < 5; {
		l := padLen(code[cave+n:])
		if l == 0 {
			return // not this code: never patch blindly
		}
		n += l
	}
	at, ok := w.emit(code, vaddr, sc, sc)
	if !ok {
		return
	}
	code[cave] = 0xe9
	binary.LittleEndian.PutUint32(code[cave+1:], uint32(int32(w.base+at-(vaddr+uint64(cave)+5))))
	code[sc], code[sc+1] = 0xeb, byte(int8(r))
	w.Fast++
}

// emit appends the trampoline for the run code[ins:sc] and the syscall at
// sc, returning its offset in the area.
func (w *Rewriter) emit(code []byte, vaddr uint64, ins, sc int) (uint64, bool) {
	at := uint64(len(w.tramp))
	if at+trampMax > w.limit {
		return 0, false // area full: the ud2 path still works
	}
	after := vaddr + uint64(sc) + 2
	t := w.tramp
	t = append(t, code[ins:sc]...)
	if w.tpSlot != 0 {
		t = append(t, 0x48, 0x8d, 0x0d) // lea rcx, [rip+disp32]
		t = binary.LittleEndian.AppendUint32(t, uint32(int32(after-(w.base+uint64(len(t))+4))))
		t = append(t, 0xff, 0x25) // jmp [rip+entry]
		t = binary.LittleEndian.AppendUint32(t, uint32(int32(0-(len(t)+4))))
		w.tramp = t
		return at, true
	}
	// lea r11, [rip+disp32] to the resume address.
	t = append(t, 0x4c, 0x8d, 0x1d)
	t = binary.LittleEndian.AppendUint32(t, uint32(int32(after-(w.base+uint64(len(t))+4))))
	if w.spSlot != 0 {
		// Own-%gs anchor. Entry: mark the thread busy before saving the guest sp,
		// so a kick taken while the island owns the thread is latched (onKick
		// keeps it) rather than redirecting onto the half-built service frame and
		// overwriting the saved sp; clear kicked first so the acquire cannot erase
		// a kick. Then save the guest sp (%gs:spSlot) and switch rsp to the
		// per-thread service stack (%gs:scratchSlot), so nothing of the service
		// runs on the guest's own stack.
		t = append(t, 0x65, 0xc7, 0x04, 0x25) // movl $0, %gs:kickedSlot
		t = binary.LittleEndian.AppendUint32(t, w.kickedSlot)
		t = binary.LittleEndian.AppendUint32(t, 0)
		t = append(t, 0x65, 0xc7, 0x04, 0x25) // movl $1, %gs:busySlot
		t = binary.LittleEndian.AppendUint32(t, w.busySlot)
		t = binary.LittleEndian.AppendUint32(t, 1)
		t = append(t, 0x65, 0x48, 0x89, 0x24, 0x25) // mov %rsp, %gs:spSlot
		t = binary.LittleEndian.AppendUint32(t, w.spSlot)
		t = append(t, 0x65, 0x48, 0x8b, 0x24, 0x25) // mov %gs:scratchSlot, %rsp
		t = binary.LittleEndian.AppendUint32(t, w.scratchSlot)
		t = append(t, 0xff, 0x15) // call [rip+entry] (-> lc_syscall_entry_gs)
		t = binary.LittleEndian.AppendUint32(t, uint32(int32(0-(len(t)+4))))
		t = append(t, 0x65, 0x48, 0x8b, 0x24, 0x25) // mov %gs:spSlot, %rsp
		t = binary.LittleEndian.AppendUint32(t, w.spSlot)
		// Exit: the guest sp is restored and the registers are popped into the
		// CPU, so the service Frame on the scratch stack is dead. Only now clear
		// busy, then recheck kicked without disturbing the guest flags: mov and
		// jrcxz set none, and rcx is dead after a syscall. A kick latched during
		// the service (or this epilogue) jumps to lc_latekick (area header[8],
		// set by GsAnchor), which delivers it with the full guest context;
		// otherwise fall through to the jmp back to the guest.
		t = append(t, 0x65, 0xc7, 0x04, 0x25) // movl $0, %gs:busySlot
		t = binary.LittleEndian.AppendUint32(t, w.busySlot)
		t = binary.LittleEndian.AppendUint32(t, 0)
		t = append(t, 0x65, 0x8b, 0x0c, 0x25) // mov %gs:kickedSlot, %ecx
		t = binary.LittleEndian.AppendUint32(t, w.kickedSlot)
		t = append(t, 0xe3, 0x06) // jrcxz +6 (skip the jmp when no kick)
		t = append(t, 0xff, 0x25) // jmp [rip+header8] (-> lc_latekick)
		t = binary.LittleEndian.AppendUint32(t, uint32(int32(8-(len(t)+4))))
	} else {
		t = append(t, 0x48, 0x8d, 0xa4, 0x24, 0x80, 0xff, 0xff, 0xff) // lea rsp,[rsp-128]
		t = append(t, 0xff, 0x15)                                     // call [rip+entry]
		t = binary.LittleEndian.AppendUint32(t, uint32(int32(0-(len(t)+4))))
		t = append(t, 0x48, 0x8d, 0xa4, 0x24, 0x80, 0x00, 0x00, 0x00) // lea rsp,[rsp+128]
	}
	t = append(t, 0xe9)
	t = binary.LittleEndian.AppendUint32(t, uint32(int32(after-(w.base+uint64(len(t))+4))))
	w.tramp = t
	return at, true
}
