package rewrite

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

func TestPatch(t *testing.T) {
	code := []byte{
		0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, 39
		0x0f, 0x05, // syscall
		0x48, 0xb8, 0x0f, 0x05, 0, 0, 0, 0, 0, 0, // mov rax, imm64 containing 0f 05
		0x90,       // nop: ends the run
		0x89, 0xf8, // mov eax, edi (too short to steal)
		0x0f, 0x05, // syscall
		0xc3, // ret
	}
	const vaddr, base = 0x401000, 0x300000
	w := New(base, 4096, 0x6f0000001234)
	w.Patch(code, vaddr)

	if len(w.Sites) != 2 || w.Sites[0] != vaddr+5 || w.Sites[1] != vaddr+20 {
		t.Fatalf("sites = %#x", w.Sites)
	}
	if w.Fast != 1 {
		t.Fatalf("fast = %d, want 1", w.Fast)
	}
	if !bytes.Equal(code[5:7], []byte{0x0f, 0x0b}) || !bytes.Equal(code[20:22], []byte{0x0f, 0x0b}) {
		t.Fatalf("syscalls not turned into ud2: % x", code)
	}
	if len(w.Stray) != 1 || w.Stray[0] != vaddr+9 {
		t.Fatalf("stray = %#x", w.Stray)
	}

	// The site jumps to the first trampoline...
	if code[0] != 0xe9 {
		t.Fatalf("site not patched to jmp: % x", code[:5])
	}
	target := vaddr + 5 + uint64(int32(binary.LittleEndian.Uint32(code[1:])))
	if target != base+headerSize {
		t.Fatalf("jmp target = %#x, want %#x", target, base+headerSize)
	}
	tr := w.Trampolines()
	if binary.LittleEndian.Uint64(tr) != 0x6f0000001234 {
		t.Fatal("entry pointer missing")
	}
	// ...which replays the stolen mov and jumps back past the syscall.
	body := tr[headerSize:]
	if !bytes.Equal(body[:5], []byte{0xb8, 0x27, 0, 0, 0}) {
		t.Fatalf("stolen instruction = % x", body[:5])
	}
	end := len(tr)
	back := base + uint64(end) + uint64(int32(binary.LittleEndian.Uint32(tr[end-4:])))
	if back != vaddr+7 {
		t.Fatalf("return target = %#x, want %#x", back, vaddr+7)
	}
	// call [rip+disp] must point at the entry pointer at base.
	// body: stolen(5) + lea r11(7) + lea rsp(8), then call. A Linux-native
	// rewriter (no SegmentSlot) leaves the resume address in r11, so there is
	// no %gs store between the lea r11 and the red-zone lea.
	callAt := headerSize + 5 + 7 + 8
	disp := int32(binary.LittleEndian.Uint32(tr[callAt+2:]))
	if int64(callAt+6)+int64(disp) != 0 {
		t.Fatalf("call disp points at %d, want 0", int64(callAt+6)+int64(disp))
	}
}

func TestPatchRun(t *testing.T) {
	code := []byte{
		0xb8, 0xe4, 0x00, 0x00, 0x00, // mov eax, 228
		0x48, 0x89, 0xde, // mov rsi, rbx
		0x0f, 0x05, // syscall
		0xc3, // ret
	}
	const vaddr, base = 0x401000, 0x300000
	w := New(base, 4096, 0x6f0000001234)
	w.Patch(code, vaddr)
	if w.Fast != 1 {
		t.Fatalf("fast = %d, want 1", w.Fast)
	}
	// Only the long instruction gives way to the jmp: a branch to the
	// mov rsi, rbx still runs it into the ud2.
	if code[0] != 0xe9 || !bytes.Equal(code[5:10], []byte{0x48, 0x89, 0xde, 0x0f, 0x0b}) {
		t.Fatalf("code = % x", code)
	}
	body := w.Trampolines()[headerSize:]
	if !bytes.Equal(body[:8], []byte{0xb8, 0xe4, 0, 0, 0, 0x48, 0x89, 0xde}) {
		t.Fatalf("stolen run = % x", body[:8])
	}
	tr := w.Trampolines()
	end := len(tr)
	if back := base + uint64(end) + uint64(int32(binary.LittleEndian.Uint32(tr[end-4:]))); back != vaddr+10 {
		t.Fatalf("return target = %#x, want %#x", back, vaddr+10)
	}

	// A run whose long instruction is cut off by one that cannot move
	// stays on the trap.
	code = []byte{
		0xb8, 0xe4, 0x00, 0x00, 0x00, // mov eax, 228
		0x48, 0x8d, 0x35, 0, 0, 0, 0, // lea rsi, [rip]
		0x48, 0x89, 0xde, // mov rsi, rbx
		0x0f, 0x05, // syscall
	}
	if p := Analyze(code); len(p.Sites) != 1 || p.Sites[0].Steal != 0 {
		t.Fatalf("plan = %+v", p)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	code := []byte{0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05, 0x89, 0xf8, 0x0f, 0x05, 0xc3}
	c := &Cache{Dir: t.TempDir()}
	want := Analyze(code)
	if got := c.Plan(code); len(got.Sites) != 2 {
		t.Fatalf("plan = %+v", got)
	}
	// A fresh cache must load the same plan from disk.
	got := (&Cache{Dir: c.Dir}).Plan(code)
	if len(got.Sites) != len(want.Sites) || got.Sites[0] != want.Sites[0] || got.Sites[1] != want.Sites[1] {
		t.Fatalf("disk plan = %+v, want %+v", got, want)
	}
}

func TestApplyIgnoresForeignPlan(t *testing.T) {
	code := []byte{0x90, 0x90, 0x90, 0xc3}
	w := New(0, 0, 0)
	w.Apply(Plan{Sites: []Site{{Off: 1}}}, code, 0x1000)
	if len(w.Sites) != 0 || !bytes.Equal(code, []byte{0x90, 0x90, 0x90, 0xc3}) {
		t.Fatalf("patched code that is not a syscall: % x", code)
	}
}

func TestAnalyzeEntriesSkipsDataBlob(t *testing.T) {
	// A function with a syscall, then a data blob (unreachable) full of
	// 0f 05 pairs. Descent from the entry must find the real syscall and
	// never touch the data, even swept: nothing writes eax on a way to them.
	code := []byte{
		0xb8, 0x27, 0x00, 0x00, 0x00, // 0: mov eax,39
		0x0f, 0x05, // 5: syscall
		0xc3,                               // 7: ret
		0x0f, 0x05, 0x0f, 0x05, 0x0f, 0x05, // 8: data (not reachable)
	}
	p := AnalyzeEntries(code, []int{0}, [][2]int{{0, len(code)}})
	if len(p.Sites) != 1 || p.Sites[0].Off != 5 {
		t.Fatalf("sites = %+v, want one at 5", p.Sites)
	}
}

// TestSweep: past the end of decoded code, after its padding, a function no
// entry names has its syscall found when eax was written on the way to it:
// straight on, or before a forward branch to it. Outside the swept range, or
// with nothing writing eax, it is left alone.
func TestSweep(t *testing.T) {
	code := []byte{
		0xc3,             // 0: ret (an entry)
		0xcc, 0xcc, 0xcc, // 1: padding
		0xb8, 0x27, 0x00, 0x00, 0x00, // 4: mov eax, 39
		0x0f, 0x05, // 9: syscall
		0x85, 0xc0, // 11: test eax, eax
		0x74, 0x03, // 13: je 18
		0xc3,       // 15: ret
		0x0f, 0x05, // 16: no eax on the way: data or not, left alone
		0x0f, 0x05, // 18: syscall, branched to after eax was written
		0xc3, // 20: ret
	}
	p := AnalyzeEntries(code, []int{0}, [][2]int{{0, len(code)}})
	var got []uint32
	for _, s := range p.Sites {
		got = append(got, s.Off)
	}
	slices.Sort(got)
	if !slices.Equal(got, []uint32{9, 18}) {
		t.Fatalf("swept sites = %v, want [9 18]", got)
	}
	if p := AnalyzeEntries(code, []int{0}, [][2]int{{0, 4}}); len(p.Sites) != 0 {
		t.Fatalf("outside the swept range: %+v", p.Sites)
	}
}

// TestMidway: code cut mid-instruction is swept from its first byte, so a
// syscall after an eax write is found, and so is one the code it decodes
// branches to; a bare 0f 05, or one a misaligned decode swallowed the eax
// write before, is not.
func TestMidway(t *testing.T) {
	code := []byte{
		0x24, 0x08, // 0: the tail of mov rax, [rsp+8], cut off
		0xb8, 0x27, 0x00, 0x00, 0x00, // 2: mov eax, 39
		0x0f, 0x05, // 7: syscall
		0xeb, 0x03, // 9: jmp 14
		0x0f, 0x05, // 11: data
		0xcc,                         // 13
		0xb8, 0x66, 0x00, 0x00, 0x00, // 14: mov eax, 102
		0x0f, 0x05, // 19: syscall
		0xc3, // 21: ret
	}
	var got []uint32
	for _, s := range AnalyzeMidway(code).Sites {
		got = append(got, s.Off)
	}
	slices.Sort(got)
	if !slices.Equal(got, []uint32{7, 19}) {
		t.Fatalf("sites = %v, want [7 19]", got)
	}
	for _, c := range [][]byte{
		{0x00, 0x0f, 0x05, 0xc3},
		{0x00, 0x00, 0x00, 0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3},
	} {
		if p := AnalyzeMidway(c); len(p.Sites) != 0 {
			t.Fatalf("% x: syscall taken: %+v", c, p.Sites)
		}
	}
}

func TestFuncStartsBadInput(t *testing.T) {
	if FuncStarts(nil, 0) != nil || FuncStarts([]byte{2, 0, 0, 0}, 0) != nil {
		t.Fatal("expected nil for unparseable eh_frame_hdr")
	}
}

// A thread's exit keeps the trap: no trampoline, which would write below
// a stack the thread may have given up.
func TestExitKeepsTrap(t *testing.T) {
	code := []byte{0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05, 0xc3}
	w := New(0x300000, 4096, 0x6f0000001234)
	w.Patch(code, 0x401000)
	if len(w.Sites) != 1 || w.Fast != 0 || !bytes.Equal(code, []byte{0xb8, 0x3c, 0, 0, 0, 0x0f, 0x0b, 0xc3}) {
		t.Fatalf("fast=%d code=% x", w.Fast, code)
	}
}

// With ExitStack, an exit site jumps to a trampoline that switches to the
// stub's stack before anything is written.
func TestExitStack(t *testing.T) {
	code := []byte{0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05, 0xc3}
	w := New(0x300000, 4096, 0x6f0000001234)
	w.SegmentSlot(0x1678)
	w.ExitStack(0x1660, 0x6f0000005678)
	w.Patch(code, 0x401000)
	if w.Fast != 1 || code[0] != 0xe9 || code[5] != 0x0f || code[6] != 0x0b {
		t.Fatalf("fast=%d code=% x", w.Fast, code)
	}
	tr := w.Trampolines()
	want := []byte{0xb8, 0x3c, 0, 0, 0, 0x65, 0x48, 0x8b, 0x24, 0x25, 0x60, 0x16, 0, 0, 0xff, 0x25}
	if binary.LittleEndian.Uint64(tr[8:]) != 0x6f0000005678 || !bytes.Equal(tr[16:16+len(want)], want) {
		t.Fatalf("trampolines % x", tr)
	}
	if d := int32(binary.LittleEndian.Uint32(tr[16+len(want):])); 16+len(want)+4+int(d) != 8 {
		t.Fatalf("entry disp %d", d)
	}
}

// On a segment-slot host the trampoline jumps to the entry with the resume
// address in rcx: nothing is pushed below the guest's stack pointer, where
// Linux writes nothing, and nothing per thread outlives a signal taken on the
// way in.
func TestSegmentSlotTrampolineJumps(t *testing.T) {
	code := []byte{0xb8, 0x27, 0, 0, 0, 0x0f, 0x05, 0xc3}
	w := New(0x300000, 4096, 0x6f0000001234)
	w.SegmentSlot(0x1678)
	w.Patch(code, 0x401000)
	if w.Fast != 1 || code[0] != 0xe9 {
		t.Fatalf("fast=%d code=% x", w.Fast, code)
	}
	body := w.Trampolines()[headerSize:]
	want := []byte{0xb8, 0x27, 0, 0, 0, 0x48, 0x8d, 0x0d, 0, 0, 0, 0, 0xff, 0x25}
	if len(body) != len(want)+4 || !bytes.Equal(body[:8], want[:8]) || !bytes.Equal(body[12:len(want)], want[12:]) {
		t.Fatalf("trampoline % x", body)
	}
	if d := int32(binary.LittleEndian.Uint32(body[len(want):])); headerSize+len(body)+int(d) != 0 {
		t.Fatalf("jmp disp %d does not reach the entry", d)
	}
	if after := 0x300000 + headerSize + 12 + uint64(int32(binary.LittleEndian.Uint32(body[8:]))); after != 0x401000+7 {
		t.Fatalf("resume address %#x", after)
	}
}

// On a segment-slot host, a site whose preceding instruction cannot move
// takes the compare after it into its trampoline.
func TestAfterTrampoline(t *testing.T) {
	code := []byte{0x4c, 0x89, 0xe0, 0x0f, 0x05, 0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff, 0xc3}
	w := New(0x300000, 4096, 0x6f0000001234)
	w.SegmentSlot(0x1678)
	w.Patch(code, 0x401000)
	if w.Fast != 1 || code[3] != 0xe9 || code[11] != 0xc3 || code[8] != 0xcc {
		t.Fatalf("fast=%d code=% x", w.Fast, code)
	}
	tr := w.Trampolines()[16:]
	r := 7 + int(int32(binary.LittleEndian.Uint32(tr[3:])))
	if !bytes.Equal(tr[r-2:r+6], []byte{0x0f, 0x0b, 0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff}) {
		t.Fatalf("trampoline % x (R at %d)", tr, r)
	}
	if back := 0x300000 + 16 + uint64(r+11) + uint64(int32(binary.LittleEndian.Uint32(tr[r+7:]))); back != 0x401000+11 {
		t.Fatalf("jumps back to %#x", back)
	}
	plain := []byte{0x4c, 0x89, 0xe0, 0x0f, 0x05, 0xc3}
	w = New(0x300000, 4096, 0x6f0000001234)
	w.Patch(plain, 0x401000)
	if w.Fast != 0 || plain[3] != 0x0f || plain[4] != 0x0b {
		t.Fatalf("linux host: code=% x", plain)
	}
}

// A syscall with no run to steal before it jumps through a cave, padding no
// path reaches within a two-byte jmp: glibc 2.41's single-threaded
// __syscall_cancel, whose mov of the number is a branch target and too short
// to hold a jmp.
func TestCaveTrampoline(t *testing.T) {
	code := []byte{
		0x75, 0x0b, // 0: jne 13
		0x31, 0xc0, // 2: xor eax, eax
		0xc3,                                  // 4: ret
		0x0f, 0x1f, 0x84, 0x00, 0, 0, 0, 0x00, // 5: nopl 0(%rax,%rax,1)
		0x48, 0x8b, 0x45, 0x10, // 13: mov rax, [rbp+16]
		0x0f, 0x05, // 17: syscall
		0x48, 0x89, 0xc2, // 19: mov rdx, rax
		0xc3, // 22: ret
	}
	p := AnalyzeEntries(code, []int{0}, nil)
	if len(p.Sites) != 1 || p.Sites[0].Steal != 0 || p.Sites[0].Cave != 5-17 {
		t.Fatalf("plan = %+v", p)
	}
	if got, ok := decodePlan(encodePlan(p)); !ok || len(got.Sites) != 1 || got.Sites[0] != p.Sites[0] {
		t.Fatalf("plan round trip = %+v", got)
	}
	orig := bytes.Clone(code)
	plain := New(0x300000, 4096, 0x6f0000001234)
	plain.Apply(p, code, 0x401000)
	if plain.Fast != 0 || code[17] != 0x0f || code[18] != 0x0b {
		t.Fatalf("without a per-thread stack: fast=%d code=% x", plain.Fast, code)
	}

	code = orig
	const vaddr, base = 0x401000, 0x300000
	w := New(base, 4096, 0x6f0000001234)
	w.GsAnchor(0x88, 0xc0, 0x80, 0xb4, 0x6f0000005678)
	w.Apply(p, code, vaddr)
	if w.Fast != 1 || code[17] != 0xeb || 19+int(int8(code[18])) != 5 || code[5] != 0xe9 {
		t.Fatalf("fast=%d code=% x", w.Fast, code)
	}
	if !bytes.Equal(code[:5], orig[:5]) || !bytes.Equal(code[10:17], orig[10:17]) || !bytes.Equal(code[19:], orig[19:]) {
		t.Fatalf("bytes other than the syscall and the cave changed: % x", code)
	}
	if to := vaddr + 10 + uint64(int32(binary.LittleEndian.Uint32(code[6:]))); to != base+headerSize {
		t.Fatalf("the cave jumps to %#x, want %#x", to, base+headerSize)
	}
	tr := w.Trampolines()
	if back := base + uint64(len(tr)) + uint64(int32(binary.LittleEndian.Uint32(tr[len(tr)-4:]))); back != vaddr+19 {
		t.Fatalf("the trampoline returns to %#x, want %#x", back, vaddr+19)
	}
}
