package rewrite

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestPatchFS(t *testing.T) {
	code := []byte{
		0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, // mov rax, fs:0
		0x64, 0x48, 0x2b, 0x14, 0x25, 0x28, 0x00, 0x00, 0x00, // sub rdx, fs:0x28
		0x64, 0x8b, 0x04, 0x25, 0xfc, 0xff, 0xff, 0xff, // mov eax, fs:-4
		0x64, 0x8b, 0x03, // mov eax, fs:[rbx] (too short)
		0x64, 0x48, 0x89, 0x44, 0x8b, 0x10, // mov fs:[rbx+rcx*4+0x10], rax
		0xc3,
	}
	const vaddr, base = 0x401000, 0x300000
	w := New(base, 4096, 0)
	w.SegmentSlot(0x1678)
	sites := AnalyzeFS(code)
	if len(sites) != 5 {
		t.Fatalf("sites = %v", sites)
	}
	left := w.PatchFS(code, vaddr, sites)
	if w.FS != 4 || len(left) != 1 || left[0] != vaddr+26 {
		t.Fatalf("fs = %d left = %#x", w.FS, left)
	}
	tr := w.Trampolines()
	want := [][]string{
		{"mov rax, qword ptr gs:[0x1678]", "mov rax, qword ptr [rax]"},
		{"lea rsp, ptr [rsp-0x80]", "push r11", "mov r11, qword ptr gs:[0x1678]", "sub rdx, qword ptr [r11+0x28]", "pop r11", "lea rsp, ptr [rsp+0x80]"},
		{"mov rax, qword ptr gs:[0x1678]", "mov eax, dword ptr [rax-0x4]"},
		{"lea rsp, ptr [rsp-0x80]", "push r11", "mov r11, qword ptr gs:[0x1678]", "lea r11, ptr [r11+rbx]", "mov qword ptr [r11+4*rcx+0x10], rax", "pop r11", "lea rsp, ptr [rsp+0x80]"},
	}
	ends := []int{0, 9, 18, 29}
	for i, off := range ends {
		if code[off] != 0xe9 {
			t.Fatalf("site %d not patched: % x", i, code[off:off+5])
		}
		at := vaddr + uint64(off) + 5 + uint64(int32(binary.LittleEndian.Uint32(code[off+1:])))
		p := int(at - base)
		for _, w := range want[i] {
			in, err := x86asm.Decode(tr[p:], 64)
			if got := x86asm.IntelSyntax(in, 0, nil); err != nil || got != w {
				t.Fatalf("site %d: got %q want %q", i, got, w)
			}
			p += in.Len
		}
		if in, _ := x86asm.Decode(tr[p:], 64); in.Op != x86asm.JMP {
			t.Fatalf("site %d: no jmp back", i)
		}
	}
}

// TestPatchFSRun: an %fs instruction too short for the jmp moves into its
// island with the run before it, as Go's thread-local loads do (mov r14, -8;
// mov r14, fs:[r14]); only the run's first instruction is overwritten, so a
// branch to the %fs instruction runs it as it was.
func TestPatchFSRun(t *testing.T) {
	code := []byte{
		0x49, 0xc7, 0xc6, 0xf8, 0xff, 0xff, 0xff, // mov r14, -8
		0x64, 0x4d, 0x8b, 0x36, // mov r14, fs:[r14]
		0xc3,
	}
	for _, sites := range [][]FSSite{AnalyzeFS(code), AnalyzeEntriesFS(code, []int{0}, nil).FS} {
		c := bytes.Clone(code)
		if len(sites) != 1 || sites[0] != (FSSite{7, 4, 7, 0}) {
			t.Fatalf("sites = %v", sites)
		}
		const vaddr, base = 0x401000, 0x300000
		w := New(base, 4096, 0)
		w.SegmentSlot(0x1678)
		if left := w.PatchFS(c, vaddr, sites); w.FS != 1 || len(left) != 0 {
			t.Fatalf("fs = %d left = %#x", w.FS, left)
		}
		if c[0] != 0xe9 || !bytes.Equal(c[5:], []byte{0xcc, 0xcc, 0x64, 0x4d, 0x8b, 0x36, 0xc3}) {
			t.Fatalf("patched code % x", c)
		}
		tr := w.Trampolines()
		p := int(vaddr + 5 + uint64(int32(binary.LittleEndian.Uint32(c[1:]))) - base)
		for _, want := range []string{"mov r14, -0x8", "lea rsp, ptr [rsp-0x80]", "push r11", "mov r11, qword ptr gs:[0x1678]", "lea r11, ptr [r11+r14]", "mov r14, qword ptr [r11]", "pop r11", "lea rsp, ptr [rsp+0x80]"} {
			in, err := x86asm.Decode(tr[p:], 64)
			if got := x86asm.IntelSyntax(in, 0, nil); err != nil || got != want {
				t.Fatalf("got %q want %q", got, want)
			}
			p += in.Len
		}
		in, _ := x86asm.Decode(tr[p:], 64)
		if back := base + uint64(p) + 5 + uint64(int32(binary.LittleEndian.Uint32(tr[p+1:]))); in.Op != x86asm.JMP || back != vaddr+11 {
			t.Fatalf("jmp back to %#x", back)
		}
	}
}

// TestPatchFSCave: an %fs instruction too short for the jmp, right after a
// call (Go's systemstack: a return lands on it), reaches its island through
// the padding after the function; only its own bytes change.
func TestPatchFSCave(t *testing.T) {
	code := []byte{
		0xe8, 0x10, 0x00, 0x00, 0x00, // call 21
		0x64, 0x48, 0x89, 0x11, // mov fs:[rcx], rdx
		0x49, 0x89, 0xd6, // mov r14, rdx
		0xc3,                                           // ret
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
		0xc3, // 21: ret
	}
	p := AnalyzeEntriesFS(code, []int{0}, nil)
	if len(p.FS) != 1 || p.FS[0] != (FSSite{5, 4, 0, 8}) {
		t.Fatalf("fs = %v", p.FS)
	}
	got, ok := decodePlan(encodePlan(p))
	if !ok || !slices.Equal(got.FS, p.FS) {
		t.Fatalf("round trip gave %v", got.FS)
	}
	const vaddr, base = 0x401000, 0x300000
	w := New(base, 4096, 0)
	w.SegmentSlot(0x1678)
	if left := w.PatchFS(code, vaddr, p.FS); w.FS != 1 || len(left) != 0 {
		t.Fatalf("fs = %d left = %#x", w.FS, left)
	}
	if !bytes.Equal(code[5:13], []byte{0xeb, 0x06, 0xcc, 0xcc, 0x49, 0x89, 0xd6, 0xc3}) || code[13] != 0xe9 {
		t.Fatalf("patched code % x", code)
	}
	tr := w.Trampolines()
	at := int(vaddr + 18 + uint64(int32(binary.LittleEndian.Uint32(code[14:]))) - base)
	for _, want := range []string{"lea rsp, ptr [rsp-0x80]", "push r11", "mov r11, qword ptr gs:[0x1678]", "lea r11, ptr [r11+rcx]", "mov qword ptr [r11], rdx", "pop r11", "lea rsp, ptr [rsp+0x80]"} {
		in, err := x86asm.Decode(tr[at:], 64)
		if got := x86asm.IntelSyntax(in, 0, nil); err != nil || got != want {
			t.Fatalf("got %q want %q", got, want)
		}
		at += in.Len
	}
	if back := base + uint64(at) + 5 + uint64(int32(binary.LittleEndian.Uint32(tr[at+1:]))); tr[at] != 0xe9 || back != vaddr+9 {
		t.Fatalf("jmp back to %#x", back)
	}
}

// TestFSGoBinary: in a real Go PIE, as the Windows image rewrite plans it
// (descent from its function entries), every %fs site gets an island but
// rt0_go's TLS setup, which runs once on the main thread's stack: a site left
// faults, and Windows raises the fault on the thread's own stack, under a
// goroutine's 2 KiB of it.
func TestFSGoBinary(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "gothreads")
	cmd := exec.Command("go", "build", "-buildmode=pie", "-o", exe, filepath.Join("..", "..", "testdata", "gothreads.go"))
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	f, err := elf.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	eh, sym := ELFEntries(f)
	sym = append(sym, f.Entry)
	text := ExecRanges(f)
	rt0 := map[uint64]bool{}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == "runtime.rt0_go.abi0" || s.Name == "runtime.rt0_go" {
				for a := s.Value; a < s.Value+s.Size; a++ {
					rt0[a] = true
				}
			}
		}
	}
	islands := 0
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		code := make([]byte, p.Filesz)
		if _, err := p.ReadAt(code, 0); err != nil {
			t.Fatal(err)
		}
		var ents []int
		for _, e := range append(eh, sym...) {
			if e >= p.Vaddr && e < p.Vaddr+p.Filesz {
				ents = append(ents, int(e-p.Vaddr))
			}
		}
		plan := AnalyzeEntriesFS(code, ents, SegmentRanges(text, p.Vaddr, p.Filesz))
		w := New(0x100000, plan.TrampBytes(), 0)
		w.SegmentSlot(0x1678)
		for _, a := range w.PatchFS(code, p.Vaddr, plan.FS) {
			if !rt0[a] {
				t.Errorf("%%fs site at %#x left to the fault handler", a)
			}
		}
		islands += w.FS
	}
	if islands < 100 {
		t.Fatalf("%d %%fs islands: the Go runtime has hundreds of thread-local loads", islands)
	}
}

// TestDescentFS: descent finds the %fs instructions reachable from the
// entries and skips one in data that a linear sweep would take.
func TestDescentFS(t *testing.T) {
	code := []byte{
		0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, // mov rax, fs:0
		0xeb, 0x09, // jmp +9, over the data
		0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // data that decodes as mov rax, fs:0x28
		0x64, 0x8b, 0x03, // mov eax, fs:[rbx]
		0xc3,
	}
	p := AnalyzeEntriesFS(code, []int{0}, nil)
	if len(p.FS) != 2 || p.FS[0] != (FSSite{0, 9, 0, 0}) || p.FS[1] != (FSSite{20, 3, 0, 0}) {
		t.Fatalf("descent fs = %v", p.FS)
	}
	if n := len(AnalyzeFS(code)); n != 3 {
		t.Fatalf("linear fs = %d", n)
	}
}

func TestPlanEncodingFS(t *testing.T) {
	for _, p := range []Plan{
		{Sites: []Site{{1, 5, 0}, {9, 0, -7}}},
		{Sites: []Site{{1, 5, 0}, {130, 0, 120}}, FS: []FSSite{{3, 9, 0, 0}, {40, 4, 7, 0}, {60, 4, 0, -30}}},
		{FS: []FSSite{{3, 9, 0, 0}}},
	} {
		got, ok := decodePlan(encodePlan(p))
		if !ok || !slices.Equal(got.Sites, p.Sites) || !slices.Equal(got.FS, p.FS) {
			t.Fatalf("round trip of %v gave %v %v", p, got, ok)
		}
	}
}

func TestFSIsland(t *testing.T) {
	code := []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0} // mov rax, fs:0x28
	const vaddr, island = 0x400000, 0x401000
	patch, isl, ok := FSIsland(code, vaddr, island, 0x80)
	if !ok || len(patch) != len(code) || patch[0] != 0xe9 {
		t.Fatalf("patch %x ok %v", patch, ok)
	}
	n := len(isl)
	if to := vaddr + 5 + uint64(int32(binary.LittleEndian.Uint32(patch[1:]))); to < island || to >= island+uint64(n) {
		t.Fatalf("jmp to %#x, not into the island at %#x", to, island)
	}
	if n < 5 || isl[n-5] != 0xe9 {
		t.Fatalf("island %x does not end in a jmp", isl)
	}
	if back := island + uint64(n) + uint64(int32(binary.LittleEndian.Uint32(isl[n-4:]))); back != vaddr+uint64(len(code)) {
		t.Fatalf("island jumps back to %#x, want %#x", back, vaddr+len(code))
	}
	if _, _, ok := FSIsland([]byte{0x64, 0x48, 0x8b, 0x00}, vaddr, island, 0x80); ok {
		t.Fatal("a 4-byte instruction took an island")
	}
}
