// instrcb.zig — the Windows syscall backstop (x86-64): the seccomp analog.
//
// The guest shares the stub's address space. The rewriter turns its syscall
// sites into trampolines or ud2 traps, but it cannot be provably complete (a
// `0f 05` that falls inside an immediate or a jump table). A stray `syscall`
// the rewriter missed goes straight to the NT dispatcher with no VEH-catchable
// trap (windows/probes/p4). The instrumentation callback is the one mechanism
// that sees it: the kernel enters lc_instr_thunk on every return to user mode
// with r10 = the address the syscall returns to and rax = its result.
//
// The stub emits no raw `syscall` and reaches the kernel only through ntdll, so
// a syscall returning into ntdll is the stub's own and a return anywhere else
// is a guest stray -> die(BACKSTOP_KILL), which sandbox/run_windows.go maps to
// ErrKilled. This is the Linux seccomp text-range check (stub/zig/seccomp.zig)
// expressed as a module range. Unlike seccomp it is revocable, so it is a
// backstop over the LPAC AppContainer, not a sole boundary; the hypervisor
// (WHP) backend is the airtight form. arm64 has a different callback-entry ABI
// (its own probe and thunk); until then arm64 keeps strict rewriting.

const std = @import("std");
const win = std.os.windows;
const stub = @import("stub.zig");

const ProcessInstrumentationCallback: u32 = 40;

// Stub exit status for a stray syscall; run_windows.go maps it to ErrKilled.
pub const BACKSTOP_KILL: u32 = 0x5CA11ED0;

extern "ntdll" fn NtSetInformationProcess(h: stub.HANDLE, class: u32, info: *const anyopaque, len: u32) callconv(win.WINAPI) stub.NTSTATUS;

// ntdll's mapped range: lo and span (= SizeOfImage). The only module a
// legitimate syscall returns into. Read by the thunk, RIP-relative.
export var lc_ntdll_lo: u64 = 0;
export var lc_ntdll_span: u64 = 0;

// The callback. On entry r10 = return address and rax = the syscall result;
// r11 is syscall-dead, so it is free scratch. We touch only r11 and the flags
// (saved and restored around the compare), leave rax intact, and jmp r10 on the
// common ntdll path so the stub's own syscall return is undisturbed.
comptime {
    asm (
        \\.globl lc_instr_thunk
        \\lc_instr_thunk:
        \\  pushfq
        \\  mov %r10, %r11
        \\  sub lc_ntdll_lo(%rip), %r11
        \\  cmp lc_ntdll_span(%rip), %r11
        \\  jae .Linstr_stray
        \\  popfq
        \\  jmp *%r10
        \\.Linstr_stray:
        \\  popfq
        \\  jmp lc_instr_stray
    );
}
pub extern fn lc_instr_thunk() callconv(.Naked) void;

// inNtdll reports whether pc is in ntdll, once the backstop is installed.
pub fn inNtdll(pc: u64) bool {
    return pc -% lc_ntdll_lo < lc_ntdll_span;
}

// lc_instr_stray runs when a syscall returned outside ntdll: the guest ran a
// raw syscall the rewriter missed. It does not return.
export fn lc_instr_stray() callconv(.C) noreturn {
    stub.die(BACKSTOP_KILL);
}

const Info = extern struct {
    version: u32 = 0,
    reserved: u32 = 0,
    callback: ?*const anyopaque,
};

// install resolves ntdll's range from the PEB loader list (ntdll-only: the stub
// has no kernel32 GetModuleHandle) and registers the callback process-wide. Call
// once on the first thread, just before the guest runs.
pub fn install() void {
    const ldr = @as(*const usize, @ptrFromInt(stub.peb() + 0x18)).*; // PEB.Ldr
    const exe = @as(*const usize, @ptrFromInt(ldr + 0x10)).*; // InLoadOrderModuleList -> exe entry
    const nt = @as(*const usize, @ptrFromInt(exe)).*; // exe.InLoadOrderLinks.Flink -> ntdll entry
    const base = @as(*const usize, @ptrFromInt(nt + 0x30)).*; // LDR_DATA_TABLE_ENTRY.DllBase
    const size = @as(*const u32, @ptrFromInt(nt + 0x40)).*; // .SizeOfImage
    if (@as(*const u16, @ptrFromInt(base)).* != 0x5A4D) stub.die(0xE0000010); // 'MZ'
    lc_ntdll_lo = base;
    lc_ntdll_span = size;
    const info = Info{ .callback = &lc_instr_thunk };
    if (NtSetInformationProcess(stub.SELF, ProcessInstrumentationCallback, &info, @sizeOf(Info)) != 0)
        stub.die(0xE0000011);
}
