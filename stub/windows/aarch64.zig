// arm64 half of the Windows stub (see stub.zig and windows/DESIGN.md §14).
//
// x18 is the TEB register on Windows and an ordinary register to a Linux
// guest (GCC uses it as scratch), so the stub never trusts it on entry. Its
// anchor is tpidr_el0: Windows leaves that register to user code, and the
// stub keeps the TEB address in it for every thread. The guest's own
// tpidr_el0 (its thread pointer) moves to the TEB slot SLOT_TP; the rewriter
// turns every mrs/msr tpidr_el0 into an island that reads or writes that slot
// through tpidr_el0 (rewrite.A64Rewriter.Sysreg). With the anchor in place:
//
// - lc_syscall_entry saves the guest's x18 and loads the TEB from tpidr_el0
//   before any ntdll code runs, and puts the guest's back on the way out;
// - KiUserExceptionDispatcher reads the TEB through x18, so a fault with the
//   guest's x18 live would recurse; its first instruction is patched to a
//   thunk that stores the live x18 into CONTEXT.X18 (the kernel writes 0
//   there) and loads the TEB from tpidr_el0;
// - NtContinue always resumes with x18 = TEB, so the stub resumes the guest
//   through the return gate, then this thread's slot near the target:
//   `mrs x18, tpidr_el0; ldr x18, [x18, #SLOT_AUX]; b target`, the guest's
//   x18 parked in SLOT_AUX. Code that jumps to the guest itself uses the
//   same slot, branching to it through x18.
//
// Threads, fork, futexes and signal delivery are shared (thread.zig, sig.zig,
// futex.zig); this half gives them the registers and the stack moves.

const std = @import("std");
const ool = @import("ool.zig");
const win = std.os.windows;
const stub = @import("stub.zig");
const sig = @import("sig.zig");
const sigx = @import("sig_aarch64.zig");
const thread = @import("thread.zig");

const NTSTATUS = stub.NTSTATUS;
const HANDLE = stub.HANDLE;
const SELF = stub.SELF;

extern "ntdll" fn NtAllocateVirtualMemory(proc: HANDLE, base: *usize, zero_bits: usize, size: *usize, typ: u32, prot: u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtProtectVirtualMemory(proc: HANDLE, base: *usize, size: *usize, prot: u32, old: *u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtFlushInstructionCache(proc: HANDLE, base: usize, size: usize) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn KiUserExceptionDispatcher() callconv(.C) void;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

pub fn tebLoad(comptime off: u32) u64 {
    return asm volatile ("ldr %[v], [x18, #" ++ std.fmt.comptimePrint("{d}", .{off}) ++ "]"
        : [v] "=r" (-> u64),
    );
}

pub fn tebStore(comptime off: u32, v: u64) void {
    asm volatile ("str %[v], [x18, #" ++ std.fmt.comptimePrint("{d}", .{off}) ++ "]"
        :
        : [v] "r" (v),
        : "memory"
    );
}

fn encB(from: u64, to: u64) ?u32 {
    const d: i64 = @bitCast(to -% from);
    if (d < -(1 << 27) or d >= 1 << 27) return null;
    return 0x14000000 | (@as(u32, @truncate(@as(u64, @bitCast(d)) >> 2)) & 0x03ffffff);
}

fn allocNear(addr: u64, prot: u32) ?u64 {
    var k: u64 = 1;
    while (k < 2000) : (k += 1) {
        const down = (addr & ~@as(u64, 0xffff)) -% k * 0x10000;
        const up = (addr & ~@as(u64, 0xffff)) +% k * 0x10000;
        for ([2]u64{ down, up }) |a| {
            if (a < 0x10000 or a >= 1 << 47) continue;
            var b: usize = a;
            var s: usize = 0x1000;
            if (NtAllocateVirtualMemory(SELF, &b, 0, &s, MEM_COMMIT | MEM_RESERVE, prot) >= 0) return b;
        }
    }
    // Deep inside the guest's mappings (a JVM's 240 MiB code cache) the host
    // has nothing free in range: take a page of the areas they live in.
    return stub.mem.stubPage(addr, prot);
}

// imported returns the function an import thunk (adrp x16, IAT page; ldr
// x16, [x16, #off]; br x16) jumps to.
fn imported(thunk: u64) u64 {
    const w: [*]const u32 = @ptrFromInt(thunk);
    if (w[0] & 0x9f00001f != 0x90000010 or w[1] & 0xffc003ff != 0xf9400210 or w[2] != 0xd61f0200) return thunk;
    const imm: u64 = ((w[0] >> 29) & 3) | ((w[0] >> 5) & 0x7ffff) << 2;
    const page = (thunk & ~@as(u64, 0xfff)) +% (@as(u64, @bitCast(@as(i64, @bitCast(imm << 43)) >> 43)) << 12);
    return @as(*const u64, @ptrFromInt(page + ((w[1] >> 10) & 0xfff) * 8)).*;
}

pub fn init() void {
    threadInit();
    hookDispatcher();
    sig.install();
}

// threadInit anchors the TEB in tpidr_el0 (a new thread starts with 0 there).
pub fn threadInit() void {
    asm volatile ("msr tpidr_el0, x18" ::: "memory");
}

// start binds the main thread to its slot just before stub.zig enters the
// guest.
pub fn start(_: u64, idx: usize) void {
    sig.startThread(idx, @truncate(tebLoad(0x48)));
    sig.setThread(false, 0);
}

// readyAux adds the signal-delivery entry points, the main thread's OS id
// and the exit sites' entry to the MSG_READY reply.
pub fn readyAux(a: *[6]u64) void {
    a[2] = @intFromPtr(&lc_sig_redirect);
    a[3] = @intFromPtr(&thread.lc_sig_apc);
    a[4] = @truncate(tebLoad(0x48));
    a[5] = @intFromPtr(&lc_exit_entry);
}

// hookDispatcher patches KiUserExceptionDispatcher's first instruction with
// a branch to a thunk within ±128 MB of ntdll:
//   str x18, [sp, #0x98]   CONTEXT.X18 (the CONTEXT is at sp) = the live x18
//   mrs x18, tpidr_el0     the TEB
//   <the displaced instruction; a 64-bit ldr literal reads its copy below>
//   b   KiUserExceptionDispatcher+4
fn hookDispatcher() void {
    const kiued = imported(@intFromPtr(&KiUserExceptionDispatcher));
    const ins: *u32 = @ptrFromInt(kiued);
    var first = ins.*;
    var lit: u64 = 0;
    if (first & 0xff000000 == 0x58000000) {
        lit = @as(*const u64, @ptrFromInt(kiued + ((first >> 5) & 0x7ffff) * 4)).*;
        first = 0x58000000 | (2 << 5) | (first & 0x1f);
    } else if (first & 0x1f000000 == 0x10000000 or first & 0x7c000000 == 0x14000000 or
        first & 0x7e000000 == 0x34000000 or first & 0x7e000000 == 0x36000000 or
        first & 0xff000010 == 0x54000000 or first & 0x3b000000 == 0x18000000)
    {
        stub.die(0xE0000020); // PC-relative: cannot be moved as it is
    }
    const t = allocNear(kiued, PAGE_READWRITE) orelse stub.die(0xE0000021);
    const w: [*]u32 = @ptrFromInt(t);
    w[0] = 0xf9004ff2;
    w[1] = MRS_X18_TPIDR;
    w[2] = first;
    w[3] = encB(t + 12, kiued + 4) orelse stub.die(0xE0000021);
    @as(*u64, @ptrFromInt(t + 16)).* = lit;
    var b: usize = t;
    var s: usize = 0x1000;
    var old: u32 = 0;
    if (NtProtectVirtualMemory(SELF, &b, &s, PAGE_EXECUTE_READ, &old) < 0) stub.die(0xE0000022);
    _ = NtFlushInstructionCache(SELF, t, 32);
    const br = encB(kiued, t) orelse stub.die(0xE0000021);
    b = kiued;
    s = 4;
    if (NtProtectVirtualMemory(SELF, &b, &s, PAGE_EXECUTE_READWRITE, &old) < 0) stub.die(0xE0000023);
    @atomicStore(u32, ins, br, .seq_cst);
    b = kiued;
    s = 4;
    _ = NtProtectVirtualMemory(SELF, &b, &s, old, &old);
    _ = NtFlushInstructionCache(SELF, kiued, 4);
}

// ---- resume slots ----------------------------------------------------------
//
// One 16-byte slot per channel slot in each resume page; a page is allocated
// near the first target out of every existing page's reach.

const MRS_X18_TPIDR: u32 = 0xd53bd052;
const LDR_X18_AUX: u32 = 0xf9400000 | (stub.SLOT_AUX / 8) << 10 | 18 << 5 | 18;
const MAX_PAGES = 64;
var resume_pages: [MAX_PAGES]u64 = [_]u64{0} ** MAX_PAGES;
var resume_lock: u32 = 0;

fn resumePage(pc: u64, off: u64) u64 {
    for (&resume_pages) |*p| {
        const v = @atomicLoad(u64, p, .acquire);
        if (v == 0) break;
        if (encB(v + off + 8, pc) != null) return v;
    }
    while (@cmpxchgWeak(u32, &resume_lock, 0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    defer @atomicStore(u32, &resume_lock, 0, .release);
    for (&resume_pages) |*p| {
        const v = @atomicLoad(u64, p, .acquire);
        if (v != 0) {
            if (encB(v + off + 8, pc) != null) return v;
            continue;
        }
        const n = allocNear(pc, PAGE_EXECUTE_READWRITE) orelse break;
        @atomicStore(u64, p, n, .release);
        return n;
    }
    stub.die(0xE0000024);
}

// resumeSlot readies this thread's slot to enter the guest at pc with the
// guest's x18 = x18 and returns its address.
pub fn resumeSlot(pc: u64, x18: u64) u64 {
    const off = 16 * (stub.curSlot() & 0xff);
    const s: [*]u32 = @ptrFromInt(resumePage(pc, off) + off);
    tebStore(stub.SLOT_AUX, x18);
    s[0] = MRS_X18_TPIDR;
    s[1] = LDR_X18_AUX;
    s[2] = encB(@intFromPtr(s) + 8, pc) orelse stub.die(0xE0000025);
    _ = NtFlushInstructionCache(SELF, @intFromPtr(s), 12);
    return @intFromPtr(s);
}

// resumeGuest makes an exception return to c.Pc with the guest's x18.
fn resumeGuest(c: *win.CONTEXT) void {
    prepareGuestReturn(c);
}

// Kernel returns land here before any live guest registers are used.
comptime {
    std.debug.assert(stub.SLOT_CONT == 0x1658);
    std.debug.assert(@offsetOf(sig.Ctx, "sp") == 248);
    std.debug.assert(@offsetOf(sig.Ctx, "pstate") == 264);
    std.debug.assert(@offsetOf(sig.Ctx, "fpsr") == 288);
    std.debug.assert(@offsetOf(sig.Ctx, "fpcr") == 292);
    std.debug.assert(@offsetOf(sig.Ctx, "v") == 304);
    asm (
        \\.globl lc_guest_return
        \\lc_guest_return:
        \\  mrs x18, tpidr_el0
        \\  ldr x9, [x18, #0x1660]
        \\  mov sp, x9
        \\  bl lc_return_prepare
        \\.globl lc_return_commit
        \\lc_return_commit:
        \\  ldr x1, [x0]
        \\  ldr x2, [x0, #8]
        \\  add x5, x1, #72
        \\  stlr wzr, [x5]
        \\  dmb ish
        \\  add x3, x1, #16
        \\  ldar x3, [x3]
        \\  add x4, x2, #8
        \\  ldar x4, [x4]
        \\  orr x3, x3, x4
        \\  add x4, x1, #8
        \\  ldar x4, [x4]
        \\  bic x3, x3, x4
        \\  cbnz x3, lc_guest_return
        \\  ldr x18, [x0, #16]
        \\  add x0, x0, #32
        \\  ldr w9, [x0, #288]
        \\  msr fpsr, x9
        \\  ldr w9, [x0, #292]
        \\  msr fpcr, x9
        \\  ldp q0, q1, [x0, #304]
        \\  ldp q2, q3, [x0, #336]
        \\  ldp q4, q5, [x0, #368]
        \\  ldp q6, q7, [x0, #400]
        \\  ldp q8, q9, [x0, #432]
        \\  ldp q10, q11, [x0, #464]
        \\  ldp q12, q13, [x0, #496]
        \\  ldp q14, q15, [x0, #528]
        \\  ldp q16, q17, [x0, #560]
        \\  ldp q18, q19, [x0, #592]
        \\  ldp q20, q21, [x0, #624]
        \\  ldp q22, q23, [x0, #656]
        \\  ldp q24, q25, [x0, #688]
        \\  ldp q26, q27, [x0, #720]
        \\  ldp q28, q29, [x0, #752]
        \\  ldp q30, q31, [x0, #784]
        \\  ldr x9, [x0, #264]
        \\  msr nzcv, x9
        \\  ldr x9, [x0, #248]
        \\  mov sp, x9
        \\  ldp x2, x3, [x0, #16]
        \\  ldp x4, x5, [x0, #32]
        \\  ldp x6, x7, [x0, #48]
        \\  ldp x8, x9, [x0, #64]
        \\  ldp x10, x11, [x0, #80]
        \\  ldp x12, x13, [x0, #96]
        \\  ldp x14, x15, [x0, #112]
        \\  ldp x16, x17, [x0, #128]
        \\  ldr x19, [x0, #152]
        \\  ldp x20, x21, [x0, #160]
        \\  ldp x22, x23, [x0, #176]
        \\  ldp x24, x25, [x0, #192]
        \\  ldp x26, x27, [x0, #208]
        \\  ldp x28, x29, [x0, #224]
        \\  ldr x30, [x0, #240]
        \\  ldp x0, x1, [x0]
        \\  br x18
        \\.globl lc_return_end
        \\lc_return_end:
    );
}
pub extern fn lc_guest_return() callconv(win.WINAPI) noreturn;
pub extern fn lc_return_commit() callconv(.Naked) void;
pub extern fn lc_return_end() callconv(.Naked) void;

pub fn returnTarget(c: *const sig.Ctx) u64 {
    return resumeSlot(c.pc, c.x[18]);
}

pub fn prepareGuestReturn(c: *win.CONTEXT) void {
    const saved = sig.ctxFromWin(c);
    sig.stageReturn(&saved);
    c.Pc = @intFromPtr(&lc_guest_return);
}

// ---- syscalls --------------------------------------------------------------

// LC_ICACHE is what a JIT's instruction-cache flush the supervisor replaced
// (V8's FlushICache) calls: (start, len).
const LC_ICACHE: u64 = 0x4c430027;

// local serves the clocks, as a vDSO would, and LC_ICACHE.
pub fn local(nr: u64, a: [6]u64) ?u64 {
    return switch (nr) {
        113 => sig.clockGettime(a[0], a[1]),
        169 => sig.gettimeofday(a[0], a[1]),
        LC_ICACHE => {
            _ = NtFlushInstructionCache(SELF, a[0], a[1]);
            return 0;
        },
        else => null,
    };
}

pub const Frame = sig.Frame;
pub const args = sig.args;

// The syscall numbers thread.zig serves; arm64 has no fork or vfork.
pub const NR = struct {
    pub const read: u64 = 63;
    pub const write: u64 = 64;
    pub const writev: u64 = 66;
    pub const gettid: u64 = 178;
    pub const set_tid_address: u64 = 96;
    pub const set_robust_list: u64 = 99;
    pub const futex: u64 = 98;
    pub const membarrier: u64 = 283;
    pub const clone: u64 = 220;
    pub const fork: u64 = 0x1_0000_00f0;
    pub const vfork: u64 = 0x1_0000_00f1;
    pub const clone3: u64 = 435;
    pub const exit: u64 = 93;
    pub const nanosleep: u64 = 101;
    pub const clock_nanosleep: u64 = 115;
    pub const restart_syscall: u64 = 128;
};

export fn lc_tramp_syscall(f: *Frame) callconv(.C) void {
    sig.enter();
    // Publish the register frame before posting, so a tracer's stop and
    // GETREGS see the guest state (see the x86-64 half for why unconditional).
    sigx.publishFrame(f);
    var t = sig.Trap{ .frame = f, .gsp = f.gsp, .resume_at = f.resume_at, .site = f.resume_at - 4, .nr = f.x[8] };
    const r = thread.serve(&t);
    var x0 = sig.afterSyscall(&t, r);
    if (sigx.traceState().dirty != 0) x0 = sigx.traceRestore(f, &t);
    f.x[0] = x0;
    sig.returnTrap(&t);
}

// lc_syscall_entry is reached from a rewriter island (rewrite/a64tramp.go,
// OwnStack) with sp = guest sp - 160: the island's epilogue at [sp], the
// guest's x16/x17 at [sp+16] and the resume pc in x17. It moves to the
// thread's stub stack (SLOT_STK) at once, as nothing may be written further
// below the guest's sp (a Go goroutine stack is small and its neighbour's
// lies under it), and saves the whole register file there (Frame): Windows
// code may clobber x0-x17 and the FP/SIMD registers but d8-d15, where a
// Linux svc clobbers only x0. Then it swaps the TEB into x18. The return
// gate restores the saved guest state and bypasses the island's epilogue.
comptime {
    std.debug.assert(stub.SLOT_STK == 0x1660);
    asm (
        \\.globl lc_syscall_entry
        \\lc_syscall_entry:
        \\  str x17, [sp, #8]
        \\  mov x17, sp
        \\  mrs x16, tpidr_el0
        \\  ldr x16, [x16, #0x1660]
        \\  sub sp, x16, #800
        \\  stp x0, x1, [sp, #0]
        \\  stp x2, x3, [sp, #16]
        \\  stp x4, x5, [sp, #32]
        \\  stp x6, x7, [sp, #48]
        \\  stp x8, x9, [sp, #64]
        \\  stp x10, x11, [sp, #80]
        \\  stp x12, x13, [sp, #96]
        \\  stp x14, x15, [sp, #112]
        \\  ldp x0, x1, [x17, #16]
        \\  stp x0, x1, [sp, #128]
        \\  stp x18, x19, [sp, #144]
        \\  stp x20, x21, [sp, #160]
        \\  stp x22, x23, [sp, #176]
        \\  stp x24, x25, [sp, #192]
        \\  stp x26, x27, [sp, #208]
        \\  stp x28, x29, [sp, #224]
        \\  mrs x9, nzcv
        \\  stp x30, x9, [sp, #240]
        \\  ldr x0, [x17, #8]
        \\  add x1, x17, #160
        \\  stp x0, x1, [sp, #256]
        \\  stp q0, q1, [sp, #272]
        \\  stp q2, q3, [sp, #304]
        \\  stp q4, q5, [sp, #336]
        \\  stp q6, q7, [sp, #368]
        \\  stp q8, q9, [sp, #400]
        \\  stp q10, q11, [sp, #432]
        \\  stp q12, q13, [sp, #464]
        \\  stp q14, q15, [sp, #496]
        \\  stp q16, q17, [sp, #528]
        \\  stp q18, q19, [sp, #560]
        \\  stp q20, q21, [sp, #592]
        \\  stp q22, q23, [sp, #624]
        \\  stp q24, q25, [sp, #656]
        \\  stp q26, q27, [sp, #688]
        \\  stp q28, q29, [sp, #720]
        \\  stp q30, q31, [sp, #752]
        \\  mrs x9, fpcr
        \\  mrs x10, fpsr
        \\  str x9, [sp, #784]
        \\  str x10, [sp, #792]
        \\  mrs x18, tpidr_el0
        \\  mov x0, sp
        \\  bl lc_tramp_syscall
        \\  brk #0
    );
}

pub extern fn lc_syscall_entry() callconv(.Naked) void;

// lc_exit_entry is where an exit site's island jumps once it has switched to
// this thread's stub stack (SLOT_STK): the guest's stack may already be
// someone else's (Go frees a thread's stack before its exit syscall, musl's
// __unmapself unmaps it), so nothing may be written there, not even the
// exception frame a trap would push. x0 holds the exit code; x18 is the
// guest's.
//
// lc_sig_redirect is where the supervisor points a thread it stole the
// context of (a thread running guest code), on the thread's stub stack: x0
// holds the guest-view address of the saved CONTEXT in this thread's slot
// scratch. GetThreadContext does not report x18, which is still the guest's,
// so it goes into the saved CONTEXT first.
//
// lc_on_stub calls f(arg) (x1, x0) on this thread's stub stack and returns
// its result on the stack it came from.
comptime {
    asm (
        \\.globl lc_exit_entry
        \\lc_exit_entry:
        \\  mrs x18, tpidr_el0
        \\  mov x29, xzr
        \\  bl lc_exit_thread
        \\  brk #0
        \\.globl lc_sig_redirect
        \\lc_sig_redirect:
        \\  str x18, [x0, #0x98]
        \\  mrs x18, tpidr_el0
        \\  b lc_sig_redirect_c
        \\.globl lc_on_stub
        \\lc_on_stub:
        \\  stp x29, x30, [sp, #-16]!
        \\  mov x29, sp
        \\  ldr x9, [x18, #0x1660]
        \\  mov sp, x9
        \\  blr x1
        \\  mov sp, x29
        \\  ldp x29, x30, [sp], #16
        \\  ret
    );
}

pub extern fn lc_exit_entry() callconv(.Naked) void;
pub extern fn lc_sig_redirect() callconv(.Naked) void;
extern fn lc_on_stub(arg: *anyopaque, f: *const fn (*anyopaque) callconv(.C) i32) callconv(.C) i32;

export fn lc_exit_thread(code: u64) callconv(.C) noreturn {
    thread.exitThread(code);
}

export fn lc_sig_redirect_c(saved: *win.CONTEXT) callconv(.C) noreturn {
    sig.redirect(saved);
}

// onStubStack moves to this thread's stub stack and calls f(arg) there.
pub fn onStubStack(f: *const fn (*sig.Ctx) callconv(.C) noreturn, arg: *sig.Ctx) noreturn {
    _ = lc_on_stub(arg, @ptrCast(f));
    unreachable;
}

// prefaultStack commits 64 KiB of the current (Windows) stack below the
// stack pointer while the TEB still describes it, so the stub stack never
// meets a guard page once the TEB describes the guest's stack.
pub fn prefaultStack() void {
    var a = (curSp() & ~@as(u64, 0xfff)) - 0x1000;
    const end = curSp() - (64 << 10);
    while (a >= end) : (a -= 0x1000) _ = @as(*volatile const u8, @ptrFromInt(a)).*;
}

fn curSp() u64 {
    return asm volatile ("mov %[v], sp"
        : [v] "=r" (-> u64),
    );
}

// markStubStack records the current stack pointer as this thread's stub stack
// before it leaves for the guest: nothing below it is live once the thread
// runs guest code.
fn markStubStack() void {
    const top = (curSp() - 64) & ~@as(u64, 15);
    tebStore(stub.SLOT_STK, top);
    sig.setStubSp(top);
}

// resumeFrame enters the guest at pc on stack sp with f's registers and a
// zero x0: a clone child's return through the common gate.
pub fn resumeFrame(f: *const Frame, sp: u64, pc: u64) noreturn {
    const t = sig.Trap{ .frame = f, .gsp = sp, .resume_at = pc, .site = pc -% 4, .nr = f.x[8] };
    var c = sig.ctxFromTrap(&t);
    c.x[0] = 0;
    markStubStack();
    sig.returnCtx(&c);
}

// exitOnStubStack ends the calling thread (exit with other threads running,
// or a CLONE_VM child's end) from its stub stack, as an exit site's island
// does: the guest's stack may be someone else's.
pub fn exitOnStubStack(code: u64) noreturn {
    asm volatile (
        \\  ldr x1, [x18, #0x1660]
        \\  mov sp, x1
        \\  b lc_exit_entry
        :
        : [c] "{x0}" (code),
        : "memory"
    );
    unreachable;
}

// endThread is the supervisor's REP_THREAD_END: this thread (a CLONE_VM
// child process) ends while its stub lives on.
pub fn endThread(code: u64) noreturn {
    exitOnStubStack(code);
}

// ---- exceptions ------------------------------------------------------------

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x80000002;
const STATUS_BREAKPOINT: u32 = 0x80000003;
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;
const STATUS_IN_PAGE_ERROR: u32 = 0xC0000006;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC0000094;
const STATUS_STACK_OVERFLOW: u32 = 0xC00000FD;

const MRS_CTR: u32 = 0xd53b0020;
const MRS_MIDR: u32 = 0xd5380000;
const MRS_MPIDR: u32 = 0xd53800a0;
const MRS_REVIDR: u32 = 0xd53800c0;
const MRS_ISAR0: u32 = 0xd5380600;
const MRS_ISAR1: u32 = 0xd5380620;
const MRS_ISAR2: u32 = 0xd5380640;
const IC_IVAU: u32 = 0xd50b7520;
const DC_ZVA: u32 = 0xd50b7420;

// The guest's ID_AA64ISAR0/1/2, from the host features (the supervisor's
// isarFromHwcap), set once at boot (setIdregs). MPIDR_EL1 reads 0x80000000
// (bit 31 RES1, affinity 0) and REVIDR_EL1 0, as Linux's emulation gives a
// single uniprocessor view; the registers that also carry layout values are
// left to trap.
var isar0: u64 = 0;
var isar1: u64 = 0;
var isar2: u64 = 0;

pub fn setIdregs(a: u64, b: u64, c: u64) void {
    isar0 = a;
    isar1 = b;
    isar2 = c;
}

// idreg is the value an mrs of a feature ID register reads, or null if the
// stub does not serve that register (it keeps trapping).
fn idreg(ins: u32) ?u64 {
    return switch (ins & 0xffffffe0) {
        MRS_CTR => CTR_VALUE,
        MRS_MIDR => MIDR_VALUE,
        MRS_MPIDR => 0x80000000,
        MRS_REVIDR => 0,
        MRS_ISAR0 => isar0,
        MRS_ISAR1 => isar1,
        MRS_ISAR2 => isar2,
        else => null,
    };
}

// zeroBlock runs the dc zva at pc, which Windows traps at EL0 where Linux
// lets it run, as the guest's own stores of zeros over the block holding the
// address in xt (stur xzr, its offsets from xt), out of line: they fault, and
// a hot page cools, as any store does. The block is DCZID_EL0's.
fn zeroBlock(c: *win.CONTEXT, t: u5) bool {
    const bs: u64 = @as(u64, 4) << @truncate(asm volatile ("mrs %[o], dczid_el0"
        : [o] "=r" (-> u64),
    ) & 0xf);
    if (t == 31 or bs > 256 or bs / 8 > ool.MAX) return false;
    const k: i64 = @intCast(c.DUMMYUNIONNAME.X[t] & (bs - 1));
    var words: [ool.MAX]u32 = undefined;
    for (0..bs / 8) |j| {
        const imm: u32 = @truncate(@as(u64, @bitCast(@as(i64, @intCast(8 * j)) - k)) & 0x1ff);
        words[j] = 0xf800001f | imm << 12 | @as(u32, t) << 5; // stur xzr, [xt, #imm]
    }
    c.Pc = ool.runFor(stub.curSlot(), words[0 .. bs / 8], c.Pc) orelse return false;
    return true;
}

// isDataCacheClean matches dc cvac/cvau/cvap/cvadp/civac, which Windows traps
// at EL0 like ic ivau (the supervisor drops those it finds in an image).
fn isDataCacheClean(ins: u32) bool {
    return switch (ins & 0xffffffe0) {
        0xd50b7a20, 0xd50b7b20, 0xd50b7c20, 0xd50b7d20, 0xd50b7e20 => true,
        else => false,
    };
}
// The CTR_EL0 the guest sees (the supervisor's ctrEL0): IDC=DIC=0, 64-byte
// data-cache lines and 128 KiB instruction-cache ones, which an ic ivau
// flushes whole. MIDR_EL1: an Arm Neoverse N1.
const CTR_VALUE: u64 = 0x8444c00f;
const ILINE: u64 = 4 << (CTR_VALUE & 0xf);
const MIDR_VALUE: u64 = 0x413fd0c1;

// onException serves the udf the rewriter leaves at syscall sites without an
// island, emulates the mrs reads and the cache maintenance Windows traps
// (ic ivau as a flush of its line, dc cleans as nothing), and turns other
// guest faults
// into Linux signals (delivered to a handler, or ending the process when
// there is none). Anything in the stub itself is not ours. Exceptions are
// dispatched on the faulting (guest) stack, so the work moves to the stub
// stack: a signal frame built on the guest stack would overwrite the
// handler's own frames.
// readGuest and writeGuest copy n bytes from or to guest memory that may be
// bad, and report whether it all copied. They vouch for the range first
// (mem.copyGuest) rather than take a fault and resume: an exception raised on
// the stub's stack, outside the stack the TEB names, is a fast fail in the
// arm64 exception dispatcher.
pub fn readGuest(buf: u64, guest: u64, n: u64) bool {
    return stub.mem.copyGuest(guest, buf, n, false);
}

pub fn writeGuest(guest: u64, buf: u64, n: u64) bool {
    return stub.mem.copyGuest(guest, buf, n, true);
}

// guestLoad32 reads the aligned guest word at addr in one load (a futex
// word), or null when the range is not guest memory it may read.
pub fn guestLoad32(addr: u64) ?u32 {
    return stub.mem.load32(addr);
}

pub fn onException(ep: *win.EXCEPTION_POINTERS) callconv(win.WINAPI) i32 {
    const c = ep.ContextRecord;
    // The supervisor redirected the thread (a signal) while the kernel was
    // raising this exception: the context already enters lc_sig_redirect.
    // CONTEXT.X18 holds the guest's x18 (the dispatcher hook put it there),
    // which the redirect would otherwise take from the live x18, the TEB once
    // this resumes; hand it over and skip those two instructions.
    if (c.Pc == @intFromPtr(&lc_sig_redirect)) {
        const regs = &c.DUMMYUNIONNAME.X;
        @as(*win.CONTEXT, @ptrFromInt(regs[0])).DUMMYUNIONNAME.X[18] = regs[18];
        c.Pc += 8;
        return -1;
    }
    // Hold the thread for the handler: it talks to the supervisor (isTrap,
    // wxFault's hot/cool, exclTrap, sig.fault) and must not be context-stolen
    // mid-exchange. A signal that arrives meanwhile is taken on the way out: a
    // guest fault's resume goes through the return gate, which delivers it
    // (stageReturn clears the hold); the noreturn exits clear it themselves.
    // The handler runs in place on the guest stack, where the kernel dispatched
    // it: unlike x86-64, arm64 fast-fails any exception taken while sp is off
    // the TEB stack, and the W^X engine takes designed nested faults (touch),
    // so it cannot move to the stub stack. serveUdf and sig.fault still hop to
    // the stub stack per path, as before, so no signal frame lands on the
    // handler's own frames.
    const guest = !stub.ownCode(c.Pc) and sig.inGuest();
    sig.faultEnter();
    const r = faultHandle(ep);
    sig.faultLeave();
    const staged = c.Pc == @intFromPtr(&lc_guest_return);
    if (r == -1 and guest and !staged and !ool.inSlot(stub.curSlot(), c.Pc)) prepareGuestReturn(c);
    return r;
}

fn serveUdfOnStub(arg: *anyopaque) callconv(.C) i32 {
    return serveUdf(@as(*win.EXCEPTION_POINTERS, @ptrCast(@alignCast(arg))).ContextRecord);
}

fn faultOnStub(arg: *anyopaque) callconv(.C) i32 {
    return if (sig.fault(@ptrCast(@alignCast(arg)))) 1 else 0;
}

fn faultHandle(ep: *win.EXCEPTION_POINTERS) i32 {
    const c = ep.ContextRecord;
    const rec = ep.ExceptionRecord;
    const regs = &c.DUMMYUNIONNAME.X;
    const addr = if (rec.NumberParameters >= 2) rec.ExceptionInformation[1] else c.Pc;
    if (rec.ExceptionCode == STATUS_BREAKPOINT or rec.ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
        // The brk after instructions run out of line (ool.zig), which
        // Windows reports as either.
        if (ool.exit(stub.curSlot(), c.Pc)) |e| {
            c.Pc = e.target;
            for (e.holds) |h| stub.mem.letGo(h);
            return -1;
        }
    }
    if (rec.ExceptionCode == STATUS_ACCESS_VIOLATION and rec.NumberParameters >= 2) {
        const page = addr & ~@as(u64, 0xfff);
        var st: stub.mem.Step = .{ .from_slot = ool.inSlot(stub.curSlot(), c.Pc), .lost = ool.lost(stub.curSlot(), c.Pc, page) };
        switch (stub.mem.wxFault(addr, rec.ExceptionInformation[0], c.Pc, &st)) {
            .handled => return -1,
            .retry => {
                ool.tried(stub.curSlot(), c.Pc, page);
                return -1;
            },
            .step => {
                const words: [*]const u32 = @ptrCast(@alignCast(&st.code));
                if (ool.runA64(stub.curSlot(), words[0..st.n], st.start, st.hold)) |p| {
                    c.Pc = p;
                    return -1;
                }
                stub.mem.letGo(st.hold);
                if (st.again) return -1;
            },
            .attach => {
                if (!ool.addHold(stub.curSlot(), st.hold)) stub.mem.letGo(st.hold);
                return -1;
            },
            .hot, .cool, .wait => |v| {
                for (ool.dropHolds(stub.curSlot())) |h| stub.mem.letGo(h);
                stub.mem.settle(v, &st);
                return -1;
            },
            .fail => {
                if (st.rs != 31) regs[st.rs] = 1;
                c.Pc += 4;
                return -1;
            },
            .none => {},
        }
    }
    const signo: u64 = switch (rec.ExceptionCode) {
        STATUS_ILLEGAL_INSTRUCTION => {
            const ins = @as(*const u32, @ptrFromInt(c.Pc)).*;
            if (ins == stub.mem.XTRAP or ool.loadExclusive(ins)) {
                var st: stub.mem.Step = .{};
                switch (stub.mem.exclTrap(c.Pc, regs, c.Sp, &st)) {
                    .handled => return -1,
                    .step => {
                        const words: [*]const u32 = @ptrCast(@alignCast(&st.code));
                        if (ool.runA64(stub.curSlot(), words[0..st.n], st.start, st.hold)) |p| {
                            c.Pc = p;
                            return -1;
                        }
                        stub.mem.letGo(st.hold);
                        if (ool.runA64(stub.curSlot(), words[0..1], st.start, 0)) |p| {
                            c.Pc = p;
                            return -1;
                        }
                    },
                    else => {},
                }
            }
            // A udf #0 is a syscall only where the rewriter or the stub put
            // it: any other is the guest's. One whose page was stopped since
            // holds the svc again, and is served as the trap it was.
            if ((ins == 0 or ins == 0xd4000001) and stub.mem.isTrap(c.Pc)) return lc_on_stub(@ptrCast(ep), &serveUdfOnStub);
            const n = ins & 0x1f;
            if (idreg(ins)) |v| {
                if (n != 31) regs[n] = v;
            } else if (ins & 0xffffffe0 == IC_IVAU) {
                // The kernel cleans the data cache to the point of
                // unification and invalidates the line's instructions.
                const a = if (n == 31) 0 else regs[n];
                _ = NtFlushInstructionCache(SELF, a & ~(ILINE - 1), ILINE);
            } else if (ins & 0xffffffe0 == DC_ZVA) {
                if (n == 31) return faultOut(ep, stub.SIGSEGV, 0);
                if (zeroBlock(c, @truncate(n))) return -1;
                return faultOut(ep, stub.SIGILL, c.Pc);
            } else if (!isDataCacheClean(ins)) {
                return faultOut(ep, stub.SIGILL, c.Pc);
            }
            c.Pc += 4;
            resumeGuest(c);
            return -1;
        },
        STATUS_ACCESS_VIOLATION, STATUS_STACK_OVERFLOW => stub.SIGSEGV,
        STATUS_DATATYPE_MISALIGNMENT, STATUS_IN_PAGE_ERROR => stub.SIGBUS,
        STATUS_INTEGER_DIVIDE_BY_ZERO => stub.SIGFPE,
        STATUS_BREAKPOINT => stub.SIGTRAP,
        else => return 0,
    };
    return faultOut(ep, signo, addr);
}

// faultOut delivers a guest fault to a handler if one is installed (sig.fault,
// which refuses a stub-code or busy-thread fault itself), else falls back to
// the LC_FAULT path that ends the process as killed.
fn faultOut(ep: *win.EXCEPTION_POINTERS, signo: u64, addr: u64) i32 {
    if (sig.inGuest() and lc_on_stub(@ptrCast(ep), &faultOnStub) != 0) return -1;
    return if (stub.fault(signo, addr, ep.ContextRecord.Pc, sig.accessKind(ep.ExceptionRecord))) -1 else 0;
}

// serveUdf handles a syscall site that fell to the exception path: service
// it from the CONTEXT and deliver any pending signal on the way out.
fn serveUdf(c: *win.CONTEXT) i32 {
    sig.enter();
    var f = Frame{ .x = c.DUMMYUNIONNAME.X, .nzcv = c.Cpsr, .resume_at = c.Pc + 4, .gsp = c.Sp, .q = undefined, .fpcr = c.Fpcr, .fpsr = c.Fpsr };
    for (&f.q, c.V) |*d, s| d.* = @bitCast(s);
    sigx.publishFrame(&f);
    var t = sig.Trap{ .frame = &f, .gsp = c.Sp, .resume_at = c.Pc + 4, .site = c.Pc, .nr = f.x[8] };
    const r = thread.serve(&t);
    c.DUMMYUNIONNAME.X[0] = sig.afterSyscall(&t, r);
    c.Sp = t.gsp;
    c.Pc += 4;
    resumeGuest(c);
    return -1;
}

// trapsAt reports whether the syscall site at pc is the udf the rewriter
// leaves where no island reaches.
pub fn trapsAt(pc: u64) bool {
    return @as(*const u32, @ptrFromInt(pc)).* == 0;
}

// serveSite serves the syscall at such a site, which c resumes at, as
// serveUdf would, and moves c past it.
pub fn serveSite(c: *sig.Ctx) void {
    c.pc += 4;
    var f: Frame = undefined;
    var t = sigx.trapFromCtx(c, c.x[8], &f);
    c.x[0] = sig.afterSyscall(&t, thread.serve(&t));
    c.sp = t.gsp;
}

// enter starts guest code at entry on stack sp, as the kernel does at exec:
// x0 (the dynamic linker's fini pointer), x18, fp and lr are zero.
pub fn enter(entry: u64, sp: u64) noreturn {
    const c = sig.Ctx{ .sp = sp, .pc = entry };
    markStubStack();
    sig.returnCtx(&c);
}

// The compiler's memcpy, memmove and memset: there is no CRT.
comptime {
    asm (
        \\.globl memcpy
        \\memcpy:
        \\.globl memmove
        \\memmove:
        \\  mov x3, x0
        \\  cbz x2, 3f
        \\  cmp x0, x1
        \\  b.hi 2f
        \\1:
        \\  ldrb w4, [x1], #1
        \\  strb w4, [x3], #1
        \\  subs x2, x2, #1
        \\  b.ne 1b
        \\  ret
        \\2:
        \\  sub x2, x2, #1
        \\  ldrb w4, [x1, x2]
        \\  strb w4, [x0, x2]
        \\  cbnz x2, 2b
        \\3:
        \\  ret
        \\.globl memset
        \\memset:
        \\  mov x3, x0
        \\  cbz x2, 2f
        \\1:
        \\  strb w1, [x3], #1
        \\  subs x2, x2, #1
        \\  b.ne 1b
        \\2:
        \\  ret
    );
}
