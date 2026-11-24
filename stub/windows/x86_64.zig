// x86-64 half of the Windows stub (see stub.zig): the TEB is %gs, guest
// syscalls are `syscall` sites turned into trampolines or ud2, and the Linux
// thread pointer (the FS base) lives in SLOT_TP, read by the rewriter's %fs
// islands; the real FS base is 0 and Windows resets it on every reschedule.
//
// Threads, fork, futexes and signal delivery are shared (thread.zig, sig.zig,
// futex.zig); this half gives them the registers and the stack moves. Every
// syscall return runs through sig.afterSyscall, which delivers pending signals (building the Linux
// rt_sigframe and resuming via NtContinue) or restarts the call.

const std = @import("std");
const ool = @import("ool.zig");
const win = std.os.windows;
const stub = @import("stub.zig");
const sig = @import("sig.zig");
const sigx = @import("sig_x86_64.zig");
const thread = @import("thread.zig");
const instrcb = @import("instrcb.zig");

extern "ntdll" fn RtlCaptureContext(ctx: *win.CONTEXT) callconv(win.WINAPI) void;

const SLOT_TP = stub.SLOT_TP;
const SLOT_CHAN = stub.SLOT_CHAN;

// SLOT_CONT points to sig.Return. IRETQ restores PC, SP and flags together:
// TF must not single-step a partially restored gate.
// All registers below are disposable until restored from the saved Ctx.
comptime {
    std.debug.assert(stub.SLOT_CONT == 0x1658);
    std.debug.assert(@offsetOf(sig.Ctx, "fx") == 160);
    asm (
        \\.globl lc_guest_return
        \\lc_guest_return:
        \\  mov %gs:0x1660, %rsp
        \\  cld
        \\  sub $32, %rsp
        \\  call lc_return_prepare
        \\  add $32, %rsp
        \\.globl lc_return_commit
        \\lc_return_commit:
        \\  mov 0(%rax), %rcx
        \\  mov 8(%rax), %rdx
        \\  movl $0, 72(%rcx)
        \\  mfence
        \\  mov 16(%rcx), %r8
        \\  or 8(%rdx), %r8
        \\  mov 8(%rcx), %r9
        \\  not %r9
        \\  test %r9, %r8
        \\  jnz lc_guest_return
        \\  lea 32(%rax), %rax
        \\  fxrstor64 160(%rax)
        \\  xor %edx, %edx
        \\  mov %ss, %dx
        \\  push %rdx
        \\  pushq 120(%rax)
        \\  pushq 136(%rax)
        \\  mov %cs, %dx
        \\  push %rdx
        \\  pushq 128(%rax)
        \\  mov 0(%rax), %r8
        \\  mov 8(%rax), %r9
        \\  mov 16(%rax), %r10
        \\  mov 24(%rax), %r11
        \\  mov 32(%rax), %r12
        \\  mov 40(%rax), %r13
        \\  mov 48(%rax), %r14
        \\  mov 56(%rax), %r15
        \\  mov 64(%rax), %rdi
        \\  mov 72(%rax), %rsi
        \\  mov 80(%rax), %rbp
        \\  mov 88(%rax), %rbx
        \\  mov 96(%rax), %rdx
        \\  mov 112(%rax), %rcx
        \\  mov 104(%rax), %rax
        \\  iretq
        \\.globl lc_return_end
        \\lc_return_end:
    );
}
pub extern fn lc_guest_return() callconv(win.WINAPI) noreturn;
pub extern fn lc_return_commit() callconv(.Naked) void;
pub extern fn lc_return_end() callconv(.Naked) void;

pub fn returnTarget(c: *const sig.Ctx) u64 {
    return c.rip;
}

pub fn prepareGuestReturn(c: *win.CONTEXT) void {
    const saved = sig.ctxFromWin(c);
    sig.stageReturn(&saved);
    c.Rip = @intFromPtr(&lc_guest_return);
    c.EFlags &= ~@as(u32, 0x100); // restore TF only at the final IRETQ
}

pub fn tebLoad(comptime off: u32) u64 {
    return asm volatile ("mov %%gs:" ++ std.fmt.comptimePrint("{d}", .{off}) ++ ", %[v]"
        : [v] "=r" (-> u64),
    );
}

pub fn tebStore(comptime off: u32, v: u64) void {
    asm volatile ("mov %[v], %%gs:" ++ std.fmt.comptimePrint("{d}", .{off})
        :
        : [v] "r" (v),
        : "memory"
    );
}

pub fn init() void {
    sigx.initXstate();
    sig.install();
}

// start binds the main thread to its slot just before stub.zig enters the
// guest.
pub fn start(_: u64, idx: usize) void {
    sig.startThread(idx, @truncate(tebLoad(0x48)));
    sig.setThread(false, 0);
}

// readyAux adds the signal-delivery entry points and the main thread's OS id to
// the MSG_READY reply, so the supervisor can reach this thread.
pub fn readyAux(a: *[6]u64) void {
    a[2] = @intFromPtr(&lc_sig_redirect);
    a[3] = @intFromPtr(&thread.lc_sig_apc);
    a[4] = @truncate(tebLoad(0x48));
    a[5] = @intFromPtr(&lc_exit_entry);
}

const EINVAL: u64 = @bitCast(@as(i64, -22));
const EFAULT: u64 = @bitCast(@as(i64, -14));

// local serves arch_prctl, which is per thread: the slot is the thread's.
pub fn local(nr: u64, a: [6]u64) ?u64 {
    switch (nr) {
        158 => switch (a[0]) {
            0x1002 => {
                tebStore(SLOT_TP, a[1]);
                return 0;
            },
            0x1003 => return if (sig.put(u64, a[1], tebLoad(SLOT_TP))) 0 else EFAULT,
            else => return EINVAL,
        },
        NR_CLOCK_GETTIME => return sig.clockGettime(a[0], a[1]),
        NR_GETTIMEOFDAY => return sig.gettimeofday(a[0], a[1]),
        NR_TIME => return sig.timeNow(a[0]),
        else => return null,
    }
}

const NR_CLOCK_GETTIME: u64 = 228;
const NR_GETTIMEOFDAY: u64 = 96;
const NR_TIME: u64 = 201;

pub const Frame = sig.Frame;
pub const args = sig.args;

// The syscall numbers thread.zig serves.
pub const NR = struct {
    pub const read: u64 = 0;
    pub const write: u64 = 1;
    pub const writev: u64 = 20;
    pub const gettid: u64 = 186;
    pub const set_tid_address: u64 = 218;
    pub const set_robust_list: u64 = 273;
    pub const futex: u64 = 202;
    pub const membarrier: u64 = 324;
    pub const clone: u64 = 56;
    pub const fork: u64 = 57;
    pub const vfork: u64 = 58;
    pub const clone3: u64 = 435;
    pub const exit: u64 = 60;
    pub const nanosleep: u64 = 35;
    pub const clock_nanosleep: u64 = 230;
    pub const restart_syscall: u64 = 219;
};

export fn lc_tramp_syscall(f: *Frame, fx: [*]const u8) callconv(win.WINAPI) void {
    sig.enter();
    const resume_rip = f.rcx;
    // Above the frame: the guest's rsp, as the trampoline jumped here.
    const gsp = @as(*const u64, @ptrFromInt(@intFromPtr(f) + 128)).*;
    const rflags = @as(*const u64, @ptrFromInt(@intFromPtr(f) + 120)).*;
    // Publish the register frame before posting, so the supervisor's ptrace
    // stops and GETREGS see the guest state. Unconditional: the Windows stdio
    // word carries event handles, not a traced bit, and the write lands in the
    // record's free region, so it is cheap and harmless when untraced.
    sigx.publishFrame(f, resume_rip, gsp, rflags);
    var t = trap(f, fx, gsp, resume_rip, rflags);
    const r = thread.serve(&t);
    var rax = sig.afterSyscall(&t, r);
    // A tracer may have edited the registers during a stop; apply them before
    // the guest resumes, overriding the result in rax.
    if (sigx.traceState().dirty != 0) rax = sigx.traceRestore(f, &t);
    f.rax = rax;
    sig.returnTrap(&t);
}

fn trap(f: *const Frame, fx: [*]const u8, gsp: u64, resume_rip: u64, rflags: u64) sig.Trap {
    return .{ .frame = f, .gsp = gsp, .resume_at = resume_rip, .rflags = rflags, .fx = fx, .site = resume_rip -% 2, .nr = f.rax };
}

// The frame lives on the thread's stub stack (SLOT_STK, 0x1660 below):
// nothing may be written below the guest's stack pointer, where a 2 KiB Go
// goroutine stack ends in its neighbour's or in an unmapped page. The
// trampoline jumps here, and r11, which a syscall clobbers, carries the guest
// rsp across.
comptime {
    std.debug.assert(stub.SLOT_STK == 0x1660);
}

// lc_syscall_entry is reached from a rewriter trampoline, which has put the
// resume address in rcx, as the syscall instruction would, and jumped here.
// It saves the guest's rflags, the 15 GPRs and the full SSE state, since Win64
// code may clobber rax, rcx, rdx, r8-r11 and xmm0-5, where a Linux syscall
// clobbers only rax, rcx, r11. rflags sits just above the frame; the fxsave
// image is passed to the handler so a signal frame can carry it.
comptime {
    asm (
        \\.globl lc_syscall_entry
        \\lc_syscall_entry:
        \\  mov %rsp, %r11
        \\  mov %gs:0x1660, %rsp
        \\  push %r11
        \\  pushfq
        \\  push %rax
        \\  push %rdi
        \\  push %rsi
        \\  push %rdx
        \\  push %rcx
        \\  push %r8
        \\  push %r9
        \\  push %r10
        \\  push %r11
        \\  push %rbx
        \\  push %rbp
        \\  push %r12
        \\  push %r13
        \\  push %r14
        \\  push %r15
        \\  mov %rsp, %rbx
        \\  sub $512, %rsp
        \\  and $-16, %rsp
        \\  fxsave64 (%rsp)
        \\  mov %rsp, %rdx
        \\  cld
        \\  mov %rbx, %rcx
        \\  sub $32, %rsp
        \\  call lc_tramp_syscall
        \\  ud2
    );
}

pub extern fn lc_syscall_entry() callconv(.Naked) void;

// lc_exit_entry is where an exit site's trampoline jumps once it has switched
// to this thread's stub stack (SLOT_STK): the guest's stack may already be
// someone else's (Go frees a thread's stack before its exit syscall, musl's
// __unmapself unmaps it), so nothing may be written there, not even the
// exception frame a trap would push. rdi holds the exit code.
comptime {
    asm (
        \\.globl lc_exit_entry
        \\lc_exit_entry:
        \\  and $-16, %rsp
        \\  mov %rdi, %rcx
        \\  sub $32, %rsp
        \\  call lc_exit_thread
        \\  ud2
    );
}

pub extern fn lc_exit_entry() callconv(.Naked) void;

export fn lc_exit_thread(code: u64) callconv(win.WINAPI) noreturn {
    thread.exitThread(code);
}

// lc_sig_redirect is where the supervisor points a thread it stole the context
// of (a thread running guest code): rcx holds the guest-view address of the
// saved CONTEXT in this thread's slot scratch; the stub delivers from it.
pub export fn lc_sig_redirect(saved: *win.CONTEXT) callconv(win.WINAPI) noreturn {
    sig.redirect(saved);
}

// threadInit readies a new OS thread for guest code: nothing on x86-64.
pub fn threadInit() void {}

// lc_on_stub calls f(arg) on this thread's stub stack (SLOT_STK) and returns
// its result. A fault in guest code is handled there so that nothing of the
// stub's own -- its frames, spills, the chain under serveUd2 -- lands under the
// guest's stack pointer, where the guest (unlike on Linux) would later read it
// as live data. The kernel's own exception frame below the guest sp cannot be
// helped. arm64 does the same (aarch64.zig lc_on_stub).
comptime {
    asm (
        \\.globl lc_on_stub
        \\lc_on_stub:
        \\  push %rbp
        \\  mov %rsp, %rbp
        \\  mov %gs:0x1660, %rsp
        \\  sub $32, %rsp
        \\  call *%rdx
        \\  mov %rbp, %rsp
        \\  pop %rbp
        \\  ret
    );
}
extern fn lc_on_stub(arg: *anyopaque, f: *const fn (*anyopaque) callconv(.C) i32) callconv(.C) i32;

fn faultHandleOnStub(arg: *anyopaque) callconv(.C) i32 {
    return faultHandle(@ptrCast(@alignCast(arg)));
}

// onStubStack moves to this thread's stub stack and calls f(arg) there.
pub fn onStubStack(f: *const fn (*sig.Ctx) callconv(.C) noreturn, arg: *sig.Ctx) noreturn {
    asm volatile (
        \\ mov %%rdx, %%rsp
        \\ sub $32, %%rsp
        \\ call *%%rax
        \\ ud2
        :
        : [sp] "{rdx}" (tebLoad(stub.SLOT_STK)),
          [c] "{rcx}" (arg),
          [f] "{rax}" (f),
        : "memory"
    );
    unreachable;
}

// prefaultStack commits 64 KiB of the current (Windows) stack below the
// stack pointer while the TEB still describes it, so the stub stack never
// meets a guard page once the TEB describes the guest's stack.
pub fn prefaultStack() void {
    const sp = asm volatile ("mov %%rsp, %[v]"
        : [v] "=r" (-> u64),
    );
    var a = (sp & ~@as(u64, 0xfff)) - 0x1000;
    const end = sp - (64 << 10);
    while (a >= end) : (a -= 0x1000) _ = @as(*volatile const u8, @ptrFromInt(a)).*;
}

// markStubStack records the current stack pointer as this thread's stub stack
// before it leaves for the guest: nothing below it is live once the thread
// runs guest code.
fn markStubStack() void {
    const sp = asm volatile ("mov %%rsp, %[v]"
        : [v] "=r" (-> u64),
    );
    const top = (sp - 64) & ~@as(u64, 15);
    tebStore(stub.SLOT_STK, top);
    sig.setStubSp(top);
}

// resumeFrame enters the guest at rip on stack sp with f's registers and a
// zero rax: a clone child's return.
pub fn resumeFrame(f: *const Frame, sp: u64, rip: u64) noreturn {
    var w: win.CONTEXT = undefined;
    RtlCaptureContext(&w);
    const fx: [*]const u8 = @ptrCast(&w.DUMMYUNIONNAME.FltSave);
    const t = trap(f, fx, sp, rip, w.EFlags);
    var c = sig.ctxFromTrap(&t);
    c.rax = 0;
    markStubStack();
    sig.returnCtx(&c);
}

// exitOnStubStack ends the calling thread (exit with other threads running,
// or a CLONE_VM child's end) from its stub stack, as an exit site's
// trampoline does: the guest's stack may be someone else's.
pub fn exitOnStubStack(code: u64) noreturn {
    asm volatile ("mov %%gs:" ++ std.fmt.comptimePrint("{d}", .{stub.SLOT_STK}) ++ ", %%rsp\n jmp lc_exit_entry"
        :
        : [c] "{rdi}" (code),
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

const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;
const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC0000096;
const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC0000094;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC0000095;
const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xC00002B5;
const STATUS_BREAKPOINT: u32 = 0x80000003;
const STATUS_SINGLE_STEP: u32 = 0x80000004;

fn rdfsbase() u64 {
    return asm volatile ("rdfsbase %[r]"
        : [r] "=r" (-> u64),
    );
}

fn wrfsbase(v: u64) void {
    asm volatile ("wrfsbase %[v]"
        :
        : [v] "r" (v),
    );
}

fn fsPrefixed(ip: [*]const u8) bool {
    var i: usize = 0;
    while (i < 14) : (i += 1) {
        switch (ip[i]) {
            0x64 => return true,
            0x26, 0x2e, 0x36, 0x3e, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3 => {},
            else => return false,
        }
    }
    return false;
}

fn fsFault(c: *win.CONTEXT) bool {
    const tp = tebLoad(SLOT_TP);
    if (tp == 0 or rdfsbase() == tp) return false;
    if (!fsPrefixed(@ptrFromInt(c.Rip))) return false;
    wrfsbase(tp);
    return true;
}

// lc_guest_copy(dst, src, n) copies n bytes between guest memory and the stub
// and returns 0, or 1 when a guest address faults: onException resumes a fault
// inside it at lc_guest_copy_fault, as the kernel's exception table does for
// copy_from_user and copy_to_user.
comptime {
    asm (
        \\.globl lc_guest_copy
        \\.globl lc_guest_copy_begin
        \\.globl lc_guest_copy_end
        \\.globl lc_guest_copy_fault
        \\lc_guest_copy:
        \\  push %rdi
        \\  push %rsi
        \\  mov %rcx, %rdi
        \\  mov %rdx, %rsi
        \\  mov %r8, %rcx
        \\  cld
        \\lc_guest_copy_begin:
        \\  rep movsb
        \\lc_guest_copy_end:
        \\  xor %eax, %eax
        \\  pop %rsi
        \\  pop %rdi
        \\  ret
        \\lc_guest_copy_fault:
        \\  mov $1, %eax
        \\  pop %rsi
        \\  pop %rdi
        \\  ret
        \\.globl lc_guest_load32
        \\.globl lc_guest_load32_end
        \\.globl lc_guest_load32_fault
        \\lc_guest_load32:
        \\  mov (%rcx), %eax
        \\lc_guest_load32_end:
        \\  ret
        \\lc_guest_load32_fault:
        \\  mov $-1, %rax
        \\  ret
    );
}

extern fn lc_guest_copy(dst: u64, src: u64, n: u64) callconv(.C) u64;
extern fn lc_guest_copy_begin() callconv(.C) void;
extern fn lc_guest_copy_end() callconv(.C) void;
extern fn lc_guest_copy_fault() callconv(.C) void;

// readGuest and writeGuest copy n bytes from or to guest memory that may be
// bad, and report whether it all copied.
pub fn readGuest(buf: u64, guest: u64, n: u64) bool {
    return lc_guest_copy(buf, guest, n) == 0;
}

pub fn writeGuest(guest: u64, buf: u64, n: u64) bool {
    return lc_guest_copy(guest, buf, n) == 0;
}

extern fn lc_guest_load32(addr: u64) callconv(.C) u64;
extern fn lc_guest_load32_end() callconv(.C) void;
extern fn lc_guest_load32_fault() callconv(.C) void;

// guestLoad32 reads the aligned guest word at addr in one load (a futex
// word), or null when it faults.
pub fn guestLoad32(addr: u64) ?u32 {
    const v = lc_guest_load32(addr);
    return if (v > 0xffffffff) null else @truncate(v);
}

// guestFixup resumes a fault in lc_guest_copy or lc_guest_load32 at its fault
// exit and reports whether it was one.
fn guestFixup(c: *win.CONTEXT) bool {
    if (c.Rip >= @intFromPtr(&lc_guest_copy_begin) and c.Rip < @intFromPtr(&lc_guest_copy_end)) {
        c.Rip = @intFromPtr(&lc_guest_copy_fault);
        return true;
    }
    if (c.Rip == @intFromPtr(&lc_guest_load32)) {
        c.Rip = @intFromPtr(&lc_guest_load32_fault);
        return true;
    }
    return false;
}

// onException serves the ud2 the rewriter leaves at a syscall site without a
// trampoline, the %fs accesses left without an island, and guest faults, which
// become Linux signals (delivered to a handler, or ending the process when
// there is none).
pub fn onException(ep: *win.EXCEPTION_POINTERS) callconv(win.WINAPI) i32 {
    const c = ep.ContextRecord;
    // The supervisor redirected the thread (a signal) while the kernel was
    // raising this exception: the context, and the exception address with
    // it, already enter lc_sig_redirect, whose first instruction cannot
    // fault. Let it run: it delivers from the stolen context, and the
    // faulting instruction runs again when that context resumes.
    if (c.Rip == @intFromPtr(&lc_sig_redirect)) return -1;
    // A guest thread faulting in ntdll got there by a raw syscall the
    // backstop let through because the kernel resumed it in ntdll (a
    // service that transfers control, as a callback return does): it is no
    // guest fault, and ends the guest as the backstop does.
    if (!stub.ownCode(c.Rip) and sig.inGuest() and instrcb.inNtdll(c.Rip)) stub.die(instrcb.BACKSTOP_KILL);
    // The handler is stub code that talks to the supervisor (isTrap, wxFault's
    // hot/cool, rewritePage, sig.fault): held against a context steal while it
    // runs. A signal that arrives meanwhile is taken on the way out -- the hold
    // ends, then pending is read (send sets pending before reading the hold; we
    // clear the hold before reading pending, so one side always sees the
    // other), and a pending one resumes through the return gate, which delivers.
    // Guest (or trampoline/ool-slot) code faulted: the stub stack is idle, so
    // run the handler there and leave the guest stack as Linux would. A fault
    // in the stub's own code is already on the stub stack; handle it in place.
    const guest = !stub.ownCode(c.Rip) and sig.inGuest();
    sig.faultEnter();
    if (guest) sig.noteDirt(asm volatile ("mov %%rsp, %[v]"
        : [v] "=r" (-> u64),
    ), c.Rsp);
    const r = if (guest) lc_on_stub(@ptrCast(ep), &faultHandleOnStub) else faultHandle(ep);
    sig.faultLeave();
    // A guest fault's resume goes through the return gate so it wipes the
    // handler's stack dirt (and delivers any pending signal); a stub-code fault
    // only when a signal is pending. When the resume stays off the gate (it is
    // already staged, runs an instruction out of line, or crashes), drop the
    // dirt floor so a later gate pass never wipes live stack.
    const staged = c.Rip == @intFromPtr(&lc_guest_return);
    if (r == -1 and guest and !staged and !ool.inSlot(stub.curSlot(), c.Rip)) {
        prepareGuestReturn(c);
    } else if (!staged) {
        sig.clearDirt();
    }
    return r;
}

fn faultHandle(ep: *win.EXCEPTION_POINTERS) i32 {
    const c = ep.ContextRecord;
    const code = ep.ExceptionRecord.ExceptionCode;
    if (code == STATUS_BREAKPOINT) {
        // The int3 after an instruction run out of line (ool.zig).
        if (ool.exit(stub.curSlot(), c.Rip)) |e| {
            c.Rip = e.target;
            for (e.holds) |h| stub.mem.letGo(h);
            return -1;
        }
    }
    if (code == STATUS_ACCESS_VIOLATION and ep.ExceptionRecord.NumberParameters >= 2) {
        const page = ep.ExceptionRecord.ExceptionInformation[1] & ~@as(u64, 0xfff);
        var st: stub.mem.Step = .{ .from_slot = ool.inSlot(stub.curSlot(), c.Rip), .lost = ool.lost(stub.curSlot(), c.Rip, page) };
        switch (stub.mem.wxFault(ep.ExceptionRecord.ExceptionInformation[1], ep.ExceptionRecord.ExceptionInformation[0], c.Rip, &st)) {
            .handled => return -1,
            .retry => {
                ool.tried(stub.curSlot(), c.Rip, page);
                return -1;
            },
            .step => {
                if (st.call) {
                    const regs = [16]u64{ c.Rax, c.Rcx, c.Rdx, c.Rbx, c.Rsp, c.Rbp, c.Rsi, c.Rdi, c.R8, c.R9, c.R10, c.R11, c.R12, c.R13, c.R14, c.R15 };
                    switch (ool.callOf(st.code[0..st.n], st.start, &regs, &stub.mem.load64)) {
                        .call => |cl| if (ool.runCall(stub.curSlot(), cl, st.start, st.hold)) |p| {
                            c.Rip = p;
                            return -1;
                        },
                        .fault => {
                            // Run in place, it reads its operand and faults so.
                            stub.mem.letGo(st.hold);
                            return -1;
                        },
                        .no => {},
                    }
                } else if (ool.runX64(stub.curSlot(), st.code[0..st.n], st.at, st.start, st.hold)) |p| {
                    c.Rip = p;
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
            .fail, .none => {},
        }
    }
    if (code == STATUS_ACCESS_VIOLATION and guestFixup(c)) return -1;
    switch (code) {
        STATUS_ACCESS_VIOLATION, STATUS_PRIVILEGED_INSTRUCTION => {
            // An instruction fetch from a bad address has no instruction
            // to inspect: reading it would fault again, inside the handler.
            const fetch = code == STATUS_ACCESS_VIOLATION and ep.ExceptionRecord.NumberParameters >= 1 and ep.ExceptionRecord.ExceptionInformation[0] == 8;
            if (!fetch and fsFault(c)) {
                prepareGuestReturn(c);
                return -1;
            }
            return faultOut(ep, stub.SIGSEGV, faultAddr(ep, c.Rip));
        },
        STATUS_INTEGER_DIVIDE_BY_ZERO, STATUS_INTEGER_OVERFLOW, STATUS_FLOAT_DIVIDE_BY_ZERO => return faultOut(ep, stub.SIGFPE, c.Rip),
        STATUS_BREAKPOINT => {
            // Windows leaves rip at the int3; Linux reports it past.
            if (@as(*const u8, @ptrFromInt(c.Rip)).* == 0xcc) c.Rip += 1;
            return faultOut(ep, stub.SIGTRAP, c.Rip);
        },
        STATUS_SINGLE_STEP => return faultOut(ep, stub.SIGTRAP, c.Rip),
        STATUS_ILLEGAL_INSTRUCTION => {},
        else => return 0,
    }
    // A ud2 is a syscall only where the rewriter or the stub put it: any
    // other is the guest's. One whose page was stopped since holds the
    // syscall again, and is served as the trap it was.
    const ip: [*]const u8 = @ptrFromInt(c.Rip);
    if (ip[0] != 0x0f or (ip[1] != 0x0b and ip[1] != 0x05) or !stub.mem.isTrap(c.Rip)) return faultOut(ep, stub.SIGILL, c.Rip);
    return serveUd2(c);
}

fn faultAddr(ep: *win.EXCEPTION_POINTERS, pc: u64) u64 {
    return if (ep.ExceptionRecord.NumberParameters >= 2) ep.ExceptionRecord.ExceptionInformation[1] else pc;
}

// faultOut delivers a guest fault to a handler if one is installed (sig.fault),
// else falls back to the LC_FAULT path that ends the process as killed.
fn faultOut(ep: *win.EXCEPTION_POINTERS, signo: u64, addr: u64) i32 {
    if (sig.fault(ep)) return -1;
    return if (stub.fault(signo, addr, ep.ContextRecord.Rip, sig.accessKind(ep.ExceptionRecord))) -1 else 0;
}

// serveUd2 handles a syscall site that fell to the exception path: service it
// from the CONTEXT and deliver any pending signal on the way out.
fn serveUd2(c: *win.CONTEXT) i32 {
    sig.enter();
    var f = Frame{
        .r15 = c.R15, .r14 = c.R14, .r13 = c.R13, .r12 = c.R12,
        .rbp = c.Rbp, .rbx = c.Rbx, .r11 = c.R11, .r10 = c.R10,
        .r9 = c.R9,   .r8 = c.R8,   .rcx = c.Rcx, .rdx = c.Rdx,
        .rsi = c.Rsi, .rdi = c.Rdi, .rax = c.Rax,
    };
    const resume_rip = c.Rip + 2;
    const fx: [*]const u8 = @ptrCast(&c.DUMMYUNIONNAME.FltSave);
    var t = trap(&f, fx, c.Rsp, resume_rip, c.EFlags);
    const r = thread.serve(&t);
    c.Rax = sig.afterSyscall(&t, r); // may NtContinue; else returns the result
    c.Rsp = t.gsp;
    c.Rip += 2;
    prepareGuestReturn(c);
    return -1; // EXCEPTION_CONTINUE_EXECUTION
}

// trapsAt reports whether the syscall site at pc is the trap the rewriter
// leaves where no trampoline fits.
pub fn trapsAt(pc: u64) bool {
    const ip: [*]const u8 = @ptrFromInt(pc);
    return ip[0] == 0x0f and ip[1] == 0x0b;
}

// serveSite serves the syscall at such a site, which c resumes at, as
// serveUd2 would, and moves c past it.
pub fn serveSite(c: *sig.Ctx) void {
    c.rip += 2;
    var f: Frame = undefined;
    var t = sigx.trapFromCtx(c, c.rax, &f);
    c.rax = sig.afterSyscall(&t, thread.serve(&t));
    c.rsp = t.gsp;
}

// enter starts guest code at entry on stack sp, as the kernel does at exec.
pub fn enter(entry: u64, sp: u64) noreturn {
    var w: win.CONTEXT = undefined;
    RtlCaptureContext(&w);
    w.Rsp = sp;
    w.Rip = entry;
    w.Rdx = 0;
    w.Rbp = 0;
    const c = sig.ctxFromWin(&w);
    markStubStack();
    sig.returnCtx(&c);
}

// The compiler's memcpy and memset: there is no CRT.
export fn memcpy(dst: [*]u8, src: [*]const u8, n: usize) callconv(.C) [*]u8 {
    asm volatile ("rep movsb"
        :
        : [d] "{rdi}" (dst),
          [s] "{rsi}" (src),
          [n] "{rcx}" (n),
        : "rdi", "rsi", "rcx", "memory"
    );
    return dst;
}

export fn memset(dst: [*]u8, c: u8, n: usize) callconv(.C) [*]u8 {
    asm volatile ("rep stosb"
        :
        : [d] "{rdi}" (dst),
          [c] "{al}" (c),
          [n] "{rcx}" (n),
        : "rdi", "rcx", "memory"
    );
    return dst;
}

export fn memmove(dst: [*]u8, src: [*]const u8, n: usize) callconv(.C) [*]u8 {
    if (@intFromPtr(dst) < @intFromPtr(src)) {
        var i: usize = 0;
        while (i < n) : (i += 1) dst[i] = src[i];
    } else {
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            dst[i] = src[i];
        }
    }
    return dst;
}
