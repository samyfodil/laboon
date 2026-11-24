// arm64 half of the stub. The guest owns tpidr_el0 and there is no spare
// user-writable thread register, so a thread finds its channel slot from its
// stack pointer when it runs on one of its slot's stacks (stub.slotBySp), and
// elsewhere through a private table indexed by its kernel tid (one gettid per
// lookup). The table is sparse anonymous memory; a forked child inherits it
// and records its own tid.
//
// A rewritten `svc #0` becomes `b island`; the island (built by the
// supervisor, see rewrite.A64Rewriter, OwnStack) saves x16/x17, pushes the
// address of its own epilogue and branches to lc_syscall_entry with the
// resume pc in x17, which finds the slot and services the call on the slot's
// own stack. The fallback is `udf #0`, which traps here as SIGILL. Linux
// leaves memory below sp alone across svc, and code relies on the 128 bytes
// under it (Go's runtime.clone), so neither path writes there: the island
// and the entry use 48 bytes below that gap, and the SIGILL handler runs on
// a per-thread alternate stack.

const std = @import("std");
const stub = @import("stub.zig");
const sig = stub.sig;
const trace = @import("trace.zig");
const nr = stub.nr;

pub const AUDIT_ARCH: u32 = 0xc00000b7;
pub const R_RELATIVE: u64 = 1027; // R_AARCH64_RELATIVE

pub const allowed = [_]stub.SYS{
    .read,  .write,  .writev,       .mmap,           .mprotect, .munmap, .mremap, .madvise,
    .getpid, .gettid, .futex,       .rt_sigreturn,   .rt_sigprocmask, .clone,
    .exit,  .exit_group, .sigaltstack, .tgkill,     .recvmsg, .close,  .msync, .mincore,
    .clock_gettime, .clock_getres, .gettimeofday, .getrusage, .getcpu,
    .rseq,          .restart_syscall, .membarrier, .set_tid_address,
};

// guest is what a guest thread may call (seccomp.zig).
pub const guest = [_]stub.SYS{
    .read,          .write,        .writev,       .getpid,    .gettid, .futex, .rt_sigreturn,
    .rt_sigprocmask, .clone,       .exit,         .exit_group, .sigaltstack, .tgkill,
    .clock_gettime, .clock_getres, .gettimeofday, .getrusage, .getcpu,
    .rseq,          .restart_syscall,
};

inline fn tidsAddr() u64 {
    return stub.winBase + 0x16000000000;
}
const MAX_TID: u64 = 4 << 20; // PID_MAX_LIMIT

pub inline fn sys6(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) u64 {
    return asm volatile ("svc #0"
        : [ret] "={x0}" (-> u64),
        : [n] "{x8}" (n),
          [a] "{x0}" (a),
          [b] "{x1}" (b),
          [c] "{x2}" (c),
          [d] "{x3}" (d),
          [e] "{x4}" (e),
          [f] "{x5}" (f),
        : "memory"
    );
}

pub inline fn pause() void {
    asm volatile ("yield");
}

// ticks reads the virtual count register (cntvct_el0), the system counter --
// a steady tick clock shared with the supervisor, so a measured park cost
// carries over.
pub inline fn ticks() u64 {
    return asm volatile ("mrs %[r], cntvct_el0"
        : [r] "=r" (-> u64),
    );
}

pub fn init() void {
    const prot_rw = 3;
    const flags = 0x02 | 0x10 | 0x20 | 0x4000; // PRIVATE|FIXED|ANONYMOUS|NORESERVE
    if (sys6(nr(.mmap), tidsAddr(), MAX_TID * 8, prot_rw, flags, ~@as(u64, 0), 0) != tidsAddr()) stub.die(124);
    lc_tids = tidsAddr();
}

// lc_thread_start sets up a new stub thread: its slot, its alternate signal
// stack, an empty signal mask and its id for the supervisor's kicks.
export fn lc_thread_start(slot_addr: u64) callconv(.C) void {
    setSlot(slot_addr);
    stub.setAltstack(slot_addr);
    stub.unblockSignals();
    sig.recOf(@ptrFromInt(slot_addr)).host_tid = @truncate(sys6(nr(.gettid), 0, 0, 0, 0, 0, 0));
    stub.traceStart(@ptrFromInt(slot_addr));
}

fn tidSlot() *u64 {
    const tid = sys6(nr(.gettid), 0, 0, 0, 0, 0, 0);
    const t: [*]u64 = @ptrFromInt(tidsAddr());
    return &t[tid % MAX_TID];
}

pub fn slot() *stub.Chan {
    return @ptrFromInt(slotAddr());
}

// slotAddr is 0 for a thread that has not set its slot yet. On one of its
// slot's stacks the stack pointer names the slot (stub.slotBySp); elsewhere the
// tid table does.
pub fn slotAddr() u64 {
    const s = stub.slotBySp(asm volatile ("mov %[r], sp"
        : [r] "=r" (-> u64),
    ));
    return if (s != 0) s else tidSlot().*;
}

pub fn redZone(sp: u64) u64 {
    return sp;
}

pub fn setSlot(addr: u64) void {
    tidSlot().* = addr;
    sig.recOf(@ptrFromInt(addr)).scratch_top = stub.scratchTop(@ptrFromInt(addr));
}

// lc_tids is where the tid table is, for lc_syscall_entry.
export var lc_tids: u64 = 0;

// Frame is the guest's register file at a syscall: x0..x30 and NZCV. The
// stub is built without FP/SIMD, so those registers are never touched and
// need no saving. resume_at is the guest pc after the svc, sp its sp.
pub const Frame = extern struct {
    x: [31]u64,
    nzcv: u64,
    resume_at: u64,
    sp: u64,

    pub fn number(f: *const Frame) u64 {
        return f.x[8];
    }

    pub fn args(f: *const Frame) [6]u64 {
        return f.x[0..6].*;
    }
};

comptime {
    if (@sizeOf(Frame) != 272) @compileError("lc_syscall_entry and the islands assume a 272-byte frame");
}

extern fn lc_clone_thread(flags: u64, sp: u64, ctid: u64) callconv(.C) u64;
extern fn lc_enter_guest(block: u64) callconv(.C) noreturn;

const HANDOFF = 288;

// clone creates a new stub thread for a guest clone. args from the
// supervisor: [0]=guest child stack, [1]=guest TLS (tpidr_el0, 0 to
// inherit), [2]=new slot address, [3]=stub bootstrap stack top. The child
// restores the guest registers and resumes at guest_rip with x0=0 on the
// child stack; x16 carries the branch target.
// enterGuest resumes the guest at pc on stack sp with frame f's registers
// and x0=0, as a clone child starts (a fork child given a stack).
pub fn enterGuest(f: *const Frame, pc: u64, sp: u64) noreturn {
    var b: [36]u64 align(16) = undefined;
    b[1] = 0; // tpidr_el0 as it is
    b[2] = pc;
    b[3] = sp;
    for (0..31) |i| b[4 + i] = f.x[i];
    b[35] = f.nzcv;
    lc_enter_guest(@intFromPtr(&b));
}

pub fn clone(ch: *stub.Chan, f: *const Frame) u64 {
    // Handoff block: { slot, tls, pc, childstack, x0..x30, nzcv }.
    const b: [*]u64 = @ptrFromInt(ch.args[3] - HANDOFF);
    b[0] = ch.args[2];
    b[1] = ch.args[1];
    b[2] = ch.guest_rip;
    b[3] = ch.args[0];
    for (0..31) |i| b[4 + i] = f.x[i];
    b[35] = f.nzcv;
    return lc_clone_thread(stub.THREAD_FLAGS, ch.args[3] - HANDOFF, ch.args[2] + stub.ALIVE_OFF);
}

comptime {
    asm (
        \\.globl lc_clone_thread
        \\lc_clone_thread:
        \\  mov x4, x2
        \\  mov x2, xzr
        \\  mov x3, xzr
        \\  mov x8, #220
        \\  svc #0
        \\  cbz x0, 1f
        \\  ret
        \\1:
        \\  mov x19, sp
        \\  ldr x0, [x19, #0]
        \\  bl lc_thread_start
        \\.Lguest:
        \\  ldr x2, [x19, #8]
        \\  cbz x2, 2f
        \\  msr tpidr_el0, x2
        \\2:
        \\  bl lc_trace_child
        \\  ldr x9, [x19, #280]
        \\  msr nzcv, x9
        \\  ldr x16, [x19, #16]
        \\  ldr x9, [x19, #24]
        \\  mov sp, x9
        \\  ldp x1, x2, [x19, #40]
        \\  ldp x3, x4, [x19, #56]
        \\  ldp x5, x6, [x19, #72]
        \\  ldp x7, x8, [x19, #88]
        \\  ldp x9, x10, [x19, #104]
        \\  ldp x11, x12, [x19, #120]
        \\  ldp x13, x14, [x19, #136]
        \\  ldr x15, [x19, #152]
        \\  ldp x17, x18, [x19, #168]
        \\  ldp x20, x21, [x19, #192]
        \\  ldp x22, x23, [x19, #208]
        \\  ldp x24, x25, [x19, #224]
        \\  ldp x26, x27, [x19, #240]
        \\  ldp x28, x29, [x19, #256]
        \\  ldr x30, [x19, #272]
        \\  ldr x19, [x19, #184]
        \\  mov x0, xzr
        \\  br x16
        \\.globl lc_enter_guest
        \\lc_enter_guest:
        \\  mov x19, x0
        \\  b .Lguest
    );
}

// hopSpawn starts the process's host-op thread, lc_hop_loop, on the stack at
// stack_top, serving the request page at req with spin cap cap (cputicks); the
// parent returns the tid. Both reach the thread in registers: once the guest
// runs, the stub's memory is the guest's to write.
pub fn hopSpawn(stack_top: u64, req: u64, cap: u64) u64 {
    return lc_hop_spawn(stub.THREAD_FLAGS, stack_top, req, cap);
}
extern fn lc_hop_spawn(flags: u64, sp: u64, req: u64, cap: u64) callconv(.C) u64;

// lc_all_signals is the hop thread's signal mask: it takes none, so the
// process's go to its guest threads, and none runs a handler on its stack.
export const lc_all_signals: u64 = ~@as(u64, 0);

// lc_hop_loop serves the hop's requests. It trusts nothing in writable memory:
// its state is in registers -- x19 the request page, x25 the reply page
// (HOP_REP past it), x26/x27 their hop_sleep and sup_sleep words, w21 the
// last request's sequence number, x20 the spin cap, x22/x23/x24 the spin
// budget and the EWMAs of caught requests' latency and its deviation
// (stub.zig spinHit/spinMiss) -- and it touches no stack. A request (seq past
// w21) is a syscall nr(args) whose result goes on the reply page, or
// HOP_FORK; a fork's child takes its copy's arguments to lc_hop_forked.
comptime {
    asm (
        \\.globl lc_hop_spawn
        \\lc_hop_spawn:
        \\  stp x19, x20, [sp, #-16]!
        \\  mov x19, x2
        \\  mov x20, x3
        \\  mov x2, xzr
        \\  mov x3, xzr
        \\  mov x4, xzr
        \\  mov x8, #220
        \\  svc #0
        \\  cbz x0, lc_hop_loop
        \\  ldp x19, x20, [sp], #16
        \\  ret
        \\lc_hop_loop:
        \\  mov x0, #2
        \\  adrp x1, lc_all_signals
        \\  add x1, x1, :lo12:lc_all_signals
        \\  mov x2, xzr
        \\  mov x3, #8
        \\  mov x8, #135
        \\  svc #0
        \\  mov w21, wzr
        \\  mov x22, x20
        \\  mov x23, xzr
        \\  mov x24, xzr
        \\  movz x25, #4, lsl #32
        \\  add x25, x19, x25
        \\  add x26, x25, #4
        \\  add x27, x19, #4
        \\.Lhwait:
        \\  mrs x9, cntvct_el0
        \\  add x10, x9, x22
        \\.Lhspin:
        \\  mov w11, #32
        \\.Lhpoll:
        \\  ldar w12, [x19]
        \\  cmp w12, w21
        \\  b.ne .Lhhit
        \\  yield
        \\  subs w11, w11, #1
        \\  b.ne .Lhpoll
        \\  mrs x12, cntvct_el0
        \\  cmp x12, x10
        \\  b.lo .Lhspin
        \\.Lhpark:
        \\  mov w12, #1
        \\  stlr w12, [x26]
        \\  ldar w12, [x19]
        \\  cmp w12, w21
        \\  b.ne .Lhwoke
        \\  mov x0, x19
        \\  mov x1, xzr
        \\  mov w2, w21
        \\  mov x3, xzr
        \\  mov x8, #98
        \\  svc #0
        \\.Lhwoke:
        \\  stlr wzr, [x26]
        \\  ldar w12, [x19]
        \\  cmp w12, w21
        \\  b.eq .Lhpark
        \\  mrs x12, cntvct_el0
        \\  sub x12, x12, x9
        \\  cmp x12, x20
        \\  b.hs .Lhfar
        \\  sub x13, x20, x22
        \\  add x22, x22, x13, lsr #1
        \\  b .Lhgot
        \\.Lhfar:
        \\  sub x22, x22, x22, lsr #2
        \\  cmp x22, x20, lsr #7
        \\  b.hs .Lhgot
        \\  mov x22, xzr
        \\  b .Lhgot
        \\.Lhhit:
        \\  mrs x12, cntvct_el0
        \\  sub x12, x12, x9
        \\  sub x23, x23, x23, lsr #3
        \\  add x23, x23, x12, lsr #3
        \\  subs x13, x12, x23
        \\  cneg x13, x13, lo
        \\  sub x24, x24, x24, lsr #3
        \\  add x24, x24, x13, lsr #3
        \\  add x22, x23, x24, lsl #2
        \\  cmp x22, x20
        \\  csel x22, x22, x20, ls
        \\.Lhgot:
        \\  ldr x8, [x19, #8]
        \\  cmn x8, #1
        \\  b.eq .Lhfork
        \\  ldp x0, x1, [x19, #16]
        \\  ldp x2, x3, [x19, #32]
        \\  ldp x4, x5, [x19, #48]
        \\  svc #0
        \\.Lhreply:
        \\  str x0, [x25, #8]
        \\  ldr w12, [x19]
        \\  mov w21, w12
        \\  stlr w12, [x25]
        \\  ldar w13, [x27]
        \\  cbz w13, .Lhwait
        \\  mov x0, x25
        \\  mov x1, #1
        \\  mov x2, #1
        \\  mov x8, #98
        \\  svc #0
        \\  b .Lhwait
        \\.Lhfork:
        \\  mov x0, #0x8011
        \\  mov x1, xzr
        \\  ldp x2, x3, [x19, #16]
        \\  ldp x4, x5, [x19, #32]
        \\  mov x8, #220
        \\  svc #0
        \\  cbnz x0, .Lhreply
        \\  mov x0, x2
        \\  mov x1, x3
        \\  mov x2, x4
        \\  mov x3, x5
        \\  mov x4, x20
        \\  mov x29, xzr
        \\  mov x30, xzr
        \\  bl lc_hop_forked
        \\  brk #0
    );
}

comptime {
    if (stub.FORK_FLAGS != 0x8011 or stub.HOP_FORK != ~@as(u64, 0) or stub.HOP_REP != 0x400000000) @compileError("lc_hop_loop's constants moved");
}

// forkChildOn runs stub.zig lc_fork_child(cs, req, ctx, stack, cap) on the
// stack at top, never returning to the caller's.
pub fn forkChildOn(top: u64, cs: u64, req: u64, ctx: u64, stack: u64, cap: u64) noreturn {
    lc_fork_child_on(top, cs, req, ctx, stack, cap);
}
extern fn lc_fork_child_on(top: u64, cs: u64, req: u64, ctx: u64, stack: u64, cap: u64) callconv(.C) noreturn;

comptime {
    asm (
        \\.globl lc_fork_child_on
        \\lc_fork_child_on:
        \\  mov sp, x0
        \\  mov x0, x1
        \\  mov x1, x2
        \\  mov x2, x3
        \\  mov x3, x4
        \\  mov x4, x5
        \\  mov x29, xzr
        \\  mov x30, xzr
        \\  bl lc_fork_child
        \\  brk #0
    );
}

// guestTls is the guest's thread pointer, tpidr_el0.
pub fn guestTls() u64 {
    return asm volatile ("mrs %[r], tpidr_el0"
        : [r] "=r" (-> u64),
    );
}

const FPSIMD_MAGIC = 0x46508001;
const FPSIMD_SIZE = 528; // the kernel's fpsimd_context: head, fpsr, fpcr, v0-v31

// saveFp stores the guest's FP/SIMD state at dst as the kernel's
// fpsimd_context: from the signal frame at uc when the syscall came in one,
// else the live registers, which the stub never touches.
pub fn saveFp(dst: u64, uc: u64) void {
    if (uc != 0) {
        var r = uc + UC_RESERVED;
        const end = r + 4096;
        while (r + 8 <= end) {
            const magic = rd(u32, r);
            const size = rd(u32, r + 4);
            if (magic == 0 or size < 8) break;
            if (magic == FPSIMD_MAGIC) {
                copy(dst, r, FPSIMD_SIZE);
                return;
            }
            r += size;
        }
    }
    asm volatile (
        \\ .arch_extension fp
        \\ .arch_extension simd
        \\ mrs x9, fpsr
        \\ str w9, [x0, #8]
        \\ mrs x9, fpcr
        \\ str w9, [x0, #12]
        \\ stp q0, q1, [x0, #16]
        \\ stp q2, q3, [x0, #48]
        \\ stp q4, q5, [x0, #80]
        \\ stp q6, q7, [x0, #112]
        \\ stp q8, q9, [x0, #144]
        \\ stp q10, q11, [x0, #176]
        \\ stp q12, q13, [x0, #208]
        \\ stp q14, q15, [x0, #240]
        \\ stp q16, q17, [x0, #272]
        \\ stp q18, q19, [x0, #304]
        \\ stp q20, q21, [x0, #336]
        \\ stp q22, q23, [x0, #368]
        \\ stp q24, q25, [x0, #400]
        \\ stp q26, q27, [x0, #432]
        \\ stp q28, q29, [x0, #464]
        \\ stp q30, q31, [x0, #496]
        :
        : [d] "{x0}" (dst),
        : "x9", "memory"
    );
}

// resumeFork enters the guest as the forking thread's copy: its registers
// (with the fork's 0 result), its tpidr_el0, its FP/SIMD state from fp, at
// its resume pc on stack sp. It leaves through the trap, which delivers a
// signal already pending as at any syscall's return; the trap takes the
// registers from a Frame just below sp, where an island puts one.
pub fn resumeFork(c: *stub.ForkCtx, fp: u64, sp: u64) noreturn {
    const t = sig.thr();
    const f: *Frame = @ptrFromInt(sp - 432);
    f.* = c.frame;
    f.sp = sp;
    t.orig = f.x[0];
    f.x[0] = 0;
    t.frame = @intFromPtr(f);
    t.resume_pc = c.rip;
    t.restart = c.rip - 4;
    t.sp = sp;
    asm volatile (
        \\ .arch_extension fp
        \\ .arch_extension simd
        \\ msr tpidr_el0, x1
        \\ ldr w9, [x0, #8]
        \\ msr fpsr, x9
        \\ ldr w9, [x0, #12]
        \\ msr fpcr, x9
        \\ ldp q0, q1, [x0, #16]
        \\ ldp q2, q3, [x0, #48]
        \\ ldp q4, q5, [x0, #80]
        \\ ldp q6, q7, [x0, #112]
        \\ ldp q8, q9, [x0, #144]
        \\ ldp q10, q11, [x0, #176]
        \\ ldp q12, q13, [x0, #208]
        \\ ldp q14, q15, [x0, #240]
        \\ ldp q16, q17, [x0, #272]
        \\ ldp q18, q19, [x0, #304]
        \\ ldp q20, q21, [x0, #336]
        \\ ldp q22, q23, [x0, #368]
        \\ ldp q24, q25, [x0, #400]
        \\ ldp q26, q27, [x0, #432]
        \\ ldp q28, q29, [x0, #464]
        \\ ldp q30, q31, [x0, #496]
        :
        : [fp] "{x0}" (fp),
          [tls] "{x1}" (c.tls),
        : "x9", "memory"
    );
    trap();
}

// exitWake ends the thread as CLONE_CHILD_CLEARTID would at its tid word:
// it clears ctid, wakes a joiner (both futex kinds a libc may wait with) and
// exits, touching no stack after the wake: the joiner may unmap it as soon as
// it runs.
pub fn exitWake(ctid: u64, code: u64) noreturn {
    asm volatile (
        \\ str wzr, [x3]
        \\ mov x0, x3
        \\ mov x1, #1
        \\ mov x2, #1
        \\ mov x8, #98
        \\ svc #0
        \\ mov x0, x3
        \\ mov x1, #129
        \\ mov x2, #1
        \\ mov x8, #98
        \\ svc #0
        \\ mov x0, x6
        \\ mov x8, #93
        \\ svc #0
        :
        : [ctid] "{x3}" (ctid),
          [code] "{x6}" (code),
        : "x0", "x1", "x2", "x8", "memory"
    );
    unreachable;
}

// execHandoff switches to the slot's exec stack and branches into the exec
// service loop, never returning to the caller's (guest) stack, so the
// supervisor can tear the old address space down with no live stack underfoot.
pub fn execHandoff(sp: u64, ch: *stub.Chan) noreturn {
    asm volatile (
        \\ mov sp, x1
        \\ mov x0, x2
        \\ b lc_exec_on_stack
        :
        : [sp] "{x1}" (sp),
          [ch] "{x2}" (ch),
        : "memory"
    );
    unreachable;
}

// enter starts guest code at entry on stack sp, as the kernel does at exec:
// x0 (the dynamic linker's fini pointer), fp and lr are zero.
pub fn enter(entry: u64, sp: u64) noreturn {
    asm volatile (
        \\ mov sp, x1
        \\ mov x0, xzr
        \\ mov x29, xzr
        \\ mov x30, xzr
        \\ br x2
        :
        : [sp] "{x1}" (sp),
          [entry] "{x2}" (entry),
        : "memory"
    );
    unreachable;
}

// Offsets into the kernel's ucontext (uc_mcontext at 176): regs, sp, pc,
// pstate, then the __reserved records. The kernel's rt_sigframe is
// { siginfo (128), ucontext } with the records and any extra_context data
// after it.
const UC_REGS = 184;
const UC_SP = 432;
const UC_PC = 440;
const UC_PSTATE = 448;
const UC_RESERVED = 464;
pub const UC_SIGMASK = 40;
const FRAME_SIZE = 128 + UC_RESERVED + 4096;
const EXTRA_MAGIC = 0x45585401;

fn reg(uc: [*]u8, i: usize) *align(1) u64 {
    return @ptrCast(uc + UC_REGS + i * 8);
}

// lc_cp_sys(n, a0..a5, kicked) is a syscall a kick can cancel before it is
// made: from lc_cp_begin to the svc it checks *kicked, and a kick landing
// there is moved to lc_cp_cancel (cpCancel); one landing in the syscall
// interrupts it. Either way the result is EINTR.
comptime {
    asm (
        \\.globl lc_cp_sys
        \\.globl lc_cp_begin
        \\.globl lc_cp_end
        \\.globl lc_cp_cancel
        \\lc_cp_sys:
        \\  mov x8, x0
        \\  mov x0, x1
        \\  mov x1, x2
        \\  mov x2, x3
        \\  mov x3, x4
        \\  mov x4, x5
        \\  mov x5, x6
        \\lc_cp_begin:
        \\  ldr w9, [x7]
        \\  cbnz w9, lc_cp_cancel
        \\  svc #0
        \\lc_cp_end:
        \\  ret
        \\lc_cp_cancel:
        \\  mov x0, #-4
        \\  ret
    );
}

extern fn lc_cp_sys(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, kicked: *const u32) callconv(.C) u64;
extern fn lc_cp_begin() callconv(.C) void;
extern fn lc_cp_end() callconv(.C) void;
extern fn lc_cp_cancel() callconv(.C) void;

pub fn cpSys(n: u64, a: [6]u64, kicked: *const u32) u64 {
    return lc_cp_sys(n, a[0], a[1], a[2], a[3], a[4], a[5], kicked);
}

// lc_copy_in(dst, src, n) copies n bytes between guest memory and the stub,
// either way, and returns how many it copied: all, or those before a fault, which copyFixup
// resumes at lc_copy_end with x3 counting the bytes copied. lc_str_in(dst,
// src, max) copies a NUL-terminated string, the NUL included, up to max bytes,
// and returns how many it copied; a fault resumes at lc_str_end. Only
// integer registers: the stub leaves the guest's FP/SIMD state alone.
comptime {
    asm (
        \\.globl lc_copy_in
        \\.globl lc_copy_begin
        \\.globl lc_copy_end
        \\lc_copy_in:
        \\  mov x3, #0
        \\lc_copy_begin:
        \\  sub x5, x2, x3
        \\  cmp x5, #16
        \\  b.lo 2f
        \\  ldp x4, x6, [x1]
        \\  stp x4, x6, [x0]
        \\  add x0, x0, #16
        \\  add x1, x1, #16
        \\  add x3, x3, #16
        \\  b lc_copy_begin
        \\2:
        \\  cmp x3, x2
        \\  b.hs lc_copy_end
        \\  ldrb w4, [x1], #1
        \\  strb w4, [x0], #1
        \\  add x3, x3, #1
        \\  b 2b
        \\lc_copy_end:
        \\  mov x0, x3
        \\  ret
        \\.globl lc_str_in
        \\.globl lc_str_begin
        \\.globl lc_str_end
        \\lc_str_in:
        \\  mov x3, #0
        \\lc_str_begin:
        \\  cmp x3, x2
        \\  b.hs lc_str_end
        \\  ldrb w4, [x1, x3]
        \\  strb w4, [x0, x3]
        \\  add x3, x3, #1
        \\  cbnz w4, lc_str_begin
        \\lc_str_end:
        \\  mov x0, x3
        \\  ret
    );
}

extern fn lc_copy_in(dst: [*]u8, src: u64, n: u64) callconv(.C) u64;
extern fn lc_copy_begin() callconv(.C) void;
extern fn lc_copy_end() callconv(.C) void;
extern fn lc_str_in(dst: [*]u8, src: u64, max: u64) callconv(.C) u64;
extern fn lc_str_begin() callconv(.C) void;
extern fn lc_str_end() callconv(.C) void;

pub fn copyUser(dst: [*]u8, src: u64, n: u64) u64 {
    return lc_copy_in(dst, src, n);
}

pub fn strIn(dst: [*]u8, src: u64, max: u64) u64 {
    return lc_str_in(dst, src, max);
}

// copyFixup resumes a fault in lc_copy_in or lc_str_in at its exit, as the
// kernel's exception table does for copy_from_user, and reports whether the
// fault was one. A fault is always a load, before the count moves.
pub fn copyFixup(uc: [*]u8) bool {
    const pc = at(uc, UC_PC).*;
    if (pc >= @intFromPtr(&lc_copy_begin) and pc < @intFromPtr(&lc_copy_end)) {
        at(uc, UC_PC).* = @intFromPtr(&lc_copy_end);
        return true;
    }
    if (pc >= @intFromPtr(&lc_str_begin) and pc < @intFromPtr(&lc_str_end)) {
        at(uc, UC_PC).* = @intFromPtr(&lc_str_end);
        return true;
    }
    return false;
}

// cpCancel moves a kick that interrupted lc_cp_sys before its svc to the
// cancelled exit.
pub fn cpCancel(uc: [*]u8) void {
    const pc = at(uc, UC_PC).*;
    if (pc >= @intFromPtr(&lc_cp_begin) and pc < @intFromPtr(&lc_cp_end))
        at(uc, UC_PC).* = @intFromPtr(&lc_cp_cancel);
}

// ucPc is the interrupted pc of a host signal context.
pub fn ucPc(uc: [*]u8) u64 {
    return at(uc, UC_PC).*;
}

fn at(uc: [*]u8, off: usize) *align(1) u64 {
    return @ptrCast(uc + off);
}

pub fn ucSp(uc: [*]u8) *align(1) u64 {
    return at(uc, UC_SP);
}

pub fn ucRet(uc: [*]u8) *align(1) u64 {
    return reg(uc, 0);
}

// setRestart makes the syscall re-execute: x0 is its first argument again.
pub fn setRestart(uc: [*]u8, pc: u64, orig: u64) void {
    at(uc, UC_PC).* = pc;
    reg(uc, 0).* = orig;
}

// setRestartBlock points the restart at restart_syscall (x8 is the number).
pub fn setRestartBlock(uc: [*]u8, pc: u64, orig: u64) void {
    setRestart(uc, pc, orig);
    reg(uc, 8).* = @intFromEnum(stub.SYS.restart_syscall);
}

fn rd(comptime T: type, a: u64) T {
    return @as(*align(1) const T, @ptrFromInt(a)).*;
}

fn wr(comptime T: type, a: u64, v: T) void {
    @as(*align(1) T, @ptrFromInt(a)).* = v;
}

fn copy(dst: u64, src: u64, n: u64) void {
    @memcpy(@as([*]u8, @ptrFromInt(dst))[0..n], @as([*]const u8, @ptrFromInt(src))[0..n]);
}

// hostFrame returns the extent of the kernel's frame around uc, and its
// extra_context record (0 if none).
fn hostFrame(uc: [*]u8) struct { lo: u64, hi: u64, extra: u64 } {
    const lo = @intFromPtr(uc) - 128;
    var hi = lo + FRAME_SIZE;
    var r = @intFromPtr(uc) + UC_RESERVED;
    const end = r + 4096;
    var extra: u64 = 0;
    while (r + 8 <= end) {
        const magic = rd(u32, r);
        const size = rd(u32, r + 4);
        if (magic == 0 or size < 8) break;
        if (magic == EXTRA_MAGIC) {
            extra = r;
            hi = @max(hi, rd(u64, r + 8) + rd(u32, r + 16));
        }
        r += size;
    }
    return .{ .lo = lo, .hi = (hi + 15) & ~@as(u64, 15), .extra = extra };
}

// pushFrame writes the guest's rt_sigframe and frame record below st.top,
// as the kernel's get_sigframe and setup_rt_frame do, copying the kernel's
// frame of the host handler (which holds the interrupted context, FP/SIMD
// and SVE state included), and points uc at the handler.
pub fn pushFrame(uc: [*]u8, st: sig.Stack, signo: u32, info: *const [128]u8, handler: u64, restorer: u64, uc_mask: u64) void {
    const h = hostFrame(uc);
    const rec = (st.top - 16) & ~@as(u64, 15);
    wr(u64, rec, reg(uc, 29).*);
    wr(u64, rec + 8, reg(uc, 30).*);
    const fr = (rec - (h.hi - h.lo)) & ~@as(u64, 15);
    copy(fr, h.lo, h.hi - h.lo);
    if (h.extra != 0) {
        const r = fr + (h.extra - h.lo);
        wr(u64, r + 8, rd(u64, r + 8) - h.lo + fr);
    }
    copy(fr, @intFromPtr(info), 128);
    const guc = fr + 128;
    wr(u64, guc + 8, 0);
    wr(u64, guc + 16, st.ss_sp);
    wr(u64, guc + 24, st.ss_flags);
    wr(u64, guc + 32, st.ss_size);
    wr(u64, guc + UC_SIGMASK, uc_mask);
    reg(uc, 0).* = signo;
    reg(uc, 1).* = fr;
    reg(uc, 2).* = guc;
    reg(uc, 29).* = rec;
    reg(uc, 30).* = restorer;
    at(uc, UC_SP).* = fr;
    at(uc, UC_PC).* = handler;
    at(uc, UC_PSTATE).* &= ~@as(u64, 0xc00); // BTYPE
}

// The guest's rt_sigreturn finds its frame at sp: siginfo, then ucontext.
pub fn frameOk(sp: u64) bool {
    return sp & 15 == 0;
}

pub fn frameUc(sp: u64) [*]u8 {
    return @ptrFromInt(sp + 128);
}

// frameOurs: arm64 has no nested-stub path (no gs-anchor port), so every frame
// this stub completes is its own. See the x86_64 version for the nesting case.
pub fn frameOurs(_: [*]u8) bool {
    return true;
}

// sigreturn performs the host rt_sigreturn on the frame at sp, clearing
// busy only once off the stub's stacks.
pub fn sigreturn(sp: u64, busy: *u32) noreturn {
    asm volatile (
        \\ mov sp, %[sp]
        \\ str wzr, [%[busy]]
        \\ mov x8, #139
        \\ svc #0
        :
        : [sp] "r" (sp),
          [busy] "r" (busy),
        : "x8", "memory"
    );
    unreachable;
}

// trap enters onSigill at lc_sig_trap.
pub fn trap() noreturn {
    asm volatile ("bl lc_sig_trap" ::: "x30", "memory");
    unreachable;
}

// lc_guest_restorer is the return address of a handler installed without
// SA_RESTORER (glibc and Go rely on the vDSO's, which the guest lacks).
pub export fn lc_guest_restorer() callconv(.Naked) noreturn {
    asm volatile (
        \\ mov x0, sp
        \\ bl lc_restorer_c
        \\ udf #0
    );
}

// lc_sig_trap traps into onSigill to deliver from the trampoline path.
pub export fn lc_sig_trap() callconv(.Naked) noreturn {
    asm volatile ("udf #0");
}

// ucFromFrame loads the guest's context at an island syscall's return into
// uc: the Frame's registers, NZCV and sp, and the resume pc.
fn ucFromFrame(uc: [*]u8, fp: u64, resume_pc: u64) void {
    const f: *const Frame = @ptrFromInt(fp);
    for (0..31) |i| reg(uc, i).* = f.x[i];
    const ps = at(uc, UC_PSTATE);
    ps.* = (ps.* & ~@as(u64, 0xf0000000)) | (f.nzcv & 0xf0000000);
    at(uc, UC_SP).* = f.sp;
    at(uc, UC_PC).* = resume_pc;
}

pub fn onSigill(_: i32, info: *const [128]u8, uc: [*]u8) callconv(.C) void {
    const pc = at(uc, UC_PC);
    if (pc.* == @intFromPtr(&lc_sig_trap)) {
        const t = sig.thr();
        if (t.frame != 0) ucFromFrame(uc, t.frame, t.resume_pc);
        trace.restore(uc);
        sig.deliverAll(uc, .{ .code = reg(uc, 0).*, .pc = t.restart, .orig = t.orig });
        @atomicStore(u32, &t.busy, 0, .seq_cst);
        return;
    }
    sig.beginSyscall(sig.thr());
    var f: Frame = undefined;
    for (0..31) |i| f.x[i] = reg(uc, i).*;
    f.nzcv = at(uc, UC_PSTATE).*;
    const site = pc.*;
    f.resume_at = site + 4;
    const r = stub.handle(slot(), &f, site, site + 4, at(uc, UC_SP).*, @intFromPtr(uc));
    const t = sig.thr();
    if (r == stub.NOT_A_SITE) {
        sig.fault(uc, sig.SIGILL, info);
    } else {
        reg(uc, 0).* = r;
        pc.* = site + 4;
        trace.restore(uc);
        if (sig.isRestart(r) or sig.deliverable(t) != 0)
            sig.deliverAll(uc, .{ .code = r, .pc = site, .orig = f.x[0] });
    }
    @atomicStore(u32, &t.busy, 0, .seq_cst);
}

// onSigsys services a raw guest syscall the rewriter left un-rewritten: the
// stub's seccomp filter TRAPs an out-of-text svc here instead of killing it.
// Mirrors onSigill but with site 0 (a raw syscall, like a trampoline call, so
// the supervisor does not validate it). The kernel's saved pc (ELR) is past
// the 4-byte svc, so the guest resumes at UC_PC and a restart re-runs at
// UC_PC-4. A SIGSYS the guest raised for itself is delivered on, like a fault.
pub fn onSigsys(_: i32, info: *const [128]u8, uc: [*]u8) callconv(.C) void {
    const pc = at(uc, UC_PC);
    const siCode = std.mem.readInt(i32, info[8..12], .little);
    const siErrno = std.mem.readInt(i32, info[4..8], .little);
    if (slotAddr() == 0) stub.die(128 + sig.SIGSYS);
    if (siCode != sig.SI_CODE_SECCOMP or @as(u32, @bitCast(siErrno)) != sig.SECCOMP_TRAP_TAG) {
        const t = sig.thr();
        if (@atomicLoad(u32, &t.busy, .seq_cst) != 0) stub.die(128 + sig.SIGSYS);
        @atomicStore(u32, &t.busy, 1, .seq_cst);
        sig.fault(uc, sig.SIGSYS, info);
        @atomicStore(u32, &t.busy, 0, .seq_cst);
        return;
    }
    sig.beginSyscall(sig.thr());
    var f: Frame = undefined;
    for (0..31) |i| f.x[i] = reg(uc, i).*;
    f.nzcv = at(uc, UC_PSTATE).*;
    const resume_pc = pc.*; // already past the svc
    f.resume_at = resume_pc;
    const orig = f.x[0];
    const r = stub.handle(slot(), &f, 0, resume_pc, at(uc, UC_SP).*, @intFromPtr(uc));
    const t = sig.thr();
    reg(uc, 0).* = r;
    pc.* = resume_pc;
    trace.restore(uc);
    if (sig.isRestart(r) or sig.deliverable(t) != 0)
        sig.deliverAll(uc, .{ .code = r, .pc = resume_pc - 4, .orig = orig });
    @atomicStore(u32, &t.busy, 0, .seq_cst);
}

// lc_tramp_syscall services a syscall taken through an island
// (lc_syscall_entry), on the slot's own stack. The entry has already cleared
// kicked and marked the thread busy, so it does not beginSyscall, which would
// lose a kick taken since; it leaves busy set on the fast return, which the
// entry clears once it is back on the guest's stack.
export fn lc_tramp_syscall(f: *Frame) callconv(.C) void {
    const ch = slot();
    const orig = f.x[0];
    const r = stub.handle(ch, f, 0, f.resume_at, f.sp, 0);
    f.x[0] = r;
    stub.trampExitGs(@intFromPtr(f), r, f.resume_at, f.resume_at - 4, orig);
}

// lc_tramp_latekick delivers a kick lc_syscall_entry found on its way out
// (kicked after it cleared busy), with the guest's whole context from the
// Frame still on the slot's stack, as trampExit's trap tail does.
export fn lc_tramp_latekick(f: *Frame) callconv(.C) void {
    const t = sig.thr();
    t.frame = @intFromPtr(f);
    t.resume_pc = f.resume_at;
    t.restart = f.resume_at - 4;
    t.orig = f.x[0];
    trap();
}

// lc_syscall_entry is reached from an island (OwnStack) with sp = guest sp -
// 160: [sp] = &epilogue, [sp+16] = guest x16, x17; x17 = resume pc. Nothing
// may go on the guest's stack beyond that (a Go goroutine stack is small and
// its neighbour lies under it), so it spills x0 and x8 just below, finds the
// slot through the tid table (gettid), marks the thread busy (clearing kicked
// first, so the acquire cannot lose a kick) before sp leaves the guest's
// stack, and saves the Frame on the slot's own stack (Thread.scratch_top),
// with the guest's sp, under a stash of the island's return address and the
// slot. While the syscall is served nothing below the guest's sp is live, as
// on Linux, whose kernel keeps a blocked thread's state off its stack: a vfork
// child runs on that stack meanwhile. On the fast return it restores every
// register but x0 (the result) and x16/x17, writes the island's words back
// below the guest's sp (its epilogue reloads x16/x17 there), clears busy and,
// unless a kick came meanwhile (lc_latekick), returns through the epilogue.
// Thread is at REC_OFF 128: busy +0, kicked +52, scratch_top +64.
comptime {
    std.debug.assert(sig.REC_OFF == 128);
    std.debug.assert(@offsetOf(sig.Thread, "busy") == 0);
    std.debug.assert(@offsetOf(sig.Thread, "kicked") == 52);
    std.debug.assert(@offsetOf(sig.Thread, "scratch_top") == 64);
    std.debug.assert(MAX_TID == 1 << 22);
    std.debug.assert(@offsetOf(Frame, "resume_at") == 256 and @offsetOf(Frame, "sp") == 264);
    asm (
        \\.globl lc_syscall_entry
        \\lc_syscall_entry:
        \\  stp x0, x8, [sp, #-16]!
        \\  mov x8, #178
        \\  svc #0
        \\  and x0, x0, #0x3fffff
        \\  adrp x16, lc_tids
        \\  ldr x16, [x16, :lo12:lc_tids]
        \\  ldr x16, [x16, x0, lsl #3]
        \\  str wzr, [x16, #180]
        \\  mov w8, #1
        \\  str w8, [x16, #128]
        \\  dmb ish
        \\  ldr x8, [x16, #192]
        \\  mov x0, sp
        \\  sub sp, x8, #288
        \\  stp x17, x0, [sp, #272]
        \\  add x8, x0, #176
        \\  str x8, [sp, #280]
        \\  ldr x8, [x0, #16]
        \\  stp x8, x16, [sp]
        \\  mov x17, x0
        \\  ldp x0, x8, [x17]
        \\  stp x0, x1, [sp, #16]
        \\  stp x2, x3, [sp, #32]
        \\  stp x4, x5, [sp, #48]
        \\  stp x6, x7, [sp, #64]
        \\  stp x8, x9, [sp, #80]
        \\  stp x10, x11, [sp, #96]
        \\  stp x12, x13, [sp, #112]
        \\  stp x14, x15, [sp, #128]
        \\  ldp x0, x1, [x17, #32]
        \\  stp x0, x1, [sp, #144]
        \\  stp x18, x19, [sp, #160]
        \\  stp x20, x21, [sp, #176]
        \\  stp x22, x23, [sp, #192]
        \\  stp x24, x25, [sp, #208]
        \\  stp x26, x27, [sp, #224]
        \\  stp x28, x29, [sp, #240]
        \\  mrs x9, nzcv
        \\  stp x30, x9, [sp, #256]
        \\  add x0, sp, #16
        \\  bl lc_tramp_syscall
        \\  ldp x30, x9, [sp, #256]
        \\  msr nzcv, x9
        \\  ldp x28, x29, [sp, #240]
        \\  ldp x26, x27, [sp, #224]
        \\  ldp x24, x25, [sp, #208]
        \\  ldp x22, x23, [sp, #192]
        \\  ldp x20, x21, [sp, #176]
        \\  ldp x18, x19, [sp, #160]
        \\  ldp x14, x15, [sp, #128]
        \\  ldp x12, x13, [sp, #112]
        \\  ldp x10, x11, [sp, #96]
        \\  ldp x8, x9, [sp, #80]
        \\  ldp x6, x7, [sp, #64]
        \\  ldp x4, x5, [sp, #48]
        \\  ldp x2, x3, [sp, #32]
        \\  ldr x17, [sp, #280]
        \\  ldp x0, x1, [sp, #144]
        \\  stp x0, x1, [x17, #-144]
        \\  ldp x0, x16, [sp]
        \\  str x0, [x17, #-160]
        \\  ldp x0, x1, [sp, #16]
        \\  sub sp, x17, #160
        \\  str wzr, [x16, #128]
        \\  dmb ish
        \\  ldr w17, [x16, #180]
        \\  cbnz w17, lc_latekick
        \\  ldr x16, [sp]
        \\  br x16
    );
}

// lc_latekick is branched to from lc_syscall_entry's exit when kicked is set
// after it cleared busy: the guest's registers are back but for x16 (the
// slot) and x17, and sp is the island's. It reacquires busy before it leaves
// the guest's stack, goes back to the Frame, still whole on the slot's stack,
// and delivers through lc_tramp_latekick.
comptime {
    asm (
        \\.globl lc_latekick
        \\lc_latekick:
        \\  mov w17, #1
        \\  str w17, [x16, #128]
        \\  dmb ish
        \\  ldr x17, [x16, #192]
        \\  sub sp, x17, #272
        \\  mov x0, sp
        \\  bl lc_tramp_latekick
        \\  brk #0
    );
}

pub export fn stub_restorer() callconv(.Naked) noreturn {
    asm volatile (
        \\ mov x8, #139
        \\ svc #0
    );
}

pub export fn _start() callconv(.Naked) noreturn {
    asm volatile (
        \\ mov x29, xzr
        \\ mov x30, xzr
        \\ mov x0, sp
        \\ and x1, x0, #-16
        \\ mov sp, x1
        \\ bl stub_main
        \\ brk #0
    );
}

pub const Registers = extern struct { x: [31]u64, sp: u64, pc: u64, pstate: u64 };

pub fn frameRegs(f: *const Frame, pc: u64, sp: u64) Registers {
    return .{ .x = f.x, .sp = sp, .pc = pc, .pstate = f.nzcv & 0xf0000000 };
}

pub fn saveRegs(uc: [*]u8) Registers {
    var r: Registers = undefined;
    for (0..31) |i| r.x[i] = reg(uc, i).*;
    r.sp = ucSp(uc).*;
    r.pc = ucPc(uc);
    r.pstate = at(uc, UC_PSTATE).*;
    return r;
}

pub fn restoreRegs(uc: [*]u8, r: *const Registers) void {
    for (0..31) |i| reg(uc, i).* = r.x[i];
    at(uc, UC_SP).* = r.sp;
    at(uc, UC_PC).* = r.pc;
    at(uc, UC_PSTATE).* = r.pstate;
}
