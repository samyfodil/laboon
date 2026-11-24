// x86-64 half of the stub. A thread running on one of its slot's stacks finds
// the slot from its stack pointer (stub.slotBySp); elsewhere through a private
// table indexed by its kernel tid (one gettid per lookup), the same way arm64
// does. The table (tidsAddr()) is sparse anonymous memory; a forked child
// inherits it and records its own tid, a new thread records its in setSlot.
// The stub also owns the real %gs as a per-thread anchor for the syscall
// trampoline (setSlot): %gs:scratch_top is this thread's service stack and
// %gs:sp holds the guest sp, so the trampoline needs no syscall and touches
// no guest stack. Each stub process owns its own %gs, so nesting composes; the
// guest's own %gs is virtualized (Thread.guest_gs), as the slot lookup stays
// on the tid table rather than %gs.

const std = @import("std");
const stub = @import("stub.zig");
const sig = stub.sig;
const trace = @import("trace.zig");
const nr = stub.nr;

pub const AUDIT_ARCH: u32 = 0xc000003e;
pub const R_RELATIVE: u64 = 8; // R_X86_64_RELATIVE

const ARCH_SET_GS = 0x1001;
const ARCH_SET_FS = 0x1002;
const ARCH_GET_GS = 0x1004;

pub const allowed = [_]stub.SYS{
    .read,  .write,        .writev,         .mmap,       .mprotect, .munmap, .mremap, .madvise,
    .getpid, .gettid,      .futex,          .rt_sigreturn, .rt_sigprocmask, .arch_prctl, .clone,
    .exit,  .exit_group,   .sigaltstack,    .tgkill,     .recvmsg,  .close,  .msync, .mincore,
    .clock_gettime, .clock_getres, .gettimeofday, .getrusage, .getcpu,
    .rseq,          .restart_syscall, .membarrier, .set_tid_address,
};

// guest is what a guest thread may call (seccomp.zig).
pub const guest = [_]stub.SYS{
    .read,          .write,        .writev,       .getpid,    .gettid, .futex, .rt_sigreturn,
    .rt_sigprocmask, .arch_prctl,  .clone,        .exit,      .exit_group, .sigaltstack, .tgkill,
    .clock_gettime, .clock_getres, .gettimeofday, .getrusage, .getcpu,
    .rseq,          .restart_syscall,
};

pub inline fn sys6(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) u64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> u64),
        : [n] "{rax}" (n),
          [a] "{rdi}" (a),
          [b] "{rsi}" (b),
          [c] "{rdx}" (c),
          [d] "{r10}" (d),
          [e] "{r8}" (e),
          [f] "{r9}" (f),
        : "rcx", "r11", "memory"
    );
}

pub inline fn pause() void {
    asm volatile ("pause");
}

// ticks reads the time-stamp counter -- a steady cycle clock shared with the
// supervisor (same invariant TSC), so the park cost it measures is valid here.
pub inline fn ticks() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

inline fn tidsAddr() u64 {
    return stub.winBase + 0x16000000000;
}
const MAX_TID: u64 = 4 << 20; // PID_MAX_LIMIT

pub fn init() void {
    const flags = 0x02 | 0x10 | 0x20 | 0x4000; // PRIVATE|FIXED|ANONYMOUS|NORESERVE
    if (sys6(nr(.mmap), tidsAddr(), MAX_TID * 8, 3, flags, ~@as(u64, 0), 0) != tidsAddr()) stub.die(124);
}

fn tidSlot() *u64 {
    const tid = sys6(nr(.gettid), 0, 0, 0, 0, 0, 0);
    const t: [*]u64 = @ptrFromInt(tidsAddr());
    return &t[tid % MAX_TID];
}

pub fn slot() *stub.Chan {
    return @ptrFromInt(slotAddr());
}

// slotAddr is 0 for a thread that has not set its slot yet.
pub fn slotAddr() u64 {
    const s = stub.slotBySp(asm volatile ("mov %%rsp, %[r]"
        : [r] "=r" (-> u64),
    ));
    return if (s != 0) s else tidSlot().*;
}

pub fn redZone(sp: u64) u64 {
    return sp - 128;
}

pub fn setSlot(addr: u64) void {
    tidSlot().* = addr;
    // Own %gs for this thread: its base is the slot page, so a syscall
    // trampoline reads its service-stack top (%gs:scratch_top) and saves the
    // guest sp (%gs:sp) with no syscall and no guest-stack write. The stub
    // itself is never rewritten, so this arch_prctl runs directly even when the
    // stub is a nested laboon's guest; each stub process owns its own %gs. The
    // guest's own %gs is virtualized in Thread.guest_gs.
    const t = sig.recOf(@ptrFromInt(addr));
    t.scratch_top = stub.scratchTop(@ptrFromInt(addr));
    _ = sys6(nr(.arch_prctl), ARCH_SET_GS, addr, 0, 0, 0, 0);
}

// Frame is the guest's general-purpose register file at a syscall. It is
// built on both syscall paths so a clone child can be given the guest's full
// register state, which glibc/musl pass on the child stack but Go passes in
// registers (r12=fn, r13=mp, r9=gp).
pub const Frame = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rax: u64,
    eflags: u64,

    pub fn number(f: *const Frame) u64 {
        return f.rax;
    }

    pub fn args(f: *const Frame) [6]u64 {
        return .{ f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9 };
    }
};

extern fn lc_clone_thread(flags: u64, sp: u64, ctid: u64) callconv(.C) u64;
extern fn lc_enter_guest(block: u64) callconv(.C) noreturn;

// clone creates a new stub thread for a guest clone. args from the
// supervisor: [0]=guest child stack, [1]=guest TLS (fs base, 0 to inherit),
// [2]=new slot address (recorded in the tid table), [3]=stub bootstrap stack
// top. The child restores the guest register frame, sets fs, records its slot,
// and resumes at guest_rip with rax=0 on the child stack. The real thread tid
// is irrelevant to the guest.
pub fn clone(ch: *stub.Chan, f: *const Frame) u64 {
    // A handoff block near the top of the child bootstrap stack:
    // { slot, fs, rip, childstack, frame }. Offsets match lc_clone_thread.
    // The block is 16-byte aligned for the call to lc_thread_start.
    const b: [*]u64 = @ptrFromInt(ch.args[3] - 160);
    b[0] = ch.args[2];
    b[1] = ch.args[1];
    b[2] = ch.guest_rip;
    b[3] = ch.args[0];
    @as(*Frame, @ptrCast(b + 4)).* = f.*;
    return lc_clone_thread(stub.THREAD_FLAGS, ch.args[3] - 160, ch.args[2] + stub.ALIVE_OFF);
}

// enterGuest resumes the guest at rip on stack sp with frame f's registers
// and rax=0, as a clone child starts (a fork child given a stack).
pub fn enterGuest(f: *const Frame, rip: u64, sp: u64) noreturn {
    var b: [4 + @sizeOf(Frame) / 8]u64 align(16) = undefined;
    b[1] = 0; // fs as it is
    b[2] = rip;
    b[3] = sp;
    @as(*Frame, @ptrCast(&b[4])).* = f.*;
    lc_enter_guest(@intFromPtr(&b));
}

// lc_thread_start sets up a new stub thread: its slot, its alternate signal
// stack, an empty signal mask (our handlers must run; the guest's own mask is
// virtual) and its id for the supervisor's kicks.
export fn lc_thread_start(slot_addr: u64) callconv(.C) void {
    setSlot(slot_addr);
    stub.setAltstack(slot_addr);
    stub.unblockSignals();
    sig.recOf(@ptrFromInt(slot_addr)).host_tid = @truncate(stub.sys(nr(.gettid), 0, 0, 0, 0, 0, 0));
    stub.traceStart(@ptrFromInt(slot_addr));
}

// lc_clone_thread(flags, block, ctid) clones; the parent returns the tid. The
// child starts with rsp at the handoff block, sets up the thread, sets fs
// unless asked to inherit it, restores the guest frame and jumps to the
// guest with rax=0.
comptime {
    asm (
        \\.globl lc_clone_thread
        \\lc_clone_thread:
        \\  mov %rdx, %r10
        \\  xor %edx, %edx
        \\  xor %r8d, %r8d
        \\  xor %r9d, %r9d
        \\  mov $56, %eax
        \\  syscall
        \\  test %rax, %rax
        \\  jnz 1f
        \\  mov %rsp, %rbx
        \\  mov 0(%rbx), %rdi
        \\  call lc_thread_start
        \\.Lguest:
        \\  mov 8(%rbx), %rsi
        \\  test %rsi, %rsi
        \\  jz 2f
        \\  mov $158, %eax
        \\  mov $0x1002, %edi
        \\  syscall
        \\2:
        \\  call lc_trace_child
        \\  mov 16(%rbx), %r11
        \\  mov 32(%rbx), %r15
        \\  mov 40(%rbx), %r14
        \\  mov 48(%rbx), %r13
        \\  mov 56(%rbx), %r12
        \\  mov 64(%rbx), %rbp
        \\  mov 88(%rbx), %r10
        \\  mov 96(%rbx), %r9
        \\  mov 104(%rbx), %r8
        \\  mov 120(%rbx), %rdx
        \\  mov 128(%rbx), %rsi
        \\  mov 136(%rbx), %rdi
        \\  mov 24(%rbx), %rsp
        \\  mov 72(%rbx), %rbx
        \\  xor %eax, %eax
        \\  jmp *%r11
        \\1:
        \\  ret
        \\.globl lc_enter_guest
        \\lc_enter_guest:
        \\  mov %rdi, %rbx
        \\  jmp .Lguest
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
// its state is in registers -- r12 the request page (the reply page is
// HOP_REP past it), r14 the last request's sequence number, r15 the spin cap,
// rbx/rbp/r13 the spin budget and the EWMAs of caught requests' latency and
// its deviation (stub.zig spinHit/spinMiss) -- and it touches no stack. A
// request (seq past r14) is a syscall nr(args) whose result goes on the reply
// page, or HOP_FORK; a fork's child takes its copy's arguments to
// lc_hop_forked.
comptime {
    asm (
        \\.globl lc_hop_spawn
        \\lc_hop_spawn:
        \\  push %r12
        \\  push %r15
        \\  mov %rdx, %r12
        \\  mov %rcx, %r15
        \\  xor %edx, %edx
        \\  xor %r10d, %r10d
        \\  xor %r8d, %r8d
        \\  mov $56, %eax
        \\  syscall
        \\  test %rax, %rax
        \\  jz lc_hop_loop
        \\  pop %r15
        \\  pop %r12
        \\  ret
        \\lc_hop_loop:
        \\  mov $14, %eax
        \\  mov $2, %edi
        \\  lea lc_all_signals(%rip), %rsi
        \\  xor %edx, %edx
        \\  mov $8, %r10d
        \\  syscall
        \\  xor %r14d, %r14d
        \\  mov %r15, %rbx
        \\  xor %ebp, %ebp
        \\  xor %r13d, %r13d
        \\.Lhwait:
        \\  rdtsc
        \\  shl $32, %rdx
        \\  or %rdx, %rax
        \\  mov %rax, %r8
        \\  lea (%rax,%rbx), %r9
        \\.Lhspin:
        \\  mov $32, %ecx
        \\.Lhpoll:
        \\  mov (%r12), %eax
        \\  cmp %r14d, %eax
        \\  jne .Lhhit
        \\  pause
        \\  dec %ecx
        \\  jnz .Lhpoll
        \\  rdtsc
        \\  shl $32, %rdx
        \\  or %rdx, %rax
        \\  cmp %r9, %rax
        \\  jb .Lhspin
        \\.Lhpark:
        \\  movabs $0x400000004, %rdx
        \\  add %r12, %rdx
        \\  mov $1, %eax
        \\  xchg %eax, (%rdx)
        \\  mov (%r12), %eax
        \\  cmp %r14d, %eax
        \\  jne .Lhwoke
        \\  mov $202, %eax
        \\  mov %r12, %rdi
        \\  xor %esi, %esi
        \\  mov %r14d, %edx
        \\  xor %r10d, %r10d
        \\  syscall
        \\.Lhwoke:
        \\  movabs $0x400000004, %rdx
        \\  add %r12, %rdx
        \\  xor %eax, %eax
        \\  xchg %eax, (%rdx)
        \\  mov (%r12), %eax
        \\  cmp %r14d, %eax
        \\  je .Lhpark
        \\  rdtsc
        \\  shl $32, %rdx
        \\  or %rdx, %rax
        \\  sub %r8, %rax
        \\  cmp %r15, %rax
        \\  jae .Lhfar
        \\  mov %r15, %rax
        \\  sub %rbx, %rax
        \\  shr $1, %rax
        \\  add %rax, %rbx
        \\  jmp .Lhgot
        \\.Lhfar:
        \\  mov %rbx, %rax
        \\  shr $2, %rax
        \\  sub %rax, %rbx
        \\  mov %r15, %rax
        \\  shr $7, %rax
        \\  cmp %rax, %rbx
        \\  jae .Lhgot
        \\  xor %ebx, %ebx
        \\  jmp .Lhgot
        \\.Lhhit:
        \\  rdtsc
        \\  shl $32, %rdx
        \\  or %rdx, %rax
        \\  sub %r8, %rax
        \\  mov %rbp, %rcx
        \\  shr $3, %rcx
        \\  sub %rcx, %rbp
        \\  mov %rax, %rcx
        \\  shr $3, %rcx
        \\  add %rcx, %rbp
        \\  sub %rbp, %rax
        \\  jae 1f
        \\  neg %rax
        \\1:
        \\  mov %r13, %rcx
        \\  shr $3, %rcx
        \\  sub %rcx, %r13
        \\  shr $3, %rax
        \\  add %rax, %r13
        \\  lea (%rbp,%r13,4), %rbx
        \\  cmp %r15, %rbx
        \\  jbe .Lhgot
        \\  mov %r15, %rbx
        \\.Lhgot:
        \\  mov 8(%r12), %rax
        \\  cmp $-1, %rax
        \\  je .Lhfork
        \\  mov 16(%r12), %rdi
        \\  mov 24(%r12), %rsi
        \\  mov 32(%r12), %rdx
        \\  mov 40(%r12), %r10
        \\  mov 48(%r12), %r8
        \\  mov 56(%r12), %r9
        \\  syscall
        \\.Lhreply:
        \\  movabs $0x400000000, %rdx
        \\  add %r12, %rdx
        \\  mov %rax, 8(%rdx)
        \\  mov (%r12), %ecx
        \\  mov %ecx, %r14d
        \\  xchg %ecx, (%rdx)
        \\  mov 4(%r12), %eax
        \\  test %eax, %eax
        \\  jz .Lhwait
        \\  mov $202, %eax
        \\  mov %rdx, %rdi
        \\  mov $1, %esi
        \\  mov $1, %edx
        \\  syscall
        \\  jmp .Lhwait
        \\.Lhfork:
        \\  mov $0x8011, %edi
        \\  xor %esi, %esi
        \\  mov 16(%r12), %rdx
        \\  mov 24(%r12), %r10
        \\  mov 32(%r12), %r8
        \\  mov 40(%r12), %r9
        \\  mov $56, %eax
        \\  syscall
        \\  test %rax, %rax
        \\  jnz .Lhreply
        \\  mov %rdx, %rdi
        \\  mov %r10, %rsi
        \\  mov %r8, %rdx
        \\  mov %r9, %rcx
        \\  mov %r15, %r8
        \\  and $-16, %rsp
        \\  xor %ebp, %ebp
        \\  call lc_hop_forked
        \\  ud2
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
        \\  mov %rdi, %rsp
        \\  mov %rsi, %rdi
        \\  mov %rdx, %rsi
        \\  mov %rcx, %rdx
        \\  mov %r8, %rcx
        \\  mov %r9, %r8
        \\  xor %ebp, %ebp
        \\  call lc_fork_child
        \\  ud2
    );
}

// guestTls is the guest's thread pointer, its fs base.
pub fn guestTls() u64 {
    return fsBase();
}

// saveFp stores the guest's FP/SIMD state at dst (64-aligned) in XSAVE's
// standard form: from the signal frame at uc when the syscall came in one
// (the kernel reset the live registers for the handler), else the live
// registers, which the stub never touches.
pub fn saveFp(dst: u64, uc: u64) void {
    const fp = if (uc != 0) rd(u64, uc + UC_FPSTATE) else 0;
    if (fp != 0) {
        if (rd(u32, fp + FP_SW_MAGIC1) == FP_XSTATE_MAGIC1) {
            copy(dst, fp, rd(u32, fp + FP_SW_XSTATE_SIZE));
        } else {
            copy(dst, fp, 512);
            xsaveHeader(dst, 3); // x87 and SSE, the legacy area's
        }
        return;
    }
    xsaveHeader(dst, 0); // XSAVE sets the components it saves
    asm volatile (".byte 0x48, 0x0f, 0xae, 0x27" // xsave64 (%rdi)
        :
        : [d] "{rdi}" (dst),
          [lo] "{eax}" (@as(u32, 0xffffffff)),
          [hi] "{edx}" (@as(u32, 0xffffffff)),
        : "memory"
    );
}

// xsaveHeader clears the XSAVE header at dst+512, whose reserved bytes XRSTOR
// requires zero, with bv as the components present.
fn xsaveHeader(dst: u64, bv: u64) void {
    @memset(@as([*]u8, @ptrFromInt(dst + 512))[0..64], 0);
    wr(u64, dst + 512, bv);
}

// resumeFork enters the guest as the forking thread's copy: its registers
// (with the fork's 0 result), its fs, its FP/SIMD state from fp, at its
// resume pc on stack sp. It leaves through the trap, which delivers a signal
// already pending as at any syscall's return.
pub fn resumeFork(c: *stub.ForkCtx, fp: u64, sp: u64) noreturn {
    const t = sig.thr();
    t.orig = c.frame.rax;
    c.frame.rax = 0;
    t.frame = @intFromPtr(&c.frame);
    t.resume_pc = c.rip;
    t.restart = c.rip - 2;
    t.sp = sp;
    _ = sys6(nr(.arch_prctl), ARCH_SET_FS, c.tls, 0, 0, 0, 0);
    asm volatile (".byte 0x48, 0x0f, 0xae, 0x2f" // xrstor64 (%rdi)
        :
        : [d] "{rdi}" (fp),
          [lo] "{eax}" (@as(u32, 0xffffffff)),
          [hi] "{edx}" (@as(u32, 0xffffffff)),
        : "memory"
    );
    trap();
}

// exitWake ends the thread as CLONE_CHILD_CLEARTID would at its tid word:
// it clears ctid, wakes a joiner (both futex kinds a libc may wait with) and
// exits, touching no stack after the wake: the joiner may unmap it as soon as
// it runs.
pub fn exitWake(ctid: u64, code: u64) noreturn {
    asm volatile (
        \\ movl $0, (%%rdi)
        \\ mov $202, %%eax
        \\ mov $1, %%esi
        \\ mov $1, %%edx
        \\ syscall
        \\ mov $202, %%eax
        \\ mov $129, %%esi
        \\ mov $1, %%edx
        \\ syscall
        \\ mov %%r8, %%rdi
        \\ mov $60, %%eax
        \\ syscall
        :
        : [ctid] "{rdi}" (ctid),
          [code] "{r8}" (code),
        : "rax", "rsi", "rdx", "rcx", "r11", "memory"
    );
    unreachable;
}

// execHandoff switches to the slot's exec stack and jumps into the exec
// service loop, never returning to the caller's (guest) stack. The supervisor
// then tears down the old address space without pulling out a live stack.
pub fn execHandoff(sp: u64, ch: *stub.Chan) noreturn {
    asm volatile (
        \\ mov %%rax, %%rsp
        \\ jmp lc_exec_on_stack
        :
        : [sp] "{rax}" (sp),
          [ch] "{rdi}" (ch),
        : "memory"
    );
    unreachable;
}

// enter starts guest code at entry on stack sp, as the kernel does at exec.
pub fn enter(entry: u64, sp: u64) noreturn {
    asm volatile (
        \\ mov %%rdi, %%rsp
        \\ xor %%edx, %%edx
        \\ xor %%ebp, %%ebp
        \\ jmp *%%rax
        :
        : [sp] "{rdi}" (sp),
          [entry] "{rax}" (entry),
        : "memory"
    );
    unreachable;
}

// Offsets into the kernel's ucontext: gregs start at byte 40, the fpstate
// pointer follows them at 224, then 64 reserved bytes, and uc_sigmask is at
// 296. The kernel's rt_sigframe is { pretcode, ucontext (304), siginfo }.
const G_R8 = 0;
const G_R9 = 1;
const G_R10 = 2;
const G_R11 = 3;
const G_R12 = 4;
const G_R13 = 5;
const G_R14 = 6;
const G_R15 = 7;
const G_RDI = 8;
const G_RSI = 9;
const G_RBP = 10;
const G_RBX = 11;
const G_RDX = 12;
const G_RAX = 13;
const G_RCX = 14;
const G_RSP = 15;
const G_RIP = 16;
const G_EFL = 17;
const UC_FPSTATE = 224;
// A reserved sigcontext word the kernel ignores: the frame keeps the slot's
// guest_rip in it, which a syscall entered just before the signal still
// needs and the handler's own syscalls overwrite.
const UC_GUEST_RIP = 232;
// Another reserved sigcontext word: the frame records which stub instance
// built it (its slot-region base). Under nesting a stub may be left to complete
// an rt_sigreturn for a frame a different layer built (the completer is the
// syscall site's owner, not always the frame's builder), so it adopts the
// frame's alternate stack into its own record only when it built the frame --
// a foreign frame's uc_stack is another instance's. See sig.sigreturn and frameOurs.
const UC_PROV = 240;
pub const UC_SIGMASK = 296;
const UC_SIZE = 304;
const FP_XSTATE_MAGIC1 = 0x46505853;
// The kernel's _fpx_sw_bytes, in the legacy area's software-reserved bytes.
const FP_SW_MAGIC1 = 464;
const FP_SW_XSTATE_SIZE = 480;

// ucPc is the interrupted pc of a host signal context.
pub fn ucPc(uc: [*]u8) u64 {
    return gregs(uc)[G_RIP];
}

fn gregs(uc: [*]u8) [*]align(1) u64 {
    return @ptrCast(uc + 40);
}

pub fn ucSp(uc: [*]u8) *align(1) u64 {
    return &gregs(uc)[G_RSP];
}

pub fn ucRet(uc: [*]u8) *align(1) u64 {
    return &gregs(uc)[G_RAX];
}

// setRestart makes the syscall re-execute: rax is its number again.
pub fn setRestart(uc: [*]u8, pc: u64, orig: u64) void {
    gregs(uc)[G_RIP] = pc;
    gregs(uc)[G_RAX] = orig;
}

// setRestartBlock points the restart at restart_syscall (rax is the number).
pub fn setRestartBlock(uc: [*]u8, pc: u64, _: u64) void {
    gregs(uc)[G_RIP] = pc;
    gregs(uc)[G_RAX] = @intFromEnum(stub.SYS.restart_syscall);
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

// pushFrame writes the guest's rt_sigframe below st.top, as the kernel's
// get_sigframe and setup_rt_frame do, from the interrupted context in uc
// (whose FP state the kernel saved for the host handler), and points uc at
// the handler.
pub fn pushFrame(uc: [*]u8, st: sig.Stack, signo: u32, info: *const [128]u8, handler: u64, restorer: u64, uc_mask: u64) void {
    const g = gregs(uc);
    const fp_src = rd(u64, @intFromPtr(uc) + UC_FPSTATE);
    var sp = st.top;
    var fp_dst: u64 = 0;
    if (fp_src != 0) {
        var n: u64 = 512;
        if (rd(u32, fp_src + 464) == FP_XSTATE_MAGIC1) n = rd(u32, fp_src + 468);
        sp = (sp - n) & ~@as(u64, 63);
        fp_dst = sp;
        copy(fp_dst, fp_src, n);
    }
    const fr = ((sp - (8 + UC_SIZE + 128)) & ~@as(u64, 15)) - 8;
    const guc = fr + 8;
    wr(u64, fr, restorer);
    copy(guc, @intFromPtr(uc), UC_SIZE);
    wr(u64, guc + 8, 0);
    wr(u64, guc + 16, st.ss_sp);
    wr(u64, guc + 24, st.ss_flags);
    wr(u64, guc + 32, st.ss_size);
    wr(u64, guc + UC_FPSTATE, fp_dst);
    wr(u64, guc + UC_GUEST_RIP, slot().guest_rip);
    wr(u64, guc + UC_PROV, stub.slotsAddr());
    wr(u64, guc + UC_SIGMASK, uc_mask);
    copy(guc + UC_SIZE, @intFromPtr(info), 128);
    g[G_RIP] = handler;
    g[G_RSP] = fr;
    g[G_RDI] = signo;
    g[G_RSI] = guc + UC_SIZE;
    g[G_RDX] = guc;
    g[G_RAX] = 0;
    g[G_EFL] &= ~@as(u64, 0x500); // DF, TF
}

// The guest's rt_sigreturn finds its ucontext at sp: the handler's ret
// popped pretcode.
pub fn frameOk(_: u64) bool {
    return true;
}

pub fn frameUc(sp: u64) [*]u8 {
    slot().guest_rip = rd(u64, sp + UC_GUEST_RIP);
    return @ptrFromInt(sp);
}

// frameOurs reports whether this stub instance built the frame at uc, by the
// instance stamp pushFrame wrote. A stub can be left to complete a frame an
// inner instance built; that frame's alternate stack is the inner instance's
// and must not enter this record (the mask is restored regardless).
pub fn frameOurs(uc: [*]u8) bool {
    return rd(u64, @intFromPtr(uc) + UC_PROV) == stub.slotsAddr();
}

// sigreturn performs the host rt_sigreturn on the frame whose ucontext is
// at sp, clearing busy only once off the stub's stacks.
pub fn sigreturn(sp: u64, busy: *u32) noreturn {
    asm volatile (
        \\ mov %[sp], %%rsp
        \\ movl $0, (%[busy])
        \\ mov $15, %%eax
        \\ syscall
        :
        : [sp] "r" (sp),
          [busy] "r" (busy),
        : "rax", "rcx", "r11", "memory"
    );
    unreachable;
}

// trap enters onSigill at lc_sig_trap.
pub fn trap() noreturn {
    asm volatile ("call lc_sig_trap" ::: "memory");
    unreachable;
}

// lc_guest_restorer is the return address of a handler installed without
// SA_RESTORER.
pub export fn lc_guest_restorer() callconv(.Naked) noreturn {
    asm volatile (
        \\ mov %%rsp, %%rdi
        \\ and $-16, %%rsp
        \\ call lc_restorer_c
        \\ ud2
    );
}

// lc_cp_sys(n, a0..a5, kicked) is a syscall a kick can cancel before it is
// made: from lc_cp_begin to the syscall instruction it checks *kicked, and a
// kick landing there is moved to lc_cp_cancel (cpCancel); one landing in the
// syscall interrupts it. Either way the result is EINTR.
comptime {
    asm (
        \\.globl lc_cp_sys
        \\.globl lc_cp_begin
        \\.globl lc_cp_end
        \\.globl lc_cp_cancel
        \\lc_cp_sys:
        \\  mov %rdi, %rax
        \\  mov %rsi, %rdi
        \\  mov %rdx, %rsi
        \\  mov %rcx, %rdx
        \\  mov %r8, %r10
        \\  mov %r9, %r8
        \\  mov 8(%rsp), %r9
        \\  mov 16(%rsp), %r11
        \\lc_cp_begin:
        \\  cmpl $0, (%r11)
        \\  jne lc_cp_cancel
        \\  syscall
        \\lc_cp_end:
        \\  ret
        \\lc_cp_cancel:
        \\  mov $-4, %rax
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

// symAddr returns a text symbol's runtime address with a RIP-relative lea, so
// the stub stays free of GOT relocations and runs at any load base verbatim
// (the nested PIE is placed wherever a free window is, with no fixup).
inline fn symAddr(comptime name: []const u8) u64 {
    return asm (" lea " ++ name ++ "(%rip), %[r]"
        : [r] "=r" (-> u64),
    );
}

// cpCancel moves a kick that interrupted lc_cp_sys before its syscall to
// the cancelled exit.
pub fn cpCancel(uc: [*]u8) void {
    const pc = gregs(uc)[G_RIP];
    if (pc >= symAddr("lc_cp_begin") and pc < symAddr("lc_cp_end"))
        gregs(uc)[G_RIP] = symAddr("lc_cp_cancel");
}

// lc_copy_in(dst, src, n) copies n bytes between guest memory and the stub,
// either way, and returns how many it copied: all, or those before a fault, which copyFixup
// resumes at lc_copy_fault with rcx counting the bytes left. lc_str_in(dst,
// src, max) copies a NUL-terminated string, the NUL included, up to max bytes,
// and returns how many it copied; a fault resumes at lc_str_end. The
// direction flag is cleared: a guest may call with it set.
comptime {
    asm (
        \\.globl lc_copy_in
        \\.globl lc_copy_begin
        \\.globl lc_copy_end
        \\.globl lc_copy_fault
        \\lc_copy_in:
        \\  mov %rdx, %rcx
        \\  cld
        \\lc_copy_begin:
        \\  rep movsb
        \\lc_copy_end:
        \\  mov %rdx, %rax
        \\  ret
        \\lc_copy_fault:
        \\  mov %rdx, %rax
        \\  sub %rcx, %rax
        \\  ret
        \\.globl lc_str_in
        \\.globl lc_str_begin
        \\.globl lc_str_end
        \\lc_str_in:
        \\  xor %eax, %eax
        \\lc_str_begin:
        \\  cmp %rdx, %rax
        \\  jae lc_str_end
        \\  movzbl (%rsi,%rax), %ecx
        \\  movb %cl, (%rdi,%rax)
        \\  inc %rax
        \\  test %cl, %cl
        \\  jnz lc_str_begin
        \\lc_str_end:
        \\  ret
    );
}

extern fn lc_copy_in(dst: [*]u8, src: u64, n: u64) callconv(.C) u64;
extern fn lc_str_in(dst: [*]u8, src: u64, max: u64) callconv(.C) u64;

pub fn copyUser(dst: [*]u8, src: u64, n: u64) u64 {
    return lc_copy_in(dst, src, n);
}

pub fn strIn(dst: [*]u8, src: u64, max: u64) u64 {
    return lc_str_in(dst, src, max);
}

// copyFixup resumes a fault in lc_copy_in or lc_str_in at its fault exit, as
// the kernel's exception table does for copy_from_user, and reports whether
// the fault was one.
pub fn copyFixup(uc: [*]u8) bool {
    const pc = gregs(uc)[G_RIP];
    if (pc >= symAddr("lc_copy_begin") and pc < symAddr("lc_copy_end")) {
        gregs(uc)[G_RIP] = symAddr("lc_copy_fault");
        return true;
    }
    if (pc >= symAddr("lc_str_begin") and pc < symAddr("lc_str_end")) {
        gregs(uc)[G_RIP] = symAddr("lc_str_end");
        return true;
    }
    return false;
}

// lc_sig_trap traps into onSigill to deliver from the trampoline path.
pub export fn lc_sig_trap() callconv(.Naked) noreturn {
    asm volatile ("ud2");
}

// ucFromFrame loads the guest's context at a trampoline syscall's return
// into uc: the Frame's registers, sp above the Frame, the call and the red
// zone, and the resume pc.
fn ucFromFrame(uc: [*]u8, fp: u64, resume_pc: u64, sp: u64) void {
    const f: *const Frame = @ptrFromInt(fp);
    const g = gregs(uc);
    g[G_R15] = f.r15;
    g[G_R14] = f.r14;
    g[G_R13] = f.r13;
    g[G_R12] = f.r12;
    g[G_RBP] = f.rbp;
    g[G_RBX] = f.rbx;
    g[G_R11] = f.r11;
    g[G_R10] = f.r10;
    g[G_R9] = f.r9;
    g[G_R8] = f.r8;
    g[G_RCX] = f.rcx;
    g[G_RDX] = f.rdx;
    g[G_RSI] = f.rsi;
    g[G_RDI] = f.rdi;
    g[G_RAX] = f.rax;
    g[G_RSP] = sp; // the saved guest sp: the Frame is on the service stack
    g[G_RIP] = resume_pc;
    g[G_EFL] = f.eflags;
}

pub fn onSigill(_: i32, info: *const [128]u8, uctx: [*]u8) callconv(.C) void {
    const g = gregs(uctx);
    if (g[G_RIP] == @intFromPtr(&lc_sig_trap)) {
        const t = sig.thr();
        if (t.frame != 0) ucFromFrame(uctx, t.frame, t.resume_pc, t.sp);
        trace.restore(uctx);
        sig.deliverAll(uctx, .{ .code = g[G_RAX], .pc = t.restart, .orig = t.orig });
        @atomicStore(u32, &t.busy, 0, .seq_cst);
        return;
    }
    sig.beginSyscall(sig.thr());
    var f = Frame{
        .r15 = g[G_R15], .r14 = g[G_R14], .r13 = g[G_R13], .r12 = g[G_R12],
        .rbp = g[G_RBP], .rbx = g[G_RBX], .r11 = g[G_R11], .r10 = g[G_R10],
        .r9 = g[G_R9],   .r8 = g[G_R8],   .rcx = g[G_RCX], .rdx = g[G_RDX],
        .rsi = g[G_RSI], .rdi = g[G_RDI], .rax = g[G_RAX], .eflags = g[G_EFL],
    };
    const site = g[G_RIP];
    const r = stub.handle(slot(), &f, site, site + 2, g[G_RSP], @intFromPtr(uctx));
    const t = sig.thr();
    if (r == stub.NOT_A_SITE) {
        sig.fault(uctx, sig.SIGILL, info);
    } else {
        g[G_RAX] = r;
        g[G_RIP] = site + 2;
        trace.restore(uctx);
        if (sig.isRestart(r) or sig.deliverable(t) != 0)
            sig.deliverAll(uctx, .{ .code = r, .pc = site, .orig = f.rax });
    }
    @atomicStore(u32, &t.busy, 0, .seq_cst);
}

// onSigsys services a raw guest syscall the rewriter left un-rewritten: the
// stub's seccomp filter TRAPs an out-of-text syscall here instead of killing
// it (seccomp.zig). It is the same work as a trampoline call, so it hands
// stub.handle a site of 0 (the supervisor does not validate a 0 rip) and the
// register file. The kernel advances the saved pc past the 2-byte syscall
// before delivery, so the guest resumes at G_RIP and a restart re-runs the
// syscall at G_RIP-2. A SIGSYS the guest raised for itself (not our seccomp
// trap) is delivered on, like a fault.
pub fn onSigsys(_: i32, info: *const [128]u8, uctx: [*]u8) callconv(.C) void {
    const g = gregs(uctx);
    const siCode = std.mem.readInt(i32, info[8..12], .little);
    const siErrno = std.mem.readInt(i32, info[4..8], .little);
    if (slotAddr() == 0) stub.die(128 + sig.SIGSYS);
    if (siCode != sig.SI_CODE_SECCOMP or @as(u32, @bitCast(siErrno)) != sig.SECCOMP_TRAP_TAG) {
        // A guest cannot raise a real host SIGSYS (its seccomp and kill are
        // emulated), so this is unexpected; hand it to the guest, or end if we
        // are in stub code.
        const t = sig.thr();
        if (@atomicLoad(u32, &t.busy, .seq_cst) != 0) stub.die(128 + sig.SIGSYS);
        @atomicStore(u32, &t.busy, 1, .seq_cst);
        sig.fault(uctx, sig.SIGSYS, info);
        @atomicStore(u32, &t.busy, 0, .seq_cst);
        return;
    }
    sig.beginSyscall(sig.thr());
    var f = Frame{
        .r15 = g[G_R15], .r14 = g[G_R14], .r13 = g[G_R13], .r12 = g[G_R12],
        .rbp = g[G_RBP], .rbx = g[G_RBX], .r11 = g[G_R11], .r10 = g[G_R10],
        .r9 = g[G_R9],   .r8 = g[G_R8],   .rcx = g[G_RCX], .rdx = g[G_RDX],
        .rsi = g[G_RSI], .rdi = g[G_RDI], .rax = g[G_RAX], .eflags = g[G_EFL],
    };
    const orig = f.rax;
    const resume_pc = g[G_RIP]; // already past the syscall
    const r = stub.handle(slot(), &f, 0, resume_pc, g[G_RSP], @intFromPtr(uctx));
    const t = sig.thr();
    g[G_RAX] = r;
    g[G_RIP] = resume_pc;
    trace.restore(uctx);
    if (sig.isRestart(r) or sig.deliverable(t) != 0)
        sig.deliverAll(uctx, .{ .code = r, .pc = resume_pc - 2, .orig = orig });
    @atomicStore(u32, &t.busy, 0, .seq_cst);
}

// lc_syscall_entry is reached from a rewriter trampoline, which leaves the
// guest resume address in r11 (a real syscall clobbers r11, so the guest never
// relies on it). It builds a full Frame on the stack (so clone has the register
// file) and services the syscall. We copy the resume address into the slot's
// guest_rip here, where slot() is resolved, so clone can hand it to the child.
export fn lc_tramp_syscall(f: *Frame) callconv(.C) void {
    const ch = slot();
    sig.beginSyscall(sig.recOf(ch));
    ch.guest_rip = f.r11;
    const resume_pc = ch.guest_rip;
    const orig = f.rax;
    // The guest sp is in the slot (the trampoline saved it at %gs:sp before
    // switching to the service stack), not derivable from the Frame address:
    // the Frame is on the service stack now, not the guest's.
    const r = stub.handle(ch, f, 0, resume_pc, sig.recOf(ch).sp, 0);
    f.rax = r;
    stub.trampExit(@intFromPtr(f), r, resume_pc, resume_pc - 2, orig);
}

// lc_tramp_syscall_gs services a syscall taken through the %gs-anchor island
// (lc_syscall_entry_gs). The island has already marked the thread busy and
// cleared kicked before it saved the guest sp -- so unlike lc_tramp_syscall it
// does NOT beginSyscall, which would clear a kick taken since the island
// acquired busy (losing a cancellation for a blocking service). It leaves busy
// set on the fast return; the island clears it only once the guest sp and
// registers are restored.
export fn lc_tramp_syscall_gs(f: *Frame) callconv(.C) void {
    const ch = slot();
    ch.guest_rip = f.r11;
    const resume_pc = ch.guest_rip;
    const orig = f.rax;
    const r = stub.handle(ch, f, 0, resume_pc, sig.recOf(ch).sp, 0);
    f.rax = r;
    stub.trampExitGs(@intFromPtr(f), r, resume_pc, resume_pc - 2, orig);
}

// lc_tramp_latekick delivers a kick the %gs-anchor island caught in its exit
// epilogue (kicked set after busy was cleared) with the full guest context,
// resuming at the island's saved resume address (Frame.r11). lc_latekick has
// reacquired busy and rebuilt the Frame on the scratch stack; this mirrors
// trampExit's trap tail so onSigill delivers and sigreturns to the guest.
export fn lc_tramp_latekick(f: *Frame) callconv(.C) void {
    const t = sig.thr();
    t.frame = @intFromPtr(f);
    t.resume_pc = f.r11;
    t.restart = f.r11 -% 2;
    t.orig = f.rax;
    trap();
}

// The %gs-anchor island reads Thread fields through %gs (whose base is the slot
// page); lc_syscall_entry_gs / lc_latekick below, and the island in
// rewrite.go, hard-code these offsets.
comptime {
    std.debug.assert(sig.REC_OFF == 128);
    std.debug.assert(@offsetOf(sig.Thread, "busy") == 0);
    std.debug.assert(@offsetOf(sig.Thread, "sp") == 8);
    std.debug.assert(@offsetOf(sig.Thread, "kicked") == 52);
    std.debug.assert(@offsetOf(sig.Thread, "scratch_top") == 64);
}

comptime {
    asm (
        \\.globl lc_syscall_entry
        \\lc_syscall_entry:
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
        \\  cld
        \\  and $-16, %rsp
        \\  mov %rbx, %rdi
        \\  call lc_tramp_syscall
        \\  mov %rbx, %rsp
        \\  pop %r15
        \\  pop %r14
        \\  pop %r13
        \\  pop %r12
        \\  pop %rbp
        \\  pop %rbx
        \\  pop %r11
        \\  pop %r10
        \\  pop %r9
        \\  pop %r8
        \\  pop %rcx
        \\  pop %rdx
        \\  pop %rsi
        \\  pop %rdi
        \\  pop %rax
        \\  popfq
        \\  ret
    );
}

// lc_syscall_entry_gs is lc_syscall_entry for the %gs-anchor island: identical,
// but it services through lc_tramp_syscall_gs (which does not beginSyscall, so
// the kick the island cleared then latched is preserved).
comptime {
    asm (
        \\.globl lc_syscall_entry_gs
        \\lc_syscall_entry_gs:
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
        \\  cld
        \\  and $-16, %rsp
        \\  mov %rbx, %rdi
        \\  call lc_tramp_syscall_gs
        \\  mov %rbx, %rsp
        \\  pop %r15
        \\  pop %r14
        \\  pop %r13
        \\  pop %r12
        \\  pop %rbp
        \\  pop %rbx
        \\  pop %r11
        \\  pop %r10
        \\  pop %r9
        \\  pop %r8
        \\  pop %rcx
        \\  pop %rdx
        \\  pop %rsi
        \\  pop %rdi
        \\  pop %rax
        \\  popfq
        \\  ret
    );
}

// lc_latekick is jumped to (not called) from the %gs-anchor island when its
// exit epilogue finds kicked set after it cleared busy: the guest sp and
// registers are already restored (rsp = guest sp, r11 = resume address). It
// reacquires busy BEFORE it touches the sp slot or the scratch stack (a kick
// in between would otherwise overwrite them), rebuilds the Frame on the scratch
// stack, and delivers through lc_tramp_latekick. %gs base is the slot page, so
// busy is %gs:0x80, sp is %gs:0x88, scratch_top is %gs:0xc0 (REC_OFF 128).
comptime {
    asm (
        \\.globl lc_latekick
        \\lc_latekick:
        \\  movl $1, %gs:0x80
        \\  mov %rsp, %gs:0x88
        \\  mov %gs:0xc0, %rsp
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
        \\  cld
        \\  and $-16, %rsp
        \\  mov %rbx, %rdi
        \\  call lc_tramp_latekick
        \\  ud2
    );
}

pub export fn stub_restorer() callconv(.Naked) noreturn {
    asm volatile (
        \\ mov $15, %%eax
        \\ syscall
    );
}

pub export fn _start() callconv(.Naked) noreturn {
    asm volatile (
        \\ xor %%rbp, %%rbp
        \\ mov %%rsp, %%rdi
        \\ and $-16, %%rsp
        \\ call stub_main
        \\ hlt
    );
}

pub const Registers = extern struct {
    r15: u64, r14: u64, r13: u64, r12: u64, rbp: u64, rbx: u64,
    r11: u64, r10: u64, r9: u64, r8: u64, rax: u64, rcx: u64,
    rdx: u64, rsi: u64, rdi: u64, orig_rax: u64, rip: u64,
    cs: u64, eflags: u64, rsp: u64, ss: u64,
    fs_base: u64, gs_base: u64, ds: u64, es: u64, fs: u64, gs: u64,
};

fn fsBase() u64 {
    if (stub.fsgsbase) return asm volatile (".byte 0xf3, 0x48, 0x0f, 0xae, 0xc0" // rdfsbase %rax
        : [r] "={rax}" (-> u64),
    );
    var base: u64 = 0;
    _ = sys6(nr(.arch_prctl), 0x1003, @intFromPtr(&base), 0, 0, 0, 0);
    return base;
}

pub fn frameRegs(f: *const Frame, pc: u64, sp: u64) Registers {
    return .{
        .r15 = f.r15, .r14 = f.r14, .r13 = f.r13, .r12 = f.r12,
        .rbp = f.rbp, .rbx = f.rbx, .r11 = f.eflags, .r10 = f.r10,
        .r9 = f.r9, .r8 = f.r8, .rax = f.rax, .rcx = pc,
        .rdx = f.rdx, .rsi = f.rsi, .rdi = f.rdi, .orig_rax = f.rax,
        .rip = pc, .cs = 0x33, .eflags = f.eflags, .rsp = sp, .ss = 0x2b,
        .fs_base = fsBase(), .gs_base = sig.thr().guest_gs, .ds = 0, .es = 0, .fs = 0, .gs = 0,
    };
}

const regMap = [_]usize{ G_R15, G_R14, G_R13, G_R12, G_RBP, G_RBX,
    G_R11, G_R10, G_R9, G_R8, G_RAX, G_RCX, G_RDX, G_RSI, G_RDI };

pub fn saveRegs(uc: [*]u8) Registers {
    var r = std.mem.zeroes(Registers);
    const words: [*]u64 = @ptrCast(&r);
    const g = gregs(uc);
    for (regMap, 0..) |i, j| words[j] = g[i];
    r.orig_rax = ~@as(u64, 0);
    r.rip = g[G_RIP];
    r.rsp = g[G_RSP];
    r.eflags = g[G_EFL];
    r.cs = 0x33;
    r.ss = 0x2b;
    r.fs_base = fsBase();
    r.gs_base = sig.thr().guest_gs;
    return r;
}

pub fn restoreRegs(uc: [*]u8, r: *const Registers) void {
    const words: [*]const u64 = @ptrCast(r);
    const g = gregs(uc);
    for (regMap, 0..) |i, j| g[i] = words[j];
    g[G_RIP] = r.rip;
    g[G_RSP] = r.rsp;
    g[G_EFL] = r.eflags;
    _ = sys6(nr(.arch_prctl), 0x1002, r.fs_base, 0, 0, 0, 0);
    // The stub owns the real %gs (the per-thread anchor); the guest's %gs is
    // virtual. Record it, but leave the anchor in the register.
    sig.thr().guest_gs = r.gs_base;
}
