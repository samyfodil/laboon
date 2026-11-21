// sig.zig — Linux signal delivery. The stub owns every guest thread's CPU
// state, so it is the one that builds the arm64 rt_sigframe, redirects a thread
// into its handler and restores it on rt_sigreturn. The supervisor (Go) owns
// routing and policy: it posts signals into the shared signal area and kicks
// the stub process with a Darwin SIGUSR1.
//
// Signal state lives in the signal area, a shared region after the channel
// slots, one record per slot: the thread's mask and sigaltstack, and a copy of
// its pending bits and (at the thread-group leader's slot) its process's. The
// pending sets themselves and the actions are the supervisor's, out of the
// guest's reach: the stub takes a signal, with its action, by a call
// (LC_SIGTAKE), and sigaction is the supervisor's.
//
// Every context switch into a handler, and back out on rt_sigreturn, goes
// through a Darwin signal handler: it receives the interrupted Darwin context
// and whatever it leaves there is what the kernel restores, every register
// included. From a syscall return the stub traps itself into that handler with
// a `brk` (lc_sig_switch). A thread is never redirected while busy in the stub
// (between its trampoline entry and exit); a kick then only wakes a local wait,
// and the pending signal is taken on the way out of the syscall.

const std = @import("std");
const chan = @import("chan.zig");
const futex = @import("futex.zig");
const jit = @import("jit.zig");
const mem = @import("mem.zig");
const wx = @import("wx.zig");
const ool = @import("ool.zig");
const hwcap = @import("hwcap.zig");
const service = @import("service.zig");
const tstate = @import("tstate.zig");
const proc = @import("proc.zig");
const fsmem = @import("fsmem.zig");

pub const AREA_OFF: usize = chan.SLOT_SIZE * chan.MAX_SLOTS;
pub const STRIDE: usize = 0x4000;
pub const AREA_LEN: usize = STRIDE * chan.MAX_SLOTS;
const PROC_OFF: usize = 0x1000;

// Info is the first 32 bytes of a Linux siginfo_t: a and b are its bytes 16..32
// (the union), laid out by the sender exactly as Linux does.
pub const Info = extern struct { signo: i32, errno: i32, code: i32, pad: i32, a: u64, b: u64 };
pub const Act = extern struct { handler: u64, flags: u64, restorer: u64, mask: u64 };

pub const Thread = extern struct {
    _res: u32,
    proc: u32, // slot of the thread-group leader (its Proc record)
    mask: u64,
    pending: u64,
    waitset: u64, // signals that wake a sigtimedwait although blocked
    ss_sp: u64,
    ss_size: u64, // 0 = no alternate stack
    ss_flags: u32, // SS_AUTODISARM only
    tid: u32,
    tgid: u32,
    // saved: a syscall (pselect, ppoll, epoll_pwait) runs under a temporary
    // mask; saved_mask is the real one, put back on the way out.
    saved: u32,
    saved_mask: u64,
    _win: [2]u32, // the Windows stub's busy and in-handler flags
    // host_tid is the Darwin id of the thread on the slot, by which the
    // supervisor reads its CPU time; 0 while none runs there.
    host_tid: u64,
};

pub const Proc = extern struct {
    _res: u64,
    pending: u64, // the process-directed pending bits
    mem: u64, // what the stub process leading this slot has mapped, for the run's memory cap
};

comptime {
    std.debug.assert(@offsetOf(Thread, "mask") == 8);
    std.debug.assert(@offsetOf(Thread, "pending") == 16);
    std.debug.assert(@offsetOf(Thread, "waitset") == 24);
    std.debug.assert(@offsetOf(Thread, "ss_sp") == 32);
    std.debug.assert(@offsetOf(Thread, "ss_size") == 40);
    std.debug.assert(@offsetOf(Thread, "ss_flags") == 48);
    std.debug.assert(@offsetOf(Thread, "tid") == 52);
    std.debug.assert(@offsetOf(Thread, "tgid") == 56);
    std.debug.assert(@offsetOf(Thread, "saved") == 60);
    std.debug.assert(@offsetOf(Thread, "saved_mask") == 64);
    std.debug.assert(@offsetOf(Thread, "host_tid") == 80);
    std.debug.assert(@offsetOf(Proc, "pending") == 8);
    std.debug.assert(@offsetOf(Proc, "mem") == 16);
    std.debug.assert(@sizeOf(Thread) <= PROC_OFF);
    std.debug.assert(@sizeOf(Proc) <= STRIDE - PROC_OFF);
}

// Linux arm64 syscall numbers served here, and the stub->supervisor calls a
// default action needs (outside the Linux range).
pub const NR_SIGALTSTACK: u64 = 132;
pub const NR_RT_SIGSUSPEND: u64 = 133;
pub const NR_RT_SIGPROCMASK: u64 = 135;
pub const NR_RT_SIGPENDING: u64 = 136;
pub const NR_RT_SIGTIMEDWAIT: u64 = 137;
pub const NR_RT_SIGRETURN: u64 = 139;
const NR_EXIT: u64 = 93; // arm64; trapEnter serves arm64 only
const NR_RESTART_SYSCALL: u64 = 128;
// epipeRaises matches these against frame[8], which is the raw guest number
// (asm-generic on arm64, x86-64 on x86-64), not the translated dispatch number.
const NR_WRITE: u64 = if (tstate.arm64) 64 else 1;
const NR_WRITEV: u64 = if (tstate.arm64) 66 else 20;
const NR_SENDTO: u64 = if (tstate.arm64) 206 else 44;
const NR_SENDMSG: u64 = if (tstate.arm64) 211 else 46;
const NR_SENDMMSG: u64 = if (tstate.arm64) 269 else 307;
const LC_SIGDIE: u64 = 0x4c430010; // after mem.zig's 0x4c4300xx
const LC_SIGSTOP: u64 = 0x4c430011;
const LC_SIGTAKE: u64 = 0x4c430012;
const LC_SIGSETTLE: u64 = 0x4c430013;
const LC_SIGFAULT: u64 = 0x4c430014;
const LC_SIGRAISE: u64 = 0x4c430015;

// Linux signals.
const SIGILL: u32 = 4;
const SIGTRAP: u32 = 5;
const SIGBUS: u32 = 7;
const SIGFPE: u32 = 8;
const SIGKILL: u32 = 9;
const SIGSEGV: u32 = 11;
const SIGPIPE: u32 = 13;
const SIGCHLD: u32 = 17;
const SIGCONT: u32 = 18;
const SIGSTOP: u32 = 19;
const SIGTSTP: u32 = 20;
const SIGTTIN: u32 = 21;
const SIGTTOU: u32 = 22;
const SIGURG: u32 = 23;
const SIGWINCH: u32 = 28;
const SIGSYS: u32 = 31;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

const SA_RESTORER: u64 = 0x04000000;
const SA_ONSTACK: u64 = 0x08000000;
const SA_RESTART: u64 = 0x10000000;
const SA_NODEFER: u64 = 0x40000000;

const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
const SS_AUTODISARM: u32 = 1 << 31;
const MINSIGSTKSZ: u64 = 5120;

// si_code values.
const SI_USER: i32 = 0;
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;
const BUS_ADRALN: i32 = 1;
const BUS_ADRERR: i32 = 2;
const ILL_ILLOPC: i32 = 1;
const TRAP_BRKPT: i32 = 1;

// Linux errnos (negated on return) and the restart codes a supervisor-served
// or stub-local syscall returns when a signal interrupts it.
const EPERM: i64 = 1;
const EINTR: i64 = 4;
const EFAULT: i64 = 14;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EINVAL: i64 = 22;
const EPIPE: i64 = 32;
const ERESTARTSYS: i64 = 512;
const ERESTARTNOINTR: i64 = 513;
const ERESTARTNOHAND: i64 = 514;
const ERESTART_RESTARTBLOCK: i64 = 516;

const KILLSTOP: u64 = bit(SIGKILL) | bit(SIGSTOP);

// arm64 rt_sigframe: siginfo (128) + ucontext (4560); the sigcontext sits at
// ucontext+176 and its __reserved area at sigcontext+288.
const FRAME_SIZE: u64 = 128 + 4560;
const UC_MCONTEXT: u64 = 176;
const SC_RESERVED: u64 = 288;
const FPSIMD_MAGIC: u32 = 0x46508001;
const FPSIMD_SIZE: u32 = 528;
const ESR_MAGIC: u32 = 0x45535201;

// x86-64 Linux user segment selectors (__USER_CS / __USER_DS); the stub's
// sigreturn forces them, as the kernel does, so they are only cosmetic in the
// frame.
const USER_CS: u16 = 0x33;
const USER_SS: u16 = 0x2b;

// Darwin.
const DW_SIGILL: c_int = 4;
const DW_SIGTRAP: c_int = 5;
const DW_SIGFPE: c_int = 8;
const DW_SIGBUS: c_int = 10;
const DW_SIGSEGV: c_int = 11;
const DW_SIGPIPE: c_int = 13;
const DW_SIGUSR1: c_int = 30; // supervisor -> process: route pending signals
const DW_SIGUSR2: c_int = 31; // stub thread -> thread: take your signals
const DW_SA_ONSTACK: c_int = 0x1;
const DW_SA_SIGINFO: c_int = 0x40;
const DW_SIG_DFL: usize = 0;
const DW_SIG_IGN: usize = 1;
const ALT_SIZE: usize = 0x10000;
const MCONTEXT_AVX64: u64 = 1028;
const PAGEZERO_END: u64 = 0x100000000;

const DwHandler = *const fn (c_int, *std.c.siginfo_t, ?*anyopaque) callconv(.C) void;
const DwSigaction = extern struct { handler: DwHandler, mask: u32, flags: c_int };
const DwStack = extern struct { sp: u64, size: u64, flags: c_int };

extern "c" fn sigaction(sig: c_int, act: *const DwSigaction, old: ?*DwSigaction) c_int;
extern "c" fn signal(sig: c_int, handler: usize) usize;
extern "c" fn pthread_key_create(key: *c_ulong, destructor: ?*const anyopaque) c_int;
extern "c" fn pthread_setspecific(key: c_ulong, value: ?*const anyopaque) c_int;
extern "c" fn pthread_getspecific(key: c_ulong) ?*anyopaque;
extern "c" fn getsegmentdata(mhp: *const anyopaque, segname: [*:0]const u8, size: *u64) ?[*]u8;
extern const _mh_execute_header: u8;
extern fn lc_tc_busy() callconv(.C) void;

// lc_busy_tsd is the byte offset, from a thread's TSD base, of the slot that
// holds its tl.busy, which tramp_common sets as it enters the stub.
export var lc_busy_tsd: u64 = 0;
// g_text is the stub's own __TEXT segment.
var g_text: [2]u64 = .{ 0, 0 };
extern "c" fn sigaltstack(ss: *const DwStack, old: ?*DwStack) c_int;
extern "c" fn pthread_sigmask(how: c_int, set: ?*const u32, old: ?*u32) c_int;
const SIG_UNBLOCK: c_int = 2;
const SIG_SETMASK: c_int = 3;
const KICK_MASK: u32 = (1 << (DW_SIGUSR1 - 1)) | (1 << (DW_SIGUSR2 - 1));
extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) ?*anyopaque;
extern "c" fn pthread_self() usize;
extern "c" fn pthread_threadid_np(thread: usize, id: *u64) c_int;
extern "c" fn pthread_mach_thread_np(t: usize) c_uint;
extern "c" fn _exit(code: c_int) noreturn;
extern "c" fn sched_yield() c_int;

// Ctx is a guest thread's full user state, the currency between the trap frame,
// the Darwin signal context and the Linux sigcontext. Its shape is per-arch (the
// register file and FP state differ); fromMc/toMc/deliverOnto map it to the
// Darwin mcontext and the Linux sigcontext field by field, so its own layout is
// private to the stub.
pub const Ctx = if (tstate.arm64) CtxArm else CtxX64;

const CtxArm = extern struct {
    x: [31]u64,
    sp: u64,
    pc: u64,
    pstate: u64,
    v: [32]u128,
    fpsr: u32,
    fpcr: u32,
    fault: u64,
    esr: u64,
};

const CtxX64 = extern struct {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
    // FP/SSE state as the 512-byte FXSAVE image, the common currency between
    // Darwin's x86_float_state64 and Linux's _fpstate (both FXSAVE-derived);
    // fromMc/toMc (phase 1c) convert at the edges.
    fx: [512]u8 align(16),
    // Fault detail for a delivered SIGSEGV/SIGBUS/SIGILL, the x86-64 analogue of
    // arm64's fault/esr: the faulting address and the trap number / error code
    // (es.faultvaddr / es.trapno / es.err).
    fault: u64,
    trapno: u64,
    err: u64,
};

var g_area: [*]u8 = undefined;
// g_ports holds each live guest thread's Mach thread port by slot, for the
// router to kick it.
var g_ports: [chan.MAX_SLOTS]u32 = [_]u32{0} ** chan.MAX_SLOTS;
// g_restorer is the sigreturn trampoline used when a handler has none.
pub var g_restorer: u64 = 0;

// Per-thread state, one thread-local block (each access to a Darwin
// thread-local is a call, so hot paths take its address once).
const Tls = struct {
    slot: usize = 0,
    rec: *Thread = undefined,
    prec: *Proc = undefined,
    ready: bool = false,
    // busy: in stub code with the channel or stub state in use; never redirect.
    busy: bool = true,
    in_handler: bool = false,
    // A local wait (sigsuspend, sigtimedwait, nanosleep) sleeps on word, which
    // a kick sets; a futex wait sleeps on the guest's word, which a kick wakes.
    word: u32 = 0,
    waiting: bool = false,
    futex: u64 = 0,
    // kicked: a kick came while busy, or as the thread entered the stub,
    // since the last look for signals (cpSys).
    kicked: u32 = 0,
    // The guest state the thread goes back to, recorded before busy clears:
    // a kick that lands before the guest runs delivers onto it (guestState).
    leaving: bool = false,
    leave_frame: [*]u64 = undefined,
    leave_x0: u64 = 0,
    leave_sp: u64 = 0,
    // The pending switch handed to the brk trap: the guest state to load and
    // the signal to deliver onto it first.
    switch_ctx: Ctx = undefined,
    first_sig: u32 = 0,
    first_info: Info = undefined,
    first_act: Act = undefined,
    first_mask: u64 = 0,
    alt: u64 = 0, // this thread's Darwin alternate stack
};
threadlocal var tl: Tls = .{};

fn bit(sig: u32) u64 {
    return @as(u64, 1) << @intCast(sig - 1);
}

fn neg(e: i64) u64 {
    return @bitCast(-e);
}

// runRegion is what every stub reads of the run as a whole (sandbox/
// lx_signal.go's sigRunOff, in slot 0's stride).
pub fn runRegion() [*]u8 {
    return g_area + 0x2000;
}

// runProcs is how many processes the run has (sandbox/lx_signal.go's
// sigRunOff, in slot 0's stride).
pub fn runProcs() u32 {
    return @atomicLoad(u32, @as(*const u32, @ptrCast(@alignCast(g_area + 0x2000))), .acquire);
}

// runMemCap is the run's memory cap, 0 for none (sigRunOff + 8).
pub fn runMemCap() u64 {
    return @atomicLoad(u64, @as(*const u64, @ptrCast(@alignCast(g_area + 0x2000 + 8))), .acquire);
}

fn procAt(slot: usize) *Proc {
    return @ptrCast(@alignCast(g_area + slot * STRIDE + PROC_OFF));
}

// procMem is what the stub process leading slot has mapped.
pub fn procMem(slot: usize) u64 {
    return @atomicLoad(u64, &procAt(slot).mem, .acquire);
}

pub fn setProcMem(slot: usize, n: u64) void {
    @atomicStore(u64, &procAt(slot).mem, n, .release);
}

// othersMem is what every stub process but the one leading slot has mapped.
pub fn othersMem(slot: usize) u64 {
    var n: u64 = 0;
    for (0..chan.MAX_SLOTS) |s| {
        if (s != slot) n +|= procMem(s);
    }
    return n;
}

fn thrAt(slot: usize) *Thread {
    return @ptrCast(@alignCast(g_area + slot * STRIDE));
}

fn thr() *Thread {
    return tl.rec;
}

fn procOf(t: *Thread) *Proc {
    return @ptrCast(@alignCast(g_area + @as(usize, @atomicLoad(u32, &t.proc, .acquire)) * STRIDE + PROC_OFF));
}

// Trace frame: the guest register image a tracer reads, published at offset 256
// of this thread's record (past the Thread struct, before PROC_OFF). The layout
// matches the Linux stub's trace.State and the supervisor's traceFrame: a kind
// and dirty word, then the arch's ptrace register image — arm64 NT_PRSTATUS
// (x0..x30, sp, pc, pstate) or the x86-64 user_regs_struct.
pub const TraceRegs = if (tstate.arm64) TraceRegsArm else TraceRegsX64;
const TraceRegsArm = extern struct { x: [31]u64, sp: u64, pc: u64, pstate: u64 };
const TraceRegsX64 = extern struct {
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
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
};
pub const TraceState = extern struct { kind: u64, dirty: u64, regs: TraceRegs };

comptime {
    std.debug.assert(256 + @sizeOf(TraceState) <= PROC_OFF);
}

pub fn traceState() *TraceState {
    return @ptrFromInt(@intFromPtr(thr()) + 256);
}

// publishFrame records a traced thread's guest state at a trapped syscall:
// x0..x30 from the trap frame, the guest sp (proc.guestSp), the resume pc,
// and NZCV. The supervisor reads this for the syscall stop and GETREGS.
pub fn publishFrame(frame: [*]u64, pc: u64) void {
    if (!tstate.arm64) @compileError("publishFrame: x86-64 frame image pending the trampoline register frame (AMD64.md 1e/1f)");
    const s = traceState();
    s.kind = 1;
    s.dirty = 0;
    for (0..31) |i| s.regs.x[i] = frame[i];
    s.regs.sp = proc.guestSp(frame);
    s.regs.pc = pc;
    s.regs.pstate = frame[31] & 0xf0000000;
}

// traceRestore applies a tracer's register edits (SETREGS/POKEUSER) to the
// trap frame before the guest resumes: x1..x30, the resume pc and NZCV go back
// into the frame the trampoline epilogue restores, and the edited x0 is
// returned (x0 is the handler's return value, not restored from the frame).
// The guest sp cannot be moved here (the frame sits on it), matching the
// supervisor's refusal to relocate it.
pub fn traceRestore(frame: [*]u64) u64 {
    if (!tstate.arm64) @compileError("traceRestore: x86-64 frame image pending the trampoline register frame (AMD64.md 1e/1f)");
    const s = traceState();
    s.dirty = 0;
    for (1..31) |i| frame[i] = s.regs.x[i];
    frame[33] = s.regs.pc;
    frame[31] = (frame[31] & ~@as(u64, 0xf0000000)) | (s.regs.pstate & 0xf0000000);
    return s.regs.x[0];
}

fn ld(p: *const u64) u64 {
    return @atomicLoad(u64, p, .acquire);
}

// ---- setup ----------------------------------------------------------------------

// install maps the area base and installs the Darwin handlers; it must run
// before Seatbelt, which forbids sigaction.
pub fn install(chan_base: [*]u8) void {
    g_area = chan_base + AREA_OFF;
    var key: c_ulong = 0;
    if (pthread_key_create(&key, null) != 0) _exit(126);
    lc_busy_tsd = key * 8;
    var n: u64 = 0;
    const text = getsegmentdata(&_mh_execute_header, "__TEXT", &n) orelse _exit(126);
    g_text = .{ @intFromPtr(text), @intFromPtr(text) + n };
    const block: u32 = (1 << (DW_SIGUSR1 - 1)) | (1 << (DW_SIGUSR2 - 1));
    const flags = DW_SA_SIGINFO | DW_SA_ONSTACK;
    const fault = DwSigaction{ .handler = onFault, .mask = block, .flags = flags };
    for ([_]c_int{ DW_SIGSEGV, DW_SIGBUS, DW_SIGILL, DW_SIGFPE, DW_SIGTRAP }) |s| _ = sigaction(s, &fault, null);
    _ = sigaction(DW_SIGUSR1, &.{ .handler = onRoute, .mask = block, .flags = flags }, null);
    _ = sigaction(DW_SIGUSR2, &.{ .handler = onKick, .mask = block, .flags = flags }, null);
    // EPIPE comes back to the guest, which then gets its own (Linux) SIGPIPE.
    _ = signal(DW_SIGPIPE, DW_SIG_IGN);
}

// startThread binds the calling OS thread to its slot and gives it the Darwin
// alternate stack the handlers above run on (guest stacks may be tiny, and a
// frame is built just below the guest sp).
fn bind(slot: usize) void {
    tl.slot = slot;
    tl.rec = thrAt(slot);
    tl.prec = procOf(tl.rec);
}

pub fn startThread(slot: usize) void {
    bind(slot);
    _ = pthread_setspecific(lc_busy_tsd / 8, &tl.busy);
    if (mmap(null, ALT_SIZE, 3, 0x1002, -1, 0)) |p| {
        if (@intFromPtr(p) != std.math.maxInt(usize)) tl.alt = @intFromPtr(p);
    }
    setAltStack();
    @atomicStore(u32, &g_ports[slot], pthread_mach_thread_np(pthread_self()), .release);
    var id: u64 = 0;
    _ = pthread_threadid_np(0, &id);
    @atomicStore(u64, &tl.rec.host_tid, id, .release);
    tl.ready = true;
}

fn setAltStack() void {
    if (tl.alt != 0) _ = sigaltstack(&.{ .sp = tl.alt, .size = ALT_SIZE, .flags = 0 }, null);
}

pub fn endThread() void {
    @atomicStore(u32, &g_ports[tl.slot], 0, .release);
    @atomicStore(u64, &tl.rec.host_tid, 0, .release);
    tl.ready = false;
}

// enterGuest marks the thread as running guest code: from here a kick may
// redirect it.
pub fn enterGuest() void {
    tl.busy = false;
}

pub fn enter() void {
    setBusy(&tl, true);
    tl.leaving = false;
}

// leaveTo records the guest state this thread goes back to, before busy
// clears: the frame's registers with x0 and sp, at the frame's resume pc.
pub fn leaveTo(frame: [*]u64, x0: u64, sp: u64) void {
    tl.leave_frame = frame;
    tl.leave_x0 = x0;
    tl.leave_sp = sp;
    tl.leaving = true;
}

// clearKick answers the kicks so far: the caller looks for signals next.
pub fn clearKick() void {
    @atomicStore(u32, &tl.kicked, 0, .seq_cst);
}

// cpSys makes a Darwin syscall that may block, which a signal for this
// thread must cut short with EINTR however close to it its kick lands: one
// since this syscall began has set kicked, which lc_cp_sys checks; one
// between that check and the svc is moved off it (cpCancel); one during it
// interrupts it. It returns the result or the negated errno.
pub fn cpSys(nr: u64, a: [6]u64) i64 {
    return lc_cp_sys(a[0], a[1], a[2], a[3], a[4], a[5], &tl.kicked, nr);
}

comptime {
    if (tstate.arm64) asm (
        \\ .text
        \\ .p2align 2
        \\ .globl _lc_cp_sys
        \\ .globl _lc_cp_begin
        \\ .globl _lc_cp_end
        \\ .globl _lc_cp_cancel
        \\_lc_cp_sys:
        \\ mov x16, x7
        \\_lc_cp_begin:
        \\ ldr w9, [x6]
        \\ cbnz w9, 2f
        \\ svc #0x80
        \\_lc_cp_end:
        \\ b.cc 1f
        \\ neg x0, x0
        \\1:
        \\ ret
        \\_lc_cp_cancel:
        \\2:
        \\ mov x0, #-4
        \\ ret
    ) else asm (
        // x86-64: C args a0..a5 in rdi,rsi,rdx,rcx,r8,r9; kicked at 8(%rsp), nr
        // at 16(%rsp). A Darwin BSD syscall wants rax=class|nr and arg4 in r10
        // (not rcx). On return CF=error, rax=errno; negate it as the arm64 path
        // does. VERIFY ON MAC.
        \\ .text
        \\ .p2align 4
        \\ .globl _lc_cp_sys
        \\ .globl _lc_cp_begin
        \\ .globl _lc_cp_end
        \\ .globl _lc_cp_cancel
        \\_lc_cp_sys:
        \\ movq 16(%rsp), %rax
        \\ orq $0x2000000, %rax
        \\ movq %rcx, %r10
        \\ movq 8(%rsp), %rcx
        \\_lc_cp_begin:
        \\ cmpl $0, (%rcx)
        \\ jne 2f
        \\ syscall
        \\_lc_cp_end:
        \\ jc 1f
        \\ ret
        \\1:
        \\ negq %rax
        \\ ret
        \\_lc_cp_cancel:
        \\2:
        \\ movq $-4, %rax
        \\ ret
    );
}
extern fn lc_cp_sys(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, kicked: *const u32, nr: u64) callconv(.C) i64;
extern fn lc_cp_begin() callconv(.C) void;
extern fn lc_cp_end() callconv(.C) void;
extern fn lc_cp_cancel() callconv(.C) void;

// cpCancel moves a kick that interrupted lc_cp_sys before its svc to the
// cancelled exit.
fn cpCancel(mc: *std.c.mcontext_t) void {
    const pc = tstate.pc(mc);
    if (pc >= @intFromPtr(&lc_cp_begin) and pc < @intFromPtr(&lc_cp_end)) tstate.setPc(mc, @intFromPtr(&lc_cp_cancel));
}

// setBusy orders busy against this thread's own signal handlers only, which
// needs a compiler barrier, not a hardware one.
inline fn setBusy(s: *Tls, on: bool) void {
    asm volatile ("" ::: "memory");
    @atomicStore(bool, &s.busy, on, .monotonic);
    asm volatile ("" ::: "memory");
}

// ---- pending sets ---------------------------------------------------------------

fn pendingAllowed(allow: u64) u64 {
    const t = thr();
    return (ld(&t.pending) | ld(&tl.prec.pending)) & allow;
}

fn deliverableFor(t: *Thread) u64 {
    const allow = ~ld(&t.mask) | ld(&t.waitset);
    return (ld(&t.pending) | ld(&procOf(t).pending)) & allow;
}

// interrupted reports whether a signal is waiting for this thread to take it,
// which ends a blocking stub-local wait.
pub fn interrupted() bool {
    return tl.ready and pendingAllowed(~ld(&thr().mask)) != 0;
}

// take dequeues the next signal in allow (thread-directed first) with its
// action: for a delivery, the supervisor resets an SA_RESETHAND action as it
// hands it over; for a wait (sigtimedwait) the action is not looked at.
// Returns 0 if none.
fn take(allow: u64, info: *Info, act: ?*Act) u32 {
    const s: u32 = @truncate(goCall(LC_SIGTAKE, allow, @intFromBool(act == null)));
    if (s == 0) return 0;
    const r = replyOf(myChan());
    info.* = r.info;
    if (act) |a| a.* = r.act;
    return s;
}

const Reply = extern struct { info: Info, act: Act };

// replyOf is the supervisor's reply to a signal call, in the slot scratch.
fn replyOf(ch: *chan.Chan) Reply {
    return @as(*align(1) const Reply, @ptrFromInt(@intFromPtr(ch) + chan.SCRATCH_OFF)).*;
}

noinline fn raiseSelf(sig: u32, code: i32) void {
    _ = goCall(LC_SIGRAISE, sig, @as(u32, @bitCast(code)));
}

const Kind = enum { ignore, stop, term, handler };

fn classify(sig: u32, act: Act) Kind {
    if (act.handler == SIG_IGN) return .ignore;
    if (act.handler != SIG_DFL) return .handler;
    return switch (sig) {
        SIGCHLD, SIGURG, SIGWINCH, SIGCONT => .ignore,
        SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU => .stop,
        else => .term,
    };
}

fn ignoredByDefault(sig: u32) bool {
    return sig == SIGCHLD or sig == SIGURG or sig == SIGWINCH or sig == SIGCONT;
}

// ---- supervisor calls -----------------------------------------------------------

fn myChan() *chan.Chan {
    return @ptrFromInt(@intFromPtr(g_area) - AREA_OFF + tl.slot * chan.SLOT_SIZE);
}

fn goCall(nr: u64, a0: u64, a1: u64) u64 {
    return goCallArgs(nr, .{ a0, a1, 0, 0, 0, 0 });
}

// codeCall makes a call for wx.zig from its fault handling, the thread busy
// meanwhile: a supervisor read of memory gone since faults into the copy's
// recovery rather than the stub.
pub fn codeCall(nr: u64, args: [6]u64) u64 {
    const was = tl.busy;
    setBusy(&tl, true);
    defer setBusy(&tl, was);
    return goCallArgs(nr, args);
}

// scratch is this thread's slot scratch, where a call's reply lands.
pub fn scratch() [*]u8 {
    return @ptrFromInt(@intFromPtr(myChan()) + chan.SCRATCH_OFF);
}

fn goCallArgs(nr: u64, args: [6]u64) u64 {
    const ch = myChan();
    ch.kind = chan.MSG_SYSCALL;
    ch.nr = nr;
    ch.args = args;
    // The supervisor may hold the call in a ptrace stop, through which the
    // tracer reads and writes this task's memory.
    while (true) {
        chan.exchange(ch);
        if (!@import("root").serveRequest(ch)) return ch.ret;
    }
}

// die ends the process with a fatal signal's default action: the supervisor
// records the signal as the exit status, and the whole task exits (or the one
// thread, when the supervisor answers REP_THREAD_END).
fn die(sig: u32) noreturn {
    _ = goCall(LC_SIGDIE, sig, 0);
    // A CLONE_VM child process is a thread of its parent's stub: only it ends.
    if (myChan().kind == chan.REP_THREAD_END) @import("root").threadExit(128 + sig);
    _exit(@intCast(128 + sig));
}

// stopSelf has the supervisor stop this process, which it does before
// replying. The trap after it makes this thread halt on the way back to user
// mode instead of running on until the stop reaches it.
fn stopSelf(sig: u32) void {
    _ = goCall(LC_SIGSTOP, sig, 0);
    _ = sched_yield();
}

// ---- contexts -------------------------------------------------------------------

// fromFrame loads the guest state tramp_common saved: x0..x30 at 0, NZCV at
// 248, FPCR|FPSR<<32 at 256, q0..q31 at 272; the guest sp from the island's
// sp at 784 (proc.guestSp).
fn fromFrame(c: *Ctx, frame: [*]u64, x0: u64, pc: u64) void {
    if (!tstate.arm64) return; // x86-64 serves from the mcontext, not a saved frame
    for (0..31) |i| c.x[i] = frame[i];
    c.x[0] = x0;
    c.sp = proc.guestSp(frame);
    c.pc = pc;
    c.pstate = frame[31] & 0xf0000000;
    c.fpcr = @truncate(frame[32]);
    c.fpsr = @truncate(frame[32] >> 32);
    const q: *const [32]u128 = @ptrFromInt(@intFromPtr(frame) + 272);
    c.v = q.*;
    c.fault = 0;
    c.esr = 0;
}

fn fromMc(c: *Ctx, mc: *const std.c.mcontext_t) void {
    if (tstate.arm64) {
        for (0..29) |i| c.x[i] = mc.ss.regs[i];
        c.x[29] = mc.ss.fp;
        c.x[30] = mc.ss.lr;
        c.sp = mc.ss.sp;
        c.pc = ool.guestPc(tl.slot, mc.ss.pc); // run out of line: the guest's own
        for (ool.release(tl.slot, mc.ss.pc)) |h| wx.letGo(h);
        c.pstate = mc.ss.cpsr & 0xf0000000;
        c.v = mc.ns.q;
        c.fpsr = mc.ns.fpsr;
        c.fpcr = mc.ns.fpcr;
        c.fault = mc.es.far;
        c.esr = mc.es.esr;
    } else {
        c.rax = mc.ss.rax;
        c.rbx = mc.ss.rbx;
        c.rcx = mc.ss.rcx;
        c.rdx = mc.ss.rdx;
        c.rsi = mc.ss.rsi;
        c.rdi = mc.ss.rdi;
        c.rbp = mc.ss.rbp;
        c.rsp = mc.ss.rsp;
        c.r8 = mc.ss.r8;
        c.r9 = mc.ss.r9;
        c.r10 = mc.ss.r10;
        c.r11 = mc.ss.r11;
        c.r12 = mc.ss.r12;
        c.r13 = mc.ss.r13;
        c.r14 = mc.ss.r14;
        c.r15 = mc.ss.r15;
        // The guest's own rip: the x86-64 out-of-line layer (phase 3) must map a
        // relocated copy's rip back here, as arm64's ool.guestPc does above;
        // until it exists the Darwin rip is the guest rip.
        c.rip = mc.ss.rip;
        c.rflags = mc.ss.rflags;
        // Darwin's float_state is the FXSAVE image behind an 8-byte reserved
        // prefix (fcw onward is 512 bytes); Linux's _fpstate is FXSAVE-shaped
        // too. The FIP/FDP form wants confirming on the mac.
        const fxsrc: *const [512]u8 = @ptrCast(@as([*]const u8, @ptrCast(&mc.fs)) + 8);
        c.fx = fxsrc.*;
        c.fault = mc.es.faultvaddr;
        c.trapno = mc.es.trapno;
        c.err = mc.es.err;
    }
}

fn toMc(mc: *std.c.mcontext_t, c: *const Ctx) void {
    if (tstate.arm64) {
        for (0..29) |i| mc.ss.regs[i] = c.x[i];
        mc.ss.fp = c.x[29];
        mc.ss.lr = c.x[30];
        mc.ss.sp = c.sp;
        mc.ss.pc = c.pc;
        mc.ss.cpsr = (mc.ss.cpsr & 0x0fffffff) | @as(u32, @truncate(c.pstate & 0xf0000000));
        mc.ns.q = c.v;
        mc.ns.fpsr = c.fpsr;
        mc.ns.fpcr = c.fpcr;
    } else {
        mc.ss.rax = c.rax;
        mc.ss.rbx = c.rbx;
        mc.ss.rcx = c.rcx;
        mc.ss.rdx = c.rdx;
        mc.ss.rsi = c.rsi;
        mc.ss.rdi = c.rdi;
        mc.ss.rbp = c.rbp;
        mc.ss.rsp = c.rsp;
        mc.ss.r8 = c.r8;
        mc.ss.r9 = c.r9;
        mc.ss.r10 = c.r10;
        mc.ss.r11 = c.r11;
        mc.ss.r12 = c.r12;
        mc.ss.r13 = c.r13;
        mc.ss.r14 = c.r14;
        mc.ss.r15 = c.r15;
        mc.ss.rip = c.rip;
        mc.ss.rflags = c.rflags;
        const fxdst: *[512]u8 = @ptrCast(@as([*]u8, @ptrCast(&mc.fs)) + 8);
        fxdst.* = c.fx;
    }
}

fn onStack(t: *Thread, sp: u64) bool {
    return t.ss_size != 0 and sp > t.ss_sp and sp - t.ss_sp <= t.ss_size;
}

fn wr(comptime T: type, addr: u64, v: T) void {
    @as(*align(1) T, @ptrFromInt(addr)).* = v;
}

fn rd(comptime T: type, addr: u64) T {
    return @as(*align(1) const T, @ptrFromInt(addr)).*;
}

// lc_copy copies n bytes from src to dst (x0, x1, x2), 16 at a time and then
// the rest, and returns 0, or 1 when a guest address faults: onFault resumes a
// fault inside it at lc_copy_fault.
comptime {
    if (tstate.arm64) asm (
        \\ .text
        \\ .p2align 2
        \\ .globl _lc_copy
        \\_lc_copy:
        \\ cmp x2, #16
        \\ b.lo 2f
        \\1:
        \\ ldp x3, x4, [x1], #16
        \\ stp x3, x4, [x0], #16
        \\ sub x2, x2, #16
        \\ cmp x2, #16
        \\ b.hs 1b
        \\2:
        \\ cbz x2, 4f
        \\3:
        \\ ldrb w3, [x1], #1
        \\ strb w3, [x0], #1
        \\ subs x2, x2, #1
        \\ b.ne 3b
        \\4:
        \\ mov x0, #0
        \\ ret
        \\ .globl _lc_copy_fault
        \\_lc_copy_fault:
        \\ mov x0, #1
        \\ ret
        \\ .globl _lc_load32
        \\_lc_load32:
        \\ ldr w0, [x0]
        \\ ret
        \\ .globl _lc_load32_fault
        \\_lc_load32_fault:
        \\ mov x0, #-1
        \\ ret
    ) else asm (
        // x86-64: dst=rdi, src=rsi, n=rdx. rep movsb, DF cleared (a guest may
        // have set it). The _fault labels are the resume points onFault uses
        // when a copy touches an unmapped guest address.
        \\ .text
        \\ .p2align 4
        \\ .globl _lc_copy
        \\_lc_copy:
        \\ cld
        \\ movq %rdx, %rcx
        \\ rep movsb
        \\ xorl %eax, %eax
        \\ ret
        \\ .globl _lc_copy_fault
        \\_lc_copy_fault:
        \\ movq $1, %rax
        \\ ret
        \\ .globl _lc_load32
        \\_lc_load32:
        \\ movl (%rdi), %eax
        \\ ret
        \\ .globl _lc_load32_fault
        \\_lc_load32_fault:
        \\ movq $-1, %rax
        \\ ret
    );
}
extern fn lc_copy(dst: u64, src: u64, n: u64) callconv(.C) u64;
extern fn lc_copy_fault() callconv(.C) void;
extern fn lc_load32(addr: u64) callconv(.C) u64;
extern fn lc_load32_fault() callconv(.C) void;

// load32 reads the aligned guest word at addr in one load (a futex word), or
// null when it faults: onFault resumes a fault in lc_load32 at lc_load32_fault.
pub fn load32(addr: u64) ?u32 {
    const v = lc_load32(addr);
    return if (v > 0xffffffff) null else @truncate(v);
}

pub fn copyGuest(dst: u64, src: u64, n: u64) bool {
    return lc_copy(dst, src, n) == 0;
}

// get and put access guest memory that may be bad, for syscalls that return
// EFAULT rather than crash the stub.
fn get(comptime T: type, addr: u64) ?T {
    var v: T = undefined;
    if (!copyGuest(@intFromPtr(&v), addr, @sizeOf(T))) return null;
    return v;
}

fn put(comptime T: type, addr: u64, v: T) bool {
    return copyGuest(addr, @intFromPtr(&v), @sizeOf(T));
}

pub fn getTimespec(addr: u64) ?[2]i64 {
    return get([2]i64, addr);
}

pub fn putTimespec(addr: u64, ts: [2]i64) bool {
    return put([2]i64, addr, ts);
}

// ---- restartable sequences --------------------------------------------------

// RSEQ_OFF is where a thread's record holds its registered rseq area and, 8
// bytes on, its signature (sandbox/lx_signal.go stRseq).
const RSEQ_OFF: usize = 0x800;

const RseqCs = extern struct { version: u32, flags: u32, start: u64, post: u64, abort: u64 };

// rseqAbort is where a signal delivered at pc resumes the thread instead: the
// abort handler of the critical section of a restartable sequence pc is in,
// whose descriptor it clears, as the kernel does before it builds the frame.
// A descriptor the kernel would refuse kills the process with SIGSEGV.
fn rseqAbort(t: *Thread, pc: u64) ?u64 {
    const rec = @intFromPtr(t);
    const area = @atomicLoad(u64, @as(*const u64, @ptrFromInt(rec + RSEQ_OFF)), .acquire);
    if (area == 0) return null;
    const sig = @atomicLoad(u32, @as(*const u32, @ptrFromInt(rec + RSEQ_OFF + 8)), .acquire);
    const p = get(u64, area + 8) orelse die(SIGSEGV);
    if (p == 0) return null;
    const cs = get(RseqCs, p) orelse die(SIGSEGV);
    if (cs.version != 0 or cs.start +% cs.post < cs.start or cs.abort -% cs.start < cs.post) die(SIGSEGV);
    if ((get(u32, cs.abort -% 4) orelse die(SIGSEGV)) != sig) die(SIGSEGV);
    if (!put(u64, area + 8, 0)) die(SIGSEGV);
    if (pc -% cs.start >= cs.post) return null;
    return cs.abort;
}

// deliverOnto builds the Linux rt_sigframe for sig on c's stack (or the
// alternate stack) and points c at the handler, as the kernel's setup_rt_frame
// does. uc_mask is the mask the handler's sigreturn restores.
fn deliverOnto(c: *Ctx, sig: u32, info: *const Info, act: Act, uc_mask: u64, fault: bool) void {
    const t = thr();
    if (tstate.arm64) {
        if (rseqAbort(t, c.pc)) |a| c.pc = a;
    } else if (rseqAbort(t, c.rip)) |a| c.rip = a;
    if (tstate.arm64) {
        var sp = c.sp;
        const on = onStack(t, sp);
        const ss_sp = t.ss_sp;
        const ss_size = t.ss_size;
        var ss_flags: u32 = if (ss_size == 0) SS_DISABLE else if (on) SS_ONSTACK else 0;
        ss_flags |= t.ss_flags;
        if (act.flags & SA_ONSTACK != 0 and ss_size != 0 and !on) {
            sp = ss_sp + ss_size;
            if (t.ss_flags & SS_AUTODISARM != 0) {
                t.ss_sp = 0;
                t.ss_size = 0;
                t.ss_flags = 0;
            }
        }
        sp = (sp - 16) & ~@as(u64, 15);
        const rec = sp;
        wr(u64, rec, c.x[29]);
        wr(u64, rec + 8, c.x[30]);
        const fr = (sp - FRAME_SIZE) & ~@as(u64, 15);

        @memset(@as([*]u8, @ptrFromInt(fr))[0..128], 0);
        wr(i32, fr, @intCast(sig));
        wr(i32, fr + 4, info.errno);
        wr(i32, fr + 8, info.code);
        wr(u64, fr + 16, info.a);
        wr(u64, fr + 24, info.b);

        const uc = fr + 128;
        wr(u64, uc, 0); // uc_flags
        wr(u64, uc + 8, 0); // uc_link
        wr(u64, uc + 16, ss_sp);
        wr(u32, uc + 24, ss_flags);
        wr(u32, uc + 28, 0);
        wr(u64, uc + 32, ss_size);
        wr(u64, uc + 40, uc_mask);
        @memset(@as([*]u8, @ptrFromInt(uc + 48))[0 .. UC_MCONTEXT - 48], 0);
        const mc = uc + UC_MCONTEXT;
        wr(u64, mc, if (fault) c.fault else 0);
        for (0..31) |i| wr(u64, mc + 8 + i * 8, c.x[i]);
        wr(u64, mc + 256, c.sp);
        wr(u64, mc + 264, c.pc);
        wr(u64, mc + 272, c.pstate);
        wr(u64, mc + 280, 0);
        var r = mc + SC_RESERVED;
        wr(u32, r, FPSIMD_MAGIC);
        wr(u32, r + 4, FPSIMD_SIZE);
        wr(u32, r + 8, c.fpsr);
        wr(u32, r + 12, c.fpcr);
        for (0..32) |i| wr(u128, r + 16 + i * 16, c.v[i]);
        r += FPSIMD_SIZE;
        if (fault and c.esr != 0) {
            wr(u32, r, ESR_MAGIC);
            wr(u32, r + 4, 16);
            wr(u64, r + 8, c.esr);
            r += 16;
        }
        wr(u64, r, 0); // terminator {magic 0, size 0}

        var nm = t.mask | act.mask;
        if (act.flags & SA_NODEFER == 0) nm |= bit(sig);
        @atomicStore(u64, &t.mask, nm & ~KILLSTOP, .release);

        c.x[0] = sig;
        c.x[1] = fr;
        c.x[2] = uc;
        c.x[29] = rec;
        c.x[30] = if (act.flags & SA_RESTORER != 0) act.restorer else g_restorer;
        c.sp = fr;
        c.pc = act.handler;
    } else {
        // x86-64 Linux rt_sigframe: [pretcode(8)][ucontext(304)][siginfo(128)],
        // with the 512-byte FXSAVE _fpstate placed above and pointed to by
        // sigcontext.fpstate. The handler runs with rsp = &frame (pretcode is
        // its return address, so rsp must be 8 mod 16), rdi=sig, rsi=&info,
        // rdx=&uc. Offsets are the kernel UAPI sigcontext_64 / ucontext layout.
        // VERIFY ON MAC: the frame offsets, the 8-mod-16 entry alignment and the
        // _fpstate placement.
        var sp = c.rsp;
        const on = onStack(t, sp);
        const ss_sp = t.ss_sp;
        const ss_size = t.ss_size;
        var ss_flags: u32 = if (ss_size == 0) SS_DISABLE else if (on) SS_ONSTACK else 0;
        ss_flags |= t.ss_flags;
        if (act.flags & SA_ONSTACK != 0 and ss_size != 0 and !on) {
            sp = ss_sp + ss_size;
            if (t.ss_flags & SS_AUTODISARM != 0) {
                t.ss_sp = 0;
                t.ss_size = 0;
                t.ss_flags = 0;
            }
        }
        const fpst = (sp - 512) & ~@as(u64, 63);
        @as(*[512]u8, @ptrFromInt(fpst)).* = c.fx;
        const fr = ((fpst - 440) & ~@as(u64, 15)) - 8;
        wr(u64, fr, if (act.flags & SA_RESTORER != 0) act.restorer else g_restorer); // pretcode
        const uc = fr + 8;
        wr(u64, uc, 0); // uc_flags
        wr(u64, uc + 8, 0); // uc_link
        wr(u64, uc + 16, ss_sp); // uc_stack.ss_sp
        wr(u32, uc + 24, ss_flags);
        wr(u32, uc + 28, 0);
        wr(u64, uc + 32, ss_size);
        const sc = uc + 40; // sigcontext_64
        wr(u64, sc + 0, c.r8);
        wr(u64, sc + 8, c.r9);
        wr(u64, sc + 16, c.r10);
        wr(u64, sc + 24, c.r11);
        wr(u64, sc + 32, c.r12);
        wr(u64, sc + 40, c.r13);
        wr(u64, sc + 48, c.r14);
        wr(u64, sc + 56, c.r15);
        wr(u64, sc + 64, c.rdi);
        wr(u64, sc + 72, c.rsi);
        wr(u64, sc + 80, c.rbp);
        wr(u64, sc + 88, c.rbx);
        wr(u64, sc + 96, c.rdx);
        wr(u64, sc + 104, c.rax);
        wr(u64, sc + 112, c.rcx);
        wr(u64, sc + 120, c.rsp);
        wr(u64, sc + 128, c.rip);
        wr(u64, sc + 136, c.rflags);
        wr(u16, sc + 144, USER_CS);
        wr(u16, sc + 146, 0); // gs
        wr(u16, sc + 148, 0); // fs
        wr(u16, sc + 150, USER_SS);
        wr(u64, sc + 152, if (fault) c.err else 0);
        wr(u64, sc + 160, if (fault) c.trapno else 0);
        wr(u64, sc + 168, uc_mask); // oldmask
        wr(u64, sc + 176, if (fault) c.fault else 0); // cr2
        wr(u64, sc + 184, fpst); // fpstate pointer
        @memset(@as([*]u8, @ptrFromInt(sc + 192))[0..64], 0); // reserved1[8]
        wr(u64, uc + 296, uc_mask); // uc_sigmask (first 8 bytes = the active mask)
        const si = uc + 304; // siginfo
        @memset(@as([*]u8, @ptrFromInt(si))[0..128], 0);
        wr(i32, si, @intCast(sig));
        wr(i32, si + 4, info.errno);
        wr(i32, si + 8, info.code);
        wr(u64, si + 16, info.a);
        wr(u64, si + 24, info.b);

        var nm = t.mask | act.mask;
        if (act.flags & SA_NODEFER == 0) nm |= bit(sig);
        @atomicStore(u64, &t.mask, nm & ~KILLSTOP, .release);

        c.rdi = sig;
        c.rsi = si;
        c.rdx = uc;
        c.rax = 0; // varargs ABI: no vector registers passed
        c.rsp = fr;
        c.rip = act.handler;
    }
}

// dispatchAll takes every signal deliverable to this thread and acts on it:
// handlers stack their frames on c (the last one taken runs first, as on
// Linux), ignored ones vanish, a stop stops, a fatal one ends the process.
fn dispatchAll(c: *Ctx) bool {
    var changed = false;
    while (true) {
        var info: Info = undefined;
        var act: Act = undefined;
        const s = take(~ld(&thr().mask), &info, &act);
        if (s == 0) return changed;
        switch (classify(s, act)) {
            .ignore => {},
            .stop => stopSelf(s),
            .term => die(s),
            .handler => {
                deliverOnto(c, s, &info, act, ld(&thr().mask), false);
                changed = true;
            },
        }
    }
}

// lc_sig_switch is the trap a syscall return uses to load tl.switch_ctx (and deliver
// tl.first_sig onto it) from a Darwin signal context.
export fn lc_sig_switch() callconv(.Naked) noreturn {
    asm volatile (if (tstate.arm64) "brk #0x5c" else "ud2");
}

fn switchNow() noreturn {
    asm volatile ("b _lc_sig_switch");
    unreachable;
}

// x86-64 signal delivery. There is no arm64 brk-trap context switch: serveTrap
// stores the trap's mcontext in g_sigmc, and the handler / sigsuspend /
// sigreturn paths build tl.switch_ctx and apply it -- with any pending handlers
// stacked by doSwitch -- straight onto that mcontext. g_sig_delivered tells
// serveTrap the mcontext now holds the handler or restored context, so it
// resumes there instead of writing the syscall result past the trap.
pub threadlocal var g_sigmc: *std.c.mcontext_t = undefined;
pub threadlocal var g_sig_delivered: bool = false;

// x64SaveCtx seeds tl.switch_ctx from the trapped mcontext (GPRs + FP) with the
// syscall's result in rax and the resume pc -- frame[33] (just past the trapped
// syscall) normally, or the syscall site itself for a restart, where rax keeps
// the call number so the re-executed syscall reissues with its arguments.
fn x64SaveCtx(rax: u64, rip: u64) void {
    fromMc(&tl.switch_ctx, g_sigmc);
    tl.switch_ctx.rax = rax;
    tl.switch_ctx.rip = rip;
}

fn x64Deliver() void {
    doSwitch(g_sigmc);
    g_sig_delivered = true;
}

// A trap wx.zig placed for an svc is served as the svc's island would serve
// it: trapEnter pushes the guest's x16 and x17 and lc_trap_ret's address
// below its sp, past the same gap an island skips, and enters tramp_common
// with x17 the pc to resume at. tramp_common returns through lc_trap_ret,
// which restores x16 and x17 and traps once more, for trapReturn to pop the
// pushes and resume the guest at the pc tramp_common left in the island's
// spare slot: no register is free to branch with. A thread's exit goes to its
// own stack instead, as its island would.
fn trapEnter(mc: *std.c.mcontext_t) void {
    const own = if (mc.ss.regs[8] == NR_EXIT) @intFromPtr(pthread_getspecific(@import("root").g_stk_key)) else 0;
    const sp = if (own != 0) own else mc.ss.sp;
    setBusy(&tl, true);
    const ok = put(u64, sp - 144, mc.ss.regs[16]) and put(u64, sp - 136, mc.ss.regs[17]) and put(u64, sp - 160, @intFromPtr(&lc_trap_ret));
    setBusy(&tl, false);
    if (!ok) die(SIGSEGV);
    mc.ss.regs[17] = mc.ss.pc + 4;
    mc.ss.sp = sp - proc.ISLAND_PUSH;
    mc.ss.pc = if (own != 0) @intFromPtr(&@import("root").tramp_common_here) else @intFromPtr(&@import("root").tramp_common);
}

export fn lc_trap_ret() callconv(.Naked) noreturn {
    if (tstate.arm64) {
        asm volatile (
            \\ ldp x16, x17, [sp, #16]
            \\ brk #0x5d
        );
    } else {
        asm volatile ("ud2");
    }
}

fn trapReturn(mc: *std.c.mcontext_t) void {
    const island: [*]const u64 = @ptrFromInt(mc.ss.sp);
    mc.ss.pc = island[1];
    mc.ss.sp += proc.ISLAND_PUSH;
}

fn doSwitch(mc: *std.c.mcontext_t) void {
    var c = tl.switch_ctx;
    tl.in_handler = true;
    if (tl.first_sig != 0) {
        const s = tl.first_sig;
        tl.first_sig = 0;
        deliverOnto(&c, s, &tl.first_info, tl.first_act, tl.first_mask, false);
    }
    _ = dispatchAll(&c);
    toMc(mc, &c);
    tl.in_handler = false;
    tl.busy = false;
}

fn isRestart(r: u64) bool {
    const v: i64 = @bitCast(r);
    return v == -ERESTARTSYS or v == -ERESTARTNOINTR or v == -ERESTARTNOHAND or v == -ERESTART_RESTARTBLOCK;
}

fn epipeRaises(frame: [*]u64) bool {
    const MSG_NOSIGNAL: u64 = 0x4000;
    return switch (frame[8]) {
        NR_WRITE, NR_WRITEV => true,
        NR_SENDTO, NR_SENDMMSG => frame[3] & MSG_NOSIGNAL == 0,
        NR_SENDMSG => frame[2] & MSG_NOSIGNAL == 0,
        else => false,
    };
}

// afterSyscall runs on every trampoline return with the syscall's result. It
// delivers what is pending for the thread (switching into a handler, which
// does not return here) and resolves restart codes: null means re-issue the
// syscall, as Linux does when no handler ran or the handler has SA_RESTART.
pub fn afterSyscall(frame: [*]u64, r0: u64) ?u64 {
    const s = &tl;
    if (!s.ready) return r0;
    if (@as(i64, @bitCast(r0)) == -EPIPE and epipeRaises(frame)) raiseSelf(SIGPIPE, SI_USER);
    if (!isRestart(r0)) {
        // Fast path. A kick from here on redirects the thread itself; one
        // that came earlier found busy set, but its signal is visible now.
        if (tstate.arm64) leaveTo(frame, r0, proc.guestSp(frame));
        setBusy(s, false);
        const t = s.rec;
        const pend = @atomicLoad(u64, &t.pending, .monotonic) | @atomicLoad(u64, &s.prec.pending, .monotonic);
        if (pend & ~@atomicLoad(u64, &t.mask, .monotonic) == 0 and @atomicLoad(u32, &t.saved, .monotonic) == 0) return r0;
        setBusy(s, true);
    }
    return pendingAfter(frame, r0);
}

noinline fn pendingAfter(frame: [*]u64, r0: u64) ?u64 {
    clearKick(); // answered by the look for signals below; a restart issues the call again
    // A temporary mask stays in force for the handlers of the signals that
    // interrupted the call, whose frames restore the real one; otherwise the
    // real one is back at once.
    const t = thr();
    var real: ?u64 = null;
    if (@atomicLoad(u32, &t.saved, .acquire) != 0) {
        @atomicStore(u32, &t.saved, 0, .release);
        if (@as(i64, @bitCast(r0)) == -EINTR or isRestart(r0)) {
            real = ld(&t.saved_mask);
        } else {
            @atomicStore(u64, &t.mask, ld(&t.saved_mask), .release);
        }
    }
    defer if (real) |m| @atomicStore(u64, &t.mask, m, .release);
    while (true) {
        var info: Info = undefined;
        var act: Act = undefined;
        const s = take(~ld(&thr().mask), &info, &act);
        if (s != 0) {
            switch (classify(s, act)) {
                .ignore => continue,
                .stop => {
                    stopSelf(s);
                    continue;
                },
                .term => die(s),
                .handler => {
                    const rv: i64 = @bitCast(r0);
                    const restart = rv == -ERESTARTNOINTR or (rv == -ERESTARTSYS and act.flags & SA_RESTART != 0);
                    if (!restart and rv == -ERESTART_RESTARTBLOCK) @import("local.zig").forgetRestart();
                    tl.first_sig = s;
                    tl.first_info = info;
                    tl.first_act = act;
                    tl.first_mask = real orelse ld(&thr().mask);
                    if (tstate.arm64) {
                        if (restart) {
                            fromFrame(&tl.switch_ctx, frame, frame[0], frame[33] - 4);
                        } else {
                            fromFrame(&tl.switch_ctx, frame, if (isRestart(r0)) neg(EINTR) else r0, frame[33]);
                        }
                        switchNow();
                    }
                    if (restart) {
                        x64SaveCtx(g_sigmc.ss.rax, frame[33] - 2); // re-run the syscall after the handler
                    } else {
                        x64SaveCtx(if (isRestart(r0)) neg(EINTR) else r0, frame[33]);
                    }
                    x64Deliver();
                    return r0;
                },
            }
        }
        if (isRestart(r0)) {
            // ERESTART_RESTARTBLOCK resumes as restart_syscall, which goes on
            // from the call's restart block rather than starting it over.
            if (@as(i64, @bitCast(r0)) == -ERESTART_RESTARTBLOCK) frame[8] = NR_RESTART_SYSCALL;
            return null;
        }
        if (tstate.arm64) leaveTo(frame, r0, proc.guestSp(frame));
        setBusy(&tl, false);
        if (pendingAllowed(~ld(&thr().mask)) == 0) return r0;
        setBusy(&tl, true);
    }
}

// ---- Darwin handlers ------------------------------------------------------------

// guestState loads the guest state a kick delivers onto, or reports the
// thread on its way into the stub. Out of busy sections a thread can still be
// in transit between the guest and the stub: in an island, in tramp_common,
// or in the stub on its way back. Its registers then are partly the stub's,
// so the guest state comes from where the transit keeps it: the frame it
// returns from, or the island's own saves. A thread on its way in leaves the
// signal to the syscall it enters.
fn guestState(mc: *std.c.mcontext_t, c: *Ctx) bool {
    if (!tstate.arm64) {
        fromMc(c, mc);
        return true;
    }
    const pc = mc.ss.pc;
    if (pc >= g_text[0] and pc < g_text[1]) {
        if (pc >= @intFromPtr(&@import("root").tramp_common) and pc < @intFromPtr(&lc_tc_busy)) return false;
        if (!tl.leaving) return false;
        fromLeave(c);
        return true;
    }
    fromMc(c, mc);
    const at = pc & ~@as(u64, 63);
    const off = pc - at;
    const w: *const [16]u32 = @ptrFromInt(at);
    const q: *const [8]u64 = @ptrFromInt(at);
    const common = @intFromPtr(&@import("root").tramp_common);
    if (w[0] == 0xa9b747f0 and w[2] == 0xf81f0ff0 and w[5] == 0xd61f0200 and q[5] == at + 24 and q[7] == common) {
        if (off < 24 or !tl.leaving) return false;
        fromLeave(c);
    } else if (w[0] == 0xd53bd070 and w[2] == 0xb4000050 and w[3] == 0x9100021f and w[10] == 0xd61f0200 and q[7] == @intFromPtr(&@import("root").tramp_common_here)) {
        if (off < 44 or !tl.leaving) return false;
        fromLeave(c);
    } else if (w[0] & ~@as(u32, 31) == 0xd53bd060 and w[1] == tpLoad(w[0] & 31, w[0] & 31) and w[2] >> 26 == 5) {
        // mrs xN, tpidrro_el0; ldr xN, [xN, #key*8]; b resume
        const ret = bTarget(at + 8, w[2]);
        switch (off) {
            0 => c.pc = ret - 4,
            4 => {
                c.x[w[0] & 31] = @intFromPtr(pthread_getspecific(@import("root").g_tp_key));
                c.pc = ret;
            },
            else => c.pc = ret,
        }
    } else if (w[0] & ~@as(u32, 31) == 0xf8170fe0 and w[1] == 0xd53bd060 | (w[0] & 31) and w[3] == 0xf84907e0 | (w[0] & 31) and w[4] >> 26 == 5) {
        // str xS, [sp, #-144]!; mrs xS, tpidrro_el0; str xN, [xS, #key*8];
        // ldr xS, [sp], #144; b resume
        const ret = bTarget(at + 16, w[4]);
        if (off >= 4 and off <= 12) {
            c.x[w[0] & 31] = load(mc.ss.sp) orelse return false;
            c.sp = mc.ss.sp + 144;
        }
        c.pc = if (off < 12) ret - 4 else ret;
    } else if (w[0] & ~@as(u32, 31) == 0x58000040 and w[1] >> 26 == 5 and q[1] == @import("root").CTR_EL0_VALUE) {
        // ldr xN, Lctr; b resume
        const ret = bTarget(at + 4, w[1]);
        c.pc = if (off == 0) ret - 4 else ret;
    }
    return true;
}

fn fromLeave(c: *Ctx) void {
    fromFrame(c, tl.leave_frame, tl.leave_x0, tl.leave_frame[33]);
    c.sp = tl.leave_sp;
}

fn tpLoad(rt: u32, rn: u32) u32 {
    const key: u32 = @intCast(@import("root").g_tp_key);
    return 0xf9400000 | (key << 10) | (rn << 5) | rt;
}

fn bTarget(from: u64, insn: u32) u64 {
    const imm: i64 = @as(i32, @bitCast(insn << 6)) >> 6;
    return from +% @as(u64, @bitCast(imm * 4));
}

// load reads a word of the guest's stack from a kick, where busy is clear:
// a fault in the copy then comes back as null.
fn load(addr: u64) ?u64 {
    setBusy(&tl, true);
    defer setBusy(&tl, false);
    return get(u64, addr);
}

fn kickSelf(ctx: ?*anyopaque) void {
    if (!tl.ready) return;
    if (tl.busy) {
        @atomicStore(u32, &tl.kicked, 1, .seq_cst);
        const kuc: *std.c.ucontext_t = @ptrCast(@alignCast(ctx.?));
        cpCancel(kuc.mcontext);
        if (@atomicLoad(bool, &tl.waiting, .seq_cst)) {
            @atomicStore(u32, &tl.word, 1, .seq_cst);
            futex.wakeAll(@intFromPtr(&tl.word));
        }
        const fa = @atomicLoad(u64, &tl.futex, .seq_cst);
        if (fa != 0) futex.wakeAll(fa);
        return;
    }
    if (tl.in_handler or pendingAllowed(~ld(&thr().mask)) == 0) return;
    const uc: *std.c.ucontext_t = @ptrCast(@alignCast(ctx.?));
    var c: Ctx = undefined;
    if (!guestState(uc.mcontext, &c)) {
        // On its way into the stub: the syscall it enters looks for signals.
        @atomicStore(u32, &tl.kicked, 1, .seq_cst);
        return;
    }
    tl.in_handler = true;
    defer tl.in_handler = false;
    if (dispatchAll(&c)) toMc(uc.mcontext, &c);
}

fn pthreadKill(port: u32, sig: c_int) void {
    if (tstate.arm64) {
        _ = asm volatile (
            \\ mov x16, #328
            \\ svc #0x80
            : [ret] "={x0}" (-> u64),
            : [p] "{x0}" (port),
              [s] "{x1}" (sig),
            : "x16", "cc", "memory"
        );
    } else {
        // Darwin BSD-class syscall: rax = 0x2000000 | nr, result in rax, syscall
        // clobbers rcx and r11.
        _ = asm volatile ("syscall"
            : [ret] "={rax}" (-> u64),
            : [nr] "{rax}" (@as(u64, 0x2000000 | 328)),
              [p] "{rdi}" (port),
              [s] "{rsi}" (sig),
            : "rcx", "r11", "cc", "memory"
        );
    }
}

fn onRoute(_: c_int, _: *std.c.siginfo_t, ctx: ?*anyopaque) callconv(.C) void {
    for (0..chan.MAX_SLOTS) |i| {
        const port = @atomicLoad(u32, &g_ports[i], .acquire);
        if (port == 0) continue;
        if (tl.ready and i == tl.slot) {
            kickSelf(ctx);
        } else if (deliverableFor(thrAt(i)) != 0) {
            pthreadKill(port, DW_SIGUSR2);
        }
    }
}

fn onKick(_: c_int, _: *std.c.siginfo_t, ctx: ?*anyopaque) callconv(.C) void {
    kickSelf(ctx);
}

// faultSignal translates a Darwin fault into Linux's signal and si_code. Darwin
// reports a write to a read-only page as SIGBUS; Linux calls every permission
// or translation fault SIGSEGV and keeps SIGBUS for alignment. arm64 reads the
// ESR exception class; x86-64 reads the trap vector and, for a page fault, the
// error code's present bit.
fn faultSignal(dsig: c_int, mc: *const std.c.mcontext_t, info: *Info) u32 {
    if (tstate.arm64) {
        const esr = mc.es.esr;
        const far = mc.es.far;
        const pc = mc.ss.pc;
        var sig: u32 = SIGSEGV;
        var code: i32 = SEGV_MAPERR;
        var addr = far;
        switch (esr >> 26) {
            0x20, 0x21, 0x24, 0x25 => {
                const dfsc = esr & 0x3f;
                // As Linux, a mapping at the address makes it a protection failure,
                // none an unmapped address; Darwin's own code says ACCERR for
                // addresses it reserves without a mapping. The low 4 GiB is the
                // stub's __PAGEZERO, a mapping the guest never sees.
                if (dfsc == 0x21) {
                    sig = SIGBUS;
                    code = BUS_ADRALN;
                } else if (far < PAGEZERO_END) {} else if (mem.protAt(far)) |p| {
                    // An access the mapping permits that Darwin still could not
                    // serve -- a page of a file mapping past the file's end -- is
                    // Linux's SIGBUS; one it does not permit, a protection failure.
                    const need: u32 = if (esr >> 26 >= 0x24) (if (esr & (1 << 6) != 0) 2 else 1) else 4;
                    if (dsig == DW_SIGBUS and dfsc & 0x3c == 0x04 and p & need != 0) {
                        sig = SIGBUS;
                        code = BUS_ADRERR;
                    } else code = SEGV_ACCERR;
                }
            },
            0x22, 0x26 => {
                sig = SIGBUS;
                code = BUS_ADRALN;
                if (esr >> 26 == 0x22) addr = pc;
            },
            0x3c => {
                sig = SIGTRAP;
                code = TRAP_BRKPT;
                addr = pc;
            },
            else => switch (dsig) {
                DW_SIGILL => {
                    sig = SIGILL;
                    code = ILL_ILLOPC;
                    addr = pc;
                },
                DW_SIGTRAP => {
                    sig = SIGTRAP;
                    code = TRAP_BRKPT;
                    addr = pc;
                },
                DW_SIGFPE => {
                    sig = SIGFPE;
                    code = 0;
                    addr = pc;
                },
                DW_SIGBUS => {
                    sig = SIGBUS;
                    code = BUS_ADRERR;
                },
                else => {},
            },
        }
        info.* = .{ .signo = @intCast(sig), .errno = 0, .code = code, .pad = 0, .a = addr, .b = 0 };
        return sig;
    } else {
        const trapno = mc.es.trapno;
        const err = mc.es.err;
        const pc = mc.ss.rip;
        var sig: u32 = SIGSEGV;
        var code: i32 = SEGV_MAPERR;
        var addr: u64 = mc.es.faultvaddr;
        switch (trapno) {
            14 => if (err & 1 != 0) {
                // #PF: present bit set means a protection violation at a mapped
                // page; clear means not-present, which keeps SEGV_MAPERR.
                code = SEGV_ACCERR;
            },
            17 => { // #AC alignment check
                sig = SIGBUS;
                code = BUS_ADRALN;
            },
            6 => { // #UD invalid opcode
                sig = SIGILL;
                code = ILL_ILLOPC;
                addr = pc;
            },
            1, 3 => { // #DB debug/single-step, #BP int3
                sig = SIGTRAP;
                code = TRAP_BRKPT;
                addr = pc;
            },
            else => switch (dsig) {
                DW_SIGILL => {
                    sig = SIGILL;
                    code = ILL_ILLOPC;
                    addr = pc;
                },
                DW_SIGTRAP => {
                    sig = SIGTRAP;
                    code = TRAP_BRKPT;
                    addr = pc;
                },
                DW_SIGFPE => {
                    sig = SIGFPE;
                    code = 0;
                    addr = pc;
                },
                DW_SIGBUS => {
                    sig = SIGBUS;
                    code = BUS_ADRERR;
                },
                else => {},
            },
        }
        info.* = .{ .signo = @intCast(sig), .errno = 0, .code = code, .pad = 0, .a = addr, .b = 0 };
        return sig;
    }
}

// idReg serves an mrs of an AArch64 ID register that Darwin traps at EL0
// where Linux emulates it: the feature ID registers from the host's HWCAP
// (hwcap.isar), MIDR_EL1 as the chip's P-core (hwcap.midr), MPIDR_EL1 as a
// single uniprocessor view and REVIDR_EL1 as no errata. The registers that also carry layout values keep trapping. It
// writes the value into the guest register and steps past the mrs; false if
// the instruction is not one it serves.
fn idReg(mc: *std.c.mcontext_t) bool {
    const ins = @as(*const u32, @ptrFromInt(mc.ss.pc)).*;
    const is = hwcap.isar();
    const v: u64 = switch (ins & 0xffffffe0) {
        0xd5380600 => is[0], // ID_AA64ISAR0_EL1
        0xd5380620 => is[1], // ID_AA64ISAR1_EL1
        0xd5380640 => is[2], // ID_AA64ISAR2_EL1
        0xd5380000 => hwcap.midr, // MIDR_EL1
        0xd53800a0 => 0x80000000, // MPIDR_EL1: bit 31 RES1, affinity 0
        0xd53800c0 => 0, // REVIDR_EL1
        else => return false,
    };
    const n = ins & 0x1f;
    if (n != 31) switch (n) {
        29 => mc.ss.fp = v,
        30 => mc.ss.lr = v,
        else => mc.ss.regs[n] = v,
    };
    mc.ss.pc += 4;
    return true;
}

fn onFault(dsig_in: c_int, si: *std.c.siginfo_t, ctx: ?*anyopaque) callconv(.C) void {
    const uc: *std.c.ucontext_t = @ptrCast(@alignCast(ctx.?));
    const mc = uc.mcontext;
    // The arm64 trampoline-return and OOL-exit traps (brk/svc-return landmarks
    // and the out-of-line window exits) have no x86-64 analogue: x86-64 serves
    // syscalls from the SIGILL/mcontext path below and has no in-guest JIT
    // windows, so a SIGTRAP falls through to the generic delivery.
    if (tstate.arm64) {
        if (dsig_in == DW_SIGTRAP and tstate.pc(mc) == @intFromPtr(&lc_sig_switch)) return doSwitch(mc);
        if (dsig_in == DW_SIGTRAP and tstate.pc(mc) == @intFromPtr(&lc_trap_ret) + 4) return trapReturn(mc);
        if (dsig_in == DW_SIGTRAP and tl.ready) {
            if (ool.exit(tl.slot, mc)) |e| {
                if (e.jit) jit.initThread(); // back to execute mode
                for (e.holds) |h| wx.letGo(h);
                return;
            }
        }
    }
    if (dsig_in == DW_SIGILL and tl.ready and !tl.busy) {
        if (tstate.arm64) {
            switch (wx.isTrap(mc.ss.pc)) {
                .trap => return trapEnter(mc),
                .again => return,
                .excl => {
                    var st: wx.Step = .{};
                    switch (wx.exclTrap(mc.ss.pc, &st)) {
                        .handled => return,
                        .step => if (step(mc, &st)) return,
                        else => {},
                    }
                },
                .no => {},
            }
            if (idReg(mc)) return;
        } else {
            // A rewritten guest syscall site is a 2-byte ud2 (0f 0b). Service it
            // straight from the mcontext and resume past it (AMD64.md 1e/1f).
            if (@as(*align(1) const u16, @ptrFromInt(tstate.pc(mc))).* == 0x0b0f) {
                // Darwin hands an AVX context (es, ss, then the AVX float
                // state: 1028 bytes) to a thread that uses AVX.
                @import("root").serveTrap(mc, uc.mcsize >= MCONTEXT_AVX64);
                return;
            }
        }
    }
    // x86-64 %fs is virtualized: glibc's %fs:disp TLS reads/writes fault (the
    // physical %fs base is 0) and are emulated against the stored guest base.
    if (!tstate.arm64 and dsig_in == DW_SIGSEGV and tl.ready and !tl.busy) {
        if (fsmem.emulate(mc)) return;
    }
    var dsig = dsig_in;
    // The W^X/OOL fault handling is arm64-only (x86-64 has no in-guest JIT
    // window machinery on the syscall path).
    if (tstate.arm64) {
    if (dsig == DW_SIGSEGV or dsig == DW_SIGBUS) {
        const page = mc.es.far & ~@as(u64, 0x3fff);
        var st: wx.Step = .{ .from_slot = ool.inSlot(tl.slot, mc.ss.pc), .own = !tl.ready or tl.busy, .lost = ool.lost(tl.slot, mc.ss.pc, page) };
        const v = wx.fault(mc.es.esr, mc.es.far, mc.ss.pc, &st);
        if (v == .handled) return;
        if (v == .retry) {
            ool.tried(tl.slot, mc.ss.pc, page);
            return;
        }
        if (v == .step and step(mc, &st)) return;
        if (v == .attach) {
            if (!ool.addHold(tl.slot, st.hold)) wx.letGo(st.hold);
            return;
        }
        if (v == .wait or v == .hot or v == .cool) {
            for (ool.dropHolds(tl.slot)) |h| wx.letGo(h);
            const was = tl.busy;
            setBusy(&tl, true); // a kick meanwhile waits for the fault's retry
            switch (v) {
                .wait => wx.waitWindow(st.gen),
                .hot => {
                    service.ask(service.ID_HOT, st.id);
                    wx.holding(st.id);
                },
                else => {
                    service.ask(service.ID_COOL_ASK, st.id);
                    wx.cooled(st.id, st.gen);
                },
            }
            setBusy(&tl, was);
            return;
        }
        if (v == .other) {
            var f: jit.Fault = .{ .pc = mc.ss.pc, .esr = mc.es.esr, .far = mc.es.far, .dsig = dsig, .code = si.code };
            if (jit.flip(&f, mc, tl.slot)) return;
            dsig = f.dsig;
            si.code = f.code;
            mc.es.esr = f.esr;
            mc.es.far = f.far;
        }
    }
    }
    if (tl.busy and tstate.pc(mc) >= @intFromPtr(&lc_copy) and tstate.pc(mc) < @intFromPtr(&lc_copy_fault)) {
        tstate.setPc(mc, @intFromPtr(&lc_copy_fault));
        return;
    }
    if (tl.busy and tstate.pc(mc) == @intFromPtr(&lc_load32)) {
        tstate.setPc(mc, @intFromPtr(&lc_load32_fault));
        return;
    }
    if (!tl.ready or tl.busy) {
        _ = signal(dsig_in, DW_SIG_DFL); // a fault in the stub itself: crash for real
        return;
    }
    // A fault while building a frame (an unusable guest stack) is fatal, as
    // Linux's force_sigsegv on a failed setup_rt_frame.
    if (tl.in_handler) die(SIGSEGV);
    var info: Info = undefined;
    const sig = faultSignal(dsig, mc, &info);
    var c: Ctx = undefined;
    fromMc(&c, mc);
    tl.in_handler = true;
    defer tl.in_handler = false;
    // A synchronous signal cannot be blocked or ignored: the supervisor
    // resets it to the default action, which kills.
    const t = thr();
    _ = goCallArgs(LC_SIGFAULT, .{ sig, @intFromBool(ld(&t.mask) & bit(sig) != 0), info.a, @as(u32, @bitCast(info.code)), if (tstate.arm64) c.pc else c.rip, 0 });
    const act = replyOf(myChan()).act;
    if (classify(sig, act) != .handler) die(sig);
    deliverOnto(&c, sig, &info, act, ld(&t.mask), true);
    _ = dispatchAll(&c);
    toMc(mc, &c);
}

// step does what wx.zig asks of the thread for a store into the page that runs
// it (wx.Step): fails a store exclusive, or runs its instructions out of
// line, a window that cannot run so its first instruction alone.
fn step(mc: *std.c.mcontext_t, st: *const wx.Step) bool {
    if (st.fail) |r| {
        switch (r) {
            29 => mc.ss.fp = 1,
            30 => mc.ss.lr = 1,
            31 => {},
            else => mc.ss.regs[r] = 1,
        }
        mc.ss.pc += 4;
        return true;
    }
    if (ool.run(tl.slot, mc, st.words[0..st.n], st.start, false, st.hold)) return true;
    wx.letGo(st.hold);
    if (st.again) return true;
    return st.n > 1 and ool.run(tl.slot, mc, st.words[0..1], st.start, false, 0);
}

// ---- syscalls -------------------------------------------------------------------

// handle serves the signal syscalls that only touch this thread's or process's
// signal state. Returns null for any other nr.
pub noinline fn handle(nr: u64, frame: [*]u64) ?u64 {
    return switch (nr) {
        NR_RT_SIGPROCMASK => sysSigprocmask(frame[0], frame[1], frame[2], frame[3]),
        NR_RT_SIGPENDING => sysSigpending(frame[0], frame[1]),
        NR_SIGALTSTACK => sysSigaltstack(frame[0], frame[1], if (tstate.arm64) proc.guestSp(frame) else frame[proc.XR_RSP]),
        NR_RT_SIGRETURN => sysSigreturn(frame),
        NR_RT_SIGSUSPEND => sysSigsuspend(frame),
        NR_RT_SIGTIMEDWAIT => sysSigtimedwait(frame[0], frame[1], frame[2], frame[3]),
        else => null,
    };
}

fn sysSigprocmask(how: u64, set: u64, oset: u64, size: u64) u64 {
    if (size != 8) return neg(EINVAL);
    const t = thr();
    const old = ld(&t.mask);
    if (set != 0) {
        const s = get(u64, set) orelse return neg(EFAULT);
        const nm = switch (how) {
            0 => old | s,
            1 => old & ~s,
            2 => s,
            else => return neg(EINVAL),
        };
        @atomicStore(u64, &t.mask, nm & ~KILLSTOP, .release);
    }
    if (oset != 0 and !put(u64, oset, old)) return neg(EFAULT);
    return 0;
}

fn sysSigpending(set: u64, size: u64) u64 {
    if (size > 8) return neg(EINVAL);
    const t = thr();
    const v = (ld(&t.pending) | ld(&procOf(t).pending)) & ld(&t.mask);
    if (!copyGuest(set, @intFromPtr(&v), size)) return neg(EFAULT);
    return 0;
}

fn sysSigaltstack(ss: u64, oss: u64, sp: u64) u64 {
    const t = thr();
    const on = onStack(t, sp);
    const old_sp = t.ss_sp;
    const old_size = t.ss_size;
    const old_flags: u32 = (if (old_size == 0) SS_DISABLE else if (on) SS_ONSTACK else 0) | t.ss_flags;
    if (ss != 0) {
        if (on) return neg(EPERM);
        const n = get(extern struct { sp: u64, flags: u32, pad: u32, size: u64 }, ss) orelse return neg(EFAULT);
        const nsp = n.sp;
        const nflags = n.flags;
        const nsize = n.size;
        const mode = nflags & ~SS_AUTODISARM;
        if (mode != 0 and mode != SS_ONSTACK and mode != SS_DISABLE) return neg(EINVAL);
        if (mode == SS_DISABLE) {
            t.ss_sp = 0;
            t.ss_size = 0;
            t.ss_flags = 0;
        } else {
            if (nsize < MINSIGSTKSZ) return neg(ENOMEM);
            t.ss_sp = nsp;
            t.ss_size = nsize;
            t.ss_flags = nflags & SS_AUTODISARM;
        }
    }
    if (oss != 0 and !put(extern struct { sp: u64, flags: u32, pad: u32, size: u64 }, oss, .{ .sp = old_sp, .flags = old_flags, .pad = 0, .size = old_size })) return neg(EFAULT);
    return 0;
}

// sysSigreturn restores the state saved by deliverOnto from the guest's
// rt_sigframe at sp, including any change the handler made to it. The frame is
// guest memory: a part of it that is not mapped, or a malformed record, kills
// the process with SIGSEGV as the kernel's badframe path does.
fn sysSigreturn(frame: [*]u64) u64 {
    if (!tstate.arm64) return sysSigreturnX64(frame);
    const sp = proc.guestSp(frame);
    if (sp & 15 != 0) die(SIGSEGV);
    const uc = sp + 128;
    const mc = uc + UC_MCONTEXT;
    const head = get([4]u64, uc + 16) orelse die(SIGSEGV); // uc_stack, uc_sigmask
    const regs = get([34]u64, mc + 8) orelse die(SIGSEGV); // x0..x30, sp, pc, pstate
    var c: Ctx = undefined;
    for (0..31) |i| c.x[i] = regs[i];
    c.sp = regs[31];
    c.pc = regs[32];
    c.pstate = regs[33] & 0xf0000000;
    c.fault = 0;
    c.esr = 0;
    var r = mc + SC_RESERVED;
    var found = false;
    while (r + 8 <= mc + SC_RESERVED + 4096) {
        const rec = get([2]u32, r) orelse die(SIGSEGV);
        const magic = rec[0];
        const size = rec[1];
        if (magic == 0) break;
        if (size < 8 or size & 15 != 0) die(SIGSEGV);
        if (magic == FPSIMD_MAGIC) {
            if (size != FPSIMD_SIZE) die(SIGSEGV);
            const ctl = get([2]u32, r + 8) orelse die(SIGSEGV);
            c.fpsr = ctl[0];
            c.fpcr = ctl[1];
            c.v = get([32]u128, r + 16) orelse die(SIGSEGV);
            found = true;
        }
        r += size;
    }
    if (!found) die(SIGSEGV);
    const t = thr();
    @atomicStore(u64, &t.mask, head[3] & ~KILLSTOP, .release);
    // restore_altstack: errors (e.g. EPERM while still on it) are ignored.
    var ss: [3]u64 = .{ head[0], head[1], head[2] };
    _ = sysSigaltstack(@intFromPtr(&ss), 0, c.sp);
    tl.switch_ctx = c;
    tl.first_sig = 0;
    switchNow();
}

// sysSigreturnX64 restores the state deliverOnto saved in the x86-64
// rt_sigframe. glibc's restorer (__restore_rt) enters rt_sigreturn with rsp at
// the ucontext (fr+8), so the saved sigcontext is at uc+40, the alt-stack at
// uc+16 and the mask at uc+296. A malformed or unmapped frame kills the process
// with SIGSEGV, as the kernel's badframe path does.
fn sysSigreturnX64(frame: [*]u64) u64 {
    const uc = frame[proc.XR_RSP];
    const sc = uc + 40;
    const r = get([24]u64, sc) orelse die(SIGSEGV); // r8..cr2 then the fpstate ptr
    var c: Ctx = undefined;
    c.r8 = r[0];
    c.r9 = r[1];
    c.r10 = r[2];
    c.r11 = r[3];
    c.r12 = r[4];
    c.r13 = r[5];
    c.r14 = r[6];
    c.r15 = r[7];
    c.rdi = r[8];
    c.rsi = r[9];
    c.rbp = r[10];
    c.rbx = r[11];
    c.rdx = r[12];
    c.rax = r[13];
    c.rcx = r[14];
    c.rsp = r[15];
    c.rip = r[16];
    c.rflags = r[17];
    c.fault = 0;
    c.trapno = 0;
    c.err = 0;
    const fpst = r[23];
    c.fx = if (fpst != 0) (get([512]u8, fpst) orelse die(SIGSEGV)) else std.mem.zeroes([512]u8);
    const head = get([3]u64, uc + 16) orelse die(SIGSEGV); // uc_stack: ss_sp, ss_flags|pad, ss_size
    const mask = get(u64, uc + 296) orelse die(SIGSEGV); // uc_sigmask
    const t = thr();
    @atomicStore(u64, &t.mask, mask & ~KILLSTOP, .release);
    var ss: [3]u64 = .{ head[0], head[1], head[2] };
    _ = sysSigaltstack(@intFromPtr(&ss), 0, c.rsp);
    tl.switch_ctx = c;
    tl.first_sig = 0;
    x64Deliver();
    return 0;
}

// waitLocal sleeps until a kick or the deadline (CLOCK_MONOTONIC ns, 0 = none).
// Returns false on timeout. Pending signals in allow end it at once.
fn waitLocal(allow: u64, deadline: i64) bool {
    @atomicStore(u32, &tl.word, 0, .seq_cst);
    @atomicStore(bool, &tl.waiting, true, .seq_cst);
    defer @atomicStore(bool, &tl.waiting, false, .seq_cst);
    if (pendingAllowed(allow) != 0) return true;
    // x86-64 serves the blocking sig syscalls inside the fault handler, which
    // runs with the kick signals (USR1/USR2) blocked, so the supervisor's kick
    // cannot cut the wait short. Open them around it: a kick that landed while
    // they were blocked is delivered on the unblock, and the handler sets the
    // word so the wait returns at once. arm64 waits outside any handler, where
    // they are already open, so it leaves the mask alone.
    var saved: u32 = 0;
    if (!tstate.arm64) {
        var k: u32 = KICK_MASK;
        _ = pthread_sigmask(SIG_UNBLOCK, &k, &saved);
    }
    defer if (!tstate.arm64) {
        _ = pthread_sigmask(SIG_SETMASK, &saved, null);
    };
    if (deadline == 0) {
        futex.waitWord(&tl.word, 0, 0);
        return true;
    }
    const left = deadline - futex.nowNs();
    if (left <= 0) return false;
    futex.waitWord(&tl.word, 0, @intCast(@min(left, 3600 * std.time.ns_per_s)));
    return true;
}

// sleepUntil blocks until the monotonic deadline; true if a signal for this
// thread cut it short.
pub fn sleepUntil(deadline: i64) bool {
    while (futex.nowNs() < deadline) {
        if (tl.ready and interrupted() and settle()) return true;
        if (!tl.ready) {
            futex.sleepNs(@intCast(deadline - futex.nowNs()));
            return false;
        }
        _ = waitLocal(~ld(&thr().mask), deadline);
    }
    return false;
}

// settle has the supervisor act on the signals this thread would take now
// whose action needs no handler and no end of the process (ignore, stop), as
// the kernel does inside an interrupted wait, which then goes on. True if one
// the stub must take is pending (a handler, or a fatal default): that ends
// the wait.
pub fn settle() bool {
    return goCall(LC_SIGSETTLE, ~ld(&thr().mask), 0) != 0;
}

// mySlot is the calling guest thread's channel slot.
pub fn mySlot() usize {
    return tl.slot;
}

pub fn beginFutexWait(addr: u64) void {
    @atomicStore(u64, &tl.futex, addr, .seq_cst);
}

pub fn endFutexWait() void {
    @atomicStore(u64, &tl.futex, 0, .seq_cst);
}

fn sysSigsuspend(frame: [*]u64) u64 {
    if (frame[1] != 8) return neg(EINVAL);
    const t = thr();
    const old = ld(&t.mask);
    const temp = (get(u64, frame[0]) orelse return neg(EFAULT)) & ~KILLSTOP;
    @atomicStore(u64, &t.mask, temp, .release);
    while (true) {
        var info: Info = undefined;
        var act: Act = undefined;
        const s = take(~temp, &info, &act);
        if (s == 0) {
            _ = waitLocal(~temp, 0);
            continue;
        }
        switch (classify(s, act)) {
            .ignore => {},
            .stop => stopSelf(s),
            .term => die(s),
            .handler => {
                tl.first_sig = s;
                tl.first_info = info;
                tl.first_act = act;
                tl.first_mask = old;
                if (tstate.arm64) {
                    fromFrame(&tl.switch_ctx, frame, neg(EINTR), frame[33]);
                    switchNow();
                }
                x64SaveCtx(neg(EINTR), frame[33]);
                x64Deliver();
                return neg(EINTR);
            },
        }
    }
}

fn sysSigtimedwait(set: u64, uinfo: u64, uts: u64, size: u64) u64 {
    if (size != 8) return neg(EINVAL);
    const w = (get(u64, set) orelse return neg(EFAULT)) & ~KILLSTOP;
    var deadline: i64 = 0;
    if (uts != 0) {
        const ts = getTimespec(uts) orelse return neg(EFAULT);
        if (ts[0] < 0 or ts[1] < 0 or ts[1] >= std.time.ns_per_s) return neg(EINVAL);
        deadline = futex.nowNs() +| (ts[0] *| std.time.ns_per_s +| ts[1]);
        if (deadline == 0) deadline = 1;
    }
    const t = thr();
    @atomicStore(u64, &t.waitset, w, .release);
    defer @atomicStore(u64, &t.waitset, 0, .release);
    while (true) {
        var info: Info = undefined;
        const s = take(w, &info, null);
        if (s != 0) {
            if (uinfo != 0) {
                var out = [_]u8{0} ** 128;
                var head = info;
                head.signo = @intCast(s);
                head.pad = 0;
                @memcpy(out[0..@sizeOf(Info)], std.mem.asBytes(&head));
                if (!copyGuest(uinfo, @intFromPtr(&out), out.len)) return neg(EFAULT);
            }
            return s;
        }
        if (pendingAllowed(~ld(&t.mask) & ~w) != 0) return neg(EINTR);
        if (!waitLocal(w | ~ld(&t.mask), deadline)) return neg(EAGAIN);
    }
}
