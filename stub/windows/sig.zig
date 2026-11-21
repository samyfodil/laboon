// sig.zig — Linux signal delivery for the Windows stub. The stub owns
// every guest thread's CPU state, so it builds the Linux rt_sigframe, redirects
// a thread into its handler and restores it on rt_sigreturn. The supervisor
// (Go, sandbox/lx_signal.go and signal_windows.go) owns routing and policy: it
// posts a signal into the shared signal area and then reaches the thread.
//
// A thread running guest code is reached by the supervisor stealing its context
// (SuspendThread + Get/SetThreadContext): it stashes the stolen CONTEXT in the
// thread's channel-slot scratch and points the thread at lc_sig_redirect, which
// delivers from here. A thread parked in a stub wait (a private futex, a sleep,
// sigsuspend, sigtimedwait) is reached by a cross-process APC that breaks its
// alertable wait; the pending signal is then taken on the way out. A thread
// inside a supervisor-served syscall gets -EINTR/ERESTARTSYS and delivers on the
// way out. Synchronous faults (AV, #UD, #DE, #BP) reach the vectored handler,
// which turns them into SIGSEGV/SIGILL/SIGFPE/SIGTRAP.
//
// The signal area lives after the channel slots: one record per slot, the
// thread's mask and sigaltstack and a copy of its pending bits, and (at the
// thread-group leader's slot) a copy of the process's. The pending sets and the
// actions themselves are the supervisor's, out of the guest's reach: the stub
// takes a signal with its action by a call (LC_SIGTAKE), and sigaction is the
// supervisor's. sandbox/lx_signal.go uses the same offsets.

const std = @import("std");
const win = std.os.windows;
const futex = @import("futex.zig");
const stub = @import("stub.zig");

// The architecture half: the guest register file, the CONTEXT moves and the
// Linux rt_sigframe layout.
const A = switch (@import("builtin").cpu.arch) {
    .x86_64 => @import("sig_x86_64.zig"),
    .aarch64 => @import("sig_aarch64.zig"),
    else => @compileError("unsupported architecture"),
};
pub const Ctx = A.Ctx;
pub const Trap = A.Trap;
pub const Frame = A.Frame;
pub const ctxFromTrap = A.ctxFromTrap;
pub const ctxFromWin = A.ctxFromWin;
pub const args = A.args;
// continueWith resumes a context; it ends any fault-handler hold (in_handler),
// so a thread back in guest code is never read as building a frame.
pub fn continueWith(c: *const Ctx) noreturn {
    if (tl().ready) @atomicStore(u32, &thr().in_handler, 0, .seq_cst);
    A.continueWith(c);
}
const NR = A.NR;

const HANDLE = usize;
const NTSTATUS = i32;

pub const SLOT_SIZE: usize = 4096;
pub const MAX_SLOTS: usize = 256;
pub const AREA_OFF: usize = SLOT_SIZE * MAX_SLOTS;
pub const STRIDE: usize = 0x4000;
pub const AREA_LEN: usize = STRIDE * MAX_SLOTS;
const PROC_OFF: usize = 0x1000;

extern "ntdll" fn NtWaitForSingleObject(h: HANDLE, alertable: u8, timeout: ?*const i64) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtSetEvent(h: HANDLE, prev: ?*i32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtCreateEvent(h: *HANDLE, access: u32, attr: ?*anyopaque, typ: u32, state: u8) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn RtlQueryPerformanceCounter(counter: *i64) callconv(win.WINAPI) u8;
extern "ntdll" fn RtlQueryPerformanceFrequency(freq: *i64) callconv(win.WINAPI) u8;
extern "ntdll" fn RtlExitUserThread(code: NTSTATUS) callconv(win.WINAPI) noreturn;

const EVENT_ALL_ACCESS: u32 = 0x1f0003;
const STATUS_TIMEOUT: NTSTATUS = 0x102;
const STATUS_USER_APC: NTSTATUS = 0xC0;

// ---- shared area records (match sandbox/lx_signal.go) ----------------------

pub const Info = extern struct { signo: i32, errno: i32, code: i32, pad: i32, a: u64, b: u64 };
pub const Act = extern struct { handler: u64, flags: u64, restorer: u64, mask: u64 };

pub const Thread = extern struct {
    _res: u32,
    proc: u32,
    mask: u64,
    pending: u64,
    waitset: u64,
    ss_sp: u64,
    ss_size: u64,
    ss_flags: u32,
    tid: u32,
    tgid: u32,
    saved: u32,
    saved_mask: u64,
    // busy and in_handler live in the shared record (not thread-local) so the
    // supervisor can read them before redirecting a running thread.
    busy: u32,
    in_handler: u32,
    // stub_sp is the top of the thread's stub stack (SLOT_STK), where the
    // supervisor points a thread it redirects: never the guest's stack, whose
    // bottom it cannot see (a Go goroutine's is 2 KiB).
    stub_sp: u64,
    return_lo: u64,
    return_hi: u64,
    return_retry: u64,
    return_tail: u64,
    return_tail_end: u64,
    // dirt_lo: the floor of the guest-stack region a fault handler left below
    // the guest sp (the kernel's exception frame; the handler's own ran on the
    // stub stack). The return gate wipes [dirt_lo, resume sp) so the guest sees
    // virgin memory below its sp, as on Linux. Stub-only; the supervisor never
    // reads it. (lx_signal.go mirrors only the fields above.)
    dirt_lo: u64,
};

pub const Proc = extern struct {
    _res: u64,
    pending: u64, // the process-directed pending bits
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
    std.debug.assert(@offsetOf(Thread, "busy") == 72);
    std.debug.assert(@offsetOf(Thread, "in_handler") == 76);
    std.debug.assert(@offsetOf(Thread, "stub_sp") == 80);
    std.debug.assert(@offsetOf(Thread, "return_lo") == 88);
    std.debug.assert(@offsetOf(Thread, "return_hi") == 96);
    std.debug.assert(@offsetOf(Thread, "return_retry") == 104);
    std.debug.assert(@offsetOf(Thread, "return_tail") == 112);
    std.debug.assert(@offsetOf(Thread, "return_tail_end") == 120);
    std.debug.assert(@offsetOf(Thread, "dirt_lo") == 128);
    std.debug.assert(@offsetOf(Proc, "pending") == 8);
    std.debug.assert(@sizeOf(Thread) <= PROC_OFF);
    std.debug.assert(@sizeOf(Proc) <= STRIDE - PROC_OFF);
}

// ---- Linux signal numbers -------------------------------------------------

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
const MINSIGSTKSZ: u64 = 2048;

const SI_USER: i32 = 0;
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;
const ILL_ILLOPC: i32 = 1;
const FPE_INTDIV: i32 = 1;
const TRAP_BRKPT: i32 = 1;
const TRAP_TRACE: i32 = 2;
const BUS_ADRALN: i32 = 1;
const BUS_ADRERR: i32 = 2;

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

// LC_* calls to the supervisor for default actions (outside the Linux range).
const LC_SIGDIE: u64 = 0x4c430010;
const LC_SIGSTOP: u64 = 0x4c430011;
const LC_SIGTAKE: u64 = 0x4c430012;
const LC_SIGSETTLE: u64 = 0x4c430013;
const LC_SIGFAULT: u64 = 0x4c430014;
const LC_SIGRAISE: u64 = 0x4c430015;

// Windows exception codes.
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC0000096;
const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC0000094;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC0000095;
const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xC00002B5;
const STATUS_BREAKPOINT: u32 = 0x80000003;
const STATUS_SINGLE_STEP: u32 = 0x80000004;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x80000002;
const STATUS_IN_PAGE_ERROR: u32 = 0xC0000006;

// ---- per-thread state ------------------------------------------------------

const Tls = struct {
    slot: usize = 0,
    rec: *Thread = undefined,
    ready: bool = false,
    is_thread: bool = false,
    futex: u64 = 0,
    event: HANDLE = 0,
    os_tid: u32 = 0,
    ctid: u64 = 0,
    restart_at: u64 = 0, // the syscall site a restart last resumed the guest at
    sleep_deadline: i64 = 0, // the rest of a relative sleep restart_syscall resumes (Linux's restart block), 0: none
    sleep_rem: u64 = 0,
    win_stack: [3]u64 = .{ 0, 0, 0 }, // the OS thread's own TEB StackBase/StackLimit/DeallocationStack
};

// keepWinStack records the calling OS thread's own stack, which the TEB
// describes until the guest's stack takes its place.
pub fn keepWinStack() void {
    tl().win_stack = .{ stub.arch.tebLoad(0x08), stub.arch.tebLoad(0x10), stub.arch.tebLoad(0x1478) };
}

pub fn winStack() [3]u64 {
    return tl().win_stack;
}

// restoreWinStack puts the thread's own stack back in the TEB before it exits:
// thread exit frees DeallocationStack, which must not be the guest's mapping.
pub fn restoreWinStack() void {
    const w = tl().win_stack;
    if (w[0] == 0) return;
    stub.arch.tebStore(0x08, w[0]);
    stub.arch.tebStore(0x10, w[1]);
    stub.arch.tebStore(0x1478, w[2]);
}

fn setBusy(on: u32) void {
    @atomicStore(u32, &thr().busy, on, .seq_cst);
}

// noteDirt records that a fault handler is about to run from stub-stack sp rsp
// (the floor, minus a margin for the handoff thunk's own frame): the kernel's
// exception frame lies between here and the guest sp, and the return gate wipes
// it. clearDirt cancels that when the resume will not pass promptly through the
// gate (an out-of-line slot, a crash), so a stale floor never wipes live stack.
pub fn noteDirt(rsp: u64) void {
    thr().dirt_lo = rsp -% 64;
}

pub fn clearDirt() void {
    thr().dirt_lo = 0;
}

// faultEnter/faultLeave hold the thread for the whole vectored fault handler:
// it is stub code that talks to the supervisor (isTrap, wxFault's hot/cool,
// rewritePage, sig.fault) and must not be context-stolen mid-exchange. It uses
// in_handler, not busy, because busy carries stub semantics the handler reads
// (sig.fault's guest-vs-stub classification, arm64 inGuest). The gate already
// refuses to steal a thread with in_handler set.
pub fn faultEnter() void {
    if (tl().ready) @atomicStore(u32, &thr().in_handler, 1, .seq_cst);
}

pub fn faultLeave() void {
    if (tl().ready) @atomicStore(u32, &thr().in_handler, 0, .seq_cst);
}

var tls_blocks: [MAX_SLOTS]Tls = [_]Tls{.{}} ** MAX_SLOTS;
var g_area: [*]u8 = undefined;
var g_slots_base: usize = 0;
pub var g_restorer: u64 = 0;
var g_threads: u32 = 1;

fn bit(sig: u32) u64 {
    return @as(u64, 1) << @intCast(sig - 1);
}

fn neg(e: i64) u64 {
    return @bitCast(-e);
}

fn thrAt(slot: usize) *Thread {
    return @ptrCast(@alignCast(g_area + slot * STRIDE));
}

fn procAt(slot: usize) *Proc {
    return @ptrCast(@alignCast(g_area + @as(usize, @atomicLoad(u32, &thrAt(slot).proc, .acquire)) * STRIDE + PROC_OFF));
}

fn tl() *Tls {
    return &tls_blocks[stub.curSlot()];
}

fn thr() *Thread {
    return tl().rec;
}

// tracePtr is this thread's trace-frame slot, at offset 256 of its record
// (past the Thread struct, before PROC_OFF) -- the same place the supervisor's
// traceFrame reads. The arch half writes its NT_PRSTATUS image here.
pub fn tracePtr() usize {
    return @intFromPtr(thr()) + 256;
}

fn procOf(t: *Thread) *Proc {
    return @ptrCast(@alignCast(g_area + @as(usize, @atomicLoad(u32, &t.proc, .acquire)) * STRIDE + PROC_OFF));
}

fn ld(p: *const u64) u64 {
    return @atomicLoad(u64, p, .acquire);
}

// ---- setup -----------------------------------------------------------------

pub fn install() void {
    g_slots_base = stub.chan_base;
    g_area = @as([*]u8, @ptrFromInt(stub.chan_base)) + AREA_OFF;
    buildRestorer();
}

pub fn myTid() u32 {
    return @atomicLoad(u32, &thr().tid, .acquire);
}

pub fn setCtid(w: u64) void {
    tl().ctid = w;
}

// buildRestorer writes the architecture's rt_sigreturn trap into an RWX
// page; a handler with no SA_RESTORER returns to it.
fn buildRestorer() void {
    var b: usize = 0;
    var s: usize = 0x1000;
    if (stub.allocRWX(&b, &s)) |p| {
        const code = A.restorer_code;
        @memcpy(@as([*]u8, @ptrFromInt(p))[0..code.len], &code);
        if (!stub.mem.ownTrap(p + A.restorer_trap)) stub.die(0xE0000009);
        g_restorer = p;
    }
}

pub fn startThread(slot: usize, os_tid: u32) void {
    const s = &tls_blocks[slot];
    s.slot = slot;
    s.rec = thrAt(slot);
    s.os_tid = os_tid;
    if (s.event == 0) {
        var h: HANDLE = 0;
        if (NtCreateEvent(&h, EVENT_ALL_ACCESS, null, 1, 0) >= 0) s.event = h; // SynchronizationEvent
    }
    @atomicStore(u32, &s.rec.busy, 1, .seq_cst);
    @atomicStore(u32, &s.rec.in_handler, 0, .seq_cst);
    @atomicStore(u64, &s.rec.dirt_lo, 0, .seq_cst);
    s.restart_at = 0;
    s.ready = true;
}

pub fn setStubSp(v: u64) void {
    @atomicStore(u64, &thr().stub_sp, v, .seq_cst);
}

pub fn threadSlot() usize {
    return tl().slot;
}

pub fn endThread() void {
    tl().ready = false;
}

pub fn enterGuest() void {
    setBusy(0);
}

pub fn enter() void {
    setBusy(1);
}

pub fn setThread(is_thread: bool, ctid: u64) void {
    const s = tl();
    s.is_thread = is_thread;
    s.ctid = ctid;
}

pub fn ctidWord() u64 {
    return tl().ctid;
}

pub fn isThread() bool {
    return tl().is_thread;
}

pub fn threadEvent() HANDLE {
    return tl().event;
}

pub fn addThreads(d: i32) u32 {
    return if (d >= 0) @atomicRmw(u32, &g_threads, .Add, @intCast(d), .seq_cst) else @atomicRmw(u32, &g_threads, .Sub, @intCast(-d), .seq_cst);
}

pub fn threadCount() u32 {
    return @atomicLoad(u32, &g_threads, .seq_cst);
}

// ---- pending sets ----------------------------------------------------------

fn pendingAllowed(allow: u64) u64 {
    const t = thr();
    return (ld(&t.pending) | ld(&procOf(t).pending)) & allow;
}

fn deliverableFor(t: *Thread) u64 {
    const allow = ~ld(&t.mask) | ld(&t.waitset);
    return (ld(&t.pending) | ld(&procOf(t).pending)) & allow;
}

// inGuest tells whether this thread is running guest code (not stub code),
// where a fault is the guest's.
pub fn inGuest() bool {
    return tl().ready and @atomicLoad(u32, &thr().busy, .seq_cst) == 0;
}

pub fn interrupted() bool {
    return tl().ready and pendingAllowed(~ld(&thr().mask)) != 0;
}

// take dequeues the next signal in allow (thread-directed first) with its
// action: for a delivery, the supervisor resets an SA_RESETHAND action as it
// hands it over; for a wait (sigtimedwait, act null) the action is not looked
// at. Returns 0 if none.
fn take(allow: u64, out: *Info, act: ?*Act) u32 {
    const s: u32 = @truncate(stub.request(LC_SIGTAKE, .{ allow, @intFromBool(act == null), 0, 0, 0, 0 }));
    if (s == 0) return 0;
    const r = reply();
    out.* = r.info;
    if (act) |a| a.* = r.act;
    return s;
}

const Reply = extern struct { info: Info, act: Act };

// reply is the supervisor's reply to a signal call, in the slot scratch.
fn reply() Reply {
    return @as(*align(1) const Reply, @ptrCast(stub.scratch())).*;
}

fn raiseSelf(sig: u32, code: i32) void {
    _ = stub.request(LC_SIGRAISE, .{ sig, @as(u32, @bitCast(code)), 0, 0, 0, 0 });
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

// ---- supervisor calls ------------------------------------------------------

fn die(sig: u32) noreturn {
    _ = stub.request(LC_SIGDIE, .{ sig, 0, 0, 0, 0, 0 });
    stub.die(@intCast(128 + sig));
}

fn stopSelf(sig: u32) void {
    _ = stub.request(LC_SIGSTOP, .{ sig, 0, 0, 0, 0, 0 });
}

// ---- guest memory (fallible) ----------------------------------------------

pub fn get(comptime T: type, addr: u64) ?T {
    if (addr == 0) return null;
    var v: T = undefined;
    if (!stub.arch.readGuest(@intFromPtr(&v), addr, @sizeOf(T))) return null;
    return v;
}

pub fn put(comptime T: type, addr: u64, v: T) bool {
    if (addr == 0) return false;
    return stub.arch.writeGuest(addr, @intFromPtr(&v), @sizeOf(T));
}

// ---- frame build / restore -------------------------------------------------

fn onStack(t: *Thread, sp: u64) bool {
    return t.ss_size != 0 and sp > t.ss_sp and sp - t.ss_sp <= t.ss_size;
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

// deliverOnto builds the rt_sigframe for sig on c's stack (or the alternate
// stack) and points c at the handler. uc_mask is the mask sigreturn restores.
fn deliverOnto(c: *Ctx, sig: u32, info: *const Info, act: Act, uc_mask: u64, is_fault: bool) void {
    const t = thr();
    if (rseqAbort(t, A.ctxPc(c))) |a| A.setPc(c, a);
    var sp = A.sp(c);
    const on = onStack(t, sp);
    const ss_sp = t.ss_sp;
    const ss_size = t.ss_size;
    var ss_flags: u32 = if (ss_size == 0) SS_DISABLE else if (on) SS_ONSTACK else 0;
    ss_flags |= t.ss_flags & SS_AUTODISARM;
    if (act.flags & SA_ONSTACK != 0 and ss_size != 0 and !on) {
        sp = ss_sp + ss_size;
        if (t.ss_flags & SS_AUTODISARM != 0) {
            t.ss_sp = 0;
            t.ss_size = 0;
            t.ss_flags = 0;
        }
    } else {
        sp -= A.RED_ZONE;
    }
    var infob = [_]u8{0} ** 128;
    var head = info.*;
    head.signo = @intCast(sig);
    head.pad = 0;
    @memcpy(infob[0..@sizeOf(Info)], std.mem.asBytes(&head));
    const restorer = if (act.flags & SA_RESTORER != 0) act.restorer else g_restorer;
    A.buildFrame(c, sp, sig, &infob, .{ .sp = ss_sp, .flags = ss_flags, .pad = 0, .size = ss_size }, uc_mask, is_fault, act.handler, restorer);

    var nm = t.mask | act.mask;
    if (act.flags & SA_NODEFER == 0) nm |= bit(sig);
    @atomicStore(u64, &t.mask, nm & ~KILLSTOP, .release);
}

fn dispatchAll(c: *Ctx) void {
    while (true) {
        var info: Info = undefined;
        var act: Act = undefined;
        const s = take(~ld(&thr().mask), &info, &act);
        if (s == 0) return;
        switch (classify(s, act)) {
            .ignore => {},
            .stop => stopSelf(s),
            .term => die(s),
            .handler => deliverOnto(c, s, &info, act, ld(&thr().mask), false),
        }
    }
}

// A stable guest context for the entire return, including kernel restoration.
// The injector rewinds only the assembly commit range (or arm64 resume slot).
const Return = extern struct {
    th: *Thread,
    pr: *Proc,
    target: u64,
    _pad: u64 = 0,
    c: Ctx,
};
var returns: [MAX_SLOTS]Return = undefined;

comptime {
    std.debug.assert(@offsetOf(Return, "c") == 32);
}

pub fn stageReturn(c: *const Ctx) void {
    setBusy(1);
    const r = &returns[stub.curSlot()];
    r.c = c.*;
    r.th = thr();
    @atomicStore(u32, &r.th.in_handler, 0, .seq_cst); // a fault handler's hold ends with its context
    r.pr = procOf(r.th);
    stub.arch.tebStore(stub.SLOT_CONT, @intFromPtr(r));
    @atomicStore(u64, &r.th.return_lo, @intFromPtr(&stub.arch.lc_return_commit), .release);
    @atomicStore(u64, &r.th.return_hi, @intFromPtr(&stub.arch.lc_return_end), .release);
    @atomicStore(u64, &r.th.return_retry, @intFromPtr(&stub.arch.lc_guest_return), .release);
}

// The fast path uses the same gate without an NtContinue round trip.
pub fn returnCtx(c: *const Ctx) noreturn {
    stageReturn(c);
    stub.arch.lc_guest_return();
    unreachable;
}

pub fn returnTrap(t: *const Trap) noreturn {
    var c = ctxFromTrap(t);
    returnCtx(&c);
}

export fn lc_return_prepare() callconv(win.WINAPI) *Return {
    setBusy(1);
    const r: *Return = @ptrFromInt(stub.arch.tebLoad(stub.SLOT_CONT));
    // Leave the guest stack below its sp as Linux does: zero what a fault
    // handler's kernel exception frame dirtied. The guest's own live data is at
    // or above the resume sp (top); [dirt_lo, top) is committed (the kernel just
    // wrote there) and dead until the guest grows into it, except its red zone,
    // which Linux leaves virgin too. dispatchAll below rebuilds any sigframe in
    // this range afterwards.
    const dl = r.th.dirt_lo;
    if (dl != 0) {
        r.th.dirt_lo = 0;
        const top = A.sp(&r.c);
        if (dl < top and top - dl <= 64 << 10) @memset(@as([*]u8, @ptrFromInt(dl))[0 .. top - dl], 0);
    }
    if (interrupted()) dispatchAll(&r.c);
    // A restarted syscall whose site traps is served here, as the trap would
    // serve it: Windows dispatches the exception on the guest's stack, below
    // its pointer, where Linux writes nothing.
    const s = tl();
    const site = s.restart_at;
    if (site != 0 and A.ctxPc(&r.c) == site) {
        s.restart_at = 0;
        if (stub.arch.trapsAt(site)) {
            stub.arch.serveSite(&r.c);
            setBusy(1);
        }
    }
    r.target = stub.arch.returnTarget(&r.c);
    const tail = if (@import("builtin").cpu.arch == .aarch64) r.target else 0;
    @atomicStore(u64, &r.th.return_tail, tail, .release);
    @atomicStore(u64, &r.th.return_tail_end, if (tail != 0) tail + 12 else 0, .release);
    return r;
}

// ---- entry points from stub.zig --------------------------------------------

fn isRestart(r: u64) bool {
    const v: i64 = @bitCast(r);
    return v == -ERESTARTSYS or v == -ERESTARTNOINTR or v == -ERESTARTNOHAND or v == -ERESTART_RESTARTBLOCK;
}

// afterSyscall runs on every syscall return with its result r. It delivers
// what is pending (never returning, via continueWith) or returns r for the
// fast path. null is never returned: a restart re-issues the syscall itself.
pub fn afterSyscall(t: *const Trap, r: u64) u64 {
    const s = tl();
    if (!s.ready) return r;
    if (@as(i64, @bitCast(r)) == -EPIPE and A.epipeRaises(t)) raiseSelf(SIGPIPE, SI_USER);
    if (!isRestart(r)) {
        setBusy(0);
        const th = s.rec;
        const pend = ld(&th.pending) | ld(&procOf(th).pending);
        if (pend & ~ld(&th.mask) == 0 and @atomicLoad(u32, &th.saved, .acquire) == 0) return r;
        setBusy(1);
    }
    return pendingAfter(t, r);
}

// setRestart points c back at t's syscall, as Linux restarts one: an
// ERESTART_RESTARTBLOCK as restart_syscall, which goes on from the call's
// restart block rather than starting it over. The site may be a trap the
// rewriter left, which lc_return_prepare serves when the guest resumes there.
fn setRestart(c: *Ctx, t: *const Trap, r: u64) void {
    A.setRestart(c, t, if (r == neg(ERESTART_RESTARTBLOCK)) stub.arch.NR.restart_syscall else t.nr);
    tl().restart_at = t.site;
}

// keepSleep records the rest of a relative sleep a signal cut short, for
// restart_syscall; takeSleep consumes it.
pub fn keepSleep(deadline: i64, rem: u64) void {
    const s = tl();
    s.sleep_deadline = deadline;
    s.sleep_rem = rem;
}

pub fn takeSleep() ?struct { deadline: i64, rem: u64 } {
    const s = tl();
    const d = s.sleep_deadline;
    if (d == 0) return null;
    s.sleep_deadline = 0;
    return .{ .deadline = d, .rem = s.sleep_rem };
}

fn pendingAfter(t: *const Trap, r: u64) noreturn {
    const th = thr();
    var real: ?u64 = null;
    if (@atomicLoad(u32, &th.saved, .acquire) != 0) {
        @atomicStore(u32, &th.saved, 0, .release);
        if (@as(i64, @bitCast(r)) == -EINTR or isRestart(r)) {
            real = ld(&th.saved_mask);
        } else {
            @atomicStore(u64, &th.mask, ld(&th.saved_mask), .release);
        }
    }
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
                    var c = ctxFromTrap(t);
                    const rv: i64 = @bitCast(r);
                    const restart = rv == -ERESTARTNOINTR or (rv == -ERESTARTSYS and act.flags & SA_RESTART != 0);
                    if (restart) {
                        setRestart(&c, t, r);
                    } else {
                        if (rv == -ERESTART_RESTARTBLOCK) tl().sleep_deadline = 0;
                        A.setResult(&c, if (isRestart(r)) neg(EINTR) else r);
                    }
                    deliverOnto(&c, s, &info, act, real orelse ld(&thr().mask), false);
                    continueWith(&c);
                },
            }
        }
        if (isRestart(r)) {
            var c = ctxFromTrap(t);
            setRestart(&c, t, r);
            if (real) |m| @atomicStore(u64, &th.mask, m, .release);
            continueWith(&c);
        }
        if (real) |m| @atomicStore(u64, &th.mask, m, .release);
        setBusy(0);
        if (pendingAllowed(~ld(&thr().mask)) == 0) {
            var c = ctxFromTrap(t);
            A.setResult(&c, r);
            continueWith(&c);
        }
        setBusy(1);
    }
}

// resumeCtx ends syscall nr, whose trap state was copied to c (a vfork
// parent, which left the guest stack), with result r; pending signals are
// delivered on the way out as afterSyscall does.
var resume_frames: [MAX_SLOTS]Frame = undefined;

pub fn resumeCtx(c: *Ctx, nr: u64, r: u64) noreturn {
    const t = A.trapFromCtx(c, nr, &resume_frames[tl().slot]);
    A.setResult(c, afterSyscall(&t, r));
    continueWith(c);
}

// forkChild sets up a fork child's only thread: the other threads, their
// events (not inheritable) and futex waits are the parent's.
pub fn forkChild(slot: usize, os_tid: u32, stub_sp: u64, win_stack: [3]u64) void {
    for (&tls_blocks) |*b| b.* = .{};
    @atomicStore(u32, &g_threads, 1, .seq_cst);
    tls_blocks[slot].win_stack = win_stack;
    startThread(slot, os_tid);
    setThread(false, 0);
    setStubSp(stub_sp);
}

// redirect is entered when the supervisor stole a running thread's context into
// its slot scratch and pointed it here. It delivers the pending signals from
// the saved CONTEXT and resumes.
pub fn redirect(saved: *const win.CONTEXT) noreturn {
    var c = A.ctxFromWin(saved);
    // The gate stole the context while the pc was in the stub's own code (a
    // signal must never run a handler over, or build a frame on, a stub
    // context): resume it, the signal stays pending for the next syscall.
    if (stub.ownCode(A.winPc(saved))) continueWith(&c);
    leaveSlot(&c);
    @atomicStore(u32, &thr().in_handler, 1, .seq_cst);
    dispatchAll(&c);
    @atomicStore(u32, &thr().in_handler, 0, .seq_cst);
    setBusy(0);
    continueWith(&c);
}

// leaveSlot gives the guest's own pc to c, a context a signal is delivered
// from, if the thread was running instructions out of line (ool.zig): the
// guest resumes there once the handler returns.
fn leaveSlot(c: *A.Ctx) void {
    const pc = A.ctxPc(c);
    const l = @import("ool.zig").leave(stub.curSlot(), pc);
    if (l.pc != pc) A.setPc(c, l.pc);
    for (l.holds) |h| stub.mem.letGo(h);
}

// ---- vectored exception handler (synchronous faults) -----------------------

// accessKind is an access violation's kind: 0 read, 1 write, 8 execute.
pub fn accessKind(rec: *const win.EXCEPTION_RECORD) u64 {
    return if (rec.NumberParameters >= 1) rec.ExceptionInformation[0] else 0;
}

fn faultSignal(code: u32, rec: *const win.EXCEPTION_RECORD, ip: u64, info: *Info) u32 {
    var sig: u32 = SIGSEGV;
    var si: i32 = SEGV_MAPERR;
    var addr = ip;
    switch (code) {
        STATUS_ACCESS_VIOLATION => {
            sig = SIGSEGV;
            addr = if (rec.NumberParameters >= 2) rec.ExceptionInformation[1] else 0;
            si = if (rec.NumberParameters >= 1 and rec.ExceptionInformation[0] != 0) SEGV_ACCERR else SEGV_MAPERR;
            if (stub.mem.pastEof(addr, accessKind(rec))) {
                sig = SIGBUS;
                si = BUS_ADRERR;
            }
        },
        STATUS_ILLEGAL_INSTRUCTION, STATUS_PRIVILEGED_INSTRUCTION => {
            sig = SIGILL;
            si = ILL_ILLOPC;
        },
        STATUS_INTEGER_DIVIDE_BY_ZERO, STATUS_INTEGER_OVERFLOW, STATUS_FLOAT_DIVIDE_BY_ZERO => {
            sig = SIGFPE;
            si = FPE_INTDIV;
        },
        STATUS_BREAKPOINT => {
            sig = SIGTRAP;
            si = TRAP_BRKPT;
        },
        STATUS_SINGLE_STEP => {
            sig = SIGTRAP;
            si = TRAP_TRACE; // the supervisor reads this to report a step stop
        },
        STATUS_DATATYPE_MISALIGNMENT, STATUS_IN_PAGE_ERROR => {
            sig = SIGBUS;
            si = if (code == STATUS_IN_PAGE_ERROR) BUS_ADRERR else BUS_ADRALN;
            if (rec.NumberParameters >= 2) addr = rec.ExceptionInformation[1];
        },
        else => {},
    }
    info.* = .{ .signo = @intCast(sig), .errno = 0, .code = si, .pad = 0, .a = addr, .b = 0 };
    return sig;
}

// fault turns a guest synchronous fault into a Linux signal. When a handler is
// installed it builds the rt_sigframe and resumes into the handler with
// NtContinue -- never returning, since the kernel's exception record lives on
// the guest stack where the frame is built and would be clobbered. It returns
// false (the VEH then falls back to LC_FAULT) only when there is no handler, or
// when the fault is the stub's own bug.
pub fn fault(ep: *win.EXCEPTION_POINTERS) bool {
    const s = tl();
    const c = ep.ContextRecord;
    // A fault whose pc is in the stub's own code is never a guest signal, whatever
    // busy says: delivering it would build an rt_sigframe on the stub's stack.
    if (!s.ready or @atomicLoad(u32, &thr().busy, .seq_cst) != 0 or stub.ownCode(A.winPc(c))) return false;
    var info: Info = undefined;
    const sig = faultSignal(ep.ExceptionRecord.ExceptionCode, ep.ExceptionRecord, A.winPc(c), &info);
    var gc = A.faultCtx(c, ep.ExceptionRecord, info.a);
    leaveSlot(&gc);
    const t = thr();
    // Publish the register frame so a tracer stopped on this signal reads the
    // real registers; the supervisor returns the signal to deliver (0 when a
    // tracer consumed it), and may have edited the registers.
    A.publishFrameCtx(&gc);
    const dsig: u32 = @truncate(stub.request(LC_SIGFAULT, .{ sig, @intFromBool(ld(&t.mask) & bit(sig) != 0), info.a, @as(u64, @intCast(info.code)), 0, 0 }));
    if (A.traceState().dirty != 0) A.traceRestoreCtx(&gc);
    if (dsig == 0) {
        // A tracer consumed the signal (a single-step trap, or suppressed it):
        // resume the guest with the restored registers.
        @atomicStore(u32, &thr().busy, 0, .seq_cst);
        continueWith(&gc);
    }
    const act = reply().act;
    // No handler: let the LC_FAULT path end the process (it reports the signal,
    // address and pc); a synchronous signal cannot be blocked or ignored.
    if (classify(dsig, act) != .handler) return false;
    info.signo = @intCast(dsig);
    @atomicStore(u32, &thr().in_handler, 1, .seq_cst);
    deliverOnto(&gc, dsig, &info, act, ld(&t.mask), true);
    dispatchAll(&gc); // stack any other pending handlers, as Linux does
    @atomicStore(u32, &thr().in_handler, 0, .seq_cst);
    @atomicStore(u32, &thr().busy, 0, .seq_cst);
    continueWith(&gc); // noreturn
}

// ---- signal syscalls -------------------------------------------------------

// handleSyscall serves the signal syscalls that touch only this thread's or
// process's state. gsp is the guest rsp (for rt_sigreturn's frame). Returns
// null for any other nr. rt_sigreturn and rt_sigsuspend resume via continueWith
// and never return.
pub fn handleSyscall(nr: u64, a: [6]u64, gsp: u64) ?u64 {
    return switch (nr) {
        NR.rt_sigprocmask => sysSigprocmask(a[0], a[1], a[2], a[3]),
        NR.rt_sigpending => sysSigpending(a[0], a[1]),
        NR.sigaltstack => sysSigaltstack(a[0], a[1], gsp),
        NR.rt_sigreturn => sysSigreturn(gsp),
        NR.rt_sigsuspend => sysSigsuspend(a[0], a[1], gsp),
        NR.rt_sigtimedwait => sysSigtimedwait(a[0], a[1], a[2], a[3]),
        else => null,
    };
}

fn sysSigprocmask(how: u64, set: u64, oset: u64, size: u64) u64 {
    if (size != 8) return neg(EINVAL);
    const t = thr();
    const old = ld(&t.mask);
    if (set != 0) {
        const v = get(u64, set) orelse return neg(EFAULT);
        const nm = switch (how) {
            0 => old | v,
            1 => old & ~v,
            2 => v,
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
    if (!put(u64, set, v)) return neg(EFAULT);
    return 0;
}

pub const StackT = extern struct { sp: u64, flags: u32, pad: u32, size: u64 };

fn sysSigaltstack(ss: u64, oss: u64, sp: u64) u64 {
    const t = thr();
    const on = onStack(t, sp);
    const old_sp = t.ss_sp;
    const old_size = t.ss_size;
    const old_flags: u32 = (if (old_size == 0) SS_DISABLE else if (on) SS_ONSTACK else 0) | (t.ss_flags & SS_AUTODISARM);
    if (ss != 0) {
        if (on) return neg(EPERM);
        const n = get(StackT, ss) orelse return neg(EFAULT);
        const mode = n.flags & ~SS_AUTODISARM;
        if (mode != 0 and mode != SS_ONSTACK and mode != SS_DISABLE) return neg(EINVAL);
        if (mode == SS_DISABLE) {
            t.ss_sp = 0;
            t.ss_size = 0;
            t.ss_flags = 0;
        } else {
            if (n.size < MINSIGSTKSZ) return neg(ENOMEM);
            t.ss_sp = n.sp;
            t.ss_size = n.size;
            t.ss_flags = n.flags & SS_AUTODISARM;
        }
    }
    if (oss != 0 and !put(StackT, oss, .{ .sp = old_sp, .flags = old_flags, .pad = 0, .size = old_size })) return neg(EFAULT);
    return 0;
}

fn sysSigreturn(gsp: u64) noreturn {
    var c = Ctx{};
    var mask: u64 = 0;
    var ss: StackT = undefined;
    if (!A.readFrame(gsp, &c, &mask, &ss)) die(SIGSEGV);
    @atomicStore(u64, &thr().mask, mask & ~KILLSTOP, .release);
    var sst = StackT{ .sp = ss.sp, .flags = ss.flags, .pad = 0, .size = ss.size };
    _ = sysSigaltstack(@intFromPtr(&sst), 0, A.sp(&c));
    setBusy(0);
    continueWith(&c);
}

// ---- local waits (sigsuspend, sigtimedwait, nanosleep) ---------------------

// The counter is read in user mode where the host allows it (the TSC page),
// with no system call; the frequency is fixed at boot.
var qpc_freq: i64 = 0;

pub fn nowNs() i64 {
    var freq = @atomicLoad(i64, &qpc_freq, .monotonic);
    if (freq == 0) {
        _ = RtlQueryPerformanceFrequency(&freq);
        if (freq <= 0) freq = 1;
        @atomicStore(i64, &qpc_freq, freq, .monotonic);
    }
    var cnt: i64 = 0;
    _ = RtlQueryPerformanceCounter(&cnt);
    const q = @divTrunc(cnt, freq);
    const r = @rem(cnt, freq);
    return q *% std.time.ns_per_s + @divTrunc(r *% std.time.ns_per_s, freq);
}

// The clocks the stub serves itself, as a Linux vDSO would: the realtime
// ones from the precise system time, the monotonic and boot-time ones from
// the performance counter, which the supervisor's CLOCK_MONOTONIC also
// reads. The CPU-time clocks go to the supervisor (null).
fn clockNs(clock: u64) ?i64 {
    return switch (clock) {
        0, 5, 8 => realtimeNs(),
        1, 4, 6, 7, 9 => nowNs(),
        else => null,
    };
}

extern "ntdll" fn RtlGetSystemTimePrecise() callconv(win.WINAPI) i64;

fn realtimeNs() i64 {
    return (RtlGetSystemTimePrecise() - 116444736000000000) * 100;
}

pub fn clockGettime(clock: u64, tsp: u64) ?u64 {
    const ns = clockNs(clock) orelse return null;
    if (!put([2]i64, tsp, .{ @divTrunc(ns, std.time.ns_per_s), @rem(ns, std.time.ns_per_s) })) return neg(EFAULT);
    return 0;
}

pub fn gettimeofday(tvp: u64, tzp: u64) ?u64 {
    if (tvp != 0) {
        const ns = realtimeNs();
        if (!put([2]i64, tvp, .{ @divTrunc(ns, std.time.ns_per_s), @divTrunc(@rem(ns, std.time.ns_per_s), 1000) })) return neg(EFAULT);
    }
    return if (tzp == 0) 0 else null; // a timezone: the supervisor's
}

pub fn timeNow(tp: u64) u64 {
    const t = @divTrunc(realtimeNs(), std.time.ns_per_s);
    if (tp != 0 and !put(i64, tp, t)) return neg(EFAULT);
    return @bitCast(t);
}

// waitLocal sleeps until a kick (APC), a futex wake of tl.word, or the deadline
// (monotonic ns, 0 = none), unless a signal in allow is pending. The wait is
// alertable so a signal APC breaks it. The pending check comes last, with no
// channel exchange after it: an exchange waits alertably too, and takes the
// APC of a signal sent meanwhile, whose pending bit the check then sees.
fn waitLocal(allow: u64, deadline: i64) void {
    const s = tl();
    var to: i64 = 0;
    var top: ?*const i64 = null;
    if (deadline != 0) {
        const left = deadline - nowNs();
        if (left <= 0) return;
        to = -@divTrunc(left, 100); // relative, 100ns units
        top = &to;
    }
    if (pendingAllowed(allow) != 0) return;
    _ = NtWaitForSingleObject(s.event, 1, top);
}

pub fn sleepUntil(deadline: i64) bool {
    while (nowNs() < deadline) {
        if (interrupted() and settle()) return true;
        waitLocal(~ld(&thr().mask), deadline);
    }
    return false;
}

// settle has the supervisor act on the signals this thread would take now
// whose action needs no handler and no end of the process (ignore, stop).
// True if one the stub must take is pending (that ends the wait).
pub fn settle() bool {
    return stub.request(LC_SIGSETTLE, .{ ~ld(&thr().mask), 0, 0, 0, 0, 0 }) != 0;
}

pub fn beginFutexWait(addr: u64) void {
    @atomicStore(u64, &tl().futex, addr, .seq_cst);
}

pub fn endFutexWait() void {
    @atomicStore(u64, &tl().futex, 0, .seq_cst);
}

// futexQueued reports whether this thread still waits on its futex: a wake
// takes the thread off, as Linux dequeues a waiter it wakes.
pub fn futexQueued() bool {
    return @atomicLoad(u64, &tl().futex, .seq_cst) != 0;
}

// park sleeps alertably until a wake, an APC, or the deadline; the futex module
// calls it so a signal APC can break a futex wait.
pub fn park(deadline: i64) void {
    waitLocal(~ld(&thr().mask), deadline);
}

// futexWake releases up to n guest threads parked on addr (other than the
// caller) and returns how many it woke. Intra-guest futex wakes stay in-stub;
// each waiter owns an auto-reset event. A waiter is taken off addr as it is
// woken, so a second wake before it runs goes to another waiter, not to it
// again.
pub fn futexWake(addr: u64, n: u32) u32 {
    var woke: u32 = 0;
    const self = tl().slot;
    var i: usize = 0;
    while (i < MAX_SLOTS and woke < n) : (i += 1) {
        if (i == self) continue;
        const w = &tls_blocks[i];
        if (!w.ready or w.event == 0) continue;
        if (@cmpxchgStrong(u64, &w.futex, addr, 0, .seq_cst, .seq_cst) != null) continue;
        _ = NtSetEvent(w.event, null);
        woke += 1;
    }
    return woke;
}

// sysSigsuspend installs a temporary mask and blocks until a signal deliverable
// under it is pending, then returns -EINTR; afterSyscall delivers the handler
// under the temporary mask and sigreturn restores the real one (the saved-mask
// mechanism, as pselect/ppoll use).
fn sysSigsuspend(set: u64, size: u64, gsp: u64) ?u64 {
    _ = gsp;
    if (size != 8) return neg(EINVAL);
    const t = thr();
    const temp = (get(u64, set) orelse return neg(EFAULT)) & ~KILLSTOP;
    @atomicStore(u64, &t.saved_mask, ld(&t.mask), .release);
    @atomicStore(u32, &t.saved, 1, .release);
    @atomicStore(u64, &t.mask, temp, .release);
    while (pendingAllowed(~temp) == 0) waitLocal(~temp, 0);
    return neg(EINTR);
}

fn sysSigtimedwait(set: u64, uinfo: u64, uts: u64, size: u64) u64 {
    if (size != 8) return neg(EINVAL);
    const w = (get(u64, set) orelse return neg(EFAULT)) & ~KILLSTOP;
    var deadline: i64 = 0;
    if (uts != 0) {
        const ts = get([2]i64, uts) orelse return neg(EFAULT);
        if (ts[0] < 0 or ts[1] < 0 or ts[1] >= std.time.ns_per_s) return neg(EINVAL);
        deadline = nowNs() +| (ts[0] *| std.time.ns_per_s +| ts[1]);
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
                if (!put([128]u8, uinfo, out)) return neg(EFAULT);
            }
            return s;
        }
        if (pendingAllowed(~ld(&t.mask) & ~w) != 0) return neg(EINTR);
        if (deadline != 0 and nowNs() >= deadline) return neg(EAGAIN);
        waitLocal(w | ~ld(&t.mask), deadline);
    }
}
