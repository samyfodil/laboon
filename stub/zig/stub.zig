// stub is the process a guest runs in. It is freestanding (no libc, no TLS of
// its own) because the guest owns the thread pointer once it starts.
//
// Each guest thread runs on its own stub thread, which owns one channel slot
// in a shared region (fd 3). How a thread finds its slot is per-architecture:
// see slot() in x86_64.zig and aarch64.zig.
//
// The supervisor asks the stub to perform host memory syscalls, writes guest
// memory with process_vm_writev, then sends START. Rewritten guest syscalls
// trap (x86 ud2, arm64 udf: SIGILL) or branch to a trampoline; both reach
// handle. A guest clone is performed here by spawning a new stub thread; a
// fork is performed by the process's hop thread (see forkPrep).
//
// A seccomp filter (seccomp.zig) restricts the process to the syscalls in
// arch.allowed, issued only from the stub's own text, and pins the arguments
// of clone and tgkill. A guest syscall the rewriter missed is killed by the
// kernel.

const std = @import("std");
const trace = @import("trace.zig");
const builtin = @import("builtin");

pub const sig = @import("sig.zig");
const args = @import("args.zig");
const seccomp = @import("seccomp.zig");
const landlock = @import("landlock.zig");

pub const arch = switch (builtin.cpu.arch) {
    .x86_64 => @import("x86_64.zig"),
    .aarch64 => @import("aarch64.zig"),
    else => @compileError("unsupported architecture"),
};

pub const SYS = std.os.linux.SYS;

pub fn nr(s: SYS) u64 {
    return @intFromEnum(s);
}

// The stub's private window -- channel slots, per-slot signal/exec stacks, and
// (per arch) the tid->slot table -- sits at winBase, a base chosen AT RUN TIME,
// not baked in. winBase is the stub's own load base (&__ehdr_start): the
// top-level stub is an ET_EXEC linked at STUB_BASE (0x6c...), and a nested stub
// is a PIE the outer's loader places at a free high window, so every nesting
// level gets a window clear of its outer's and one relocatable stub serves all
// depths. The offsets below are fixed; only winBase moves. The supervisor
// learns winBase from the ready handshake. STUB_BASE is the top-level base and
// the first window the outer's loader tries for a nested stub.
pub const STUB_BASE: u64 = @import("layout.zig").STUB_BASE;
pub const WIN_SIZE: u64 = 0x40000000000; // 4 TiB of address space per stub window
pub var winBase: u64 = STUB_BASE;

// fsgsbase is set when the kernel lets user code read the thread pointer
// directly (AT_HWCAP2 HWCAP2_FSGSBASE), which spares a syscall per guest call.
pub var fsgsbase = false;

// lc_window_note is the loader contract that places a nested stub: an ELF note
// in a PT_NOTE segment declaring that this image wants a private high-address
// window of win_size (aligned to align_) rather than the ordinary exe bias. A
// laboon loading this image as a guest honors it (sandbox/load_linux.go); the
// kernel ignores it, so the top-level stub is an ET_EXEC linked high instead.
// It names no stub bytes, path, or version -- any image carrying the note gets
// a window, so nesting composes to any depth.
const WindowNote = extern struct {
    namesz: u32 = 7,
    descsz: u32 = 24,
    ntype: u32 = 1,
    name: [8]u8 = .{ 'l', 'a', 'b', 'o', 'o', 'n', 0, 0 },
    win_size: u64 = WIN_SIZE,
    win_align: u64 = WIN_SIZE,
    img_off: u64 = 0, // the window base is the image's load base
};
export const lc_window_note linksection(".note.laboon") = WindowNote{};

// memset/memcpy with hidden visibility, so the freestanding stub calls them
// PC-relative rather than through the GOT. That keeps the PIE zero-reloc: it
// runs at whatever window the loader places it, with no relocation fixup (the
// loader applies none). compiler-rt would otherwise supply GOT-referenced ones.
fn lcMemset(dest: [*]u8, c: u8, n: usize) callconv(.C) [*]u8 {
    for (0..n) |i| dest[i] = c;
    return dest;
}
fn lcMemcpy(dest: [*]u8, src: [*]const u8, n: usize) callconv(.C) [*]u8 {
    for (0..n) |i| dest[i] = src[i];
    return dest;
}
comptime {
    @export(lcMemset, .{ .name = "memset", .visibility = .hidden });
    @export(lcMemcpy, .{ .name = "memcpy", .visibility = .hidden });
}
pub inline fn slotsAddr() u64 {
    return winBase + 0x1000000000;
}
pub const SLOT_SIZE: u64 = 4096;
// MAX_SLOTS is the slot index space: PID_MAX_LIMIT, as many threads as Linux
// can ever have. The shared regions indexed by slot are mapped whole (memfd
// pages cost nothing until touched); the private per-slot stacks are mapped
// STACK_CHUNK slots at a time, by the supervisor through the hop thread, once
// a thread of this process is to run on a slot of that chunk (stackChunk).
pub const MAX_SLOTS: u64 = 1 << 22;
pub const STACK_CHUNK: u64 = 64;
// One alternate signal stack per channel slot, indexed like the slots. It is
// large enough for the signal frame with SVE and SME state.
pub inline fn altsAddr() u64 {
    return winBase + 0x1b000000000;
}
pub const ALT_SIZE: u64 = 128 << 10;
// One per-slot stack for servicing an execve's address-space teardown. It
// lives in the stub window (never a guest mapping), so unmapping every old
// guest VMA cannot pull it out from under the stub.
pub inline fn execsAddr() u64 {
    return winBase + 0x17000000000;
}
pub const EXEC_SIZE: u64 = 64 << 10;

// One per-slot service stack, indexed like the slots. A syscall trampoline
// switches to it (via %gs:scratch_top) before servicing, so no servicing runs
// on the guest's own stack -- a guest with small, adjacently packed thread
// stacks (a nested laboon's Go goroutine stacks) would otherwise be corrupted
// by a servicing frame underflowing into a neighbor. It lives in the stub
// window, never a guest mapping.
pub inline fn scratchAddr() u64 {
    return winBase + 0x23000000000;
}
pub const SCRATCH_SIZE: u64 = 64 << 10;

// mapStackChunk maps chunk c of the three per-slot stack arrays. The
// supervisor maps the others through the hop thread (sandbox/stacks_linux.go).
fn mapStackChunk(c: u64) bool {
    const flags = 0x02 | 0x10 | 0x20 | 0x4000; // PRIVATE|FIXED|ANONYMOUS|NORESERVE
    const arrays = [_][2]u64{ .{ altsAddr(), ALT_SIZE }, .{ execsAddr(), EXEC_SIZE }, .{ scratchAddr(), SCRATCH_SIZE } };
    inline for (arrays) |a| {
        const at = a[0] + c * STACK_CHUNK * a[1];
        if (sys(nr(.mmap), at, STACK_CHUNK * a[1], PROT_RW, flags, ~@as(u64, 0), 0) != at) return false;
    }
    return true;
}

// slotBySp is the slot of the thread running on stack pointer sp when sp is in
// one of the stacks indexed like the slots -- the service stack (a trampoline),
// the alternate signal stack (a trap or a signal) or the exec stack -- which a
// thread runs on only for its own slot; it is 0 on any other stack. The slot is
// then found with no syscall. A stack's top belongs to it, so sp - 1 is placed.
pub inline fn slotBySp(sp: u64) u64 {
    const stacks = [_][2]u64{ .{ scratchAddr(), SCRATCH_SIZE }, .{ altsAddr(), ALT_SIZE }, .{ execsAddr(), EXEC_SIZE } };
    inline for (stacks) |s| {
        const o = sp -% 1 -% s[0];
        if (o < MAX_SLOTS * s[1]) return slotsAddr() + o / s[1] * SLOT_SIZE;
    }
    return 0;
}

// scratchTop is the top of ch's slot's service stack, 16-aligned.
pub fn scratchTop(ch: *Chan) u64 {
    const slot = (@intFromPtr(ch) - slotsAddr()) / SLOT_SIZE;
    return (scratchAddr() + (slot + 1) * SCRATCH_SIZE) & ~@as(u64, 15);
}

// The host-op ("hop") area (sandbox/hop_linux.go): per stub process, a request
// page mapped read-only and a reply page mapped read-write, after the channel
// region of the shared memfd (HOP_OFF is the Go side's chanLen). The process's
// hop thread runs the process-wide host calls -- mappings, descriptors, forks
// -- the supervisor posts there, so guest threads need not, and may not
// (seccomp.zig). It runs in the guest's address space with no more than the
// stub's text and its registers to trust: the guest can write any other
// memory, its stack and the stub's variables included, so its loop keeps its
// state in registers and takes its requests only from the read-only page.
const WIN_BYTES: u64 = 256 << 10; // sandbox/chanwin.go winSize
const HOP_OFF: u64 = sig.AREA_LEN + MAX_SLOTS * WIN_BYTES;
// The syscall argument areas (args.zig) follow the hop pages in the memfd.
const ARGS_OFF: u64 = HOP_OFF + 2 * MAX_SLOTS * SLOT_SIZE;
// The window offsets, each region MAX_SLOTS entries long: 0x010_ slots, their
// signal areas and windows (to 0x124_), 0x130_ argument areas (args.zig),
// 0x150_ hop request and reply pages, 0x158_ the hop stack, 0x160_ the tid
// table (arch), 0x168_ left free for the guest's parked vDSO (sandbox/
// vdso_linux.go specialPark), 0x170_ exec stacks, 0x1b0_ alternate stacks,
// 0x230_ service stacks (to 0x270_), all within WIN_SIZE.
pub inline fn hopReqAddr() u64 {
    return winBase + 0x15000000000;
}
pub inline fn hopRepAddr() u64 {
    return hopReqAddr() + MAX_SLOTS * SLOT_SIZE;
}
pub inline fn hopStackAddr() u64 {
    return winBase + 0x15800000000;
}
const HOP_STACK_SIZE: u64 = 64 << 10;

// The request and reply pages, as sandbox/hop_linux.go writes and reads them
// and the hop loop (arch lc_hop_loop) reads and writes them, at these offsets;
// a hop's reply page is HOP_REP past its request page.
const HopReq = extern struct { seq: u32, sup_sleep: u32, nr: u64, args: [6]u64 };
const HopRep = extern struct { seq: u32, hop_sleep: u32, ret: u64 };
pub const HOP_REP: u64 = MAX_SLOTS * SLOT_SIZE;
// HOP_FORK, as a request's nr, has the hop thread fork the process: args are
// the child's slot, its hop's request page, the forking thread's context and
// the guest stack (stub.zig lc_hop_forked).
pub const HOP_FORK: u64 = ~@as(u64, 0);

comptime {
    if (@offsetOf(HopReq, "sup_sleep") != 4 or @offsetOf(HopReq, "nr") != 8 or @offsetOf(HopReq, "args") != 16 or
        @offsetOf(HopRep, "hop_sleep") != 4 or @offsetOf(HopRep, "ret") != 8 or HOP_REP != 0x400000000)
        @compileError("lc_hop_loop's offsets moved");
}

comptime {
    // sandbox/hop_linux.go stubSpOff reads the recorded guest sp here.
    if (sig.REC_OFF + @offsetOf(sig.Thread, "sp") != 136) @compileError("stubSpOff moved");
}

// The clone flags the stub uses, and the only ones its seccomp filter admits:
// a fork (CLONE_PARENT|SIGCHLD), and a thread (CLONE_VM|FS|FILES|SIGHAND|
// THREAD) whose slot's alive word the kernel zeroes once it is gone
// (CLONE_CHILD_CLEARTID), which the supervisor waits for. A forked stub is
// the supervisor's child, as every stub is: it stays its descendant however
// its guest parent ends, which process_vm_readv needs under Yama's
// ptrace_scope 1, and the supervisor reaps it.
pub const FORK_FLAGS: u32 = 0x00008000 | 17;
pub const THREAD_FLAGS: u32 = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 | 0x00010000 | 0x00200000;

const PROT_R = 1;
const PROT_RW = 3;
const MAP_SHARED = 0x01;
const MAP_FIXED = 0x10;
const SIG_UNBLOCK = 1;
const SIG_SETMASK = 2;
const FUTEX_WAIT = 0;
const FUTEX_WAKE = 1;

pub const STDIO_TRACED: u64 = 1 << 63;
// Set when the guest installed a seccomp filter: rt_sigreturn, which the stub
// otherwise completes with no round trip, must then be run past the supervisor
// so the filter is applied to it like any syscall (a guest may trap it).
pub const STDIO_SECCOMP: u64 = 1 << 61;

// Message kinds. Must match sandbox/chanabi.go.
pub const MSG_READY = 1;
pub const MSG_SYSCALL = 2;
pub const MSG_HOSTRET = 3;
pub const MSG_FORKED = 4; // child -> sup: forked, real pid in args[0]
const REP_RESULT = 1; // final syscall result in ret
pub const REP_HOST = 2; // perform syscall nr(args) on the host
const REP_START = 3; // jump to args[0] with stack args[1]
const REP_CLONE = 4; // spawn a thread: see arch.clone
const REP_EXEC = 5; // execve: jump to args[0] with stack args[1]
const REP_FORK = 6; // fork: save this thread's context, see forkPrep
const REP_FAULT = 12; // the trap was not a syscall site: a guest SIGILL
const REP_EXEC_PREPARE = 13; // move onto the exec stack before the old space is torn down
// A raw rt_sigreturn (serviced through the guest seccomp filter) that this
// layer owns: the frame may be completed here. Any other reply to it means an
// outer guest's filter trapped it -- it belongs to an inner layer -- so the
// frame is left for the delivered SIGSYS to carry inward.
pub const REP_SIGRETURN = 14;

// handle's result for REP_FAULT: no syscall returns it.
pub const NOT_A_SITE: u64 = @bitCast(@as(i64, -4096));

const ST_REQ = 1;
const ST_REP = 2;
// ST_DEAD: the supervisor is done with this thread (its process is ending);
// the thread exits rather than wait for a reply that will not come.
const ST_DEAD = 3;

// Chan is one channel slot, shared with sandbox/chanabi.go (chanPage).
pub const Chan = extern struct {
    self: u64, // points at this slot
    state: u32,
    alive: u32, // nonzero while a cloned stub thread runs on this slot
    kind: u64,
    nr: u64,
    args: [6]u64,
    rip: u64, // syscall site (validates a SIGILL)
    ret: u64, // syscall result
    stub_sleep: u32,
    sup_sleep: u32,
    guest_rip: u64, // where the guest resumes after this syscall
    stdio: u64, // bit i set: serve read/write on fd i in-process
};

pub const ALIVE_OFF = @offsetOf(Chan, "alive");

comptime {
    if (@offsetOf(Chan, "guest_rip") != 104) @compileError("guest_rip must stay at offset 104");
}

const SPIN = 4000;

// LIFELINE is the read end of a pipe whose write end only the supervisor
// holds. When the supervisor is gone the kernel sends the stubs' process
// group SIGIO (O_ASYNC), whose default action ends every stub, waiting or
// not (a forked child has no parent-death signal).
const LIFELINE = 4;
// XFER is a socket on which the supervisor passes descriptors (SCM_RIGHTS)
// for the stub to map; it receives them through REP_HOST recvmsg.
pub const XFER = 5;
const O_NONBLOCK = 0o4000;
const O_ASYNC = 0o20000;
const F_SETFL = 4;
const F_SETOWN = 8;

pub inline fn sys(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) u64 {
    return arch.sys6(n, a, b, c, d, e, f);
}

pub fn setAltstack(slot_addr: u64) void {
    const ss = extern struct { sp: u64, flags: i32, size: u64 }{
        .sp = altsAddr() + (slot_addr - slotsAddr()) / SLOT_SIZE * ALT_SIZE,
        .flags = 0,
        .size = ALT_SIZE,
    };
    if (sys(nr(.sigaltstack), @intFromPtr(&ss), 0, 0, 0, 0, 0) != 0) die(124);
}

pub fn die(code: u64) noreturn {
    _ = sys(nr(.exit_group), code, 0, 0, 0, 0, 0);
    unreachable;
}

pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    die(125);
}

// exitIfDead ends the calling thread once the supervisor is done with its
// slot.
pub fn exitIfDead(ch: *Chan) void {
    if (@atomicLoad(u32, &ch.state, .seq_cst) == ST_DEAD) _ = sys(nr(.exit), 0, 0, 0, 0, 0, 0);
}

// answered reports whether the supervisor has acted on the request: a reply,
// or ST_DEAD, on which the thread exits.
fn answered(ch: *Chan) bool {
    const st = @atomicLoad(u32, &ch.state, .seq_cst);
    if (st == ST_DEAD) _ = sys(nr(.exit), 0, 0, 0, 0, 0, 0);
    return st == ST_REP;
}

// Adaptive reply spin. Like the supervisor side (sandbox/adaptspin.go), the
// stub learns per slot how long the supervisor takes to answer and spins about
// that long before parking, capped at the park cost. This matters under load:
// a fixed spin makes every waiting stub thread burn a core, starving the one
// supervisor that has to answer them; parking when answers are slow frees those
// cores. park_cost (cputicks) starts at the supervisor's calibration, handed
// over at REP_START, and then follows the wakes this process sees (parkSeen);
// while it is 0 (not supplied, or LABOON_SPIN pinned a fixed count) the stub
// uses the fixed SPIN below.
pub var park_cost: u64 = 0;

// parkSeen folds the latency of the wake that ended a park into park_cost: a
// median estimate, stepping a sixteenth toward each sample, so what parking
// costs on this machine as it runs now caps the spins, and a rare long wake
// (a preempted waiter) barely moves it. The waker stamps wake_at as it wakes.
fn parkSeen(ch: *Chan) void {
    const at = @atomicLoad(u64, &sig.recOf(ch).wake_at, .seq_cst);
    const now = arch.ticks();
    const c = @atomicLoad(u64, &park_cost, .monotonic);
    if (at == 0 or now <= at or c == 0) return;
    const step = (c >> 4) | 1;
    const n = if (now - at > c) c + step else c - step;
    @atomicStore(u64, &park_cost, @max(n, 1), .monotonic);
}

fn wakeSup(ch: *Chan) void {
    @atomicStore(u64, &sig.recOf(ch).wake_at, arch.ticks(), .seq_cst);
    _ = sys(nr(.futex), @intFromPtr(&ch.state), FUTEX_WAKE, 1, 0, 0, 0);
}

// A slot's spinner is in its thread record (sig.Thread), which the supervisor
// clears for each new thread on the slot.
const Spinner = sig.Spinner;

fn spinnerOf(ch: *Chan) ?*Spinner {
    return &sig.recOf(ch).spin;
}

// The spin budget never exceeds cap: the park cost for a reply the waiter just
// asked for, more for a hop thread whose next request comes a round trip later.
fn spinBudget(s: *Spinner, cap: u64) u64 {
    if (!s.inited) return cap; // cold: spin up to the cap, then learn
    return @min(s.budget, cap);
}

fn spinHit(s: *Spinner, k: u64, cap: u64) void {
    if (!s.inited) {
        s.inited = true;
        s.mean = k;
        s.mad = k >> 2;
    } else {
        s.mean = s.mean - (s.mean >> 3) + (k >> 3);
        const d = if (k < s.mean) s.mean - k else k - s.mean;
        s.mad = s.mad - (s.mad >> 3) + (d >> 3);
    }
    var b = s.mean + 4 * s.mad;
    if (b > cap) b = cap;
    s.budget = b;
}

fn spinMiss(s: *Spinner, g: u64, cap: u64) void {
    s.inited = true;
    if (s.budget > cap) s.budget = cap;
    if (g < 4 * cap) {
        s.budget += (cap - s.budget) >> 1;
    } else {
        s.budget -= s.budget >> 2;
        if (s.budget < cap >> 5) s.budget = 0;
    }
}

// park sleeps on the state futex until the supervisor answers (or ST_DEAD, on
// which answered() exits the thread).
fn park(ch: *Chan) void {
    while (!answered(ch)) {
        @atomicStore(u32, &ch.stub_sleep, 1, .seq_cst);
        if (!answered(ch) and sys(nr(.futex), @intFromPtr(&ch.state), FUTEX_WAIT, ST_REQ, 0, 0, 0) == 0 and answered(ch))
            parkSeen(ch);
        @atomicStore(u32, &ch.stub_sleep, 0, .seq_cst);
    }
}

// exchange posts a request and waits for the reply, spinning before it
// sleeps. Each side only wakes the other when the other says it is asleep.
// A supervisor that dies takes the stub with it (SIGIO on LIFELINE).
pub fn exchange(ch: *Chan) void {
    // Post the request unless the slot is dead, which only the exit undoes.
    var cur = @atomicLoad(u32, &ch.state, .seq_cst);
    while (true) {
        if (cur == ST_DEAD) _ = sys(nr(.exit), 0, 0, 0, 0, 0, 0);
        cur = @cmpxchgWeak(u32, &ch.state, cur, ST_REQ, .seq_cst, .seq_cst) orelse break;
    }
    // A supervisor this wakes answers a wake later than its rhythm, so the
    // spin covers that wake too (and learns nothing from it): otherwise the
    // thread parks in turn, the answer has to wake it, and from then on every
    // exchange pays two wakes.
    const woke = @atomicLoad(u32, &ch.sup_sleep, .seq_cst) != 0;
    if (woke) wakeSup(ch);

    const cap = @atomicLoad(u64, &park_cost, .monotonic);
    if (cap != 0) {
        if (spinnerOf(ch)) |sp| {
            const start = arch.ticks();
            const budget = spinBudget(sp, cap) + if (woke) cap else 0;
            if (budget > 0) {
                const deadline = start + budget;
                outer: while (true) {
                    var i: u32 = 0;
                    // Poll state a batch of times, PAUSE between reads (yields the
                    // SMT sibling, lowers power), before reading the clock.
                    while (i < 32) : (i += 1) {
                        if (answered(ch)) {
                            if (!woke) spinHit(sp, arch.ticks() - start, cap);
                            return;
                        }
                        arch.pause();
                    }
                    if (arch.ticks() >= deadline) break :outer;
                }
            }
            park(ch);
            if (!woke) spinMiss(sp, arch.ticks() - start, cap);
            return;
        }
    }

    // Fixed fallback (no park cost yet, or LABOON_SPIN pinned a fixed count).
    var i: u32 = 0;
    while (i < SPIN) : (i += 1) {
        if (answered(ch)) return;
        arch.pause();
    }
    park(ch);
}

// A fork is made by the process's hop thread, never a guest thread: the
// child's first thread is then the hop's copy, which starts the child's hop
// thread and becomes its guest thread (hopForked). The guest thread resumes from
// the forking thread's context: forkPrep saves it at the bottom of that
// thread's exec stack (unused across a fork), where the child finds its copy
// of it. The FP/SIMD state, which the stub never touches, is the live one,
// except in a signal handler, where the kernel holds it in the frame (uc).
pub const ForkCtx = extern struct {
    frame: arch.Frame,
    rip: u64, // where the guest resumes
    sp: u64, // the guest sp at the fork
    tls: u64, // the guest thread pointer
};
pub const FORK_FP_OFF: u64 = 1024; // the FP/SIMD state, after the ForkCtx

fn forkPrep(ch: *Chan, f: *const arch.Frame, uc: u64) u64 {
    const slot = (@intFromPtr(ch) - slotsAddr()) / SLOT_SIZE;
    const base = execsAddr() + slot * EXEC_SIZE;
    const c: *ForkCtx = @ptrFromInt(base);
    c.frame = f.*;
    c.rip = ch.guest_rip;
    c.sp = sig.recOf(ch).sp;
    c.tls = arch.guestTls();
    arch.saveFp(base + FORK_FP_OFF, uc);
    return base;
}

// lc_fork_child is the first thread of a process the hop thread forked, on
// slot cs's service stack. It starts the process's hop thread on the request
// page req, confines itself to the guest's policy, takes slot cs and
// announces the process; then it resumes the guest from the forking thread's
// context at ctx, on stack when the clone named one (glibc's clone(fn, stack,
// SIGCHLD, arg) pops fn from it), or with no context serves an exec: a vfork
// child moving out of its parent's stub to exec. Its memory is a copy of the
// parent's, which the parent's guest could write, so until it is confined it
// trusts only its arguments (from the hop's read-only page): the window is
// req's, and cap is the hop's spin cap.
export fn lc_fork_child(cs: u64, req: u64, ctx: u64, stack: u64, cap: u64) callconv(.C) noreturn {
    // As the hop's copy it blocks every signal, and a forked stub has no
    // parent-death signal: the lifeline's SIGIO is its only end should the
    // supervisor go before releasing it, so it is open from the start.
    const io: u64 = 1 << (sig.SIGIO - 1);
    _ = sys(nr(.rt_sigprocmask), SIG_UNBLOCK, @intFromPtr(&io), 0, 8, 0, 0);
    winBase = req & ~(WIN_SIZE - 1);
    park_cost = cap >> 2;
    startHop(req); // before announcing: the supervisor routes to it from then
    seccomp.confineGuest();
    arch.setSlot(cs);
    setAltstack(cs);
    const cc: *Chan = @ptrFromInt(cs);
    const t = sig.recOf(cc);
    // Busy in the stub until the return to the guest, which looks for
    // signals: a kick now must not deliver onto this code.
    @atomicStore(u32, &t.busy, 1, .seq_cst);
    t.host_tid = @truncate(sys(nr(.gettid), 0, 0, 0, 0, 0, 0));
    cc.kind = MSG_FORKED;
    cc.args[0] = sys(nr(.getpid), 0, 0, 0, 0, 0, 0);
    if (ctx == 0) execServe(cc);
    // The supervisor records the pid, has the thread take on what it inherits
    // from the forking thread, and releases the child.
    while (true) {
        exchange(cc);
        if (cc.kind != REP_HOST) break;
        cc.ret = host(cc);
        cc.kind = MSG_HOSTRET;
    }
    unblockSignals();
    arch.resumeFork(@ptrFromInt(ctx), ctx + FORK_FP_OFF, if (stack != 0) stack else @as(*ForkCtx, @ptrFromInt(ctx)).sp);
}

// execServe serves the exec of a vfork child that moved into a process of its
// own, as once does for an exec in place.
fn execServe(cc: *Chan) noreturn {
    while (true) {
        exchange(cc);
        switch (cc.kind) {
            REP_HOST => {
                cc.ret = host(cc);
                cc.kind = MSG_HOSTRET;
            },
            REP_EXEC_PREPARE => arch.execHandoff(execStackTop(cc), cc),
            else => die(134),
        }
    }
}

// handle serves one guest syscall and returns the value for the guest's
// result register. site is the syscall address (0 from a trampoline); resume_at
// is where the guest continues, stored for a clone child; sp is the guest's
// stack pointer at the syscall; uc is the signal context the syscall came in
// (0 from a trampoline). A syscall interrupted by a signal that is gone by now
// (taken by another thread, or ignored) is issued again.
pub fn handle(ch: *Chan, f: *arch.Frame, site: u64, resume_at: u64, sp: u64, uc: u64) u64 {
    const n = f.number();
    const a = f.args();
    sig.recOf(ch).sp = sp;
    trace.frame(f, resume_at, sp);
    if (n == nr(.rt_sigreturn)) {
        const traced = ch.stdio & STDIO_TRACED != 0 and arch.frameOk(sp);
        if (traced) {
            trace.capture(arch.frameUc(sp));
            ch.ret = arch.ucRet(arch.frameUc(sp)).*;
        }
        // rt_sigreturn is completed here with no supervisor round trip on the
        // common path. It is routed past the supervisor only when something must
        // inspect it: a rewritten site (site != 0) whose ownership a nested stub
        // confirms, a traced thread, or a guest that installed a seccomp filter
        // (STDIO_SECCOMP) which may trap rt_sigreturn like any syscall. Complete
        // locally only when the supervisor confirms this layer owns it and the
        // filter admits it (REP_SIGRETURN); any other reply is left for the
        // trap-delivery tail -- a queued SIGSYS the entry path delivers, or
        // NOT_A_SITE, which forwards an unowned nested site inward.
        if (site != 0 or traced or ch.stdio & STDIO_SECCOMP != 0) {
            const r = once(ch, n, a, f, site, resume_at, uc);
            if (ch.kind != REP_SIGRETURN) return r;
        }
        sig.sigreturn(sp);
    }
    while (true) {
        const r = once(ch, n, a, f, site, resume_at, uc);
        const t = sig.thr();
        if (!sig.isRestart(r)) {
            trace.result(r);
            return r;
        }
        // The kick that cut the call short is answered by this look for a
        // signal; one after it stays, for the call issued again.
        @atomicStore(u32, &t.kicked, 0, .seq_cst);
        if (sig.deliverable(t) != 0) return r;
        sig.restoreSaved(t);
    }
}

// once runs the request/reply loop for one guest syscall.
fn once(ch: *Chan, n: u64, a: [6]u64, f: *arch.Frame, site: u64, resume_at: u64, uc: u64) u64 {
    // Fast path: stdio read/write/writev served in-process. The buffer and
    // iovecs are in our address space, and we hold the real fd, so this is
    // a single native syscall with no supervisor round trip or copy. A
    // broken pipe goes the slow way, for the supervisor to raise SIGPIPE.
    // The stdio word allows writes on fd i with bit i and reads with bit 8+i
    // (a terminal is never read here: see sandbox/stdiofd_unix.go).
    const rd = n == nr(.read);
    if ((rd or n == nr(.write) or n == nr(.writev)) and
        a[0] < 3 and ch.stdio & (@as(u64, 1) << @intCast(a[0] + if (rd) @as(u64, 8) else 0)) != 0)
    {
        // It may block (a pipe), so a signal must be able to cut it short.
        const r = sig.waitSys(n, .{ a[0], a[1], a[2], 0, 0, 0 });
        if (r == sig.EINTR) return sig.ERESTARTSYS;
        if (r != @as(u64, @bitCast(@as(i64, -32)))) return r;
    }
    // Clocks and the CPU, as the vDSO serves them: the stub thread is the
    // guest's thread, so even the CPU-time clocks read the right one. A
    // negative clock names a host pid; the supervisor serves it.
    if (ch.stdio & STDIO_TRACED == 0 and (((n == nr(.clock_gettime) or n == nr(.clock_getres)) and a[0] < 12) or n == nr(.gettimeofday) or n == nr(.getcpu)))
        return sys(n, a[0], a[1], 0, 0, 0, 0);
    args.prefetch(ch, n, a);
    ch.kind = MSG_SYSCALL;
    ch.nr = n;
    ch.args = a;
    ch.rip = site;
    ch.guest_rip = resume_at;
    while (true) {
        exchange(ch);
        switch (ch.kind) {
            REP_HOST => {
                ch.ret = host(ch);
                ch.kind = MSG_HOSTRET;
            },
            REP_CLONE => {
                ch.ret = arch.clone(ch, f);
                ch.kind = MSG_HOSTRET;
            },
            // execve: the supervisor has replaced the address space; jump to
            // the new entry on the new stack, as at START. From the SIGILL
            // path this leaves the handler without sigreturn, so its mask
            // (every signal) would stay and the new image's first trap
            // would kill it. The thread stays busy until its first syscall
            // returns.
            REP_EXEC => {
                unblockSignals();
                if (trace.state().dirty != 0) trace.enter();
                arch.enter(ch.args[0], ch.args[1]);
            },
            REP_FORK => {
                ch.ret = forkPrep(ch, f, uc);
                ch.kind = MSG_HOSTRET;
            },
            REP_EXEC_PREPARE => arch.execHandoff(execStackTop(ch), ch),
            REP_FAULT => return NOT_A_SITE,
            else => return args.apply(ch, ch.ret),
        }
    }
}

// execStackTop is the top of ch's slot's dedicated exec stack, 16-aligned.
fn execStackTop(ch: *Chan) u64 {
    const slot = (@intFromPtr(ch) - slotsAddr()) / SLOT_SIZE;
    return (execsAddr() + (slot + 1) * EXEC_SIZE) & ~@as(u64, 15);
}

// lc_exec_on_stack runs the exec service loop on the slot's exec stack, reached
// by arch.execHandoff after REP_EXEC_PREPARE. It acks the prepare (so the
// supervisor knows no old guest stack is underfoot), then serves the old
// space's teardown and the new image's maps until REP_EXEC enters it. It never
// returns to the old guest stack.
export fn lc_exec_on_stack(ch: *Chan) noreturn {
    // No guest stack is underfoot during teardown, so the old stack is just
    // another old mapping: clear the guest sp so the supervisor does not take
    // its unmap for the thread's own (onOwnStack in sandbox/hop_linux.go).
    sig.recOf(ch).sp = 0;
    ch.kind = MSG_HOSTRET; // ack REP_EXEC_PREPARE: we are on the exec stack
    while (true) {
        exchange(ch);
        switch (ch.kind) {
            REP_HOST => {
                ch.ret = host(ch);
                ch.kind = MSG_HOSTRET;
            },
            REP_EXEC => {
                unblockSignals();
                if (trace.state().dirty != 0) trace.enter();
                arch.enter(ch.args[0], ch.args[1]);
            },
            else => die(130),
        }
    }
}

// host runs a syscall the supervisor asks this thread to: one that is the
// thread's own (a futex wait, its exit, its clocks); the process's go to its
// hop thread.
fn host(ch: *Chan) u64 {
    // A thread's exit with args[1] set clears and wakes that tid word.
    if (ch.nr == nr(.exit) and ch.args[1] != 0) arch.exitWake(ch.args[1], ch.args[0]);
    if (ch.nr == nr(.futex) and futexWaits(ch.args[1])) return sig.waitSys(ch.nr, ch.args);
    return sys(ch.nr, ch.args[0], ch.args[1], ch.args[2], ch.args[3], ch.args[4], ch.args[5]);
}

// futexWaits reports whether futex op blocks: a wait, or taking a PI lock.
fn futexWaits(op: u64) bool {
    return switch (op & 0x7f) { // FUTEX_CMD_MASK
        0, 6, 9, 11, 13 => true, // WAIT, LOCK_PI, WAIT_BITSET, WAIT_REQUEUE_PI, LOCK_PI2
        else => false,
    };
}

// trampExit ends a syscall taken through a trampoline. A signal to deliver,
// or a syscall to restart, needs the guest's whole context, FP state
// included, which a host signal frame provides: the thread traps itself and
// arch.onSigill finishes the job from the Frame at fp.
pub fn trampExit(fp: u64, r: u64, resume_pc: u64, restart: u64, orig: u64) void {
    const t = sig.thr();
    if (!sig.isRestart(r) and trace.state().dirty == 0) {
        @atomicStore(u32, &t.busy, 0, .seq_cst);
        if (sig.deliverable(t) == 0) return;
        @atomicStore(u32, &t.busy, 1, .seq_cst);
    }
    t.frame = fp;
    t.resume_pc = resume_pc;
    t.restart = restart;
    t.orig = orig;
    arch.trap();
}

// trampExitGs ends a syscall taken through the %gs-anchor trampoline. Unlike
// trampExit it never clears busy on the fast return: the island clears busy
// only after it has restored the guest sp and popped the registers, so no kick
// can be delivered onto a service continuation whose Frame is still live on the
// scratch stack (the island then rechecks kicked, routing a late one through
// lc_latekick). A signal to deliver or a syscall to restart still needs the
// full guest context, so it takes the trap path, busy held.
pub fn trampExitGs(fp: u64, r: u64, resume_pc: u64, restart: u64, orig: u64) void {
    const t = sig.thr();
    if (!sig.isRestart(r) and trace.state().dirty == 0 and sig.deliverable(t) == 0) return;
    t.frame = fp;
    t.resume_pc = resume_pc;
    t.restart = restart;
    t.orig = orig;
    arch.trap();
}

pub fn unblockSignals() void {
    const empty: u64 = 0;
    _ = sys(nr(.rt_sigprocmask), SIG_SETMASK, @intFromPtr(&empty), 0, 8, 0, 0);
}

// loadBase finds where the stub was loaded from the initial stack's auxv:
// AT_PHDR points at the program headers, which sit 0x40 into the first LOAD
// segment (right after the 64-byte ELF header), so the image base -- and thus
// the window base -- is AT_PHDR - 0x40. This needs no relocated symbol, so it
// works in the freestanding stub where &__ehdr_start does not.
// auxval is the value of auxv entry typ on the initial stack at sp, or 0.
fn auxval(sp: u64, typ: u64) u64 {
    const p: [*]const u64 = @ptrFromInt(sp);
    var i: u64 = 1 + p[0] + 1; // past argc, argv[], its NULL
    while (p[i] != 0) : (i += 1) {} // past envp[]
    i += 1; // past envp's NULL
    while (p[i] != 0) : (i += 2) {
        if (p[i] == typ) return p[i + 1];
    }
    return 0;
}

fn loadBase(sp: u64) u64 {
    const p: [*]const u64 = @ptrFromInt(sp);
    var i: u64 = 1 + p[0] + 1; // past argc, argv[], its NULL
    while (p[i] != 0) : (i += 1) {} // past envp[]
    i += 1; // past envp's NULL
    while (p[i] != 0) : (i += 2) { // auxv (type, value) pairs
        if (p[i] == 3) return p[i + 1] - 0x40; // AT_PHDR
    }
    return STUB_BASE;
}

inline fn rd64(a: u64) u64 {
    return @as(*align(1) const u64, @ptrFromInt(a)).*;
}
inline fn rd32(a: u64) u32 {
    return @as(*align(1) const u32, @ptrFromInt(a)).*;
}

// applyRelocs applies the stub's own R_*_RELATIVE relocations when it is a PIE
// placed at a non-zero base (a nested stub): the loader maps the image but does
// not relocate it, and static-PIE startup must do so itself. It reads the
// program headers from the initial stack's auxv, finds PT_DYNAMIC, and for each
// relative entry writes *(base + r_offset) = base + r_addend. This touches only
// data (GOT slots), never code, so it runs before any GOT-dependent call and
// does not conflict with the no-code-relocation rule. It uses no GOT itself
// (inline syscalls and pointer math only).
fn applyRelocs(base: u64, sp: u64) void {
    const p: [*]const u64 = @ptrFromInt(sp);
    var i: u64 = 1 + p[0] + 1; // past argc, argv[], its NULL
    while (p[i] != 0) : (i += 1) {} // past envp[]
    i += 1;
    var phdr: u64 = 0;
    var phnum: u64 = 0;
    var phent: u64 = 56;
    while (p[i] != 0) : (i += 2) {
        switch (p[i]) {
            3 => phdr = p[i + 1], // AT_PHDR
            4 => phent = p[i + 1], // AT_PHENT
            5 => phnum = p[i + 1], // AT_PHNUM
            else => {},
        }
    }
    if (phdr == 0) return;
    var dyn: u64 = 0;
    var j: u64 = 0;
    while (j < phnum) : (j += 1) {
        const ph = phdr + j * phent;
        if (rd32(ph) == 2) { // PT_DYNAMIC
            dyn = base + rd64(ph + 0x10); // p_vaddr
            break;
        }
    }
    if (dyn == 0) return;
    var rela: u64 = 0;
    var relasz: u64 = 0;
    var relaent: u64 = 24;
    var d = dyn;
    while (rd64(d) != 0) : (d += 16) { // until DT_NULL
        switch (rd64(d)) {
            7 => rela = base + rd64(d + 8), // DT_RELA
            8 => relasz = rd64(d + 8), // DT_RELASZ
            9 => relaent = rd64(d + 8), // DT_RELAENT
            else => {},
        }
    }
    var r = rela;
    while (rela != 0 and r < rela + relasz) : (r += relaent) {
        if (rd64(r + 8) & 0xffffffff == arch.R_RELATIVE) {
            const slot: *align(1) u64 = @ptrFromInt(base + rd64(r)); // r_offset
            slot.* = base +% rd64(r + 16); // base + r_addend
        }
    }
}

export fn stub_main(sp: u64) callconv(.C) noreturn {
    // The window follows wherever the stub was loaded: STUB_BASE for the
    // top-level ET_EXEC, or the free high window the outer's loader chose for
    // a nested PIE. The supervisor learns it from the ready handshake below.
    winBase = loadBase(sp);
    applyRelocs(winBase, sp);
    fsgsbase = auxval(sp, 26) & 2 != 0; // AT_HWCAP2, HWCAP2_FSGSBASE
    // The slots, their signal areas and their windows (args.zig).
    if (sys(nr(.mmap), slotsAddr(), HOP_OFF, PROT_RW, MAP_SHARED | MAP_FIXED, 3, 0) != slotsAddr())
        die(123);
    // The hop pages, before the memfd closes; forks inherit them.
    if (sys(nr(.mmap), hopReqAddr(), MAX_SLOTS * SLOT_SIZE, PROT_R, MAP_SHARED | MAP_FIXED, 3, HOP_OFF) != hopReqAddr())
        die(131);
    if (sys(nr(.mmap), hopRepAddr(), MAX_SLOTS * SLOT_SIZE, PROT_RW, MAP_SHARED | MAP_FIXED, 3, HOP_OFF + MAX_SLOTS * SLOT_SIZE) != hopRepAddr())
        die(132);
    if (sys(nr(.mmap), args.areasAddr(), MAX_SLOTS * args.AREA_SIZE, PROT_RW, MAP_SHARED | MAP_FIXED, 3, ARGS_OFF) != args.areasAddr())
        die(136);
    const flags = 0x02 | 0x10 | 0x20 | 0x4000; // PRIVATE|FIXED|ANONYMOUS|NORESERVE
    if (!mapStackChunk(0)) die(124); // slot 0, the first process's
    if (sys(nr(.mmap), hopStackAddr(), HOP_STACK_SIZE, PROT_RW, flags, ~@as(u64, 0), 0) != hopStackAddr()) die(133);

    // Keep stdio (0,1,2) so stdio read/write can be served in-process,
    // without copying through the supervisor, the lifeline and the
    // descriptor socket; close everything else.
    _ = sys(nr(.close_range), 3, 3, 0, 0, 0, 0);
    _ = sys(nr(.close_range), XFER + 1, ~@as(u32, 0), 0, 0, 0, 0);
    const pgrp = sys(nr(.getpid), 0, 0, 0, 0, 0, 0); // the supervisor made us its leader
    _ = sys(nr(.fcntl), LIFELINE, F_SETOWN, 0 -% pgrp, 0, 0, 0);
    _ = sys(nr(.fcntl), LIFELINE, F_SETFL, O_NONBLOCK | O_ASYNC, 0, 0, 0);

    arch.init();
    arch.setSlot(slotsAddr());
    setAltstack(slotsAddr());
    const ch: *Chan = @ptrFromInt(slotsAddr());
    sig.recOf(ch).host_tid = @truncate(sys(nr(.getpid), 0, 0, 0, 0, 0, 0));
    // The stub inherits the supervisor's (Go runtime's) signal mask, which
    // blocks most signals. Unblock everything so our handlers can run.
    unblockSignals();
    sig.installHandlers();
    clearOnExit(ch);
    landlock.restrict();
    seccomp.install();

    // Announce readiness and service host ops (image/stack mmaps) until the
    // supervisor replies REP_START.
    ch.kind = MSG_READY;
    ch.rip = 0;
    ch.args = .{ winBase, 0, 0, 0, 0, 0 }; // tell the supervisor our window base
    while (true) {
        exchange(ch);
        if (ch.kind != REP_HOST) break;
        ch.ret = sys(ch.nr, ch.args[0], ch.args[1], ch.args[2], ch.args[3], ch.args[4], ch.args[5]);
        ch.kind = MSG_HOSTRET;
    }
    if (ch.kind != REP_START) die(127);
    ch.stdio = ch.args[2];
    park_cost = ch.args[3]; // the supervisor's measured park cost, in cputicks
    startHop(hopReqAddr() + ch.args[4] * SLOT_SIZE);
    seccomp.confineGuest();
    arch.enter(ch.args[0], ch.args[1]);
}

// clearOnExit has the kernel zero and wake ch's alive word when the calling
// thread, a process's first, is gone, as CLONE_CHILD_CLEARTID does for the
// threads the stub clones: the supervisor waits on it for the thread's end.
fn clearOnExit(ch: *Chan) void {
    @atomicStore(u32, &ch.alive, 1, .seq_cst);
    _ = sys(nr(.set_tid_address), @intFromPtr(&ch.alive), 0, 0, 0, 0, 0);
}

// startHop starts this process's hop thread (arch lc_hop_loop) on the request
// page req.
fn startHop(req: u64) void {
    if (arch.hopSpawn(hopStackAddr() + HOP_STACK_SIZE, req, 4 * park_cost) > MAX_ERRNO) die(135);
}

pub const MAX_ERRNO: u64 = @bitCast(@as(i64, -4096));

// lc_hop_forked is the hop thread's copy in a process it forked (HOP_FORK):
// it leaves the hop stack for slot cs's service stack, where it becomes the
// child's first thread (lc_fork_child).
export fn lc_hop_forked(cs: u64, req: u64, ctx: u64, stack: u64, cap: u64) callconv(.C) noreturn {
    winBase = req & ~(WIN_SIZE - 1);
    clearOnExit(@ptrFromInt(cs));
    arch.forkChildOn(scratchTop(@ptrFromInt(cs)), cs, req, ctx, stack, cap);
}

pub const _start = arch._start;

pub fn traceStart(ch: *Chan) void {
    if (ch.stdio & STDIO_TRACED == 0) return;
    ch.kind = MSG_FORKED;
    exchange(ch);
}
