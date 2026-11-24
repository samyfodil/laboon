// Linux signal delivery to the guest. The guest's signal state is virtual:
// handlers, masks, pending sets and the alternate stack live in a region
// shared with the supervisor (sandbox/signal.go), which serves sigaction,
// sigprocmask and friends and routes kill, timers and SIGCHLD. Host signals
// only carry the delivery: the supervisor marks a signal pending and kicks
// the stub thread with a host SIGURG (KICK); faults arrive as the host signal.
//
// A guest handler is entered from a host handler, whose kernel-built frame
// already holds the interrupted context in Linux format, FP/SIMD state
// included (the stub never touches those registers). The stub copies that
// frame onto the guest's stack as the guest's rt_sigframe and rewrites the
// host context so the host sigreturn lands in the guest handler. The guest's
// rt_sigreturn becomes a host rt_sigreturn on that guest frame.
//
// A thread is never redirected while busy in the stub: from a syscall, the
// pending signals are taken on the way out. The SIGILL path does that in its
// handler; the trampoline path traps itself (lc_sig_trap) to get a host frame.

const std = @import("std");
const trace = @import("trace.zig");
const stub = @import("stub.zig");
const arch = stub.arch;
const sys = stub.sys;
const SIG_UNBLOCK = 1;
const SIG_SETMASK = 2;
const nr = stub.nr;

// The signal records are the shared layer's (sandbox/lx_signal.go): past the
// slots, a stride per slot holding the thread record of the thread on that
// slot and, for a thread-group leader's slot, the process record. The stub's
// own per-thread state follows the channel header in each slot page, and the
// supervisor's replies to the signal calls follow that (SCRATCH_OFF).
pub const REC_OFF: u64 = 128;
const SCRATCH_OFF: u64 = REC_OFF + @sizeOf(Thread); // lxScratchOff in sandbox/chan_linux.go
const XFER_OFF: u64 = 3840; // the supervisor's recvmsg scratch in each slot
pub const AREA_OFF: u64 = stub.SLOT_SIZE * stub.MAX_SLOTS;
const STRIDE: u64 = 0x4000;
const PROC_OFF: u64 = 0x1000;
pub const AREA_LEN: u64 = AREA_OFF + STRIDE * stub.MAX_SLOTS;

// Info is the first 32 bytes of a siginfo_t, laid out as Linux does.
pub const Info = extern struct { signo: i32, errno: i32, code: i32, pad: i32, a: u64, b: u64 };
pub const Act = extern struct { handler: u64, flags: u64, restorer: u64, mask: u64 };

// Thread is the stub's own state for the thread on a slot.
pub const Thread = extern struct {
    busy: u32, // 1 while the stub works for this thread: no redirection
    host_tid: u32,
    sp: u64, // guest sp at the current syscall
    frame: u64, // trap delivery: the trampoline Frame
    resume_pc: u64, // trap delivery: where the guest resumes
    restart: u64, // trap delivery: where a restarted syscall re-executes
    orig: u64, // trap delivery: the result register at syscall entry
    _res0: u32,
    kicked: u32, // a kick came while busy, since this syscall began (waitSys)
    wake_at: u64, // ticks when either side last woke the other on this slot
    scratch_top: u64, // top of this thread's service stack (%gs:stubScratchTop)
    guest_gs: u64, // the guest's virtual %gs base: the stub owns the real %gs
    spin: Spinner, // the adaptive spin of this thread's waits (stub.zig)
};

pub const Spinner = extern struct {
    budget: u64, // spin budget, ticks
    mean: u64, // EWMA of caught-reply latency
    mad: u64, // EWMA of its absolute deviation
    inited: bool,
    _pad: [7]u8,
};

// Rec is the shared signal record of a thread. The pending sets themselves,
// and the actions, are the supervisor's: pending is its copy of the bits.
pub const Rec = extern struct {
    _res: u32,
    proc: u32, // slot of the thread-group leader (its Proc record)
    mask: u64,
    pending: u64,
    waitset: u64, // supervisor only: blocked signals a sigtimedwait takes
    ss_sp: u64,
    ss_size: u64, // 0: no alternate stack
    ss_flags: u32, // SS_AUTODISARM
    tid: u32,
    tgid: u32,
    saved: u32, // a temporary mask (sigsuspend, ppoll) is in force
    saved_mask: u64,
};

pub const Proc = extern struct {
    _res: u64,
    pending: u64, // the process-directed pending bits
};

comptime {
    std.debug.assert(REC_OFF + @sizeOf(Thread) <= XFER_OFF); // see sandbox/mmap_linux.go
    std.debug.assert(@sizeOf(Thread) == 112); // stubLocalLen in sandbox/fork_linux.go
    std.debug.assert(XFER_OFF + 256 <= stub.SLOT_SIZE);
    std.debug.assert(@offsetOf(Rec, "mask") == 8);
    std.debug.assert(@offsetOf(Rec, "ss_flags") == 48);
    std.debug.assert(@offsetOf(Rec, "saved_mask") == 64);
    std.debug.assert(@offsetOf(Proc, "pending") == 8);
    std.debug.assert(@sizeOf(Rec) <= PROC_OFF);
    std.debug.assert(PROC_OFF + @sizeOf(Proc) <= STRIDE);
}

pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGPIPE: u32 = 13;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGWINCH: u32 = 28;
// SIGIO comes only from LIFELINE (O_ASYNC) as the supervisor goes, and ends
// the stub by its default action: no handler blocks it.
pub const SIGIO: u32 = 29;
// SIGSYS is raised by the stub's own seccomp filter (RET_TRAP) when a guest
// runs a syscall the rewriter left as a raw instruction: the handler services
// it through the supervisor. Like SIGIO it must never be blocked, or a missed
// site would deadlock instead of trapping.
pub const SIGSYS: u32 = 31;

// SECCOMP_TRAP_TAG stamps our out-of-text RET_TRAP in SECCOMP_RET_DATA; it
// reaches onSigsys as siginfo.si_errno, with si_code == SI_CODE_SECCOMP, so
// the handler can tell a syscall it must service from a SIGSYS the guest
// raised for itself (kill/rt_sigqueueinfo), which it delivers on instead.
pub const SECCOMP_TRAP_TAG: u32 = 0x5ca1;
pub const SI_CODE_SECCOMP: i32 = 1; // SYS_SECCOMP
// KICK is the host signal that wakes a stub thread to take a guest signal.
// Its default action is to ignore it, so the kick is harmless to any other
// process, which is all the seccomp filter lets tgkill send.
pub const KICK = SIGURG;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
pub const SA_SIGINFO: u64 = 4;
pub const SA_ONSTACK: u64 = 0x08000000;
pub const SA_RESTART: u64 = 0x10000000;
pub const SA_NODEFER: u64 = 0x40000000;
pub const SA_RESETHAND: u64 = 0x80000000;
pub const SA_RESTORER: u64 = 0x04000000;
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
const SS_AUTODISARM: u32 = 1 << 31;

pub const ERESTARTSYS: u64 = @bitCast(@as(i64, -512));
pub const ERESTARTNOINTR: u64 = @bitCast(@as(i64, -513));
pub const ERESTARTNOHAND: u64 = @bitCast(@as(i64, -514));
pub const ERESTART_RESTARTBLOCK: u64 = @bitCast(@as(i64, -516));
pub const EINTR: u64 = @bitCast(@as(i64, -4));

// The supervisor ends the process with this signal (args[0]). Outside the
// Linux syscall range; must match sandbox/signal.go.
pub const LC_SIGDIE: u64 = 0x4c430010;
pub const LC_SIGSTOP: u64 = 0x4c430011;
const LC_SIGTAKE: u64 = 0x4c430012;
const LC_SIGFAULT: u64 = 0x4c430014;

pub fn bit(sig: u32) u64 {
    return @as(u64, 1) << @intCast(sig - 1);
}

const KILLSTOP = bit(SIGKILL) | bit(SIGSTOP);

pub fn recOf(ch: *stub.Chan) *Thread {
    return @ptrFromInt(@intFromPtr(ch) + REC_OFF);
}

pub fn thr() *Thread {
    return recOf(arch.slot());
}

// rec is the shared record of the thread whose own state is t.
pub fn rec(t: *Thread) *Rec {
    const slot = (@intFromPtr(t) - REC_OFF - stub.slotsAddr()) / stub.SLOT_SIZE;
    return @ptrFromInt(stub.slotsAddr() + AREA_OFF + slot * STRIDE);
}

fn procOf(r: *Rec) *Proc {
    const leader: u64 = @atomicLoad(u32, &r.proc, .acquire);
    return @ptrFromInt(stub.slotsAddr() + AREA_OFF + leader * STRIDE + PROC_OFF);
}

fn ld(p: *u64) u64 {
    return @atomicLoad(u64, p, .acquire);
}

pub fn isRestart(r: u64) bool {
    return r == ERESTARTSYS or r == ERESTARTNOINTR or r == ERESTARTNOHAND or r == ERESTART_RESTARTBLOCK;
}

pub fn deliverable(t: *Thread) u64 {
    const r = rec(t);
    return (ld(&r.pending) | ld(&procOf(r).pending)) & ~ld(&r.mask);
}

// restoreSaved ends a sigsuspend's temporary mask when no handler ran.
pub fn restoreSaved(t: *Thread) void {
    const r = rec(t);
    if (r.saved != 0) {
        @atomicStore(u64, &r.mask, r.saved_mask, .seq_cst);
        r.saved = 0;
    }
}

// call makes a supervisor call for the signal machinery and returns its
// result, serving the host calls the supervisor asks for meanwhile.
fn call(n: u64, a0: u64, a1: u64) u64 {
    return callArgs(n, .{ a0, a1, 0, 0, 0, 0 });
}

fn callArgs(n: u64, args: [6]u64) u64 {
    const ch = arch.slot();
    ch.kind = stub.MSG_SYSCALL;
    ch.nr = n;
    ch.args = args;
    ch.rip = 0;
    while (true) {
        stub.exchange(ch);
        if (ch.kind != stub.REP_HOST) return ch.ret;
        ch.ret = sys(ch.nr, ch.args[0], ch.args[1], ch.args[2], ch.args[3], ch.args[4], ch.args[5]);
        ch.kind = stub.MSG_HOSTRET;
    }
}

// The supervisor's reply to a signal call: a siginfo head, then an action.
fn replyInfo() Info {
    return @as(*align(1) const Info, @ptrFromInt(@intFromPtr(arch.slot()) + SCRATCH_OFF)).*;
}

fn replyAct() Act {
    return @as(*align(1) const Act, @ptrFromInt(@intFromPtr(arch.slot()) + SCRATCH_OFF + 32)).*;
}

// take dequeues the next signal in allow (thread-directed first) with its
// action; the supervisor resets an SA_RESETHAND one as it hands it over.
fn take(allow: u64, info: *Info, act: *Act) u32 {
    const s: u32 = @truncate(call(LC_SIGTAKE, allow, 0));
    if (s == 0) return 0;
    info.* = replyInfo();
    act.* = replyAct();
    return s;
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

// stopSelf has the supervisor stop this process for a stop default action
// (or discard it, for an orphaned process group). The reply comes once the
// process is continued.
fn stopSelf(sig: u32) void {
    _ = call(LC_SIGSTOP, sig, 0);
}

// die asks the supervisor to end the process as killed by sig; it replies
// with the host exit to perform.
pub fn die(sig: u32) noreturn {
    dieAt(sig, 0, 0);
}

// dieAt is die for a fault, with its address and pc for the supervisor's
// trace.
fn dieAt(sig: u32, addr: u64, pc: u64) noreturn {
    const ch = arch.slot();
    ch.kind = stub.MSG_SYSCALL;
    ch.nr = LC_SIGDIE;
    ch.args = .{ sig, addr, pc, 0, 0, 0 };
    ch.rip = 0;
    while (true) {
        stub.exchange(ch);
        if (ch.kind == stub.REP_HOST) {
            ch.ret = sys(ch.nr, ch.args[0], ch.args[1], ch.args[2], ch.args[3], ch.args[4], ch.args[5]);
            ch.kind = stub.MSG_HOSTRET;
        }
    }
}

// Restart describes a syscall that returned a restart code: where it
// re-executes and the result register's value at its entry.
pub const Restart = struct { code: u64 = 0, pc: u64 = 0, orig: u64 = 0 };

// Stack is where a handler's frame goes and how uc_stack reads.
pub const Stack = struct { top: u64, ss_sp: u64, ss_size: u64, ss_flags: u32 };

fn stackFor(t: *Rec, act: Act, sp: u64) Stack {
    const on = t.ss_size != 0 and sp > t.ss_sp and sp <= t.ss_sp + t.ss_size;
    var st = Stack{
        .top = arch.redZone(sp),
        .ss_sp = t.ss_sp,
        .ss_size = t.ss_size,
        .ss_flags = (if (t.ss_size == 0) SS_DISABLE else if (on) SS_ONSTACK else 0) | t.ss_flags,
    };
    if (act.flags & SA_ONSTACK != 0 and t.ss_size != 0 and !on) {
        st.top = t.ss_sp + t.ss_size;
        if (t.ss_flags & SS_AUTODISARM != 0) {
            t.ss_sp = 0;
            t.ss_size = 0;
            t.ss_flags = 0;
        }
    }
    return st;
}

// enter builds the frame for sig on the guest's stack, points uc at the
// handler and applies the handler's mask, as the kernel's setup_rt_frame and
// signal_delivered do. uc_mask is what the handler's sigreturn restores.
fn enter(uc: [*]u8, t: *Rec, sig: u32, info: *const [128]u8, act: Act, uc_mask: u64) void {
    const st = stackFor(t, act, arch.ucSp(uc).*);
    const restorer = if (act.flags & SA_RESTORER != 0) act.restorer else @intFromPtr(&arch.lc_guest_restorer);
    arch.pushFrame(uc, st, sig, info, act.handler, restorer, uc_mask);
    var nm = ld(&t.mask) | act.mask;
    if (act.flags & SA_NODEFER == 0) nm |= bit(sig);
    @atomicStore(u64, &t.mask, nm & ~KILLSTOP, .seq_cst);
}

fn expand(i: Info) [128]u8 {
    var b = [_]u8{0} ** 128;
    @memcpy(b[0..32], std.mem.asBytes(&i));
    return b;
}

// deliverAll takes every signal deliverable to this thread and acts on it:
// handler frames stack up on uc (the last one taken runs first, as on Linux),
// ignored ones vanish, a stop stops and a fatal one ends the process. A
// syscall interrupted with a restart code is restarted or fails with EINTR,
// as the first handler asks; with no handler it restarts.
pub fn deliverAll(uc: [*]u8, rs: Restart) void {
    const t = rec(thr());
    var restart = isRestart(rs.code);
    while (true) {
        var info: Info = undefined;
        var act: Act = undefined;
        trace.capture(uc);
        if (rs.pc != 0) trace.inCall(rs.orig);
        const s = take(~ld(&t.mask), &info, &act);
        trace.restore(uc);
        if (s == 0) break;
        switch (classify(s, act)) {
            .ignore => {},
            .stop => stopSelf(s),
            .term => die(s),
            .handler => {
                if (restart) {
                    restart = false;
                    if (rs.code == ERESTARTNOINTR or rs.code == ERESTARTSYS and act.flags & SA_RESTART != 0) {
                        arch.setRestart(uc, rs.pc, rs.orig);
                    } else {
                        arch.ucRet(uc).* = EINTR;
                    }
                }
                var m = ld(&t.mask);
                if (t.saved != 0) {
                    m = t.saved_mask;
                    t.saved = 0;
                }
                const b = expand(info);
                enter(uc, t, s, &b, act, m);
            },
        }
    }
    if (restart) {
        // ERESTART_RESTARTBLOCK resumes as restart_syscall, which goes on
        // from the call's restart block rather than starting it over.
        if (rs.code == ERESTART_RESTARTBLOCK) arch.setRestartBlock(uc, rs.pc, rs.orig) else arch.setRestart(uc, rs.pc, rs.orig);
    }
    restoreSaved(thr());
}

// fault delivers a synchronous signal raised by the guest's own code. A
// blocked, ignored or default one ends the process, as force_sig does (the
// supervisor resets such an action to the default).
pub fn fault(uc: [*]u8, original: u32, info: *const [128]u8) void {
    const t = rec(thr());
    trace.capture(uc);
    const sig: u32 = @intCast(callArgs(LC_SIGFAULT, .{
        original,
        @intFromBool(ld(&t.mask) & bit(original) != 0),
        std.mem.readInt(u64, info[16..24], .little),
        std.mem.readInt(u32, info[8..12], .little),
        arch.ucPc(uc),
        arch.ucSp(uc).*,
    }));
    trace.restore(uc);
    if (sig == 0) return;
    const act = replyAct();
    // A fatal default action ends the process; report the faulting address and
    // pc so the supervisor's trace names the crash site (e.g. a guest int3).
    if (classify(sig, act) != .handler)
        dieAt(sig, std.mem.readInt(u64, info[16..24], .little), arch.ucPc(uc));
    var delivered = info.*;
    std.mem.writeInt(u32, delivered[0..4], sig, .little);
    enter(uc, t, sig, &delivered, act, ld(&t.mask));
    deliverAll(uc, .{});
}

fn hostAlt(t: *Thread) [3]u64 {
    const slot = @intFromPtr(t) - REC_OFF;
    return .{ stub.altsAddr() + (slot - stub.slotsAddr()) / stub.SLOT_SIZE * stub.ALT_SIZE, 0, stub.ALT_SIZE };
}

// sigreturn ends a guest handler: the guest's mask and alternate stack come
// back from its frame at sp, then the host restores everything else from
// that frame, after the host's own mask and stack replace the guest's in it.
pub fn sigreturn(sp: u64) noreturn {
    const lt = thr();
    const t = rec(lt);
    @atomicStore(u32, &lt.busy, 1, .seq_cst);
    // A kick from here on stays pending, to be taken once the host sigreturn
    // has put the thread back in the guest (busy clear): from here the stub
    // goes to the guest without looking for signals again after its check
    // below, so a kick it absorbed while busy would be lost.
    const k = bit(KICK);
    _ = sys(nr(.rt_sigprocmask), 0, @intFromPtr(&k), 0, 8, 0, 0);
    if (!arch.frameOk(sp)) die(SIGSEGV);
    const uc = arch.frameUc(sp);
    trace.restore(uc);
    const mask: *align(1) u64 = @ptrCast(uc + arch.UC_SIGMASK);
    const ss: [*]align(1) u64 = @ptrCast(uc + 16);
    // The mask is always restored: under nesting this stub completes the host
    // rt_sigreturn for a frame an inner stub built (a forwarded SIGILL's return
    // reaches this layer on a foreign frame), and leaving the mask alone there
    // would keep a signal this layer blocked for delivery blocked forever, so a
    // later trap it must forward is reported blocked and dropped to the default.
    @atomicStore(u64, &t.mask, mask.* & ~KILLSTOP, .seq_cst);
    t.saved = 0;
    // The alternate stack, though, is adopted only from a frame this instance
    // built. A foreign frame's uc_stack is the inner instance's (a nested Go M's
    // 0x8000 altstack); importing it would plant a stale stack that faults on the
    // next on-stack delivery once the inner level unmaps it.
    if (arch.frameOurs(uc)) {
        const ss_flags: u32 = @truncate(ss[1]);
        if (ss_flags & SS_DISABLE != 0) {
            t.ss_sp = 0;
            t.ss_size = 0;
            t.ss_flags = 0;
        } else if (ss[2] != 0) {
            t.ss_sp = ss[0];
            t.ss_size = ss[2];
            t.ss_flags = ss_flags & SS_AUTODISARM;
        }
    }
    mask.* = 0;
    const alt = hostAlt(lt);
    ss[0] = alt[0];
    ss[1] = alt[1];
    ss[2] = alt[2];
    if (deliverable(lt) != 0) {
        // Taken with the guest context once the host sigreturn is done.
        _ = sys(nr(.tgkill), sys(nr(.getpid), 0, 0, 0, 0, 0, 0), sys(nr(.gettid), 0, 0, 0, 0, 0, 0), KICK, 0, 0, 0);
    }
    arch.sigreturn(sp, &lt.busy);
}

export fn lc_restorer_c(sp: u64) callconv(.C) noreturn {
    // A handler the stub delivered without a guest restorer (the norm on arm64,
    // which has no SA_RESTORER) returns here, completing the signal with no
    // rt_sigreturn syscall for a guest seccomp filter to see. When the guest has
    // a filter (STDIO_SECCOMP), run rt_sigreturn past the supervisor so the filter
    // applies to it as the kernel would. If the filter traps it, a SIGSYS is
    // queued; deliver it on top of this frame, which the sigreturn then resumes
    // into. The common no-filter path is unchanged (a direct sigreturn).
    const ch = arch.slot();
    if (ch.stdio & stub.STDIO_SECCOMP != 0) {
        recOf(ch).sp = sp;
        _ = callArgs(nr(.rt_sigreturn), .{ 0, 0, 0, 0, 0, 0 });
        if (ch.kind != stub.REP_SIGRETURN) deliverAll(arch.frameUc(sp), .{});
    }
    sigreturn(sp);
}

fn ownThread(t: *Thread) bool {
    return t.host_tid != 0 and t.host_tid == @as(u32, @truncate(sys(nr(.gettid), 0, 0, 0, 0, 0, 0)));
}

// onKick runs when the supervisor has posted a signal for this thread.
// A kick that finds the thread busy in the stub is kept: the stub takes the
// signal on its way back to the guest, and a wait (waitSys) it is about to
// start, or is in, ends at once. One that finds it in guest code with its
// slot dead (another thread exec'd) ends it, as Linux kills the others.
fn onKick(_: i32, _: ?*anyopaque, uc: [*]u8) callconv(.C) void {
    if (arch.slotAddr() == 0) return;
    const t = thr();
    if (!ownThread(t)) return;
    if (@atomicLoad(u32, &t.busy, .seq_cst) != 0) {
        @atomicStore(u32, &t.kicked, 1, .seq_cst);
        arch.cpCancel(uc);
        return;
    }
    stub.exitIfDead(arch.slot());
    @atomicStore(u32, &t.busy, 1, .seq_cst);
    deliverAll(uc, .{});
    @atomicStore(u32, &t.busy, 0, .seq_cst);
}

// waitSys makes a blocking host call for the guest that a signal must cut
// short with EINTR, however close to it the kick lands: one since this
// syscall began has set kicked, which the call checks; one between that check
// and the syscall instruction is moved off it (arch.cpCancel); one during it
// interrupts it. KICK is unblocked meanwhile: the ud2 path runs in a handler
// that blocks it.
pub fn waitSys(n: u64, a: [6]u64) u64 {
    const t = thr();
    const k = bit(KICK);
    var old: u64 = 0;
    _ = sys(nr(.rt_sigprocmask), SIG_UNBLOCK, @intFromPtr(&k), @intFromPtr(&old), 8, 0, 0);
    const r = arch.cpSys(n, a, &t.kicked);
    _ = sys(nr(.rt_sigprocmask), SIG_SETMASK, @intFromPtr(&old), 0, 8, 0, 0);
    return r;
}

// beginSyscall marks the thread busy in the stub for a guest syscall, with
// no kick seen yet. kicked is cleared first: a kick between the two finds the
// thread not yet busy and is taken as one in guest code.
pub fn beginSyscall(t: *Thread) void {
    @atomicStore(u32, &t.kicked, 0, .seq_cst);
    @atomicStore(u32, &t.busy, 1, .seq_cst);
}

// onFault takes a fault in guest code to the guest. One in the stub (a bad
// guest pointer, or a guest stack it cannot write a frame on) ends it.
fn onFault(sig: i32, info: *const [128]u8, uc: [*]u8) callconv(.C) void {
    if (arch.copyFixup(uc)) return; // a guest range the stub copies from ends there
    const s: u32 = @intCast(sig);
    if (arch.slotAddr() == 0) stub.die(128 + s);
    const t = thr();
    if (@atomicLoad(u32, &t.busy, .seq_cst) != 0)
        dieAt(s, std.mem.readInt(u64, info[16..24], .little), arch.ucPc(uc));
    @atomicStore(u32, &t.busy, 1, .seq_cst);
    fault(uc, s, info);
    @atomicStore(u32, &t.busy, 0, .seq_cst);
}

const KSigaction = extern struct {
    handler: usize,
    flags: u64,
    restorer: usize,
    mask: u64,
};

fn install(sig: u32, handler: usize, flags: u64, mask: u64) void {
    const sa = KSigaction{
        .handler = handler,
        .flags = flags | SA_RESTORER,
        .restorer = @intFromPtr(&arch.stub_restorer),
        .mask = mask,
    };
    if (sys(nr(.rt_sigaction), sig, @intFromPtr(&sa), 0, 8, 0, 0) != 0) stub.die(126);
}

// The host signals of the stub. Every handler runs on the thread's own
// alternate stack with every other signal blocked, except the synchronous
// ones, so a fault inside a handler reaches onFault, and SIGIO.
pub fn installHandlers() void {
    const flags = SA_SIGINFO | SA_ONSTACK;
    const sync = bit(SIGSEGV) | bit(SIGBUS) | bit(SIGFPE) | bit(SIGTRAP);
    // SIGSYS stays open so a raw syscall that traps while another handler runs
    // (or while a guest signal handler runs) is still serviced, not lost.
    const open = sync | bit(SIGIO) | bit(SIGSYS);
    install(SIGILL, @intFromPtr(&arch.onSigill), flags, ~open);
    install(SIGSYS, @intFromPtr(&arch.onSigsys), flags, ~open);
    install(KICK, @intFromPtr(&onKick), flags, ~open);
    for ([_]u32{ SIGSEGV, SIGBUS, SIGFPE, SIGTRAP }) |s|
        install(s, @intFromPtr(&onFault), flags | SA_NODEFER, ~open);
    // A write to a broken pipe fails with EPIPE; the supervisor raises the
    // guest's SIGPIPE.
    install(SIGPIPE, SIG_IGN, 0, 0);
    // Exited child stubs are reaped by the kernel: their status reaches the
    // supervisor over the channel.
    install(SIGCHLD, SIG_IGN, 0x2, 0); // SA_NOCLDWAIT
}
