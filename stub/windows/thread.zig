// thread.zig — the per-thread syscalls the Windows stub serves itself:
// clone (NtCreateThreadEx), fork (RtlCloneUserProcess), vfork, thread exit,
// futexes and sleeps. The architecture half (x86_64.zig, aarch64.zig)
// provides the syscall numbers, the trap frame and the few steps that move
// between stacks or into guest code.

const std = @import("std");
const win = std.os.windows;
const stub = @import("stub.zig");
const sig = @import("sig.zig");
const futex = @import("futex.zig");
const blocks = @import("blocks.zig");
const arch = stub.arch;

const HANDLE = usize;
const NTSTATUS = i32;
const CURRENT_PROCESS: HANDLE = ~@as(usize, 0);
const CURRENT_THREAD: HANDLE = ~@as(usize, 1);
const THREAD_ALL_ACCESS: u32 = 0x1fffff;

extern "ntdll" fn NtCreateThreadEx(h: *HANDLE, access: u32, attr: ?*anyopaque, proc: HANDLE, start: *const anyopaque, arg: ?*anyopaque, flags: u32, zerobits: usize, stacksize: usize, maxstack: usize, attrlist: ?*anyopaque) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtClose(h: HANDLE) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtTerminateThread(h: HANDLE, code: NTSTATUS) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtResumeThread(h: HANDLE, prev: ?*u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtFlushProcessWriteBuffers() callconv(win.WINAPI) void;
extern "ntdll" fn RtlCloneUserProcess(flags: u32, psd: ?*anyopaque, tsd: ?*anyopaque, dbg: HANDLE, info: *CloneInfo) callconv(win.WINAPI) NTSTATUS;

const CloneInfo = extern struct {
    length: u32,
    _pad: u32 = 0,
    process: HANDLE,
    thread: HANDLE,
    pid: usize,
    tid: usize,
    image: [64]u8,
};

const EINVAL: u64 = @bitCast(@as(i64, -22));
const EFAULT: u64 = @bitCast(@as(i64, -14));
const EAGAIN: u64 = @bitCast(@as(i64, -11));
const ERESTARTNOHAND: u64 = @bitCast(@as(i64, -514));
const ERESTART_RESTARTBLOCK: u64 = @bitCast(@as(i64, -516));
const EPERM: u64 = @bitCast(@as(i64, -1));

const NR = arch.NR;
const NR_VFORK_WAIT: u64 = 0x1_0000_0001;
const NR_THREAD_GONE: u64 = 0x1_0000_0002;
const NR_FORKED: u64 = 0x1_0000_0003; // a traced clone's report of its new thread (0: none)
const LC_FORKED: u64 = 0x4c430025;
const LC_FORK_QUIESCE: u64 = 0x4c430028;
const MSG_FORKED: u64 = 4;
const MSG_THREAD_ID: u64 = 6; // a new thread's OS thread id, in args[0]
const REP_CLONE: u64 = 4;
const REP_FORK: u64 = 6;

const CLONE_VFORK: u64 = 0x4000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;

// serve services one trapped syscall and returns its raw result. The
// per-thread calls (signals, futex, clone, thread exit, sleeps) are handled
// here; the rest go through stub.handle (the arch's own calls, memory, the
// supervisor).
// membarrier runs in the guest's own process: NtFlushProcessWriteBuffers
// interrupts every processor running one of its threads, a full barrier and a
// context synchronization event for each, so it serves the private commands,
// SYNC_CORE included. A global barrier is the same flush: the guest's threads
// are the ones it can observe.
const MB_GLOBAL: u64 = 1;
const MB_PRIVATE_EXPEDITED: u64 = 8;
const MB_REGISTER_PRIVATE_EXPEDITED: u64 = 16;
const MB_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 32;
const MB_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 64;
var mb_registered: u64 = 0;

fn membarrier(cmd: u64, flags: u64) u64 {
    if (flags != 0) return EINVAL;
    switch (cmd) {
        0 => return MB_GLOBAL | MB_PRIVATE_EXPEDITED | MB_REGISTER_PRIVATE_EXPEDITED |
            MB_PRIVATE_EXPEDITED_SYNC_CORE | MB_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
        MB_GLOBAL => {},
        MB_REGISTER_PRIVATE_EXPEDITED, MB_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            _ = @atomicRmw(u64, &mb_registered, .Or, cmd, .seq_cst);
            return 0;
        },
        MB_PRIVATE_EXPEDITED, MB_PRIVATE_EXPEDITED_SYNC_CORE => {
            if (@atomicLoad(u64, &mb_registered, .seq_cst) & (cmd << 1) == 0) return EPERM;
        },
        else => return EINVAL,
    }
    NtFlushProcessWriteBuffers();
    return 0;
}

pub fn serve(t: *sig.Trap) u64 {
    const nr = t.nr;
    const a = arch.args(t.frame);
    if (stub.seccompCheck(nr, a, t.resume_at)) |r| return r;
    switch (nr) {
        NR.gettid => return stub.localTraced(nr, a, t.resume_at, @as(u64, sig.myTid())),
        NR.set_tid_address => {
            sig.setCtid(a[0]);
            return stub.localTraced(nr, a, t.resume_at, @as(u64, sig.myTid()));
        },
        NR.futex => return stub.localTraced(nr, a, t.resume_at, futex.handle(a)),
        NR.membarrier => return stub.localTraced(nr, a, t.resume_at, membarrier(a[0], a[1])),
        NR.nanosleep => return stub.localTraced(nr, a, t.resume_at, doSleep(false, a[0], a[1])),
        NR.clock_nanosleep => return stub.localTraced(nr, a, t.resume_at, doSleep(a[1] & 1 != 0, a[2], a[3])),
        NR.restart_syscall => if (sig.takeSleep()) |b| return stub.localTraced(nr, a, t.resume_at, sleepTo(b.deadline, b.rem, false)),
        NR.clone, NR.fork, NR.vfork, NR.clone3 => return doClone(t),
        NR.exit => {
            if (sig.isThread() or sig.threadCount() > 1) arch.exitOnStubStack(a[0]);
        },
        else => {},
    }
    if (sig.handleSyscall(nr, a, t.gsp)) |r| return stub.localTraced(nr, a, t.resume_at, r);
    return stub.handle(nr, a, t.site, t.resume_at);
}

// exitThread is where an exit site lands on the thread's stub stack
// (lc_exit_entry): a thread's end, or the last thread's exit.
pub fn exitThread(code: u64) noreturn {
    sig.enter();
    if (sig.isThread() or sig.threadCount() > 1) threadExit(code);
    _ = stub.handle(NR.exit, .{ code, 0, 0, 0, 0, 0 }, 0, 0);
    stub.die(0xE0000007);
}

// lc_sig_apc is the body of the cross-process APC the supervisor queues to
// break a thread's alertable wait; the pending signal is taken on the way out.
pub export fn lc_sig_apc(_: usize, _: usize, _: usize) callconv(win.WINAPI) void {}

// ---- sleeps ----------------------------------------------------------------

fn doSleep(absolute: bool, req: u64, rem: u64) u64 {
    const ts = sig.get([2]i64, req) orelse return EFAULT;
    if (ts[0] < 0 or ts[1] < 0 or ts[1] >= std.time.ns_per_s) return EINVAL;
    var ns = ts[0] *| std.time.ns_per_s +| ts[1];
    if (absolute) ns -|= sig.nowNs();
    if (ns <= 0) return 0;
    return sleepTo(sig.nowNs() +| ns, rem, absolute);
}

// sleepTo sleeps until deadline. Signals whose action needs no handler are
// acted on and the sleep goes on (a stop pauses it). One the stub must take
// cuts it short: a relative sleep reports the time left in rem and returns
// ERESTART_RESTARTBLOCK, keeping the rest for restart_syscall (a handler
// makes it EINTR), and an absolute one ERESTARTNOHAND, as Linux's
// hrtimer_nanosleep.
fn sleepTo(deadline: i64, rem: u64, absolute: bool) u64 {
    if (!sig.sleepUntil(deadline)) return 0;
    if (absolute) return ERESTARTNOHAND;
    if (rem != 0) {
        const left = @max(deadline - sig.nowNs(), 0);
        if (!sig.put([2]i64, rem, .{ @divTrunc(left, std.time.ns_per_s), @rem(left, std.time.ns_per_s) })) return EFAULT;
    }
    sig.keepSleep(deadline, rem);
    return ERESTART_RESTARTBLOCK;
}

// ---- clone / threads -------------------------------------------------------

pub const Handoff = struct {
    chan: u64,
    tls: u64,
    ctid: u64,
    child_stack: u64,
    resume_at: u64,
    flags: u64,
    frame: sig.Frame,
};

// doClone posts clone, fork, vfork or clone3 to the supervisor, which
// allocates the slot, the pid and the signal records and replies:
//   REP_CLONE  a thread, or a CLONE_VM child process: create the OS thread
//              (args: slot offset, flags, child stack, parent-tid ptr, TLS,
//              child-tid ptr); with CLONE_VFORK the parent then waits off the
//              shared stack until the child execs or exits;
//   REP_FORK   fork the stub (args: slot offset, flags, stack, -, TLS,
//              child-tid ptr);
//   REP_RESULT an error.
fn doClone(t: *sig.Trap) u64 {
    const ch = stub.slot();
    ch.kind = 2; // MSG_SYSCALL
    ch.nr = t.nr;
    ch.args = arch.args(t.frame);
    ch.rip = t.site;
    ch.guest_rip = t.resume_at;
    stub.exchangePub(ch);
    if (ch.kind == 1) return ch.ret; // REP_RESULT: an error
    if (ch.kind == REP_FORK) return doFork(t, ch);
    if (ch.kind != REP_CLONE) stub.die(0xE0000006);

    const tid = ch.ret;
    const off = ch.args[0];
    const flags = ch.args[1];
    const stack = ch.args[2];
    const ptid = ch.args[3];
    const tls = ch.args[4];
    const ctid = ch.args[5];
    const idx = off / stub.SLOT_SIZE;
    const vfork = flags & CLONE_VFORK != 0;
    const traced = ch.null_fds & stub.WIN_TRACED != 0; // as the supervisor saw it when it replied
    if (!blocks.ensure(idx)) return cloneFailed(off, vfork, traced);
    const h = &blocks.at(idx).handoff;
    h.chan = stub.chan_base + off;
    h.tls = if (flags & CLONE_SETTLS != 0) tls else arch.tebLoad(stub.SLOT_TP);
    h.ctid = if (flags & CLONE_CHILD_CLEARTID != 0) ctid else 0;
    h.child_stack = if (stack != 0) stack else t.gsp;
    h.resume_at = t.resume_at;
    h.flags = flags;
    h.frame = t.frame.*;
    if (flags & CLONE_PARENT_SETTID != 0) @as(*u32, @ptrFromInt(ptid)).* = @truncate(tid);
    if (flags & CLONE_CHILD_SETTID != 0) @as(*u32, @ptrFromInt(ctid)).* = @truncate(tid);

    var th: HANDLE = 0;
    if (NtCreateThreadEx(&th, THREAD_ALL_ACCESS, null, CURRENT_PROCESS, &lc_thread_start, h, if (vfork) 1 else 0, 0, 0, 0, null) < 0)
        return cloneFailed(off, vfork, traced);
    _ = sig.addThreads(1);
    if (vfork) vforkPark(t, tid, th);
    _ = NtClose(th);
    // A traced caller reports the started thread, for its tracer's clone event
    // and the call's exit stop, and returns what the supervisor answers.
    if (traced) return stub.request(NR_FORKED, .{ tid, 0, 0, 0, 0, 0 });
    return tid;
}

// cloneFailed gives back the slot at off, whose thread could not start.
fn cloneFailed(off: u64, vfork: bool, traced: bool) u64 {
    const cc: *stub.Chan = @ptrFromInt(stub.chan_base + off);
    cc.kind = 2;
    cc.nr = NR_THREAD_GONE;
    cc.args[0] = 0;
    stub.postReq(cc);
    if (vfork) {
        _ = stub.request(NR_VFORK_WAIT, .{ 0, 0, 0, 0, 0, 0 });
    } else if (traced) {
        _ = stub.request(NR_FORKED, .{ 0, 0, 0, 0, 0, 0 });
    }
    return EAGAIN;
}

// vforkPark holds a vfork parent until its child execs or exits. The child
// runs on the parent's stack, where this call's frames live, so the parent
// first copies its trap state out and moves to its stub stack; only then is
// the child (created suspended) let go.
pub const Vfork = struct { ctx: sig.Ctx, th: HANDLE, tid: u64, nr: u64 };

fn vforkPark(t: *const sig.Trap, tid: u64, th: HANDLE) noreturn {
    const v = &blocks.mine().vfork;
    v.* = .{ .ctx = sig.ctxFromTrap(t), .th = th, .tid = tid, .nr = t.nr };
    arch.onStubStack(&lc_vfork_wait, &v.ctx);
}

fn lc_vfork_wait(c: *sig.Ctx) callconv(.C) noreturn {
    const v = &blocks.mine().vfork;
    _ = NtResumeThread(v.th, null);
    _ = NtClose(v.th);
    _ = stub.request(NR_VFORK_WAIT, .{ 0, 0, 0, 0, 0, 0 });
    sig.resumeCtx(c, v.nr, v.tid);
}

// doFork clones the stub with RtlCloneUserProcess. The child has only the
// calling thread, the parent's memory (private pages copied on write, the
// channel and MAP_SHARED views shared) and its inheritable handles, among
// them the new slot's events the supervisor duplicated in. It takes over its
// slot and checks in (MSG_FORKED: its OS pid and thread id); the parent
// closes its copies of those events and reports the child's OS pid.
fn doFork(t: *sig.Trap, ch: *stub.Chan) u64 {
    const gpid = ch.ret;
    const off = ch.args[0];
    const flags = ch.args[1];
    const stack = ch.args[2];
    const tls = ch.args[4];
    const ctid = ch.args[5];
    const idx = off / stub.SLOT_SIZE;
    const cch: *stub.Chan = @ptrFromInt(stub.chan_base + off);
    const es: HANDLE = cch.stdio;
    const ep: HANDLE = cch.pinfo;
    const win_stack = sig.winStack(); // the clone's thread is this one, on the same OS stack
    var info = std.mem.zeroes(CloneInfo);
    info.length = @sizeOf(CloneInfo);
    // The child's block, in place before the clone: the child has the
    // parent's chunks.
    if (!blocks.ensure(idx)) {
        _ = NtClose(es);
        _ = NtClose(ep);
        return stub.request(LC_FORKED, .{ 0, 0xC0000017, 0, 0, 0, 0 }); // STATUS_NO_MEMORY
    }
    stub.mem.lockAll(); // no other thread is mid-way through the region table
    // The supervisor suspends this process's other threads where none holds
    // ntdll's vectored-handler list lock, which the child would otherwise
    // find taken for good; it resumes them once LC_FORKED reports.
    _ = stub.request(LC_FORK_QUIESCE, .{ 0, 0, 0, 0, 0, 0 });
    const st = RtlCloneUserProcess(0x2, null, null, 0, &info); // RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
    stub.mem.unlockAll();
    if (st == 0x129) { // STATUS_PROCESS_CLONED: the child
        arch.threadInit(); // the clone's thread starts with tpidr_el0 = 0 (arm64)
        stub.vehUnlock();
        arch.tebStore(stub.SLOT_CHAN, stub.chan_base + off);
        stub.forkReset(idx, es, ep);
        sig.forkChild(idx, @truncate(arch.tebLoad(0x48)), arch.tebLoad(stub.SLOT_STK), win_stack);
        if (flags & CLONE_SETTLS != 0) arch.tebStore(stub.SLOT_TP, tls);
        if (flags & CLONE_CHILD_SETTID != 0) @as(*u32, @ptrFromInt(ctid)).* = @truncate(gpid);
        if (flags & CLONE_CHILD_CLEARTID != 0) sig.setCtid(ctid);
        if (stack != 0) {
            // clone's child stack: the guest resumes on it, and the TEB
            // describes it, as the parent's described the stack it left.
            t.gsp = stack;
            if (stub.mem.region(t.gsp -% 8)) |r| {
                arch.tebStore(0x08, r[1]);
                arch.tebStore(0x10, r[0]);
                arch.tebStore(0x1478, r[0]);
            }
        }
        cch.kind = MSG_FORKED;
        cch.args[0] = arch.tebLoad(0x40);
        cch.args[1] = arch.tebLoad(0x48);
        stub.exchangePub(cch);
        if (service_on) startService(); // the clone has only this thread; its parent had a service
        return 0;
    }
    _ = NtClose(es);
    _ = NtClose(ep);
    var pid: u64 = 0;
    if (st >= 0) {
        pid = info.pid;
        _ = NtClose(info.process);
        _ = NtClose(info.thread);
    }
    return stub.request(LC_FORKED, .{ pid, @as(u32, @bitCast(st)), 0, 0, 0, 0 });
}

// lc_thread_start runs on a fresh OS stack: it adopts the channel slot, sets the
// guest thread pointer and the TEB stack fields to the guest thread's stack,
// reports its OS thread id so the supervisor can reach it, then resumes the
// guest at the clone return on the child stack with a zero result.
fn lc_thread_start(arg: ?*anyopaque) callconv(win.WINAPI) void {
    const h: *Handoff = @ptrCast(@alignCast(arg.?));
    arch.threadInit();
    arch.tebStore(stub.SLOT_CHAN, h.chan);
    arch.tebStore(stub.SLOT_TP, h.tls);
    const idx = (h.chan - stub.chan_base) / stub.SLOT_SIZE;
    const os_tid: u32 = @truncate(arch.tebLoad(0x48));
    sig.startThread(idx, os_tid);
    sig.setThread(true, h.ctid);
    arch.prefaultStack();
    sig.keepWinStack();
    if (stub.mem.region(h.child_stack -% 8)) |r| {
        arch.tebStore(0x08, r[1]);
        arch.tebStore(0x10, r[0]);
        arch.tebStore(0x1478, r[0]);
    }
    const ch: *stub.Chan = @ptrFromInt(h.chan);
    // The supervisor left this slot's channel events (duplicated into the stub)
    // in the stdio/pinfo fields; adopt them before the first exchange.
    stub.setSlotEvents(idx, ch.stdio, ch.pinfo);
    ch.kind = MSG_THREAD_ID;
    ch.args[0] = os_tid;
    stub.exchangePub(ch);
    arch.resumeFrame(&h.frame, h.child_stack, h.resume_at);
}

// endThread is the supervisor's REP_THREAD_END: this thread (a CLONE_VM
// child process) ends while its stub lives on.
pub fn endThread(code: u64) noreturn {
    arch.exitOnStubStack(code);
}

// threadExit ends the calling guest thread (exit, not exit_group, with other
// threads running): clear and wake its clear-child-tid word, notify the
// supervisor so it retires the slot, and exit the OS thread.
fn threadExit(code: u64) noreturn {
    _ = sig.addThreads(-1);
    const ctid = sig.ctidWord();
    if (ctid != 0) {
        @atomicStore(u32, @as(*u32, @ptrFromInt(ctid)), 0, .seq_cst);
        _ = sig.futexWake(ctid, 0x7fffffff);
    }
    sig.endThread();
    const ch = stub.slot();
    ch.kind = 2;
    ch.nr = NR_THREAD_GONE;
    ch.args[0] = code;
    sig.restoreWinStack();
    stub.postReq(ch);
    endOsThread(@intCast(code & 0xff));
}

// endOsThread ends the calling OS thread without ntdll's thread shutdown. That
// shutdown trims the thread pool the parent's ntdll set up at its start, whose
// worker factory handle a fork child does not have: under strict handle checks
// the trim's call on it ends the process. The stub loads nothing, so there is
// nothing for the loader to run at a thread's end.
fn endOsThread(code: NTSTATUS) noreturn {
    _ = NtTerminateThread(CURRENT_THREAD, code);
    unreachable;
}

// The service thread serves the shared-code registry's requests
// (sandbox/codereg_windows.go, mem.serveCode) on a slot of its own, whatever
// the guest's threads do: it waits on LC_SERVICE, whose replies are the
// requests (exchange serves them), until the process ends. It is no guest
// thread: no signal reaches it, and a host stop leaves it running.
const LC_SERVICE_SLOT: u64 = 0x4c43002d;
const LC_SERVICE: u64 = 0x4c43002e;
const LC_SERVICE_HELD: u64 = 0x4c430034;

// The service thread (which serves the shared-code registry) is started only
// once this process maps a view of shared memory -- a process that maps none
// has no writable mapping any other could run as code, so no freeze is ever
// owed to it and the registry need not reach it (ensureService, called from
// mem.zig). This keeps the thread, its slot and the registry round trip off
// every short-lived process (a shell, a spawn helper) that touches no shared
// memory.
var service_on: bool = false;

pub fn ensureService() void {
    if (service_on) return;
    service_on = true;
    startService();
}

// startService joins the registry, freezing what other processes run as of
// then before the guest runs on, and starts the service thread.
pub fn startService() void {
    const ch = stub.slot();
    const off = stub.request(LC_SERVICE_SLOT, .{ 0, 0, 0, 0, 0, 0 });
    if (@as(i64, @bitCast(off)) < 0) return;
    var n = ch.args[0];
    const total = ch.args[1];
    var got: u64 = 0;
    while (n > 0) {
        stub.mem.heldIn(stub.window(ch), n);
        got += n;
        if (got >= total) break;
        n = stub.request(LC_SERVICE_HELD, .{ got, 0, 0, 0, 0, 0 });
    }
    var th: HANDLE = 0;
    if (NtCreateThreadEx(&th, THREAD_ALL_ACCESS, null, CURRENT_PROCESS, &lc_service_start, @ptrFromInt(off), 0, 0, 0, 0, null) < 0) return;
    _ = NtClose(th);
}

fn lc_service_start(arg: ?*anyopaque) callconv(win.WINAPI) void {
    const off = @intFromPtr(arg);
    arch.threadInit();
    arch.tebStore(stub.SLOT_CHAN, stub.chan_base + off);
    const ch: *stub.Chan = @ptrFromInt(stub.chan_base + off);
    stub.setSlotEvents(off / stub.SLOT_SIZE, ch.stdio, ch.pinfo);
    ch.kind = 2; // MSG_SYSCALL
    ch.nr = LC_SERVICE;
    stub.exchangePub(ch);
    endOsThread(0);
}
