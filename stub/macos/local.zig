// local.zig — Linux syscalls the stub answers itself, without a supervisor
// round trip: they touch only this process (clocks, sleeping, yielding,
// randomness, the CPU number), so the trampoline cost is all they pay. Linux
// serves the clock ones from the vDSO for the same reason.

const std = @import("std");
const futex = @import("futex.zig");
const proc = @import("proc.zig");
const sig = @import("sig.zig");

extern "c" fn clock_gettime(clk: c_int, ts: *Timespec) c_int;
extern "c" fn getentropy(buf: [*]u8, len: usize) c_int;
extern "c" fn sched_yield() c_int;

const Timespec = extern struct { sec: i64, nsec: i64 };

// putClock stores clock clk's time at the guest timespec tsAddr, which may be
// bad: the time is read here and copied out as copy_to_user would.
fn putClock(clk: c_int, tsAddr: u64) u64 {
    var ts: Timespec = undefined;
    if (clock_gettime(clk, &ts) != 0) return neg(EINVAL);
    return if (sig.putTimespec(tsAddr, .{ ts.sec, ts.nsec })) 0 else neg(EFAULT);
}

const NR_NANOSLEEP: u64 = 101;
const NR_CLOCK_GETTIME: u64 = 113;
const NR_CLOCK_GETRES: u64 = 114;
const NR_CLOCK_NANOSLEEP: u64 = 115;
const NR_SCHED_YIELD: u64 = 124;
const NR_GETTIMEOFDAY: u64 = 169;
const NR_GETRANDOM: u64 = 278;
const NR_RESTART_SYSCALL: u64 = 128;

// Linux errnos, returned negated.
const ERESTARTNOHAND: i64 = 514;
const ERESTART_RESTARTBLOCK: i64 = 516;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;

// Darwin clock ids.
const DW_CLOCK_REALTIME: c_int = 0;
const DW_CLOCK_MONOTONIC_RAW: c_int = 4;
const DW_CLOCK_MONOTONIC: c_int = 6;

fn neg(e: i64) u64 {
    return @bitCast(-e);
}

// darwinClock maps a Linux clockid the stub reads itself. MONOTONIC and
// BOOTTIME both map to Darwin's MONOTONIC, which keeps counting across sleep;
// futex.zig uses the same clock for FUTEX_WAIT_BITSET deadlines. The CPU-time
// clocks are the supervisor's: it reads them from the host thread or process
// behind the guest's, any process's, which the Seatbelt keeps from the stub.
fn darwinClock(id: u64) ?c_int {
    return switch (id) {
        0, 5, 8, 11 => DW_CLOCK_REALTIME, // REALTIME, _COARSE, _ALARM, TAI
        1, 6, 7, 9 => DW_CLOCK_MONOTONIC, // MONOTONIC, _COARSE, BOOTTIME, _ALARM
        4 => DW_CLOCK_MONOTONIC_RAW,
        else => null,
    };
}

fn nowNs(clk: c_int) i64 {
    var ts: Timespec = undefined;
    _ = clock_gettime(clk, &ts);
    return ts.sec * std.time.ns_per_s + ts.nsec;
}

// handle returns the result if nr is one the stub serves, else null.
pub fn handle(nr: u64, a: [*]const u64) ?u64 {
    return switch (nr) {
        NR_CLOCK_GETTIME => blk: {
            const clk = darwinClock(a[0]) orelse break :blk null;
            break :blk putClock(clk, a[1]);
        },
        NR_CLOCK_GETRES => blk: {
            _ = darwinClock(a[0]) orelse break :blk null;
            if (a[1] != 0 and !sig.putTimespec(a[1], .{ 0, 1 })) break :blk neg(EFAULT);
            break :blk 0;
        },
        NR_GETTIMEOFDAY => blk: {
            if (a[0] != 0) {
                const ns = nowNs(DW_CLOCK_REALTIME);
                if (!sig.putTimespec(a[0], .{ @divTrunc(ns, std.time.ns_per_s), @divTrunc(@rem(ns, std.time.ns_per_s), 1000) })) break :blk neg(EFAULT);
            }
            var tz = [2]i32{ 0, 0 }; // UTC, no DST
            if (a[1] != 0 and !sig.copyGuest(a[1], @intFromPtr(&tz), @sizeOf([2]i32))) break :blk neg(EFAULT);
            break :blk 0;
        },
        NR_NANOSLEEP => sleep(DW_CLOCK_MONOTONIC, false, a[0], a[1]),
        NR_CLOCK_NANOSLEEP => blk: {
            const clk = darwinClock(a[0]) orelse break :blk neg(EINVAL);
            break :blk sleep(clk, a[1] & 1 != 0, a[2], a[3]); // TIMER_ABSTIME
        },
        NR_SCHED_YIELD => blk: {
            _ = sched_yield();
            break :blk 0;
        },
        NR_GETRANDOM => getrandom(a[0], a[1]),
        NR_RESTART_SYSCALL => blk: {
            const d = restart_deadline;
            if (d == 0) break :blk proc.handle(nr, a); // not a sleep's: the supervisor's
            restart_deadline = 0;
            break :blk sleepTo(d, restart_rem, false);
        },
        else => proc.handle(nr, a),
    };
}

// restart_deadline is the rest of a relative sleep a signal cut short, which
// restart_syscall resumes on this thread (Linux's restart block); 0 for none.
threadlocal var restart_deadline: i64 = 0;
threadlocal var restart_rem: u64 = 0;

// forgetRestart drops the restart block once a handler has run instead.
pub fn forgetRestart() void {
    restart_deadline = 0;
}

// sleep blocks for the guest timespec at req: relative, or an absolute time on
// clk.
fn sleep(clk: c_int, absolute: bool, req: u64, rem: u64) u64 {
    const ts = sig.getTimespec(req) orelse return neg(EFAULT);
    if (ts[0] < 0 or ts[1] < 0 or ts[1] >= std.time.ns_per_s) return neg(EINVAL);
    var ns = ts[0] *| std.time.ns_per_s +| ts[1];
    if (absolute) ns -|= nowNs(clk);
    if (ns <= 0) return 0;
    return sleepTo(futex.nowNs() +| ns, rem, absolute);
}

// sleepTo sleeps until deadline. Signals whose action needs no handler are
// acted on and the sleep goes on (a stop pauses it). One the stub must take
// cuts it short: a relative sleep reports the time left in rem and returns
// ERESTART_RESTARTBLOCK, keeping the rest for restart_syscall (a handler
// makes it EINTR), and an absolute one ERESTARTNOHAND, as Linux's
// hrtimer_nanosleep.
fn sleepTo(deadline: i64, rem: u64, absolute: bool) u64 {
    if (!sig.sleepUntil(deadline)) return 0;
    if (absolute) return neg(ERESTARTNOHAND);
    if (rem != 0) {
        const left = @max(deadline - futex.nowNs(), 0);
        if (!sig.putTimespec(rem, .{ @divTrunc(left, std.time.ns_per_s), @rem(left, std.time.ns_per_s) })) return neg(EFAULT);
    }
    restart_deadline = deadline;
    restart_rem = rem;
    return neg(ERESTART_RESTARTBLOCK);
}

// getrandom fills the buffer from the kernel CSPRNG (getentropy serves at most
// 256 bytes a call). It never blocks once the system is up, so the flags need
// no handling.
fn getrandom(addr: u64, len: u64) u64 {
    var chunk: [256]u8 = undefined;
    var off: u64 = 0;
    while (off < len) {
        const n = @min(len - off, chunk.len);
        if (getentropy(&chunk, n) != 0) return neg(EFAULT);
        // Copied out as copy_to_user would: a bad buffer ends the call there.
        if (!sig.copyGuest(addr + off, @intFromPtr(&chunk), n)) return if (off == 0) neg(EFAULT) else off;
        off += n;
    }
    return len;
}
