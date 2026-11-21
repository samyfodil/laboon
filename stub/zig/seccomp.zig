// The stub's seccomp policies. Guest code shares the address space and can
// branch to any syscall instruction in the stub's text, so the text-range
// check only stops stray guest syscalls; what a thread's policy admits from
// the text is the boundary.
//
// Two policies, per thread (seccomp filters are per thread and stack). Every
// thread has lc_seccomp_filter, arch.allowed: what the process's hop thread
// runs for the supervisor (memory mappings, descriptors, forks) and what the
// stub needs before the guest starts. A guest thread also has
// lc_seccomp_guest_filter, arch.guest: its channel and futexes, its signals,
// thread pointer, clocks, a new thread and its exit; the stdio it serves
// in-process; nothing that maps memory, holds descriptors or forks, which
// only the supervisor asks for, through the hop thread. Its threads inherit
// it, and the guest runs only on such threads, so a guest that branches into
// the stub's text gets no more than that.
//
// Admitted calls that are not harmless with any argument are pinned to what
// the stub itself passes: clone to a fork or a thread (a guest thread: a
// thread), tgkill to the kick signal (a guest thread: to its own process,
// SELF_PID, which confineGuest fills in), recvmsg to the descriptor socket, close
// to descriptors the stub does not keep (it keeps 0-2 stdio, 4 the lifeline
// and 5 the socket; 3, the channel, is closed early and is where a received
// descriptor lands first), seccomp to adding a filter to the calling thread,
// and a guest thread's read and write to stdio. restart_syscall is the kernel
// resuming a timed wait that a signal interrupted without running a handler
// in this thread (another thread took it).
//
// The policies are constants, which the Go tests read from the built stub and
// run. load prefixes one with the text-range check, whose bounds are only
// known at run time, and fills in the guest's SELF_PID: the base policy, which
// a fork inherits, cannot name the process.

const stub = @import("stub.zig");
const arch = stub.arch;
const nr = stub.nr;

pub const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

const LD_W_ABS = 0x00 | 0x00 | 0x20;
const JEQ_K = 0x05 | 0x10 | 0x00;
const JGE_K = 0x05 | 0x30 | 0x00;
const RET_K = 0x06 | 0x00;
const RET_KILL_PROCESS = 0x80000000;
const RET_TRAP = 0x00030000;
const RET_ALLOW = 0x7fff0000;
const SET_MODE_FILTER = 1;
const PR_SET_NO_NEW_PRIVS = 38;

// seccomp_data offsets: nr, arch, instruction_pointer, args[6]. Both
// architectures are little-endian, so a u64's low word comes first.
const NR = 0;
const ARCH = 4;
const IP = 8;
fn argLo(i: u32) u32 {
    return 16 + 8 * i;
}
fn argHi(i: u32) u32 {
    return 16 + 8 * i + 4;
}

// Jump targets of the builder: the next instruction, or a labelled one.
const L = enum { next, clone, tgkill, recvmsg, close, seccomp, stdio, kill, allow };

const Ins = struct {
    code: u16,
    k: u32 = 0,
    jt: L = .next,
    jf: L = .next,
    label: ?L = null,
};

fn ld(off: u32) Ins {
    return .{ .code = LD_W_ABS, .k = off };
}
fn jeq(k: u32, jt: L, jf: L) Ins {
    return .{ .code = JEQ_K, .k = k, .jt = jt, .jf = jf };
}
fn ret(k: u32) Ins {
    return .{ .code = RET_K, .k = k };
}
fn at(l: L, i: Ins) Ins {
    var r = i;
    r.label = l;
    return r;
}

// argFrom admits a syscall whose argument i is one or at least lo (below
// 2^32), kills it otherwise.
fn argFrom(comptime l: L, comptime i: u32, comptime one: u32, comptime lo: u32) [5]Ins {
    return .{
        at(l, ld(argHi(i))),
        jeq(0, .next, .kill),
        ld(argLo(i)),
        jeq(one, .allow, .next),
        .{ .code = JGE_K, .k = lo, .jt = .allow, .jf = .kill },
    };
}

// argIs admits a syscall whose argument i equals one of vals, kills it
// otherwise.
fn argIs(comptime l: L, comptime i: u32, comptime vals: []const u32) [3 + vals.len]Ins {
    var r: [3 + vals.len]Ins = undefined;
    r[0] = at(l, ld(argHi(i)));
    r[1] = jeq(0, .next, .kill);
    r[2] = ld(argLo(i));
    for (vals, 0..) |v, j| r[3 + j] = jeq(v, .allow, if (j + 1 == vals.len) .kill else .next);
    return r;
}

// SELF_PID stands in the guest policy for the process's pid, which no pid
// equals (pid_max is at most 2^22).
pub const SELF_PID: u32 = 0xffff_fff0;

// tgkillSelf admits tgkill of the kick signal to the process SELF_PID names.
fn tgkillSelf() [8]Ins {
    return .{
        at(.tgkill, ld(argHi(0))), jeq(0, .next, .kill),                   ld(argLo(0)), jeq(SELF_PID, .next, .kill),
        ld(argHi(2)),              jeq(0, .next, .kill),                   ld(argLo(2)), jeq(stub.sig.KICK, .allow, .kill),
    };
}

// policy builds a filter admitting syscalls, pinning clone to clones; a
// guest's also pins tgkill to its own process and read/write/writev to stdio.
fn policy(comptime syscalls: []const stub.SYS, comptime clones: []const u32, comptime confined: bool) []const Ins {
    var p: [3 + syscalls.len]Ins = undefined;
    p[0] = ld(ARCH);
    p[1] = jeq(arch.AUDIT_ARCH, .next, .kill);
    p[2] = ld(NR);
    for (syscalls, 3..) |s, i| {
        const to: L = switch (s) {
            .clone => .clone,
            .tgkill => .tgkill,
            .recvmsg => .recvmsg,
            .close => .close,
            .seccomp => .seccomp,
            .read, .write, .writev => if (confined) .stdio else .allow,
            else => .allow,
        };
        p[i] = jeq(nr(s), to, .next);
    }
    const r = p ++ [_]Ins{ret(RET_KILL_PROCESS)} ++
        argIs(.clone, 0, clones) ++
        (if (confined) tgkillSelf() else argIs(.tgkill, 2, &.{stub.sig.KICK})) ++
        argIs(.recvmsg, 0, &.{stub.XFER}) ++
        argFrom(.close, 0, 3, stub.XFER + 1) ++
        // seccomp(SECCOMP_SET_MODE_FILTER, 0, prog): a filter for this thread
        [_]Ins{
            at(.seccomp, ld(argHi(0))), jeq(0, .next, .kill), ld(argLo(0)), jeq(SET_MODE_FILTER, .next, .kill),
            ld(argHi(1)),               jeq(0, .next, .kill), ld(argLo(1)), jeq(0, .allow, .kill),
            // stdio: fd 0, 1 or 2
            at(.stdio, ld(argHi(0))),   jeq(0, .next, .kill), ld(argLo(0)),
            .{ .code = JGE_K, .k = 3, .jt = .kill, .jf = .allow },
        } ++
        [_]Ins{ at(.kill, ret(RET_KILL_PROCESS)), at(.allow, ret(RET_ALLOW)) };
    return &r;
}

fn offset(comptime p: []const Ins, comptime from: usize, comptime to: L) u8 {
    if (to == .next) return 0;
    for (p, 0..) |ins, i| {
        if (ins.label == to) {
            if (i <= from or i - from - 1 > 255) @compileError("seccomp jump out of range");
            return i - from - 1;
        }
    }
    @compileError("seccomp label missing");
}

fn assemble(comptime p: []const Ins) [p.len]SockFilter {
    @setEvalBranchQuota(100000);
    var r: [p.len]SockFilter = undefined;
    for (p, 0..) |ins, i|
        r[i] = .{ .code = ins.code, .jt = offset(p, i, ins.jt), .jf = offset(p, i, ins.jf), .k = ins.k };
    return r;
}

const base = policy(&(arch.allowed ++ [_]stub.SYS{.seccomp}), &.{ stub.FORK_FLAGS, stub.THREAD_FLAGS }, false);
const guest = policy(&arch.guest, &.{stub.THREAD_FLAGS}, true);
export const lc_seccomp_filter = assemble(base);
export const lc_seccomp_guest_filter = assemble(guest);

extern var __ehdr_start: u8;
extern var etext: u8;

// install admits lc_seccomp_filter, and only from the stub's own text, for
// the process: its threads inherit it. A syscall from outside the stub's text
// is a guest syscall the rewriter did not convert to a trampoline/ud2 (it
// cannot be statically complete: it would drift through data-in-text, or it
// cannot follow a jump table). Rather than kill -- which would make a missed
// site fatal and force the rewriter to be provably complete -- it TRAPs: the
// SIGSYS handler services it through the supervisor like any trampolined
// call, so static rewriting is an optimization and this is the correctness
// backstop. The guest still cannot run a raw syscall; it is mediated either
// way. A bad architecture, or the stub's own out-of-policy call, still kills.
pub fn install() void {
    if (stub.sys(nr(.prctl), PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) != 0) stub.die(121);
    load(&lc_seccomp_filter, null);
}

// confineGuest adds lc_seccomp_guest_filter to the calling thread, which is
// about to run the guest (and its threads, which inherit it). It starts the
// process's hop thread first, which must keep only lc_seccomp_filter.
pub fn confineGuest() void {
    load(&lc_seccomp_guest_filter, @truncate(stub.sys(nr(.getpid), 0, 0, 0, 0, 0, 0)));
}

fn load(comptime filter: anytype, pid: ?u32) void {
    const lo: u64 = @intFromPtr(&__ehdr_start);
    const hi: u64 = @intFromPtr(&etext);
    if (lo >> 32 != hi >> 32) stub.die(120);
    var f: [6 + filter.len]SockFilter = undefined;
    f[0] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = IP + 4 };
    f[1] = .{ .code = JEQ_K, .jt = 0, .jf = 3, .k = @truncate(lo >> 32) };
    f[2] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = IP };
    f[3] = .{ .code = JGE_K, .jt = 0, .jf = 1, .k = @truncate(lo) };
    f[4] = .{ .code = JGE_K, .jt = 0, .jf = 1, .k = @truncate(hi) };
    f[5] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = RET_TRAP | stub.sig.SECCOMP_TRAP_TAG };
    f[6..].* = filter.*;
    if (pid) |p| {
        for (f[6..]) |*ins| {
            if (ins.code == JEQ_K and ins.k == SELF_PID) ins.k = p;
        }
    }
    const prog = SockFprog{ .len = f.len, .filter = &f };
    if (stub.sys(nr(.seccomp), SET_MODE_FILTER, 0, @intFromPtr(&prog), 0, 0, 0) != 0) stub.die(122);
}
