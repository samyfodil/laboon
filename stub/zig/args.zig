// args: the inputs a syscall's arguments point at, which the stub copies into
// its slot's argument area as the call enters, as Linux copies a syscall's
// input structures from user memory when it starts, and the results the
// supervisor leaves in the slot's window, which the stub copies out as the
// call returns, as copy_to_user would. The supervisor then moves them through
// shared memory instead of with a process_vm_readv or writev each
// (sandbox/args_linux.go), and reads anything not copied from guest memory as
// before. The table is the Linux ABI's shape -- which arguments point at
// inputs and how long those are -- never how a call is served. A copy that
// faults stops there, as copy_from_user does, and records what it got; a
// result that faults makes the call's result EFAULT.

const std = @import("std");
const builtin = @import("builtin");
const stub = @import("stub.zig");
const arch = stub.arch;
const SYS = stub.SYS;

// The area's layout, shared with sandbox/args_linux.go: a header of input
// records {guest address, bytes copied, offset in the area} and result records
// {guest address, bytes, offset in the slot's window}, then the input bytes.
// APPLY in flags says the call returns through once, which copies results out;
// the supervisor leaves none for a call that does not.
pub const AREA_SIZE: u64 = 32 << 10;
pub const MAX_RECS = 24;
pub const MAX_OUTS = 16;
pub const DATA_OFF: u32 = 1024;
pub const APPLY: u32 = 1;

pub const Rec = extern struct { addr: u64, len: u32, off: u32 };
pub const Hdr = extern struct { n: u32, flags: u32, recs: [MAX_RECS]Rec, nout: u32, pad: u32, outs: [MAX_OUTS]Rec };

comptime {
    std.debug.assert(@sizeOf(Hdr) <= DATA_OFF);
}

// PAYLOAD_CAP bounds the data a call's buffers contribute (write, send,
// iovecs): past it a copy costs about what the process_vm_readv it saves.
const PAYLOAD_CAP: u64 = 16 << 10;
const PATH_MAX: u64 = 4096;
// struct epoll_event is packed on x86-64 only.
const EPOLL_EVENT: u32 = if (builtin.cpu.arch == .x86_64) 12 else 16;

// The argument areas, indexed like the slots (window offset 0x130_).
pub inline fn areasAddr() u64 {
    return stub.winBase + 0x13000000000;
}

// The slots' windows follow the slots and their signal areas, as in the memfd.
const WIN_BYTES: u64 = 256 << 10; // sandbox/chanwin.go winSize

fn windowOf(ch: *stub.Chan) [*]u8 {
    const slot = (@intFromPtr(ch) - stub.slotsAddr()) / stub.SLOT_SIZE;
    return @ptrFromInt(stub.slotsAddr() + stub.sig.AREA_LEN + slot * WIN_BYTES);
}

fn areaOf(ch: *stub.Chan) [*]u8 {
    const slot = (@intFromPtr(ch) - stub.slotsAddr()) / stub.SLOT_SIZE;
    return @ptrFromInt(areasAddr() + slot * AREA_SIZE);
}

const Kind = enum(u8) { none, fixed, len, str, arr, iov };

// In is one input: at argument arg, n bytes (fixed); argument len bytes, at
// most n (len); a NUL-terminated string (str); argument len elements of mul
// bytes (arr); an iovec array of argument len entries and the data they
// point at (iov).
const In = struct { kind: Kind = .none, arg: u3 = 0, n: u32 = 0, len: u3 = 0, mul: u32 = 1 };
const Spec = [6]In;

fn fixed(arg: u3, n: u32) In {
    return .{ .kind = .fixed, .arg = arg, .n = n };
}
fn len(arg: u3, l: u3, cap: u32) In {
    return .{ .kind = .len, .arg = arg, .len = l, .n = cap };
}
fn str(arg: u3) In {
    return .{ .kind = .str, .arg = arg };
}
fn arr(arg: u3, l: u3, mul: u32) In {
    return .{ .kind = .arr, .arg = arg, .len = l, .mul = mul };
}
fn iov(arg: u3, l: u3) In {
    return .{ .kind = .iov, .arg = arg, .len = l };
}

const Entry = struct { name: []const u8, ins: []const In };

const PAY: u32 = PAYLOAD_CAP;
const entries = [_]Entry{
    .{ .name = "write", .ins = &.{len(1, 2, PAY)} },
    .{ .name = "pwrite64", .ins = &.{len(1, 2, PAY)} },
    .{ .name = "writev", .ins = &.{iov(1, 2)} },
    .{ .name = "pwritev", .ins = &.{iov(1, 2)} },
    .{ .name = "pwritev2", .ins = &.{iov(1, 2)} },
    .{ .name = "readv", .ins = &.{arr(1, 2, 16)} },
    .{ .name = "preadv", .ins = &.{arr(1, 2, 16)} },
    .{ .name = "preadv2", .ins = &.{arr(1, 2, 16)} },
    .{ .name = "sendto", .ins = &.{ len(1, 2, PAY), len(4, 5, 128) } },
    .{ .name = "sendmsg", .ins = &.{fixed(1, 56)} },
    .{ .name = "recvmsg", .ins = &.{fixed(1, 56)} },
    .{ .name = "recvfrom", .ins = &.{fixed(5, 4)} },
    .{ .name = "connect", .ins = &.{len(1, 2, 128)} },
    .{ .name = "bind", .ins = &.{len(1, 2, 128)} },
    .{ .name = "accept", .ins = &.{fixed(2, 4)} },
    .{ .name = "accept4", .ins = &.{fixed(2, 4)} },
    .{ .name = "getsockname", .ins = &.{fixed(2, 4)} },
    .{ .name = "getpeername", .ins = &.{fixed(2, 4)} },
    .{ .name = "setsockopt", .ins = &.{len(3, 4, 256)} },
    .{ .name = "getsockopt", .ins = &.{fixed(4, 4)} },
    .{ .name = "epoll_ctl", .ins = &.{fixed(3, EPOLL_EVENT)} },
    .{ .name = "epoll_pwait", .ins = &.{fixed(4, 8)} },
    .{ .name = "epoll_pwait2", .ins = &.{ fixed(4, 16), fixed(5, 8) } },
    .{ .name = "poll", .ins = &.{arr(0, 1, 8)} },
    .{ .name = "ppoll", .ins = &.{ arr(0, 1, 8), fixed(2, 16), fixed(3, 8) } },
    .{ .name = "select", .ins = &.{ fixed(1, 128), fixed(2, 128), fixed(3, 128), fixed(4, 16) } },
    .{ .name = "pselect6", .ins = &.{ fixed(1, 128), fixed(2, 128), fixed(3, 128), fixed(4, 16), fixed(5, 16) } },
    .{ .name = "nanosleep", .ins = &.{fixed(0, 16)} },
    .{ .name = "clock_nanosleep", .ins = &.{fixed(2, 16)} },
    .{ .name = "rt_sigprocmask", .ins = &.{fixed(1, 8)} },
    .{ .name = "rt_sigaction", .ins = &.{fixed(1, 32)} },
    .{ .name = "rt_sigsuspend", .ins = &.{fixed(0, 8)} },
    .{ .name = "rt_sigtimedwait", .ins = &.{ fixed(0, 8), fixed(2, 16) } },
    .{ .name = "timerfd_settime", .ins = &.{fixed(2, 32)} },
    .{ .name = "prlimit64", .ins = &.{fixed(2, 16)} },
    .{ .name = "open", .ins = &.{str(0)} },
    .{ .name = "creat", .ins = &.{str(0)} },
    .{ .name = "openat", .ins = &.{str(1)} },
    .{ .name = "stat", .ins = &.{str(0)} },
    .{ .name = "lstat", .ins = &.{str(0)} },
    .{ .name = "fstatat", .ins = &.{str(1)} },
    .{ .name = "fstatat64", .ins = &.{str(1)} },
    .{ .name = "statx", .ins = &.{str(1)} },
    .{ .name = "access", .ins = &.{str(0)} },
    .{ .name = "faccessat", .ins = &.{str(1)} },
    .{ .name = "faccessat2", .ins = &.{str(1)} },
    .{ .name = "readlink", .ins = &.{str(0)} },
    .{ .name = "readlinkat", .ins = &.{str(1)} },
    .{ .name = "unlink", .ins = &.{str(0)} },
    .{ .name = "unlinkat", .ins = &.{str(1)} },
    .{ .name = "mkdir", .ins = &.{str(0)} },
    .{ .name = "mkdirat", .ins = &.{str(1)} },
    .{ .name = "rename", .ins = &.{ str(0), str(1) } },
    .{ .name = "renameat", .ins = &.{ str(1), str(3) } },
    .{ .name = "renameat2", .ins = &.{ str(1), str(3) } },
    .{ .name = "chdir", .ins = &.{str(0)} },
    .{ .name = "execve", .ins = &.{str(0)} },
    .{ .name = "execveat", .ins = &.{str(1)} },
    .{ .name = "fchmodat", .ins = &.{str(1)} },
    .{ .name = "fchownat", .ins = &.{str(1)} },
    .{ .name = "utimensat", .ins = &.{ str(1), fixed(2, 32) } },
    .{ .name = "truncate", .ins = &.{str(0)} },
    .{ .name = "statfs", .ins = &.{str(0)} },
};

const NR_MAX = 512;

const table = blk: {
    @setEvalBranchQuota(200000);
    var t = [_]Spec{[_]In{.{}} ** 6} ** NR_MAX;
    for (entries) |e| {
        if (@hasField(SYS, e.name)) {
            const n = @intFromEnum(@field(SYS, e.name));
            if (n >= NR_MAX) @compileError("syscall number past the table");
            for (e.ins, 0..) |in, i| t[n][i] = in;
        }
    }
    break :blk t;
};

// Fill appends records to the area's header as inputs are copied.
const Fill = struct {
    area: [*]u8,
    hdr: *Hdr,
    off: u32 = DATA_OFF,
    payload: u64 = 0,

    // take copies up to want bytes at guest addr as one record and returns
    // how many it got.
    fn take(f: *Fill, addr: u64, want: u64, string: bool) u64 {
        if (f.hdr.n == MAX_RECS or addr == 0 or want == 0) return 0;
        const n = @min(want, AREA_SIZE - f.off);
        if (n == 0) return 0;
        const got = if (string) arch.strIn(f.area + f.off, addr, n) else arch.copyUser(f.area + f.off, addr, n);
        if (got == 0) return 0;
        f.hdr.recs[f.hdr.n] = .{ .addr = addr, .len = @intCast(got), .off = f.off };
        f.hdr.n += 1;
        f.off += @intCast((got + 7) & ~@as(u64, 7));
        return got;
    }
};

// prefetch copies syscall n's inputs at args a into ch's argument area. A
// traced thread copies none: its tracer may change them at the entry stop.
pub fn prefetch(ch: *stub.Chan, n: u64, a: [6]u64) void {
    const area = areaOf(ch);
    var f = Fill{ .area = area, .hdr = @ptrCast(@alignCast(area)) };
    f.hdr.n = 0;
    f.hdr.nout = 0;
    f.hdr.flags = 0;
    if (ch.stdio & stub.STDIO_TRACED != 0) return;
    f.hdr.flags = APPLY;
    if (n >= NR_MAX) return;
    for (table[n]) |in| {
        const addr = a[in.arg];
        switch (in.kind) {
            .none => break,
            .fixed => _ = f.take(addr, in.n, false),
            .len => {
                // Whole or not at all: the supervisor reads a buffer in one
                // piece, and a part it cannot use.
                const want = a[in.len];
                if (want <= in.n and (in.n != PAY or f.payload + want <= PAYLOAD_CAP)) f.payload += f.take(addr, want, false);
            },
            .str => _ = f.take(addr, PATH_MAX, true),
            .arr => _ = f.take(addr, @min(a[in.len], 1024) * in.mul, false),
            .iov => {
                const cnt = @min(a[in.len], 1024);
                const at = f.off;
                const got = f.take(addr, cnt * 16, false);
                var i: u64 = 0;
                while (i < got / 16) : (i += 1) {
                    const v: [*]align(1) const u64 = @ptrCast(area + at + 16 * i);
                    const want = v[1];
                    if (f.payload + want > PAYLOAD_CAP) break;
                    f.payload += f.take(v[0], want, false);
                }
            },
        }
    }
}

// apply copies the results the supervisor left for the call that just
// returned r to guest memory and returns the call's result: r, or EFAULT when
// a result's guest range faults.
pub fn apply(ch: *stub.Chan, r: u64) u64 {
    const h: *Hdr = @ptrCast(@alignCast(areaOf(ch)));
    defer {
        h.nout = 0;
        h.flags = 0;
    }
    if (h.flags & APPLY == 0) return r;
    const w = windowOf(ch);
    for (h.outs[0..@min(h.nout, MAX_OUTS)]) |o| {
        if (o.addr == 0 or @as(u64, o.off) + o.len > WIN_BYTES) return EFAULT;
        if (arch.copyUser(@ptrFromInt(o.addr), @intFromPtr(w + o.off), o.len) != o.len) return EFAULT;
    }
    return r;
}

const EFAULT: u64 = @bitCast(@as(i64, -14));
