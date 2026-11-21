// chan.zig — the macOS stub side of the shared-memory channel protocol. It is
// the exact counterpart of struct chan in sandbox/chanabi.go and the exchange()
// in stub/csrc/stub.c, but the block/wake primitive is os_sync_wait_on_address
// / os_sync_wake_by_address (the public cross-process futex analog, macOS
// 14.4+) instead of a Linux futex. The slot page layout is byte-for-byte the
// same as chanPage so the Go supervisor reuses its serve/emulation code
// unchanged; only the handshake differs per OS.
//
// Proven pieces this builds on: m3-chan/ (os_sync handshake, Go<->stub) and
// seatbelt_probe.zig / mach_probe.zig (the backstop + exception-port setup).

const std = @import("std");

// Message kinds (stub -> supervisor). Must match chanabi.go.
pub const MSG_READY: u64 = 1;
pub const MSG_SYSCALL: u64 = 2;
pub const MSG_HOSTRET: u64 = 3;
pub const MSG_FORKED: u64 = 4;
pub const MSG_TRACE_LOCAL: u64 = 5; // an in-guest-served syscall, posted only for its ptrace stops
pub const MSG_SECCOMP: u64 = 7; // a call to run past the guest's seccomp filters before it is served

// Reply kinds (supervisor -> stub). Must match chanabi.go.
pub const REP_RESULT: u64 = 1;
pub const REP_HOST: u64 = 2;
pub const REP_START: u64 = 3;
pub const REP_CLONE: u64 = 4;
pub const REP_EXEC: u64 = 5;
pub const REP_FORK: u64 = 6;
pub const REP_PEEK: u64 = 7;
pub const REP_POKE: u64 = 8;
pub const REP_REWRITE: u64 = 10;
// End this thread (a CLONE_VM child process's): it posts NR_THREAD_GONE last.
pub const REP_THREAD_END: u64 = 11;
// Write the guest's mappings from address args[0] into the scratch as
// mem.MapEnt records; ret = count, args[1] = where to resume (0: done).
pub const REP_MAPS: u64 = 12;
// Collect fds sent over fdlink (see fdlink.sync); reply MSG_HOSTRET.
pub const REP_FDSYNC: u64 = 20;
// A pooled stub becomes a fork child: scratch holds the child slot's offset,
// the parent stub's pid and the child's gpid (sfork.zig); reply MSG_HOSTRET.
pub const REP_FORKCHILD: u64 = 21;
// Write the guest's mappings from address args[0] into the scratch as
// smaps.SmapEnt records, each with its counts; ret = count, args[1] = where to
// resume (0: done).
pub const REP_SMAPS: u64 = 22;

// Per-slot scratch buffer after the header, for the small ops that pass data.
pub const SCRATCH_OFF: usize = 128;

// state word: who owns the slot. os_sync waits/wakes on this u32.
pub const ST_REQ: u32 = 1;
pub const ST_REP: u32 = 2;
// ST_DEAD: the supervisor is done with the slot's thread (its process is
// ending). The thread ends without touching the slot again: the supervisor
// may hand it to another thread.
pub const ST_DEAD: u32 = 3;

pub const SLOT_SIZE: usize = 4096;
pub const MAX_SLOTS: usize = 256;

// SPIN mirrors the Linux stub: poll before falling back to os_sync sleep. The
// hot path never sleeps; see PERF.md (spin round-trip ~90-100 ns on the M4).
pub const SPIN: usize = 4000;

// Chan is one channel slot. Byte-for-byte identical to chanPage (chanabi.go);
// the asserts below pin the offsets. On arm64 `rip` holds the trapping pc,
// `guest_rip` the resume pc, and args[0..5] are x0..x5.
// LAYOUT_NORAND in Chan.flags: the exec places the program unrandomized
// (personality ADDR_NO_RANDOMIZE).
pub const LAYOUT_NORAND: u32 = 1;

pub const Chan = extern struct {
    self: u64, // slot address; the stub finds its own slot through this
    state: u32,
    flags: u32, // set by the supervisor before an exec: LAYOUT_NORAND
    kind: u64,
    nr: u64,
    args: [6]u64,
    rip: u64,
    ret: u64,
    stub_sleep: u32,
    sup_sleep: u32,
    guest_rip: u64,
    stdio: u64,
    pinfo: u64, // address of procinfo.info (slot 0 only)

    comptime {
        // Keep the layout locked to chanabi.go's chanPage.
        std.debug.assert(@offsetOf(Chan, "state") == 8);
        std.debug.assert(@offsetOf(Chan, "kind") == 16);
        std.debug.assert(@offsetOf(Chan, "nr") == 24);
        std.debug.assert(@offsetOf(Chan, "args") == 32);
        std.debug.assert(@offsetOf(Chan, "rip") == 80);
        std.debug.assert(@offsetOf(Chan, "ret") == 88);
        std.debug.assert(@offsetOf(Chan, "stub_sleep") == 96);
        std.debug.assert(@offsetOf(Chan, "sup_sleep") == 100);
        std.debug.assert(@offsetOf(Chan, "guest_rip") == 104); // OFF_GUEST_RIP
        std.debug.assert(@offsetOf(Chan, "stdio") == 112);
        std.debug.assert(@offsetOf(Chan, "pinfo") == 120);
        std.debug.assert(@sizeOf(Chan) == 128);
        std.debug.assert(@sizeOf(Chan) <= SCRATCH_OFF); // a new field must not overlap the scratch
    }
};

// os_sync_wait_on_address(addr, value, size, flags): sleep while *addr == value.
// os_sync_wake_by_address_any(addr, size, flags): wake one waiter.
// The SHARED flag (1) is required because the word lives in two processes.
//
// These are macOS 14.4+ symbols and are NOT in the libSystem stub Zig bundles
// for cross-compilation, so we resolve them at runtime via dlsym (the same way
// the Go supervisor reaches them through purego). init() must be called once,
// before the Seatbelt profile is applied, to populate the pointers.
const OS_SYNC_SHARED: u32 = 1;

const WaitFn = *const fn (addr: *anyopaque, value: u64, size: usize, flags: u32) callconv(.C) c_int;
const WakeFn = *const fn (addr: *anyopaque, size: usize, flags: u32) callconv(.C) c_int;

var os_sync_wait_on_address: WaitFn = undefined;
var os_sync_wake_by_address_any: WakeFn = undefined;

const RTLD_DEFAULT: ?*anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -2))));
extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;

// init resolves the os_sync symbols. Returns false if unavailable (OS too old),
// which the stub treats as fatal — the channel fast path needs them.
pub fn init() bool {
    const w = dlsym(RTLD_DEFAULT, "os_sync_wait_on_address") orelse return false;
    const k = dlsym(RTLD_DEFAULT, "os_sync_wake_by_address_any") orelse return false;
    os_sync_wait_on_address = @ptrCast(@alignCast(w));
    os_sync_wake_by_address_any = @ptrCast(@alignCast(k));
    return true;
}

inline fn load(p: *const u32) u32 {
    return @atomicLoad(u32, p, .seq_cst);
}
inline fn store(p: *u32, v: u32) void {
    @atomicStore(u32, p, v, .seq_cst);
}

// answered reports whether the supervisor has acted on the request: a reply,
// or ST_DEAD, on which the thread ends.
fn answered(ch: *Chan) bool {
    const st = load(&ch.state);
    if (st == ST_DEAD) @import("root").deadThread();
    return st == ST_REP;
}

// post sets state to ST_REQ unless the slot is dead, which it must not undo.
fn post(ch: *Chan) bool {
    var cur = load(&ch.state);
    while (cur != ST_DEAD) {
        cur = @cmpxchgWeak(u32, &ch.state, cur, ST_REQ, .seq_cst, .seq_cst) orelse return true;
    }
    return false;
}

// exchange posts a request (state = ST_REQ) and blocks until the supervisor
// replies (state = ST_REP), spinning first and only then sleeping on state via
// os_sync. Each side sets its own *_sleep flag before sleeping so the other
// issues a wake only when needed — the same handshake as the Linux stub's
// exchange(), with os_sync in place of the futex.
// postReq posts a request (state = ST_REQ) and returns without waiting for a
// reply. A dying thread uses it to signal the supervisor on its way out, when
// it will not be around to service the round trip exchange() expects.
pub fn postReq(ch: *Chan) void {
    if (!post(ch)) return;
    if (load(&ch.sup_sleep) != 0) {
        _ = os_sync_wake_by_address_any(&ch.state, 4, OS_SYNC_SHARED);
    }
}

pub fn exchange(ch: *Chan) void {
    if (!post(ch)) @import("root").deadThread();
    if (load(&ch.sup_sleep) != 0) {
        _ = os_sync_wake_by_address_any(&ch.state, 4, OS_SYNC_SHARED);
    }
    var i: usize = 0;
    while (i < SPIN) : (i += 1) {
        if (answered(ch)) return;
        std.atomic.spinLoopHint();
    }
    while (!answered(ch)) {
        store(&ch.stub_sleep, 1);
        if (!answered(ch)) {
            // Sleep while state is still ST_REQ (our posted value).
            _ = os_sync_wait_on_address(&ch.state, @as(u64, ST_REQ), 4, OS_SYNC_SHARED);
        }
        store(&ch.stub_sleep, 0);
    }
}
