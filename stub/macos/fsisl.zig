// x86-64 %fs islands. Rosetta cannot set the %fs base, so an %fs-relative
// access faults and fsmem.zig emulates it against the guest's base: about
// 15 µs a time, which a TLS-heavy program pays millions of times. The first
// fault at a site long enough for a jmp has the supervisor build an island
// (rewrite.FSIsland) that reads the guest thread pointer from its TSD slot
// (%gs:g_tp_key*8, Darwin's pthread_getspecific) and does the access there;
// the site becomes a jmp to it. Only file code is patched: the program's
// bytes do not change under it, and memory the guest writes code into stays
// wx.zig's.
const std = @import("std");
const tstate = @import("tstate.zig");
const mem = @import("mem.zig");
const wx = @import("wx.zig");

extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) ?*anyopaque;
extern "c" fn mprotect(addr: *anyopaque, len: usize, prot: c_int) c_int;
extern "c" fn munmap(addr: *anyopaque, len: usize) c_int;
extern "c" fn mach_task_self() u32;
extern "c" fn mach_vm_remap(task: u32, dst: *u64, size: u64, mask: u64, flags: c_int, src_task: u32, src: u64, copy: c_int, cur: *c_int, max: *c_int, inherit: u32) c_int;
extern "c" fn mach_vm_deallocate(task: u32, addr: u64, size: u64) c_int;

const PAGE: u64 = tstate.page;
const ARENA: u64 = 64 << 10;
const SLOT: u64 = 128; // an island's blob: rewrite's 16-byte header and the island
const REACH: u64 = (1 << 31) - 2 * ARENA;
const LC_FS_ISLAND: u64 = 0x4c430038;

// Each arena is executable at base and written through its alias wr, so no
// thread running an island ever finds its page unexecutable.
const Arena = struct { base: u64, wr: u64, used: u64 };

var arenas: [32]Arena = undefined;
var narena: usize = 0;
var busy = std.atomic.Value(bool).init(false);

// Sites that cannot have an island (too short, or no arena in reach), so they
// are not asked about again.
var refused: [1024]u64 = [_]u64{0} ** 1024;

// The sites patched, with the instructions they held. A thread can still run
// a site's old translation after the patch (Rosetta retranslates lazily): its
// %fs access faults with the jmp in place and is emulated from these bytes, and
// the int3 that held the site's first byte while it was written is run again.
const Site = struct { pc: u64 = 0, len: u8 = 0, code: [15]u8 = undefined };
var sites: [8192]Site = [_]Site{.{}} ** 8192;
var nsites: usize = 0;
const BUSY: u64 = 1; // an entry being written, which a lookup passes over

fn refusedAt(pc: u64) *u64 {
    return &refused[(pc *% 0x9e3779b97f4a7c15) >> 54];
}

// patch gives the %fs-relative instruction at pc, which just faulted, an
// island, when it is in file code and can have one: true once the site jumps
// to it, run again from pc. One emulated already need not wait for another
// thread's patch; one fsmem.zig cannot emulate must.
pub fn patch(pc: u64, tp_key: u64, wait: bool) bool {
    if (@atomicLoad(u64, refusedAt(pc), .monotonic) == pc) return false;
    while (busy.swap(true, .acquire)) {
        if (!wait) return false;
        std.atomic.spinLoopHint();
    }
    defer busy.store(false, .release);
    if (jumpsOut(pc)) return true;
    if (nsites >= sites.len / 2) return false;
    const prot = mem.protAt(pc) orelse return false;
    if (prot & 4 == 0 or prot & 2 != 0 or wx.protAt(pc) != null or mem.isShared(pc)) return false;
    const at = slot(pc) orelse return refuse(pc);
    const r = @import("sig.zig").codeCall(LC_FS_ISLAND, .{ pc, at.base + at.used, tp_key * 8, 0, 0, 0 });
    const n: usize = @intCast(r & 0xff);
    const m: usize = @intCast((r >> 8) & 0xffff);
    if (n == 0 or m == 0 or m > SLOT) return refuse(pc);
    const sc = @import("sig.zig").scratch();
    @memcpy(@as([*]u8, @ptrFromInt(at.wr + at.used))[0..m], sc[16..][0..m]);
    at.used += SLOT;
    var code: [16]u8 = undefined;
    @memcpy(code[0..n], sc[0..n]);
    const e = slotOf(pc);
    if (e.pc != pc) nsites += 1;
    @atomicStore(u64, &e.pc, BUSY, .release);
    e.len = @intCast(n);
    @memcpy(e.code[0..n], @as([*]const u8, @ptrFromInt(pc))[0..n]);
    @atomicStore(u64, &e.pc, pc, .release);
    return write(pc, code[0..n]);
}

// slotOf is the entry of pc in sites, or the free one it would take.
fn slotOf(pc: u64) *Site {
    var i: usize = @intCast((pc *% 0x9e3779b97f4a7c15) >> 51);
    while (true) : (i = (i + 1) % sites.len) {
        const v = @atomicLoad(u64, &sites[i].pc, .acquire);
        if (v == pc or v == 0) return &sites[i];
    }
}

// original is the instruction the site at pc held, while pc is one patched.
pub fn original(pc: u64) ?[]const u8 {
    const e = slotOf(pc);
    if (@atomicLoad(u64, &e.pc, .acquire) != pc) return null;
    const b: *const u8 = @ptrFromInt(pc);
    if (b.* != 0xcc and !jumpsOut(pc)) return null;
    return e.code[0..e.len];
}

fn refuse(pc: u64) bool {
    @atomicStore(u64, refusedAt(pc), pc, .monotonic);
    return false;
}

// jumpsOut reports whether the site at pc is a jmp into an arena already.
fn jumpsOut(pc: u64) bool {
    const d: [*]const u8 = @ptrFromInt(pc);
    if (d[0] != 0xe9) return false;
    const to = pc +% 5 +% @as(u64, @bitCast(@as(i64, std.mem.readInt(i32, d[1..5], .little))));
    for (arenas[0..narena]) |a| {
        if (to >= a.base and to < a.base + ARENA) return true;
    }
    return false;
}

// slot is an arena in reach of pc with room for one more island.
fn slot(pc: u64) ?*Arena {
    for (arenas[0..narena]) |*a| {
        if (a.used + SLOT <= ARENA and inReach(pc, a.base)) return a;
    }
    if (narena == arenas.len) return null;
    const c = mem.freeNear(pc, ARENA, REACH) orelse return null;
    const p = mmap(@ptrFromInt(c), ARENA, 3, 0x1002, -1, 0) orelse return null; // MAP_PRIVATE|MAP_ANON
    const b = @intFromPtr(p);
    if (b == std.math.maxInt(usize)) return null;
    if (!inReach(pc, b)) {
        _ = munmap(p, ARENA);
        return null;
    }
    const task = mach_task_self();
    var wr: u64 = 0;
    var cur: c_int = 0;
    var max: c_int = 0;
    if (mach_vm_remap(task, &wr, ARENA, 0, 1, task, b, 0, &cur, &max, 2) != 0) { // ANYWHERE, INHERIT_NONE
        _ = munmap(p, ARENA);
        return null;
    }
    if (mprotect(p, ARENA, 5) != 0) {
        _ = mach_vm_deallocate(task, wr, ARENA);
        _ = munmap(p, ARENA);
        return null;
    }
    mem.noteImage(b, b + ARENA);
    arenas[narena] = .{ .base = b, .wr = wr, .used = 0 };
    narena += 1;
    return &arenas[narena - 1];
}

fn inReach(pc: u64, a: u64) bool {
    const d = if (a > pc) a + ARENA - pc else pc - a;
    return d <= REACH;
}

// write puts code over the instruction it replaces at pc, its first byte an
// int3 until the rest is in place.
fn write(pc: u64, code: []const u8) bool {
    const lo = pc & ~(PAGE - 1);
    const hi = (pc + code.len + PAGE - 1) & ~(PAGE - 1);
    const prot: c_int = @intCast(mem.protAt(pc) orelse return false);
    if (mprotect(@ptrFromInt(lo), hi - lo, prot | 2) != 0) return false;
    const d: [*]u8 = @ptrFromInt(pc);
    @atomicStore(u8, &d[0], 0xcc, .release);
    @memcpy(d[1..code.len], code[1..]);
    @atomicStore(u8, &d[0], code[0], .release);
    _ = mprotect(@ptrFromInt(lo), hi - lo, prot);
    return true;
}

// retry reports whether the int3 a thread trapped on, ending at pc, is a
// site's first byte held while it was patched: the thread runs it again.
pub fn retry(pc: u64) bool {
    return original(pc -% 1) != null;
}

// reset drops the arenas, at an exec.
pub fn reset() void {
    const task = mach_task_self();
    for (arenas[0..narena]) |a| {
        _ = mach_vm_deallocate(task, a.wr, ARENA);
        _ = munmap(@ptrFromInt(a.base), ARENA);
    }
    narena = 0;
    @memset(&refused, 0);
    @memset(&sites, .{});
    nsites = 0;
}
