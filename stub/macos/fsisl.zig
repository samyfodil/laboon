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

// Next is where a thread whose %fs access at a site faulted goes on: the
// site's island, the access again (the lock was held: no thread waits for it
// in a handler, where a kick cannot reach it), or wherever it would without
// an island.
pub const Next = union(enum) { none, again, island: u64 };

// patch gives the %fs-relative instruction at pc, which just faulted, an
// island, when it is in file code and can have one. The faulting thread goes
// on there rather than at pc, where a stale translation of the old bytes
// would fault again.
pub fn patch(pc: u64, tp_key: u64) Next {
    if (@atomicLoad(u64, refusedAt(pc), .monotonic) == pc) return .none;
    if (busy.swap(true, .acquire)) return .again;
    defer busy.store(false, .release);
    if (islandOf(pc)) |to| return .{ .island = to };
    if (nsites >= sites.len / 2) return .none;
    const prot = mem.protAt(pc) orelse return .none;
    if (prot & 4 == 0 or prot & 2 != 0 or wx.protAt(pc) != null or mem.isShared(pc)) return .none;
    const at = slot(pc) orelse return refuse(pc);
    const isl = at.base + at.used;
    const r = @import("sig.zig").codeCall(LC_FS_ISLAND, .{ pc, isl, tp_key * 8, 0, 0, 0 });
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
    return if (write(pc, code[0..n])) .{ .island = isl } else .none;
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
fn original(pc: u64) ?[]const u8 {
    const e = slotOf(pc);
    if (@atomicLoad(u64, &e.pc, .acquire) != pc) return null;
    const b: *const u8 = @ptrFromInt(pc);
    if (b.* != 0xcc and islandOf(pc) == null) return null;
    return e.code[0..e.len];
}

fn refuse(pc: u64) Next {
    @atomicStore(u64, refusedAt(pc), pc, .monotonic);
    return .none;
}

// islandOf is the island the site at pc jumps to, once it is patched.
pub fn islandOf(pc: u64) ?u64 {
    const d: [*]const u8 = @ptrFromInt(pc);
    if (d[0] != 0xe9) return null;
    const to = pc +% 5 +% @as(u64, @bitCast(@as(i64, std.mem.readInt(i32, d[1..5], .little))));
    for (arenas[0..@atomicLoad(usize, &narena, .acquire)]) |a| {
        if (to >= a.base and to < a.base + ARENA) return to;
    }
    return null;
}

// insn is the instruction at pc for fsmem.zig to emulate: a patched site's
// old one, or the bytes there, read tail first so a patch being written
// cannot tear them (write() changes the first byte first, under TSO before
// the tail, which is all written once the first byte is the jmp's).
pub fn insn(pc: u64, buf: *[16]u8) []const u8 {
    const d: [*]const u8 = @ptrFromInt(pc);
    var n: usize = 15;
    const end = (pc | (PAGE - 1)) + 1;
    if (end - pc < n and mem.protAt(end) == null) n = end - pc;
    var i = n;
    while (i > 1) {
        i -= 1;
        buf[i] = @atomicLoad(u8, &d[i], .acquire);
    }
    buf[0] = @atomicLoad(u8, &d[0], .acquire);
    const e = slotOf(pc);
    if (@atomicLoad(u64, &e.pc, .acquire) == pc and (buf[0] == 0xcc or islandOf(pc) != null)) return e.code[0..e.len];
    return buf[0..n];
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
    @atomicStore(usize, &narena, narena + 1, .release);
    return &arenas[narena - 1];
}

fn inReach(pc: u64, a: u64) bool {
    const d = if (a > pc) a + ARENA - pc else pc - a;
    return d <= REACH;
}

// write puts code over the instruction it replaces at pc, its first byte an
// int3 until the rest is in place. It writes through a writable alias of the
// page(s), as wx patches traps: the guest's mapping keeps its protection, so
// the write cannot fault inside the handler or undo a guest mprotect racing it.
fn write(pc: u64, code: []const u8) bool {
    if (mem.protAt(pc) == null) return false;
    const lo = pc & ~(PAGE - 1);
    const task = mach_task_self();
    const a = wx.alias(lo) orelse return false;
    defer _ = mach_vm_deallocate(task, a, PAGE);
    var b: u64 = 0;
    if (pc + code.len > lo + PAGE) b = wx.alias(lo + PAGE) orelse return false;
    defer if (b != 0) {
        _ = mach_vm_deallocate(task, b, PAGE);
    };
    const at = struct {
        fn f(x: u64, y: u64, base: u64, i: u64) *u8 {
            const off = i - base;
            return @ptrFromInt(if (off < PAGE) x + off else y + off - PAGE);
        }
    }.f;
    @atomicStore(u8, at(a, b, lo, pc), 0xcc, .release);
    for (code[1..], 1..) |c, i| at(a, b, lo, pc + i).* = c;
    @atomicStore(u8, at(a, b, lo, pc), code[0], .release);
    return true;
}

// resumeAt is where a thread that trapped on an int3 ending at pc goes on, when
// the int3 is a site's first byte held while it was patched, or a stale
// translation of it: the site's island once it has one, else the site again.
pub fn resumeAt(pc: u64) ?u64 {
    const site = pc -% 1;
    if (original(site) == null) return null;
    return islandOf(site) orelse site;
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

// A fork child is a fresh stub running the parent's code, patched sites and
// all: it takes the tables over. They are read after the guest's memory is
// described and without the lock (patch holds it across mem.zig's, which the
// fork holds): an entry is published before its site is written, so every
// site patched in the child's memory is in them. The child cannot write the
// parent's arenas (their alias is not inherited), so it takes them as full,
// and puts back the old bytes of a site its memory caught being written.
const ForkHead = extern struct { narena: u64, nsite: u64 };

pub fn forkSave(buf: *std.ArrayList(u8)) bool {
    const na = @atomicLoad(usize, &narena, .acquire);
    var list = std.ArrayList(Site).init(std.heap.page_allocator);
    defer list.deinit();
    for (&sites) |*e| {
        const pc = @atomicLoad(u64, &e.pc, .acquire);
        if (pc <= BUSY) continue;
        var c = e.*;
        c.pc = pc;
        list.append(c) catch return false;
    }
    const h = ForkHead{ .narena = na, .nsite = list.items.len };
    buf.appendSlice(std.mem.asBytes(&h)) catch return false;
    for (arenas[0..na]) |a| buf.appendSlice(std.mem.asBytes(&a.base)) catch return false;
    buf.appendSlice(std.mem.sliceAsBytes(list.items)) catch return false;
    for (&refused) |*r| {
        const v = @atomicLoad(u64, r, .monotonic);
        buf.appendSlice(std.mem.asBytes(&v)) catch return false;
    }
    return true;
}

pub fn forkLoad(b: *[]const u8) bool {
    if (b.len < @sizeOf(ForkHead)) return false;
    const h = std.mem.bytesToValue(ForkHead, b.*[0..@sizeOf(ForkHead)]);
    if (h.narena > arenas.len or h.nsite > sites.len / 2) return false;
    const na = h.narena * 8;
    const ns = h.nsite * @sizeOf(Site);
    if (b.len < @sizeOf(ForkHead) + na + ns + @sizeOf(@TypeOf(refused))) return false;
    var rest = b.*[@sizeOf(ForkHead)..];
    for (std.mem.bytesAsSlice(u64, @as([]align(1) const u8, rest[0..na])), 0..) |base, i| {
        arenas[i] = .{ .base = base, .wr = 0, .used = ARENA };
    }
    narena = @intCast(h.narena);
    rest = rest[na..];
    for (std.mem.bytesAsSlice(Site, @as([]align(1) const u8, rest[0..ns]))) |e| {
        slotOf(e.pc).* = e;
        if (mem.protAt(e.pc) == null) continue;
        if (@as(*const u8, @ptrFromInt(e.pc)).* == 0xcc) _ = write(e.pc, e.code[0..e.len]);
    }
    nsites = @intCast(h.nsite);
    rest = rest[ns..];
    @memcpy(std.mem.asBytes(&refused), rest[0..@sizeOf(@TypeOf(refused))]);
    b.* = rest[@sizeOf(@TypeOf(refused))..];
    return true;
}
