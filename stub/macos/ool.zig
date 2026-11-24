// ool.zig — guest instructions run out of line: copied into a page of the
// thread's own and run there, a trap after them bringing the guest back to
// where they lead. A store into the page its own code runs from needs it
// (wx.zig, jit.zig): no protection lets the page both run the store and take
// it, but the store runs as well from anywhere else.
//
// The copy keeps the instructions' layout, so a branch among them keeps its
// offset and a pc in the copy names the guest's instruction at the same
// offset (guestPc); a branch leaving them goes to a trap of its own, which
// resumes the guest at its target. An instruction that reads pc otherwise
// (adr, adrp, a literal load), a call, a return or an exception cannot run
// out of line.

const std = @import("std");
const chan = @import("chan.zig");
const tstate = @import("tstate.zig");

extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) ?*anyopaque;
extern "c" fn mprotect(addr: *anyopaque, len: usize, prot: c_int) c_int;
extern "c" fn munmap(addr: *anyopaque, len: usize) c_int;
extern "c" fn sys_icache_invalidate(start: *anyopaque, len: usize) void;

pub const MAX = 32; // instructions at a time
const PAGE: usize = tstate.page;
const X86 = !tstate.arm64;
const EXIT: u32 = 0xd4200000 | (0x5e << 5); // brk #0x5e

// A thread's page and what it last ran: n instructions from guest address
// start, the exits after them (exits[0] where the last leads, the rest the
// targets of the branches leaving them).
const Slot = struct {
    page: usize = 0,
    start: u64 = 0,
    n: u32 = 0,
    nexit: u32 = 0,
    exits: [MAX + 1]u64 = undefined,
    jit: bool = false, // run in a MAP_JIT region's write mode (jit.zig)
    holds: Holds = .{ 0, 0 }, // the holds on memory while they run (wx.zig), 0 for none
    tried: [2]u64 = .{ 0, 0 }, // the store (pc, page) last run again in place (lost)
};

pub const Holds = [2]u64;

// Exit is how what a slot ran ended: in a MAP_JIT region's write mode, and
// the holds it kept, to let go.
pub const Exit = struct { jit: bool, holds: Holds };
threadlocal var mine: Slot = .{};

// drop lets go of the thread's page as it ends.
pub fn drop() void {
    if (mine.page != 0) _ = munmap(@ptrFromInt(mine.page), PAGE);
    mine = .{};
}

// run makes the thread resume at a copy of words, the guest's
// instructions at start as they ran; false if one cannot run out of line.
// jit: the thread is in a MAP_JIT region's write mode while they run (exit
// reports it, for jit.zig to switch back).
pub fn run(mc: *std.c.mcontext_t, words: []const u32, start: u64, jit: bool, hold: u64) bool {
    const sl = &mine;
    if (words.len == 0 or words.len > MAX) return false;
    if (sl.page == 0) {
        const p = mmap(null, PAGE, 3, 0x1002, -1, 0) orelse return false; // MAP_PRIVATE|MAP_ANON
        if (@intFromPtr(p) == std.math.maxInt(usize)) return false;
        sl.page = @intFromPtr(p);
    }
    if (mprotect(@ptrFromInt(sl.page), PAGE, 3) != 0) return false;
    const out: [*]u32 = @ptrFromInt(sl.page);
    const n: u32 = @intCast(words.len);
    var nexit: u32 = 1;
    for (words, 0..) |w, i| {
        const at = start + 4 * i;
        const b = branch(w) orelse {
            if (!movable(w)) return false;
            out[i] = w;
            continue;
        };
        const t = at +% @as(u64, @bitCast(b.off));
        if (t >= start and t < start + 4 * n) {
            out[i] = w; // among the copies: the same offset
            continue;
        }
        const e = n + nexit;
        sl.exits[nexit] = t;
        out[e] = EXIT;
        nexit += 1;
        out[i] = b.retarget(w, (@as(i64, e) - @as(i64, @intCast(i))) * 4);
    }
    out[n] = EXIT;
    sl.exits[0] = start + 4 * n;
    sl.start = start;
    sl.n = n;
    sl.nexit = nexit;
    sl.jit = jit;
    sl.holds = .{ hold, 0 };
    if (mprotect(@ptrFromInt(sl.page), PAGE, 5) != 0) return false;
    sys_icache_invalidate(@ptrFromInt(sl.page), 4 * (n + nexit));
    mc.ss.pc = sl.page;
    return true;
}

// runX64 makes the thread resume at a copy of code, the guest's
// x86-64 instruction at start, its RIP-relative displacement at at (0: none),
// an int3 after it; false if it cannot run out of line. A copy with a
// displacement runs from a page within its reach.
pub fn runX64(mc: *std.c.mcontext_t, code: []const u8, at: u32, start: u64, hold: u64) bool {
    const sl = &mine;
    if (code.len == 0 or code.len > 15 or (at != 0 and at + 4 > code.len)) return false;
    if (sl.page != 0 and at != 0 and !near(sl.page, start)) {
        _ = munmap(@ptrFromInt(sl.page), PAGE);
        sl.page = 0;
    }
    if (sl.page == 0) {
        const hint: ?*anyopaque = if (at != 0) @ptrFromInt((start -| (1 << 30)) & ~@as(u64, PAGE - 1)) else null;
        const p = mmap(hint, PAGE, 3, 0x1002, -1, 0) orelse return false;
        if (@intFromPtr(p) == std.math.maxInt(usize)) return false;
        sl.page = @intFromPtr(p);
    }
    var out: [16]u8 = undefined;
    @memcpy(out[0..code.len], code);
    if (at != 0) {
        // The operand's address stays the guest's: the displacement moves by
        // as much as the instruction does.
        if (!near(sl.page, start)) return false;
        const d: i64 = std.mem.readInt(i32, code[at..][0..4], .little);
        const nd = d + @as(i64, @bitCast(start -% sl.page));
        if (nd < std.math.minInt(i32) or nd > std.math.maxInt(i32)) return false;
        std.mem.writeInt(i32, out[at..][0..4], @intCast(nd), .little);
    }
    out[code.len] = 0xcc;
    const dst: [*]u8 = @ptrFromInt(sl.page);
    if (!std.mem.eql(u8, dst[0 .. code.len + 1], out[0 .. code.len + 1])) {
        if (mprotect(@ptrFromInt(sl.page), PAGE, 3) != 0) return false;
        @memcpy(dst[0 .. code.len + 1], out[0 .. code.len + 1]);
        if (mprotect(@ptrFromInt(sl.page), PAGE, 5) != 0) return false;
    }
    sl.exits[0] = start + code.len;
    sl.start = start;
    sl.n = @intCast(code.len);
    sl.nexit = 1;
    sl.jit = false;
    sl.holds = .{ hold, 0 };
    tstate.setPc(mc, sl.page);
    return true;
}

fn near(page: u64, pc: u64) bool {
    const far = if (page > pc) page - pc else pc - page;
    return far <= (1 << 31) - 2 * PAGE;
}

// exit takes the trap ending what the thread ran, at mc's pc: the guest resumes
// where it leads. null if pc is no exit of it. An x86-64 int3 reports the pc
// past it.
pub fn exit(mc: *std.c.mcontext_t) ?Exit {
    const sl = &mine;
    const pc = tstate.pc(mc);
    if (sl.page == 0 or pc < sl.page or sl.nexit == 0) return null;
    if (X86) {
        if (pc != sl.page + sl.n + 1) return null;
        tstate.setPc(mc, sl.exits[0]);
        sl.n = 0;
        sl.nexit = 0;
        defer sl.holds = .{ 0, 0 };
        return .{ .jit = false, .holds = sl.holds };
    }
    const i = (pc - sl.page) / 4;
    if (i < sl.n or i >= sl.n + sl.nexit) return null;
    mc.ss.pc = sl.exits[i - sl.n];
    sl.n = 0;
    sl.nexit = 0;
    defer sl.holds = .{ 0, 0 };
    return .{ .jit = sl.jit, .holds = sl.holds };
}

// release takes the holds the thread keeps from it, when pc is in what it runs:
// a signal delivered there leaves it for the guest's own pc (guestPc).
pub fn release(pc: u64) Holds {
    const sl = &mine;
    if (!inSlot(pc)) return .{ 0, 0 };
    defer sl.holds = .{ 0, 0 };
    return sl.holds;
}

// lost reports whether the thread faults again on the store at pc
// into page that it ran again in place last (tried): a thread ran the page
// again before the store landed. Each fault asks once.
pub fn lost(pc: u64, page: u64) bool {
    const sl = &mine;
    defer sl.tried = .{ 0, 0 };
    return sl.tried[0] == pc and sl.tried[1] == page;
}

pub fn tried(pc: u64, page: u64) void {
    mine.tried = .{ pc, page };
}

// inSlot reports whether pc is in what the thread runs.
pub fn inSlot(pc: u64) bool {
    const sl = &mine;
    if (sl.nexit == 0) return false;
    return sl.page != 0 and pc >= sl.page and pc < sl.page + if (X86) sl.n + 1 else 4 * (sl.n + sl.nexit);
}

// addHold has what the thread runs keep hold id too, and reports whether it can.
pub fn addHold(id: u64) bool {
    const sl = &mine;
    if (sl.nexit == 0) return false;
    for (&sl.holds) |*h| {
        if (h.* != 0) continue;
        h.* = id;
        return true;
    }
    return false;
}

// dropHolds gives up the holds what the thread runs keeps, to let go: it goes on
// without them.
pub fn dropHolds() Holds {
    const sl = &mine;
    defer sl.holds = .{ 0, 0 };
    return sl.holds;
}

// guestPc is the guest's pc for pc, this thread's, as a signal
// delivered there must see it: an instruction of the copy not run yet is the
// guest's at the same offset; an exit, the target it leads to.
pub fn guestPc(pc: u64) u64 {
    const sl = &mine;
    if (sl.page == 0 or pc < sl.page) return pc;
    if (X86) {
        if (sl.nexit == 0 or pc > sl.page + sl.n + 1) return pc;
        return if (pc < sl.page + sl.n) sl.start else sl.exits[0];
    }
    const i = (pc - sl.page) / 4;
    if (i < sl.n) return sl.start + 4 * i;
    if (i < sl.n + sl.nexit) return sl.exits[i - sl.n];
    return pc;
}

// A pc-relative branch: its offset, and how to give it another.
const Branch = struct {
    off: i64,
    lo: u5, // the offset field: bits lo..lo+bits-1, in words
    bits: u5,

    fn retarget(b: Branch, w: u32, off: i64) u32 {
        const mask: u32 = (@as(u32, 1) << b.bits) - 1;
        const f: u32 = @truncate(@as(u64, @bitCast(off >> 2)) & mask);
        return (w & ~(mask << b.lo)) | (f << b.lo);
    }
};

fn field(w: u32, lo: u5, bits: u5) Branch {
    const v: i64 = @intCast((w >> lo) & ((@as(u32, 1) << bits) - 1));
    const s = v - (@as(i64, (w >> (lo + bits - 1)) & 1) << bits);
    return .{ .off = s * 4, .lo = lo, .bits = bits };
}

// branch reads B, B.cond, CBZ/CBNZ and TBZ/TBNZ.
fn branch(w: u32) ?Branch {
    if (w & 0xfc000000 == 0x14000000) return field(w, 0, 26);
    if (w & 0xff000010 == 0x54000000) return field(w, 5, 19);
    if (w & 0x7e000000 == 0x34000000) return field(w, 5, 19);
    if (w & 0x7e000000 == 0x36000000) return field(w, 5, 14);
    return null;
}

// movable reports whether instruction w, no branch of those, runs the same
// from anywhere.
fn movable(w: u32) bool {
    if (w & 0xfc000000 == 0x94000000) return false; // BL
    if (w & 0xfe000000 == 0xd6000000) return false; // BR, BLR, RET, ERET
    if (w & 0x1f000000 == 0x10000000) return false; // ADR, ADRP
    if (w & 0x3b000000 == 0x18000000) return false; // LDR (literal), PRFM (literal)
    if (w & 0xff000000 == 0xd4000000) return false; // SVC, HVC, SMC, BRK, HLT
    if (w & 0xffff0000 == 0) return false; // UDF: a trap of the stub's
    return true;
}

// The store exclusives (STXR, STLXR, STXP, STLXP) and load exclusives (LDXR,
// LDAXR, LDXP, LDAXP), and an exclusive's status, base and size registers.
pub fn storeExclusive(w: u32) bool {
    return w & 0x3fc00000 == 0x08000000;
}

pub fn loadExclusive(w: u32) bool {
    return w & 0x3fc00000 == 0x08400000;
}

pub fn statusReg(w: u32) u5 {
    return @truncate(w >> 16);
}

// pairOf reports whether load exclusive l and store exclusive s take the
// same base, size and pairing, as one window's do.
pub fn pairOf(l: u32, s: u32) bool {
    return (l >> 5) & 31 == (s >> 5) & 31 and l >> 30 == s >> 30 and (l >> 21) & 1 == (s >> 21) & 1;
}

// window finds the exclusive window store exclusive s, at pc on a page
// whose words from page on are code, closes: from the nearest load exclusive
// before it that takes the same base, size and pairing. Its length in
// instructions, through s; null when there is none on the page.
pub fn window(code: [*]const u32, page: u64, pc: u64, s: u32) ?u32 {
    var at = pc;
    var n: u32 = 1;
    while (at > page and n < MAX) {
        at -= 4;
        n += 1;
        const l = code[(at - page) / 4];
        if (!loadExclusive(l)) continue;
        return if (pairOf(l, s)) n else null;
    }
    return null;
}

// rerunnable reports whether exclusive window words, run up to its store
// exclusive, runs the same again from its load exclusive (the load reading
// memory afresh): it writes no memory but by its store exclusive, writes no
// register it reads before writing, nor the flags it reads before setting
// them, and every branch in it leaves it, so each way through it is a run
// of its first instructions. What it cannot tell, it does not take.
pub fn rerunnable(words: []const u32) bool {
    var written: u64 = 0;
    var live: u64 = 0;
    var flags_written = false;
    var flags_live = false;
    const n = words.len;
    for (words, 0..) |w, i| {
        const u = use(w, i == 0, i == n - 1) orelse return false;
        if (u.branch) {
            if (branch(w)) |b| {
                const t = @as(i64, @intCast(4 * i)) + b.off;
                if (t >= 0 and t < 4 * @as(i64, @intCast(n))) return false;
            }
        }
        live |= u.reads & ~written;
        if (u.flags_read and !flags_written) flags_live = true;
        written |= u.writes;
        if (u.flags_set) flags_written = true;
    }
    return live & written == 0 and !(flags_live and flags_written);
}

// A register 31 read as the zero register is no input, nor written to it an
// output; as sp it is register 31.
const Use = struct { reads: u64 = 0, writes: u64 = 0, flags_read: bool = false, flags_set: bool = false, branch: bool = false };

fn r(w: u32, lo: u5) u64 {
    return @as(u64, 1) << @truncate((w >> lo) & 31);
}

// zr is r for a field where 31 is the zero register.
fn zr(w: u32, lo: u5) u64 {
    return if ((w >> lo) & 31 == 31) 0 else r(w, lo);
}

// use is what instruction w reads and writes, of the classes an exclusive
// window takes: its load exclusive (first) and store exclusive (last), and
// between them data processing, branches, hints and barriers.
fn use(w: u32, first: bool, last: bool) ?Use {
    if (first) {
        if (!loadExclusive(w)) return null;
        var u = Use{ .reads = r(w, 5), .writes = zr(w, 0) };
        if ((w >> 21) & 1 == 1) u.writes |= zr(w, 10);
        return u;
    }
    if (last) {
        if (!storeExclusive(w)) return null;
        var u = Use{ .reads = r(w, 5) | zr(w, 0) };
        if ((w >> 21) & 1 == 1) u.reads |= zr(w, 10);
        return u;
    }
    const s = (w >> 29) & 1 == 1; // the S bit of the forms that set flags
    switch (w & 0x1f800000) {
        0x11000000 => return .{ .reads = r(w, 5), .writes = if (s) zr(w, 0) else r(w, 0), .flags_set = s }, // ADD/SUB (immediate)
        0x12000000 => { // logical (immediate)
            const ands = (w >> 29) & 3 == 3;
            return .{ .reads = zr(w, 5), .writes = if (ands) zr(w, 0) else r(w, 0), .flags_set = ands };
        },
        0x12800000 => return .{ .reads = if ((w >> 29) & 3 == 3) zr(w, 0) else 0, .writes = zr(w, 0) }, // MOVN, MOVZ, MOVK
        0x13000000 => return .{ .reads = zr(w, 5) | (if ((w >> 29) & 3 == 1) zr(w, 0) else 0), .writes = zr(w, 0) }, // bitfield
        0x13800000 => return .{ .reads = zr(w, 5) | zr(w, 16), .writes = zr(w, 0) }, // EXTR
        else => {},
    }
    if (w & 0x1f000000 == 0x0a000000) { // logical (shifted register)
        const ands = (w >> 29) & 3 == 3;
        return .{ .reads = zr(w, 5) | zr(w, 16), .writes = zr(w, 0), .flags_set = ands };
    }
    if (w & 0x1f200000 == 0x0b000000) return .{ .reads = zr(w, 5) | zr(w, 16), .writes = zr(w, 0), .flags_set = s }; // ADD/SUB (shifted)
    if (w & 0x1f200000 == 0x0b200000) return .{ .reads = r(w, 5) | zr(w, 16), .writes = if (s) zr(w, 0) else r(w, 0), .flags_set = s }; // ADD/SUB (extended)
    if (w & 0x1fe00000 == 0x1a000000) return .{ .reads = zr(w, 5) | zr(w, 16), .writes = zr(w, 0), .flags_read = true, .flags_set = s }; // ADC, SBC
    if (w & 0x1fe00000 == 0x1a400000) return .{ .reads = zr(w, 5) | (if ((w >> 11) & 1 == 0) zr(w, 16) else 0), .flags_read = true, .flags_set = true }; // CCMN, CCMP
    if (w & 0x1fe00000 == 0x1a800000) return .{ .reads = zr(w, 5) | zr(w, 16), .writes = zr(w, 0), .flags_read = true }; // CSEL and kin
    if (w & 0x5fe00000 == 0x1ac00000) return .{ .reads = zr(w, 5) | zr(w, 16), .writes = zr(w, 0) }; // two-source
    if (w & 0x5fe00000 == 0x5ac00000) return .{ .reads = zr(w, 5), .writes = zr(w, 0) }; // one-source
    if (w & 0x1f000000 == 0x1b000000) return .{ .reads = zr(w, 5) | zr(w, 16) | zr(w, 10), .writes = zr(w, 0) }; // three-source
    if (w & 0xff000010 == 0x54000000) return .{ .flags_read = true, .branch = true }; // B.cond
    if (w & 0x7e000000 == 0x34000000 or w & 0x7e000000 == 0x36000000) return .{ .reads = zr(w, 0), .branch = true }; // CBZ, TBZ
    if (w & 0xfc000000 == 0x14000000) return .{ .branch = true }; // B
    if (w & 0xfffff01f == 0xd503201f) return .{}; // hints (NOP, YIELD, ...)
    if (w & 0xfffff09f == 0xd503309f) return .{}; // DSB, DMB
    return null;
}
