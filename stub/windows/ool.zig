// ool.zig — guest instructions run out of line: copied into a page of the
// thread's own and run there, a trap after them bringing the guest back to
// where they lead. A store into the page its own code runs from needs it
// (mem.zig, "code in shared memory"): no protection lets the page both run
// the store and take it, but the store runs as well from anywhere else.
// macos/stub/ool.zig is Darwin's.
//
// arm64 copies keep the instructions' layout, so a branch among them keeps
// its offset and a pc in the copy names the guest's instruction at the same
// offset (guestPc); a branch leaving them goes to an exit of its own. An
// instruction that reads pc otherwise, a call, a return or an exception
// cannot run out of line. x86-64 runs one instruction at a time, its length
// and the place of its RIP-relative displacement from the supervisor's
// decoder, in a page within a displacement's reach of it.

const std = @import("std");
const win = std.os.windows;
const root = @import("stub.zig");
const mem = @import("mem.zig");
const blocks = @import("blocks.zig");

extern "ntdll" fn NtProtectVirtualMemory(proc: usize, base: *usize, size: *usize, prot: u32, old: *u32) callconv(win.WINAPI) i32;
extern "ntdll" fn NtFlushInstructionCache(proc: usize, base: usize, size: usize) callconv(win.WINAPI) i32;

pub const MAX = 32; // arm64 instructions at a time
const PAGE: u64 = 0x1000;
const arm = @import("builtin").cpu.arch == .aarch64;
const EXIT_A64: u32 = 0xd4200000 | (0x5e << 5); // brk #0x5e
const EXIT_X64: u8 = 0xcc; // int3
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;

// A thread's page, by its slot, and what it last ran: n instructions (arm64)
// or bytes (x86-64) from guest address start, the exits after them (exits[0]
// where the last leads, the rest the targets of the branches leaving them),
// and the holds on memory while they run (mem.zig), 0 for none. One that
// stands for the single guest instruction at start (one) maps every pc of it
// there.
pub const Slot = struct {
    page: u64 = 0,
    start: u64 = 0,
    n: u32 = 0,
    nexit: u32 = 0,
    exits: [MAX + 1]u64 = undefined,
    holds: Holds = .{ 0, 0 },
    one: bool = false,
    tried: [2]u64 = .{ 0, 0 }, // the store (pc, page) last run again in place (lost)
};

pub const Holds = [2]u64;

// pageFor is slot sl's page, in reach of a RIP-relative displacement at pc
// if near.
fn pageFor(sl: *Slot, pc: u64, near: bool) ?u64 {
    const far = if (sl.page > pc) sl.page - pc else pc - sl.page;
    if (sl.page != 0 and (!near or far <= (1 << 31) - 2 * PAGE)) return sl.page;
    sl.page = mem.stubPage(pc, PAGE_EXECUTE_READ) orelse if (near) return null else mem.stubPageAny(PAGE_EXECUTE_READ) orelse return null;
    return sl.page;
}

fn writable(page: u64, w: bool) bool {
    var b: usize = page;
    var s: usize = PAGE;
    var old: u32 = 0;
    return NtProtectVirtualMemory(root.SELF, &b, &s, if (w) PAGE_READWRITE else PAGE_EXECUTE_READ, &old) >= 0;
}

// place puts code at the start of page, unless it holds it already (a store
// that runs out of line again, as in a loop): each change of the page's
// protection costs every processor a flush.
fn place(page: u64, code: []const u8) bool {
    const at: [*]u8 = @ptrFromInt(page);
    if (std.mem.eql(u8, at[0..code.len], code)) return true;
    if (!writable(page, true)) return false;
    @memcpy(at[0..code.len], code);
    if (!writable(page, false)) return false;
    _ = NtFlushInstructionCache(root.SELF, page, code.len);
    return true;
}

// runA64 copies words, the guest's arm64 instructions at start as they ran,
// into slot s's page and returns where the thread resumes to run them; null
// if one cannot run out of line.
pub fn runA64(s: usize, words: []const u32, start: u64, hold: u64) ?u64 {
    const sl = &blocks.at(s).ool;
    if (words.len == 0 or words.len > MAX) return null;
    const page = pageFor(sl, start, false) orelse return null;
    var out: [2 * MAX + 1]u32 = undefined;
    const n: u32 = @intCast(words.len);
    var nexit: u32 = 1;
    for (words, 0..) |w, i| {
        const at = start + 4 * i;
        const b = branch(w) orelse {
            if (!movable(w)) return null;
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
        out[e] = EXIT_A64;
        nexit += 1;
        out[i] = b.retarget(w, (@as(i64, e) - @as(i64, @intCast(i))) * 4);
    }
    out[n] = EXIT_A64;
    if (!place(page, std.mem.sliceAsBytes(out[0 .. n + nexit]))) return null;
    sl.exits[0] = start + 4 * n;
    sl.start = start;
    sl.n = n;
    sl.nexit = nexit;
    sl.holds = .{ hold, 0 };
    sl.one = false;
    return page;
}

// runFor runs words, arm64 instructions of no branch, in slot s's page in
// place of the guest's instruction at start, and returns where the thread
// resumes; the guest goes on after start once they ran, and a signal among
// them sees start.
pub fn runFor(s: usize, words: []const u32, start: u64) ?u64 {
    const sl = &blocks.at(s).ool;
    if (words.len == 0 or words.len > MAX) return null;
    const page = pageFor(sl, start, false) orelse return null;
    var out: [MAX + 1]u32 = undefined;
    @memcpy(out[0..words.len], words);
    out[words.len] = EXIT_A64;
    if (!place(page, std.mem.sliceAsBytes(out[0 .. words.len + 1]))) return null;
    sl.exits[0] = start + 4;
    sl.start = start;
    sl.n = @intCast(words.len);
    sl.nexit = 1;
    sl.holds = .{ 0, 0 };
    sl.one = true;
    return page;
}

// runX64 copies code, the guest's x86-64 instruction at start, its
// RIP-relative displacement at at (0: none), into slot s's page and returns
// where the thread resumes to run it, hold kept meanwhile; null if it cannot.
pub fn runX64(s: usize, code: []const u8, at: u32, start: u64, hold: u64) ?u64 {
    const sl = &blocks.at(s).ool;
    if (code.len == 0 or code.len > 15) return null;
    const page = pageFor(sl, start, at != 0) orelse return null;
    var out: [16]u8 = undefined;
    @memcpy(out[0..code.len], code);
    if (at != 0) {
        // The operand's address stays the guest's: the displacement moves by
        // as much as the instruction does.
        const d: i64 = std.mem.readInt(i32, code[at..][0..4], .little);
        const nd = d + @as(i64, @bitCast(start -% page));
        if (nd < std.math.minInt(i32) or nd > std.math.maxInt(i32)) return null;
        std.mem.writeInt(i32, out[at..][0..4], @intCast(nd), .little);
    }
    out[code.len] = EXIT_X64;
    if (!place(page, out[0 .. code.len + 1])) return null;
    sl.exits[0] = start + code.len;
    sl.start = start;
    sl.n = @intCast(code.len);
    sl.nexit = 1;
    sl.holds = .{ hold, 0 };
    sl.one = false;
    return page;
}

// A near call, decoded: where it goes, and where it returns to.
pub const Call = struct { target: u64, ret: u64 };
pub const CallOf = union(enum) { call: Call, fault: u64, no };

// callOf decodes code, the x86-64 instruction at start, as the near call it
// is (E8, FF /2), from the thread's registers regs (rax..r15) and, through
// load, the memory its operand names: fault, the address of an operand it
// cannot read; no, no call this runs.
pub fn callOf(code: []const u8, start: u64, regs: *const [16]u64, load: *const fn (u64) ?u64) CallOf {
    var i = callPrefixes(code);
    var rex: u8 = 0;
    if (i < code.len and code[i] & 0xf0 == 0x40) {
        rex = code[i];
        i += 1;
    }
    if (i >= code.len) return .no;
    const end = start + code.len;
    if (code[i] == 0xe8) {
        if (i + 5 != code.len) return .no;
        const d: i32 = std.mem.readInt(i32, code[i + 1 ..][0..4], .little);
        return .{ .call = .{ .target = end +% @as(u64, @bitCast(@as(i64, d))), .ret = end } };
    }
    if (code[i] != 0xff or i + 1 >= code.len) return .no;
    const m = code[i + 1];
    if ((m >> 3) & 7 != 2) return .no;
    const mod = m >> 6;
    const rm: u4 = @truncate(m & 7);
    const b: u4 = @truncate((rex & 1) << 3);
    if (mod == 3) return if (i + 2 == code.len) .{ .call = .{ .target = regs[rm | b], .ret = end } } else .no;
    var p = i + 2;
    var ea: u64 = 0;
    var rip = false;
    var disp32 = false; // a displacement of 32 bits with mod 0: rip-relative, or a SIB with no base
    if (rm == 4) {
        if (p >= code.len) return .no;
        const sib = code[p];
        p += 1;
        const index: u4 = @truncate(((sib >> 3) & 7) | ((rex & 2) << 2));
        if (index != 4) ea = regs[index] << @truncate(sib >> 6);
        if (sib & 7 == 5 and mod == 0) disp32 = true else ea +%= regs[@as(u4, @truncate(sib & 7)) | b];
    } else if (rm == 5 and mod == 0) {
        rip = true;
        disp32 = true;
    } else ea = regs[rm | b];
    var disp: i64 = 0;
    if (mod == 1) {
        if (p + 1 > code.len) return .no;
        disp = @as(i8, @bitCast(code[p]));
        p += 1;
    } else if (mod == 2 or disp32) {
        if (p + 4 > code.len) return .no;
        disp = std.mem.readInt(i32, code[p..][0..4], .little);
        p += 4;
    }
    if (p != code.len) return .no;
    ea +%= @bitCast(disp);
    if (rip) ea +%= end;
    return if (load(ea)) |t| .{ .call = .{ .target = t, .ret = end } } else .{ .fault = ea };
}

// runCall runs call c, the guest's at start, out of line: its return address
// pushed where it pushes it, the thread going on at its target. hold is kept
// meanwhile.
pub fn runCall(s: usize, c: Call, start: u64, hold: u64) ?u64 {
    const sl = &blocks.at(s).ool;
    const page = pageFor(sl, start, false) orelse return null;
    var out: [16]u8 = .{ 0xff, 0x35, 2, 0, 0, 0, EXIT_X64, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // push qword [rip+2]; int3; its return address
    std.mem.writeInt(u64, out[8..16], c.ret, .little);
    if (!place(page, &out)) return null;
    sl.exits[0] = c.target;
    sl.start = start;
    sl.n = 6;
    sl.nexit = 1;
    sl.holds = .{ hold, 0 };
    sl.one = false;
    return page;
}

// Exit is where what a slot ran leads, and the holds it kept, to let go.
pub const Exit = struct { target: u64, holds: Holds };

// exit takes the trap at pc ending what slot s ran; null if pc is no exit
// of it.
pub fn exit(s: usize, pc: u64) ?Exit {
    const sl = &blocks.at(s).ool;
    if (sl.page == 0 or pc < sl.page or sl.nexit == 0) return null;
    const k: ?u64 = if (arm) blk: {
        const i = (pc - sl.page) / 4;
        break :blk if (i >= sl.n and i < sl.n + sl.nexit) i - sl.n else null;
    } else if (pc == sl.page + sl.n or pc == sl.page + sl.n + 1) 0 else null; // the int3, or past it
    const e = Exit{ .target = sl.exits[k orelse return null], .holds = sl.holds };
    sl.n = 0;
    sl.nexit = 0;
    sl.holds = .{ 0, 0 };
    return e;
}

// lost reports whether the thread in slot s faults again on the store at pc
// into page that it ran again in place last (tried): a thread ran the page
// again before the store landed. Each fault asks once.
pub fn lost(s: usize, pc: u64, page: u64) bool {
    const sl = &blocks.at(s).ool;
    defer sl.tried = .{ 0, 0 };
    return sl.tried[0] == pc and sl.tried[1] == page;
}

pub fn tried(s: usize, pc: u64, page: u64) void {
    blocks.at(s).ool.tried = .{ pc, page };
}

// inSlot reports whether pc is in what slot s runs.
pub fn inSlot(s: usize, pc: u64) bool {
    const sl = &blocks.at(s).ool;
    return sl.page != 0 and sl.nexit != 0 and pc >= sl.page and pc < sl.page + PAGE;
}

// addHold has what slot s runs keep hold id too, and reports whether it can.
pub fn addHold(s: usize, id: u64) bool {
    const sl = &blocks.at(s).ool;
    if (sl.nexit == 0) return false;
    for (&sl.holds) |*h| {
        if (h.* != 0) continue;
        h.* = id;
        return true;
    }
    return false;
}

// dropHolds gives up the holds what slot s runs keeps, to let go: it goes on
// without them.
pub fn dropHolds(s: usize) Holds {
    const sl = &blocks.at(s).ool;
    const h = sl.holds;
    sl.holds = .{ 0, 0 };
    return h;
}

// leave is the guest's pc for pc, the thread in slot s's, as a signal
// delivered there must see it: an instruction of the copy not run yet is
// the guest's at the same offset; an exit, the target it leads to. It gives
// up what the slot ran (the guest resumes at that pc), and its holds.
pub fn leave(s: usize, pc: u64) struct { pc: u64, holds: Holds } {
    const sl = &blocks.at(s).ool;
    const none = Holds{ 0, 0 };
    if (sl.page == 0 or pc < sl.page or sl.nexit == 0) return .{ .pc = pc, .holds = none };
    const off = pc - sl.page;
    const g: u64 = if (arm) blk: {
        const i = off / 4;
        if (i < sl.n) break :blk if (sl.one) sl.start else sl.start + 4 * i;
        if (i < sl.n + sl.nexit) break :blk sl.exits[i - sl.n];
        return .{ .pc = pc, .holds = none };
    } else if (off == 0) sl.start else if (off == sl.n) sl.exits[0] else return .{ .pc = pc, .holds = none };
    const h = sl.holds;
    sl.n = 0;
    sl.nexit = 0;
    sl.holds = none;
    return .{ .pc = g, .holds = h };
}

// nearCall reports whether the x86-64 instruction code is a near call
// (E8, FF /2), which runCall runs.
pub fn nearCall(code: []const u8) bool {
    var i = callPrefixes(code);
    if (i < code.len and code[i] & 0xf0 == 0x40) i += 1;
    if (i >= code.len) return false;
    return code[i] == 0xe8 or (code[i] == 0xff and i + 1 < code.len and (code[i + 1] >> 3) & 7 == 2);
}

// callPrefixes is how many of code's prefixes change nothing a near call
// does in 64-bit mode: CS, DS (notrack), ES and SS, and BND.
fn callPrefixes(code: []const u8) usize {
    var i: usize = 0;
    while (i < code.len) : (i += 1) {
        switch (code[i]) {
            0x2e, 0x3e, 0x26, 0x36, 0xf2 => {},
            else => return i,
        }
    }
    return i;
}

// relocatable reports whether the x86-64 instruction code runs the same
// from anywhere, its RIP-relative displacement moved: all but a call (E8,
// FF /2, FF /3), whose return address is where it ran.
pub fn relocatable(code: []const u8) bool {
    var i: usize = 0;
    while (i < code.len) : (i += 1) {
        switch (code[i]) {
            0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x40...0x4f => continue,
            0xe8, 0x9a => return false,
            0xff => return i + 1 >= code.len or (code[i + 1] >> 3) & 7 != 2 and (code[i + 1] >> 3) & 7 != 3,
            else => return true,
        }
    }
    return true;
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
    const sv = v - (@as(i64, (w >> (lo + bits - 1)) & 1) << bits);
    return .{ .off = sv * 4, .lo = lo, .bits = bits };
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
    if (w & 0xffffffe0 == 0xd50b7420 and zvaTraps()) return false; // DC ZVA, trapped: it runs out of line itself (aarch64.zig)
    return true;
}

// zvaTraps reports whether dc zva traps here (DCZID_EL0.DZP).
fn zvaTraps() bool {
    if (!arm) return false;
    const z = asm volatile ("mrs %[o], dczid_el0"
        : [o] "=r" (-> u64),
    );
    return z & 0x10 != 0;
}

// The store exclusives (STXR, STLXR, STXP, STLXP) and load exclusives (LDXR,
// LDAXR, LDXP, LDAXP), and an exclusive's status register.
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

