// jit.zig — RWX memory for the guest. Linux lets a JIT (V8) map code pages
// read+write+execute; Apple Silicon refuses RWX except in MAP_JIT regions, and
// there a thread sees the region either writable or executable at a time,
// switched per thread with pthread_jit_write_protect_np. The guest cannot know
// to switch, so the stub does it on demand: a write to a JIT page while the
// thread is in execute mode faults (data abort) and flips it to write mode; an
// instruction fetch from a JIT page in write mode faults (instruction abort) and
// flips it back. A fault that the flip does not explain is a real one, which
// sig.zig turns into the guest's Linux signal.
//
// A MAP_JIT region's protection cannot be changed at all (mprotect is EACCES,
// with or without the allow-jit entitlement), so guest mprotect is served here:
// RWX becomes a MAP_JIT remap, and any other protection on a JIT page turns that
// page back into an ordinary mapping first, contents preserved.

const std = @import("std");
const mem = @import("mem.zig");
const ool = @import("ool.zig");
const tstate = @import("tstate.zig");

extern "c" fn pthread_jit_write_protect_np(enabled: c_int) void;
extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) ?*anyopaque;
extern "c" fn munmap(addr: *anyopaque, len: usize) c_int;
extern "c" fn mprotect(addr: *anyopaque, len: usize, prot: c_int) c_int;
extern "c" fn __error() *c_int;

const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const PROT_RWX: c_int = 7;
const MAP_PRIVATE: c_int = 2;
const MAP_FIXED: c_int = 0x10;
const MAP_JIT: c_int = 0x800;
const MAP_ANON: c_int = 0x1000;
const MAP_FAILED: usize = std.math.maxInt(usize);
const DARWIN_EACCES: c_int = 13;

const PAGE: u64 = tstate.page;

// Linux errnos, returned negated. Darwin shares these numbers.
const ENOMEM: i64 = 12;

// ESR_EL1 exception classes (bits 31:26) for aborts from EL0.
const EC_IABT_LOWER: u32 = 0x20;
const EC_DABT_LOWER: u32 = 0x24;

threadlocal var write_mode: bool = false;

fn setWrite(w: bool) void {
    pthread_jit_write_protect_np(@intFromBool(!w));
    write_mode = w;
}

// initThread puts a new guest thread in execute mode, the state the fault
// handler assumes it starts from.
pub fn initThread() void {
    setWrite(false);
}

// A data abort the stub flipped for. If the instruction that took it lives on
// a JIT page itself, the flip makes it fault again as an instruction abort at
// the same pc: no one view of the region both runs the instruction and lets it
// write (a JVM's atomic stubs, in its code cache, update words there). The
// stub then runs the instruction out of line in write mode (storeOutOfLine);
// one it cannot was a real fault after all and is handed back to be
// delivered.
pub const Fault = struct { pc: u64 = 0, esr: u32 = 0, far: u64 = 0, dsig: c_int = 0, code: c_int = 0 };
threadlocal var flipped: Fault = .{};

// flip handles a fault that is only this thread's JIT view being the wrong
// one (see the top of this file), switching it; false if the fault is real.
// f may be replaced by the earlier fault it turns out to be.
pub fn flip(f: *Fault, mc: *std.c.mcontext_t) bool {
    const ec = f.esr >> 26;
    if (ec == EC_IABT_LOWER and write_mode) {
        setWrite(false);
        if (flipped.pc == f.pc) {
            const d = flipped;
            flipped.pc = 0;
            if (storeOutOfLine(d, mc)) return true;
            f.* = d;
            return false;
        }
        return true;
    }
    flipped.pc = 0;
    // Only a write permission fault can be the JIT view: a JIT page reads in
    // either mode, and a translation fault is an unmapped address.
    const wnr = f.esr & (1 << 6) != 0;
    const perm = f.esr & 0x3c == 0x0c;
    if (ec == EC_DABT_LOWER and !write_mode and wnr and perm) {
        flipped = f.*;
        setWrite(true);
        return true;
    }
    return false;
}

// storeOutOfLine runs the store at f.pc out of line (ool.zig) in write mode,
// on this thread, when f.far is memory the guest may write: the
// guest goes on after it once it has run, back in execute mode (sig.zig). A
// store exclusive's monitor is lost to the fault: its window runs instead,
// from its load exclusive, when running it again changes nothing but what
// the load reads (ool.rerunnable); no trap can mark the load exclusive in a
// page the guest reads as it wrote it.
fn storeOutOfLine(f: Fault, mc: *std.c.mcontext_t) bool {
    if (!mem.writable(f.far)) return false;
    const w = @as(*const u32, @ptrFromInt(f.pc)).*;
    var words: [ool.MAX]u32 = undefined;
    var n: u32 = 1;
    var start = f.pc;
    words[0] = w;
    if (ool.storeExclusive(w)) {
        const page = f.pc & ~(PAGE - 1);
        const code: [*]const u32 = @ptrFromInt(page);
        n = ool.window(code, page, f.pc, w) orelse return false;
        start = f.pc - 4 * (n - 1);
        @memcpy(words[0..n], code[(start - page) / 4 ..][0..n]);
        if (!ool.rerunnable(words[0..n])) return false;
    }
    setWrite(true);
    if (ool.run(mc, words[0..n], start, true, 0)) return true;
    setWrite(false);
    return false;
}

fn neg(e: i64) u64 {
    return @bitCast(-e);
}

// protect serves a guest mprotect of a page-aligned range.
pub fn protect(addr: u64, len: u64, prot: u64) u64 {
    if (prot & 6 == 6) return mprotectRWX(addr, len);
    const p: c_int = @intCast(prot & 7);
    if (mprotect(@ptrFromInt(addr), len, p) == 0) return 0;
    const e = __error().*;
    if (e != DARWIN_EACCES) return neg(e);
    // Part of the range may be MAP_JIT: redo it page by page, converting
    // those. Elsewhere EACCES is real (a shared mapping of a read-only file).
    var a = addr;
    while (a < addr + len) : (a += PAGE) {
        if (mprotect(@ptrFromInt(a), PAGE, p) == 0) continue;
        if (__error().* != DARWIN_EACCES) return neg(ENOMEM);
        if (!mem.isJit(a)) return neg(DARWIN_EACCES);
        if (!unjit(a, p)) return neg(ENOMEM);
    }
    return 0;
}

// unjit replaces one MAP_JIT page with an ordinary anonymous page holding the
// same bytes, then applies prot. A JIT page is readable in either thread mode.
// The bounce buffer is per thread and off the guest stack, which may be small.
threadlocal var unjit_buf: [PAGE]u8 = undefined;

fn unjit(page: u64, prot: c_int) bool {
    const buf = &unjit_buf;
    const src: [*]const u8 = @ptrFromInt(page);
    @memcpy(buf[0..], src[0..PAGE]);
    const m = mmap(@ptrFromInt(page), PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (@intFromPtr(m) != page) return false;
    const dst: [*]u8 = @ptrFromInt(page);
    @memcpy(dst[0..PAGE], buf[0..]);
    return mprotect(@ptrFromInt(page), PAGE, prot) == 0;
}

// mprotectRWX gives [addr, addr+len) read+write+execute. Darwin refuses that on
// an ordinary mapping, so the range is copied aside, unmapped, and mapped again
// as MAP_JIT at the same address (MAP_FIXED is not allowed with MAP_JIT, so the
// address is a hint that must be honoured), then its contents are restored.
fn mprotectRWX(addr: u64, len: u64) u64 {
    const p: *anyopaque = @ptrFromInt(addr);
    if (mprotect(p, len, PROT_RWX) == 0) return 0; // already a JIT region
    if (__error().* != DARWIN_EACCES) return neg(ENOMEM);
    if (mprotect(p, len, PROT_READ) != 0) return neg(ENOMEM);
    const tmp = mmap(null, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) orelse return neg(ENOMEM);
    if (@intFromPtr(tmp) == MAP_FAILED) return neg(ENOMEM);
    defer _ = munmap(tmp, len);
    const src: [*]const u8 = @ptrFromInt(addr);
    const dst: [*]u8 = @ptrCast(tmp);
    @memcpy(dst[0..len], src[0..len]);
    _ = munmap(p, len);
    const j = mmap(p, len, PROT_RWX, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (j == null or @intFromPtr(j) == MAP_FAILED) return neg(ENOMEM);
    if (j != p) {
        _ = munmap(j.?, len); // another thread took the range in between
        return neg(ENOMEM);
    }
    const was = write_mode;
    setWrite(true);
    const out: [*]u8 = @ptrFromInt(addr);
    @memcpy(out[0..len], dst[0..len]);
    setWrite(was);
    return 0;
}

// copyIn fills n bytes of a MAP_JIT region at dst from src.
pub fn copyIn(dst: u64, src: u64, n: u64) void {
    const was = write_mode;
    setWrite(true);
    const d: [*]u8 = @ptrFromInt(dst);
    const s: [*]const u8 = @ptrFromInt(src);
    @memcpy(d[0..n], s[0..n]);
    setWrite(was);
}

// zero clears n bytes of a MAP_JIT region, which madvise cannot zero.
pub fn zero(addr: u64, n: u64) void {
    const was = write_mode;
    setWrite(true);
    const d: [*]u8 = @ptrFromInt(addr);
    @memset(d[0..n], 0);
    setWrite(was);
}
