// blocks.zig — each slot's own state in this stub process, for the thread of
// the process that runs on the slot. Blocks come in chunks of CHUNK slots, a
// chunk allocated as one of its slots is first used here, so a process holds
// memory only for the slots its threads have had; a slot index can be any of
// the run's, up to stub.MAX_SLOTS.

const std = @import("std");
const win = std.os.windows;
const stub = @import("stub.zig");
const sig = @import("sig.zig");
const thread = @import("thread.zig");
const ool = @import("ool.zig");
const mem = @import("mem.zig");

extern "ntdll" fn NtAllocateVirtualMemory(proc: usize, base: *usize, zero_bits: usize, size: *usize, typ: u32, prot: u32) callconv(win.WINAPI) i32;
extern "ntdll" fn NtFreeVirtualMemory(proc: usize, base: *usize, size: *usize, typ: u32) callconv(win.WINAPI) i32;

pub const Block = struct {
    tls: sig.Tls = .{},
    ret: sig.Return = undefined,
    resume_frame: sig.Frame = undefined,
    handoff: thread.Handoff = undefined,
    vfork: thread.Vfork = undefined,
    ool: ool.Slot = .{},
    wspan: mem.Span = .{},
    ev_stub: stub.HANDLE = 0, // the supervisor wakes the slot's thread by it
    ev_sup: stub.HANDLE = 0, // and the thread wakes the supervisor by this
};

pub const CHUNK = 64;
const NCHUNK = stub.MAX_SLOTS / CHUNK;

var dir = [_]?[*]Block{null} ** NCHUNK;
var nchunk: usize = 0; // past the highest chunk allocated

// ensure has the chunk of slot i in place; false if it cannot be allocated.
pub fn ensure(i: usize) bool {
    const c = i / CHUNK;
    if (c >= NCHUNK) return false;
    if (@atomicLoad(?[*]Block, &dir[c], .acquire) != null) return true;
    var b: usize = 0;
    var n: usize = CHUNK * @sizeOf(Block);
    if (NtAllocateVirtualMemory(stub.SELF, &b, 0, &n, 0x3000, 0x04) < 0) return false; // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
    const fresh: [*]Block = @ptrFromInt(b);
    for (fresh[0..CHUNK]) |*k| k.* = .{};
    if (@cmpxchgStrong(?[*]Block, &dir[c], null, fresh, .acq_rel, .acquire) != null) {
        var z: usize = 0;
        _ = NtFreeVirtualMemory(stub.SELF, &b, &z, 0x8000); // MEM_RELEASE: another thread's chunk won
    }
    _ = @atomicRmw(usize, &nchunk, .Max, c + 1, .acq_rel);
    return true;
}

// at is slot i's block, whose chunk ensure put in place.
pub fn at(i: usize) *Block {
    return &@atomicLoad(?[*]Block, &dir[i / CHUNK], .acquire).?[i % CHUNK];
}

// mine is the calling thread's block.
pub fn mine() *Block {
    return at(stub.curSlot());
}

// chunk is the c'th chunk, null if it was never allocated; chunks are those
// below count().
pub fn chunk(c: usize) ?[*]Block {
    return @atomicLoad(?[*]Block, &dir[c], .acquire);
}

pub fn count() usize {
    return @atomicLoad(usize, &nchunk, .acquire);
}
