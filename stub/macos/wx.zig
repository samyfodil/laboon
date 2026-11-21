// wx.zig — code the guest makes executable at run time: memory that is not
// code from a file the stub mapped and rewrote. Such a page runs only once
// rewritten, as file code does, else a raw svc in it (a JIT's, a loader's)
// would be a Darwin call.
//
// The host maps such memory without execute. An instruction fetch from one of
// its pages faults (fault): the stub freezes the page read-only, has the
// supervisor find its svc sites (LC_ANON_SITES, sandbox/anoncode.go), turns
// each into a trap (udf #0) through a second mapping of the page, and makes
// the page executable. A trap is served as its svc was (sig.zig, trapEnter).
// A page with no svc in it, while no page that runs has one, needs no
// analysis: it runs as it is, and is handed over later (LC_ANON_LEARN) for
// what it branches to, which only a page with svcs can need.
//
// Only traps the stub placed are served: the supervisor analyzes a page as
// the guest wrote it, and never names a trap.
//
// A write to a page that runs makes it stop running, its svcs put back, and
// writable again: what is written there runs only once rewritten too, and
// the guest reads back what it wrote. A page whose own code writes into it can
// never alternate so -- no one protection both runs that instruction and lets
// it write -- and becomes a MAP_JIT page with the traps it has: self-modifying
// code gets the read+write+execute it asked for (jit.zig), and what it writes
// there runs unrewritten.
//
// Code in a shared mapping (of a file, a memfd or shared anonymous memory)
// runs only once rewritten too, but its traps cannot go into the memory,
// which other mappings, other processes and the file see. Such a page runs
// as a shadow ("hot"): a private copy of its bytes, taken while every
// writable mapping of them in this process is frozen read-only, and
// rewritten as above. A keeper, a mapping of the page's memory of the stub's
// own, holds it meanwhile. A write through a frozen mapping, or into the hot
// page itself, cools it: the page maps its memory again, from the keeper,
// without execute, the frozen mappings thaw, and its next instruction fetch
// takes a fresh shadow. A writable mapping of memory with a hot page (made by
// mmap, mprotect or mremap) is born frozen. A page is known by its memory: its
// VM object and its offset in it (ObjPage).
//
// Other processes' mappings freeze too, through the supervisor's broker
// (sandbox/codereg_darwin.go): a process about to run a page of shared
// memory, unless it is the run's only one, first holds it with the broker
// (HOT), which has every other stub freeze its writable mappings of that
// memory (FREEZE, remote_hot here). A write through a mapping so frozen has
// the broker cool the page in its holders (COOL) before the mapping thaws.
// The supervisor's own writes to a file mapped shared and executable cool
// the hot pages of it (coolFile). A process the host is about to stop cools
// its hot pages and heats none until it goes on. No thread waits on the
// broker holding the lock the service thread needs to answer it.
//
// A store from a hot page's own code into it cannot alternate as a private
// page's does: no protection both runs the page and lets the store into its
// memory. The page cools and the store runs out of line (ool.zig), then the
// next instruction heats it again. A store exclusive cannot run so alone,
// its monitor lost to the fault: its window, from the load exclusive that
// opens it, runs out of line instead. The first time, the store fails, as
// the architecture lets one fail at any time, and the window is learned: its
// load exclusive is trapped in every shadow of the page from then on.

const std = @import("std");
const jit = @import("jit.zig");
const sig = @import("sig.zig");
const mem = @import("mem.zig");
const ool = @import("ool.zig");
const service = @import("service.zig");
const tstate = @import("tstate.zig");

const PAGE: u64 = tstate.page;
const PROT_READ: u8 = 1;
const PROT_WRITE: u8 = 2;
const PROT_EXEC: u8 = 4;
const SVC0: u32 = 0xd4000001;
const TRAP: u32 = 0; // udf #0
const LC_ANON_SITES: u64 = 0x4c430029;
const LC_ANON_LEARN: u64 = 0x4c43002a;
const ENOMEM: i64 = 12;

const VM_FLAGS_ANYWHERE: c_int = 1;
const VM_FLAGS_FIXED: c_int = 0;
const VM_FLAGS_OVERWRITE: c_int = 0x4000;
const VM_INHERIT_SHARE: u32 = 0;
const VM_INHERIT_NONE: u32 = 2;
const VM_REGION_BASIC_INFO_64: c_int = 9;
const VM_REGION_TOP_INFO: c_int = 12;
const MAP_FIXED: c_int = 0x10;
const MAP_PRIVATE: c_int = 0x2;
const MAP_ANON: c_int = 0x1000;

extern "c" fn mprotect(addr: *anyopaque, len: usize, prot: c_int) c_int;
extern "c" fn mach_task_self() u32;
extern "c" fn mach_vm_remap(task: u32, dst: *u64, size: u64, mask: u64, flags: c_int, src_task: u32, src: u64, copy: c_int, cur: *c_int, max: *c_int, inherit: u32) c_int;
extern "c" fn mach_vm_protect(task: u32, addr: u64, size: u64, set_max: c_int, prot: c_int) c_int;
extern "c" fn mach_vm_deallocate(task: u32, addr: u64, size: u64) c_int;
extern "c" fn mach_vm_region(task: u32, addr: *u64, size: *u64, flavor: c_int, info: *anyopaque, count: *c_uint, obj: *c_uint) c_int;
extern "c" fn mach_port_deallocate(task: u32, name: c_uint) c_int;
extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) ?*anyopaque;
extern "c" fn sys_icache_invalidate(start: *anyopaque, len: usize) void;
extern "c" fn __ulock_wait(op: u32, addr: *anyopaque, value: u64, timeout_us: u32) c_int;
extern "c" fn __ulock_wake(op: u32, addr: *anyopaque, wake_value: u64) c_int;

const UL_COMPARE_AND_WAIT: u32 = 1;
const ULF_WAKE_ALL: u32 = 0x100;
const ULF_NO_ERRNO: u32 = 0x1000000;

const gpa = std.heap.page_allocator;

// Region is a range of such memory and the protection the guest gave it.
pub const Region = extern struct { lo: u64, hi: u64, prot: u64 };

const List = std.ArrayListUnmanaged(Region);

var regions: List = .{}; // sorted, disjoint
var dirty_: List = .{}; // file code the guest has made writable since it was rewritten
// Run is a page that runs now: where it was entered when it began to, how
// many traps it has, and whether it holds an svc.
const Run = struct { pc: u64, traps: u32, svc: bool };

var running: std.AutoHashMapUnmanaged(u64, Run) = .{};
var with_svc: u32 = 0; // of them, those that hold an svc
var unlearned: std.AutoHashMapUnmanaged(u64, u64) = .{}; // pages run unanalyzed -> where they were entered
var traps: std.AutoHashMapUnmanaged(u64, void) = .{}; // every trap the stub placed
var jitted: std.AutoHashMapUnmanaged(u64, void) = .{}; // pages selfWrite made MAP_JIT

// ObjPage is a page of memory: its VM object and its offset in it.
const ObjPage = struct { obj: u32, off: u64 };
const Hot = struct { id: ObjPage, keeper: u64 };
const Frozen = struct { id: ObjPage, prot: u64 };

var sharedx: List = .{}; // of regions, those of shared mappings
var hot: std.AutoHashMapUnmanaged(u64, Hot) = .{}; // shared pages that run as a shadow
var frozen: std.AutoHashMapUnmanaged(u64, Frozen) = .{}; // writable pages frozen for a hot one, with the guest's protection
var heating: u64 = 0; // the page heat is making hot, which freezes the others

// An exclusive window of a page of memory, learned: the load exclusive at
// in-page offset at opens it, n instructions through its store exclusive.
const ExclKey = struct { obj: u32, off: u64, at: u32 };
const Excl = struct { n: u32, ldx: u32 };
var excl: std.AutoHashMapUnmanaged(ExclKey, Excl) = .{};
var xtraps: std.AutoHashMapUnmanaged(u64, ExclKey) = .{}; // load exclusives trapped in hot pages

// Memory a store or an exclusive window runs out of line on, held cool until
// the run ends, so what runs lands, in memory and not a shadow taken
// meanwhile: a thread that would run a page of it waits (waitWindow), and so
// does another process's FREEZE of it (svcFreeze). A thread holds nothing
// while it waits on another, or on the broker. Memory that is no shared
// mapping's is held by its address (obj 0). A hold is named by its place + 1.
const Hold = struct { id: ObjPage = .{ .obj = 0, .off = 0 }, used: bool = false };
var holds: [64]Hold = [_]Hold{.{}} ** 64;
var nholds: usize = 0;
var wake_gen: u32 = 0; // a hold let go, or a stop ended (waitWindow)

// Shared code across processes (see the top of this file): memory another
// process runs as a hot page, which this process's writable mappings of stay
// frozen for; the pages this process holds with the broker; how many
// FREEZEs the service thread has served, for a COOL's thaw to know none came
// since it asked; and whether the host is about to stop the process.
var remote_hot: std.AutoHashMapUnmanaged(ObjPage, void) = .{};
var registered: std.AutoHashMapUnmanaged(ObjPage, void) = .{};
var freezes: u32 = 0;
var stopped = false;

// The lock is reentrant: a thread that holds it may fault into fault() (a
// supervisor read of a page gone meanwhile) or call in from mem.zig again.
var mu: std.Thread.Mutex = .{};
var owner: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);
var depth: u32 = 0;
threadlocal var me: u8 = 0;

fn lock() void {
    const id = @intFromPtr(&me);
    if (owner.load(.monotonic) == id) {
        depth += 1;
        return;
    }
    mu.lock();
    owner.store(id, .monotonic);
    depth = 1;
}

fn unlock() void {
    depth -= 1;
    if (depth > 0) return;
    owner.store(0, .monotonic);
    mu.unlock();
}

fn find(addr: u64) ?usize {
    var lo: usize = 0;
    var hi = regions.items.len;
    while (lo < hi) {
        const m = (lo + hi) / 2;
        const r = regions.items[m];
        if (addr < r.lo) {
            hi = m;
        } else if (addr >= r.hi) {
            lo = m + 1;
        } else return m;
    }
    return null;
}

// hostProt is what the host maps a page of guest protection p with while it
// does not run: everything but execute, and readable (as Linux arm64 reads an
// execute-only page).
fn hostProt(p: u64) c_int {
    return @intCast(hostProtOf(p));
}

pub fn hostProtOf(p: u64) u64 {
    return (p & ~@as(u64, PROT_EXEC)) | PROT_READ;
}

fn setProt(page: u64, n: u64, p: c_int) bool {
    return mprotect(@ptrFromInt(page), n, p) == 0;
}

// cutIn removes [lo, hi) from l.
fn cutIn(l: *List, lo: u64, hi: u64) void {
    var i: usize = 0;
    while (i < l.items.len) {
        const r = l.items[i];
        if (r.hi <= lo or r.lo >= hi) {
            i += 1;
            continue;
        }
        if (r.lo < lo and r.hi > hi) {
            l.items[i].hi = lo;
            l.insert(gpa, i + 1, .{ .lo = hi, .hi = r.hi, .prot = r.prot }) catch {};
            return;
        }
        if (r.lo < lo) {
            l.items[i].hi = lo;
            i += 1;
        } else if (r.hi > hi) {
            l.items[i].lo = hi;
            i += 1;
        } else {
            _ = l.orderedRemove(i);
        }
    }
}

fn insertIn(l: *List, lo: u64, hi: u64, prot: u64) bool {
    cutIn(l, lo, hi);
    var i: usize = 0;
    while (i < l.items.len and l.items[i].lo < lo) i += 1;
    l.insert(gpa, i, .{ .lo = lo, .hi = hi, .prot = prot }) catch return false;
    return true;
}

fn cut(lo: u64, hi: u64) void {
    cutIn(&regions, lo, hi);
}

fn insert(lo: u64, hi: u64, prot: u64) bool {
    return insertIn(&regions, lo, hi, prot);
}

// forget drops what is known of the pages in [lo, hi) that run, as they are,
// traps and all: their memory is gone or replaced.
fn forget(lo: u64, hi: u64) void {
    dropRunning(lo, hi);
    dropKeys(u64, &unlearned, lo, hi);
    dropKeys(void, &jitted, lo, hi);
    dropTraps(lo, hi);
    dropHot(lo, hi);
    dropKeys(Frozen, &frozen, lo, hi);
    dropAddrs(&xtraps, lo, hi);
}

// dropHot forgets the hot pages of [lo, hi), their keepers released: their
// shadows are gone.
fn dropHot(lo: u64, hi: u64) void {
    var gone: [64]u64 = undefined;
    while (hot.count() > 0) {
        var n: usize = 0;
        var it = hot.keyIterator();
        while (it.next()) |k| {
            if (k.* >= lo and k.* < hi and n < gone.len) {
                gone[n] = k.*;
                n += 1;
            }
        }
        for (gone[0..n]) |k| {
            if (hot.fetchRemove(k)) |kv| _ = mach_vm_deallocate(mach_task_self(), kv.value.keeper, PAGE);
        }
        if (n < gone.len) break;
    }
}

// dropRunning forgets the pages of [lo, hi) that run.
fn dropRunning(lo: u64, hi: u64) void {
    if (running.count() == 0) return;
    const first = lo & ~(PAGE - 1);
    if ((hi -| first) / PAGE <= running.count()) {
        var page = first;
        while (page < hi) : (page += PAGE) {
            if (running.fetchRemove(page)) |kv| {
                if (kv.value.svc) with_svc -= 1;
            }
        }
        return;
    }
    var gone: [64]u64 = undefined;
    while (true) {
        var n: usize = 0;
        var it = running.keyIterator();
        while (it.next()) |k| {
            if (k.* >= lo and k.* < hi and n < gone.len) {
                gone[n] = k.*;
                n += 1;
            }
        }
        for (gone[0..n]) |k| {
            if (running.fetchRemove(k)) |kv| {
                if (kv.value.svc) with_svc -= 1;
            }
        }
        if (n < gone.len) break;
    }
}

// dropKeys removes the keys of m in [lo, hi), pages: by page when the range
// has fewer pages than m has keys, else by key.
// dropAddrs forgets the trapped load exclusives in [lo, hi), keyed by their
// address, not their page as dropKeys's are.
fn dropAddrs(m: *std.AutoHashMapUnmanaged(u64, ExclKey), lo: u64, hi: u64) void {
    var gone: [64]u64 = undefined;
    while (m.count() > 0) {
        var n: usize = 0;
        var it = m.keyIterator();
        while (it.next()) |k| {
            if (k.* >= lo and k.* < hi and n < gone.len) {
                gone[n] = k.*;
                n += 1;
            }
        }
        for (gone[0..n]) |k| _ = m.remove(k);
        if (n < gone.len) break;
    }
}

fn dropKeys(comptime V: type, m: *std.AutoHashMapUnmanaged(u64, V), lo: u64, hi: u64) void {
    if (m.count() == 0) return;
    const first = lo & ~(PAGE - 1);
    if ((hi -| first) / PAGE <= m.count()) {
        var page = first;
        while (page < hi) : (page += PAGE) _ = m.remove(page);
        return;
    }
    var gone: [64]u64 = undefined;
    while (true) {
        var n: usize = 0;
        var it = m.keyIterator();
        while (it.next()) |k| {
            if (k.* >= lo and k.* < hi and n < gone.len) {
                gone[n] = k.*;
                n += 1;
            }
        }
        for (gone[0..n]) |k| _ = m.remove(k);
        if (n < gone.len) break;
    }
}

// dropTraps forgets the traps in [lo, hi), which are few.
fn dropTraps(lo: u64, hi: u64) void {
    if (traps.count() == 0) return;
    var stale: [64]u64 = undefined;
    while (true) {
        var n: usize = 0;
        var it = traps.keyIterator();
        while (it.next()) |t| {
            if (t.* >= lo and t.* < hi and n < stale.len) {
                stale[n] = t.*;
                n += 1;
            }
        }
        for (stale[0..n]) |t| _ = traps.remove(t);
        if (n < stale.len) break;
    }
}

// alias maps page a second time, writable, so the stub can patch it while it
// stays frozen for every other thread. The caller deallocates it.
fn alias(page: u64) ?u64 {
    const task = mach_task_self();
    var tmp: u64 = 0;
    var cur: c_int = 0;
    var max: c_int = 0;
    if (mach_vm_remap(task, &tmp, PAGE, 0, VM_FLAGS_ANYWHERE, task, page, 0, &cur, &max, VM_INHERIT_NONE) != 0) return null;
    if (mach_vm_protect(task, tmp, PAGE, 0, PROT_READ | PROT_WRITE) != 0) {
        _ = mach_vm_deallocate(task, tmp, PAGE);
        return null;
    }
    return tmp;
}

// stop takes a running page out of execution with the guest's own bytes, its
// svcs back where the traps were (a hot page cools), and the host protection
// of guest protection p.
fn stop(page: u64, p: u64) bool {
    if (hot.contains(page)) return cool(page, p);
    const kv = running.fetchRemove(page) orelse return setProt(page, PAGE, hostProt(p));
    if (kv.value.svc) with_svc -= 1;
    _ = unlearned.remove(page);
    // No thread may run the page while its svcs are put back.
    if (!setProt(page, PAGE, PROT_READ)) return false;
    if (traps.count() > 0) {
        // Traps that cannot be taken back stay known as traps.
        if (alias(page)) |tmp| {
            var it = traps.keyIterator();
            while (it.next()) |t| {
                if (t.* < page or t.* >= page + PAGE) continue;
                const w: *u32 = @ptrFromInt(tmp + (t.* - page));
                if (w.* == TRAP) w.* = SVC0;
            }
            _ = mach_vm_deallocate(mach_task_self(), tmp, PAGE);
            dropTraps(page, page + PAGE);
        }
    }
    return setProt(page, PAGE, hostProt(p));
}

// hasSvc reports whether the frozen page holds an svc #0.
fn hasSvc(page: u64) bool {
    const w: [*]const u32 = @ptrFromInt(page);
    for (w[0 .. PAGE / 4]) |x| {
        if (x == SVC0) return true;
    }
    return false;
}

// learn hands the pages run unanalyzed over, so a page with svcs is analyzed
// with every entry they give it, and stops the pages that ran and gained one.
fn learn() bool {
    while (unlearned.count() > 0) {
        const cap = (4096 - 128) / 16; // the slot scratch, in (page, pc) pairs
        const sc: [*]align(1) u64 = @ptrCast(sig.scratch());
        var n: usize = 0;
        var it = unlearned.iterator();
        while (it.next()) |kv| {
            if (n == cap) break;
            sc[2 * n] = kv.key_ptr.*;
            sc[2 * n + 1] = kv.value_ptr.*;
            n += 1;
        }
        for (0..n) |i| _ = unlearned.remove(sc[2 * i]);
        if (@as(i64, @bitCast(sig.codeCall(LC_ANON_LEARN, .{ n, 0, 0, 0, 0, 0 }))) < 0) return false;
        againStop(@ptrCast(sig.scratch()), 0);
    }
    return true;
}

// againStop stops the pages a call's reply at sc names after its n sites:
// they ran, and have a new entry to be analyzed with the next time they run.
fn againStop(sc: [*]align(1) const u32, n: u32) void {
    const more = sc[n];
    const qs: [*]align(1) const u64 = @ptrCast(&sc[n + 1]);
    for (qs[0..more]) |q| {
        if (!running.contains(q)) continue;
        if (find(q)) |j| _ = stop(q, regions.items[j].prot);
    }
}

// run rewrites the page at page, entered at pc, and makes it executable; a
// page of a shared mapping runs as a shadow (heat).
fn run(page: u64, pc: u64) bool {
    const i = find(page) orelse return false;
    const p = regions.items[i].prot;
    if (inIn(&sharedx, page) and !heat(page, p)) return false;
    if (!setProt(page, PAGE, PROT_READ)) return false;
    const svc = hasSvc(page);
    if (!svc and with_svc == 0) {
        running.ensureUnusedCapacity(gpa, 1) catch return fail(page, p);
        unlearned.put(gpa, page, pc) catch return fail(page, p);
        running.putAssumeCapacity(page, .{ .pc = pc, .traps = 0, .svc = false });
        if (setProt(page, PAGE, PROT_READ | PROT_EXEC)) return true;
        _ = stop(page, p);
        return false;
    }
    if (!learn()) return fail(page, p);
    const rr = sig.codeCall(LC_ANON_SITES, .{ page, pc, 0, 0, 0, 0 });
    if (@as(i64, @bitCast(rr)) < 0) {
        _ = setProt(page, PAGE, hostProt(p));
        return false;
    }
    const n: u32 = @intCast(rr);
    const sc: [*]align(1) const u32 = @ptrCast(sig.scratch());
    running.ensureUnusedCapacity(gpa, 1) catch return fail(page, p);
    traps.ensureUnusedCapacity(gpa, n) catch return fail(page, p);
    var placed: u32 = 0;
    if (n > 0) {
        const tmp = alias(page) orelse return fail(page, p);
        for (sc[0..n]) |off| {
            if (off % 4 != 0 or off + 4 > PAGE) continue;
            const w: *u32 = @ptrFromInt(tmp + off);
            if (w.* != SVC0) continue;
            w.* = TRAP;
            traps.putAssumeCapacity(page + off, {});
            placed += 1;
        }
        _ = mach_vm_deallocate(mach_task_self(), tmp, PAGE);
        sys_icache_invalidate(@ptrFromInt(page), PAGE);
    }
    running.putAssumeCapacity(page, .{ .pc = pc, .traps = placed, .svc = svc });
    if (svc) with_svc += 1;
    if (hot.get(page)) |h| placeExcl(page, h.id);
    if (!setProt(page, PAGE, PROT_READ | PROT_EXEC)) {
        _ = stop(page, p);
        return false;
    }
    againStop(sc, n);
    return true;
}

fn fail(page: u64, p: u64) bool {
    _ = setProt(page, PAGE, hostProt(p));
    return false;
}

// selfWrite makes a running page whose own code writes into it a MAP_JIT page,
// read+write+execute (see the top of this file): the traps it has stay, and
// what is written there from then on runs unrewritten.
fn selfWrite(page: u64) bool {
    const kv = running.fetchRemove(page) orelse return false;
    if (kv.value.svc) with_svc -= 1;
    _ = unlearned.remove(page);
    jitted.put(gpa, page, {}) catch return false;
    if (jit.protect(page, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        _ = jitted.remove(page);
        return false;
    }
    cut(page, page + PAGE);
    return true;
}

// ---- the fault handler ----------------------------------------------------------

pub const Verdict = enum { other, handled, retry, real, step, attach, wait, hot, cool };

// Step is what a fault asks of the thread for a store into code (step):
// words, the guest's instructions at start, to run out of line (ool.zig),
// hold kept meanwhile, and whether the store may run again in place instead
// (again); or, with fail, the store exclusive to fail, its status register
// taking 1 and the guest going on after it. attach: hold, for the run out of
// line the store is part of to keep. retry: handled, a store that may lose to
// a thread running its page (ool.tried). In: whether the fault is the
// thread's run out of line (from_slot), the stub's own (own), or a store that
// ran again in place and lost (lost).
pub const Step = struct {
    words: [ool.MAX]u32 = undefined,
    n: u32 = 0,
    start: u64 = 0,
    fail: ?u5 = null,
    hold: u64 = 0,
    again: bool = false,
    gen: u32 = 0,
    id: service.Page = .{ .obj = 0, .off = 0 },
    from_slot: bool = false,
    own: bool = false,
    lost: bool = false,
};

// fault decides an abort at far (pc, esr) the stub takes: one this file
// handles (the access is retried), a real fault of such a page, or none of
// its business.
pub fn fault(esr: u32, far: u64, pc: u64, st: *Step) Verdict {
    const ec = esr >> 26;
    if (ec != 0x20 and ec != 0x24) return .other; // instruction and data aborts from EL0
    const fsc = esr & 0x3c;
    // Translation, access flag and permission faults: a page mapped afresh
    // (one a shared page cools into) has its access flag clear, and a fetch
    // from it while it may not run reports that first.
    if (fsc != 0x04 and fsc != 0x08 and fsc != 0x0c) return .other;
    const page = far & ~(PAGE - 1);
    lock();
    defer unlock();
    if (ec == 0x24 and esr & (1 << 6) != 0) {
        if (frozen.get(page)) |f| {
            // A write through a mapping frozen for a hot page: the page cools,
            // in another process too, and the store runs held (storeHeld).
            if (remote(f.id)) return coolAsk(f.id, st);
            if (!thaw(f.id)) return .real;
            return storeHeld(f.id, far, pc, st);
        }
    }
    const i = find(page) orelse {
        // A page selfWrite made MAP_JIT is unmapped while it is mapped again:
        // an access then was made too early.
        if (fsc == 0x04 and jitted.contains(page)) return .handled;
        // A write to a shared page frozen for a hot one, which another thread
        // thawed meanwhile: the host never maps a shared page executable, so
        // one writable now refused the write only while frozen, or as another
        // view of its memory was remapped, which the host reports as no page
        // there at all. A page of a file mapping past the file's end has none
        // for real, and the fault is the guest's.
        if (ec == 0x24 and esr & (1 << 6) != 0 and !(fsc == 0x04 and mem.pastEnd(far))) {
            if (regionAt(page)) |r| {
                if (r.lo <= page and r.inherit == VM_INHERIT_SHARE and r.prot & PROT_WRITE != 0) return .handled;
            }
        }
        return .other;
    };
    const p = regions.items[i].prot;
    if (ec == 0x20) {
        if (running.contains(page)) return .handled; // made to run meanwhile
        if (heldPage(page) or (stopped and inIn(&sharedx, page))) {
            st.gen = wake_gen;
            return .wait;
        }
        if (inIn(&sharedx, page)) {
            if (holdAsk(page, st)) |v| return v;
        }
        return if (run(page, pc)) .handled else .real;
    }
    if (esr & (1 << 6) == 0) return .other; // a read: such a page always reads
    if (p & PROT_WRITE == 0) return .real;
    if (!running.contains(page)) {
        // Stopped meanwhile, or frozen for a rewrite that has made it run.
        return if (setProt(page, PAGE, hostProt(p))) .handled else .real;
    }
    if (hot.get(page)) |h| {
        if (remote(h.id)) return coolAsk(h.id, st);
    }
    if (pc & ~(PAGE - 1) == page and !st.from_slot) {
        if (hot.contains(page)) return selfStore(page, p, pc, st);
        return if (selfWrite(page)) .handled else .real;
    }
    const id = memOf(page);
    if (!stop(page, p)) return .real;
    return storeHeld(id, far, pc, st);
}

// storeHeld readies a write at pc into memory id at addr, just taken out of
// execution, from code elsewhere: the store runs again in place (retry). One
// that lost to a thread that ran the memory again before it landed runs out
// of line, the memory held (st), so none can before it lands: a store
// exclusive, whose monitor the fault lost, with its window from its load
// exclusive, when that runs the same again (ool.rerunnable), its memory
// touched first, as a fault in the window would lose the monitor again. A
// store already run out of line keeps the hold until its run ends (attach);
// the stub's own, and one that cannot run out of line, runs again in place.
fn storeHeld(id: ObjPage, addr: u64, pc: u64, st: *Step) Verdict {
    if (st.own) return .handled;
    if (st.from_slot) {
        st.hold = holdMem(id);
        return .attach;
    }
    if (!st.lost) return .retry;
    const w = @as(*const u32, @ptrFromInt(pc)).*;
    if (ool.storeExclusive(w)) {
        const cp = pc & ~(PAGE - 1);
        const n = ool.window(@ptrFromInt(cp), cp, pc, w) orelse return .handled;
        @memcpy(st.words[0..n], @as([*]const u32, @ptrFromInt(pc - 4 * (n - 1)))[0..n]);
        if (!ool.rerunnable(st.words[0..n])) return .handled;
        st.n = n;
        st.start = pc - 4 * (n - 1);
        _ = @atomicRmw(u8, @as(*u8, @ptrFromInt(addr)), .Add, 0, .monotonic);
    } else {
        st.words[0] = w;
        st.n = 1;
        st.start = pc;
    }
    st.hold = holdMem(id);
    st.again = true;
    return .step;
}

// memOf is the memory page is: a shared mapping's VM object and offset, else
// its address.
fn memOf(page: u64) ObjPage {
    if (hot.get(page)) |h| return h.id;
    if (inIn(&sharedx, page)) {
        if (regionAt(page)) |r| {
            if (r.lo <= page and r.inherit == VM_INHERIT_SHARE) return .{ .obj = r.obj, .off = r.off + (page - r.lo) };
        }
    }
    return .{ .obj = 0, .off = page };
}

fn holdMem(id: ObjPage) u64 {
    for (&holds, 0..) |*h, k| {
        if (h.used) continue;
        h.* = .{ .id = id, .used = true };
        nholds += 1;
        return k + 1;
    }
    return 0;
}

fn heldMem(id: ObjPage) bool {
    if (nholds == 0) return false;
    for (holds) |h| {
        if (h.used and h.id.obj == id.obj and h.id.off == id.off) return true;
    }
    return false;
}

fn heldPage(page: u64) bool {
    return nholds != 0 and heldMem(memOf(page));
}

// letGo ends hold id.
pub fn letGo(id: u64) void {
    if (id == 0) return;
    lock();
    defer unlock();
    if (holds[id - 1].used) nholds -= 1;
    holds[id - 1].used = false;
    wake();
}

pub const TrapVerdict = enum { no, trap, again, excl };

// isTrap reports whether the undefined instruction at pc was a trap the stub
// placed for an svc, or one a stop has just taken back: the svc then runs
// rewritten anew; or a trap of an exclusive window (exclTrap).
pub fn isTrap(pc: u64) TrapVerdict {
    lock();
    defer unlock();
    const w = @as(*const u32, @ptrFromInt(pc)).*;
    if (w == TRAP and traps.contains(pc)) return .trap;
    if (w == TRAP and xtraps.contains(pc)) return .excl;
    // A load exclusive is never undefined: one that faulted so was a trap of
    // a window, read before its page cooled.
    if (ool.loadExclusive(w) and find(pc) != null) return .again;
    if (w == SVC0 and find(pc) != null and !running.contains(pc & ~(PAGE - 1))) return .again;
    return .no;
}

// trapFile records a trap placed in file code, where an svc found no island.
pub fn trapFile(pc: u64) bool {
    lock();
    defer unlock();
    traps.put(gpa, pc, {}) catch return false;
    return true;
}

// ---- mappings (mem.zig) ------------------------------------------------------------

// protect gives the guest's protection prot to [lo, lo+n), the host's through
// jit.protect: code the guest made executable without it being file code it
// has not written (emulate) is emulated as above.
pub fn protect(lo: u64, n: u64, prot: u64, emulate: bool, shared: bool) u64 {
    lock();
    defer unlock();
    reset(lo, lo + n);
    dropKeys(void, &jitted, lo, lo + n);
    cutIn(&sharedx, lo, lo + n);
    if (!emulate) {
        cut(lo, lo + n);
        const r = jit.protect(lo, n, prot);
        if (r == 0 and shared and prot & PROT_WRITE != 0) bornFrozen(lo, lo + n);
        return r;
    }
    const r = jit.protect(lo, n, @intCast(hostProt(prot)));
    if (r == 0 and !insert(lo, lo + n, prot)) return @bitCast(-ENOMEM);
    if (r == 0 and shared) {
        _ = insertIn(&sharedx, lo, lo + n, prot);
        if (prot & PROT_WRITE != 0) bornFrozen(lo, lo + n);
    }
    return r;
}

// mapped records a fresh mapping of [lo, lo+n), emulated with guest
// protection prot when emulate, whatever was there before gone.
pub fn mapped(lo: u64, n: u64, prot: u64, emulate: bool, shared: bool) void {
    lock();
    defer unlock();
    forget(lo, lo + n);
    cut(lo, lo + n);
    cutIn(&dirty_, lo, lo + n);
    cutIn(&sharedx, lo, lo + n);
    if (emulate) _ = insert(lo, lo + n, prot);
    if (emulate and shared) _ = insertIn(&sharedx, lo, lo + n, prot);
    if (shared and prot & PROT_WRITE != 0) bornFrozen(lo, lo + n);
}

// aliased records [dst, dst+n), a second mapping of the shared memory at
// [old, old+n) (mremap with no old size), as old's is known: its emulated
// code emulated alike, its writable pages over hot ones frozen.
pub fn aliased(old: u64, dst: u64, n: u64) void {
    lock();
    defer unlock();
    forget(dst, dst + n);
    cut(dst, dst + n);
    cutIn(&sharedx, dst, dst + n);
    moveIn(&regions, old, n, dst, n, true);
    moveIn(&sharedx, old, n, dst, n, true);
    bornFrozen(dst, dst + n);
}

// unmapped forgets [lo, hi).
pub fn unmapped(lo: u64, hi: u64) void {
    lock();
    defer unlock();
    forget(lo, hi);
    cut(lo, hi);
    cutIn(&dirty_, lo, hi);
    cutIn(&sharedx, lo, hi);
}

// dirty records that the guest may write the file code in [lo, hi).
pub fn dirty(lo: u64, hi: u64) void {
    lock();
    defer unlock();
    _ = insertIn(&dirty_, lo, hi, 0);
}

pub fn dirtyIn(lo: u64, hi: u64) bool {
    lock();
    defer unlock();
    for (dirty_.items) |r| {
        if (r.lo < hi and lo < r.hi) return true;
    }
    return false;
}

// hold and release keep the tables still across a change of the mappings
// that must not interleave with a rewrite.
pub fn hold() void {
    lock();
}

pub fn release() void {
    unlock();
}

// reset stops the pages of [lo, hi) that run, before their memory is moved,
// discarded or given another protection.
pub fn reset(lo: u64, hi: u64) void {
    lock();
    defer unlock();
    thawIn(lo, hi);
    if (running.count() == 0) return;
    var page = lo & ~(PAGE - 1);
    while (page < hi) : (page += PAGE) {
        if (!running.contains(page)) continue;
        const i = find(page) orelse {
            forget(page, page + PAGE);
            continue;
        };
        _ = stop(page, regions.items[i].prot);
    }
}

// settle freezes what of [lo, hi), reset for a change that left it mapped
// (madvise), maps memory with a hot page.
pub fn settle(lo: u64, hi: u64) void {
    lock();
    defer unlock();
    bornFrozen(lo, hi);
}

// moved records [old, old+on) moved to dst and n bytes long there, the part
// past on fresh memory like the last page; with keep, the old range stays
// mapped as it was.
pub fn moved(old: u64, on: u64, dst: u64, n: u64, keep: bool) void {
    lock();
    defer unlock();
    forget(old, old + on);
    moveIn(&regions, old, on, dst, n, keep);
    moveIn(&dirty_, old, on, dst, n, keep);
    moveIn(&sharedx, old, on, dst, n, keep);
    bornFrozen(dst, dst + n);
}

fn moveIn(l: *List, old: u64, on: u64, dst: u64, n: u64, keep: bool) void {
    var add: [64]Region = undefined;
    var k: usize = 0;
    var tail: ?u64 = null;
    for (l.items) |r| {
        if (r.hi <= old or r.lo >= old + on or k == add.len) continue;
        const lo = @max(r.lo, old);
        const hi = @min(r.hi, old + on);
        if (hi == old + on) tail = r.prot;
        if (lo - old >= n) continue;
        add[k] = .{ .lo = lo - old + dst, .hi = @min(hi - old, n) + dst, .prot = r.prot };
        k += 1;
    }
    if (!keep) cutIn(l, old, old + on);
    cutIn(l, dst, dst + n);
    for (add[0..k]) |r| _ = insertIn(l, r.lo, r.hi, r.prot);
    if (n > on) {
        if (tail) |p| _ = insertIn(l, dst + on, dst + n, p);
    }
}

// protAt is the guest protection of the emulated memory at addr, and where
// that run of it ends; null outside it.
pub fn protAt(addr: u64) ?Region {
    lock();
    defer unlock();
    const i = find(addr) orelse return null;
    return regions.items[i];
}

// frozenProt is the guest's protection of addr's page while it is frozen
// for a hot page, else null.
pub fn frozenProt(addr: u64) ?u64 {
    lock();
    defer unlock();
    const f = frozen.get(addr & ~(PAGE - 1)) orelse return null;
    return f.prot;
}

// nextAt is where the first emulated region at or above addr starts, or
// maxInt.
pub fn nextAt(addr: u64) u64 {
    lock();
    defer unlock();
    for (regions.items) |r| {
        if (r.hi > addr) return @max(r.lo, addr);
    }
    return std.math.maxInt(u64);
}

// clear forgets everything, at an exec.
pub fn clear() void {
    lock();
    defer unlock();
    dropHot(0, std.math.maxInt(u64));
    frozen.clearRetainingCapacity();
    registered.clearRetainingCapacity();
    excl.clearRetainingCapacity();
    xtraps.clearRetainingCapacity();
    holds = [_]Hold{.{}} ** holds.len;
    nholds = 0;
    sharedx.clearRetainingCapacity();
    regions.clearRetainingCapacity();
    dirty_.clearRetainingCapacity();
    running.clearRetainingCapacity();
    with_svc = 0;
    unlearned.clearRetainingCapacity();
    traps.clearRetainingCapacity();
    jitted.clearRetainingCapacity();
}

// ---- fork (sfork.zig) ----------------------------------------------------------------

// forkLock holds the tables still across a fork's walk of the memory, which
// copies running pages as they are, traps and all; forkUnlock releases them.
// The hot pages cool first, for the child to share their memory, not copy
// their shadows.
pub fn forkLock() void {
    lock();
    // The child shares the memory: what this process holds is held anew,
    // the child told.
    registered.clearRetainingCapacity();
    while (hot.count() > 0) {
        var it = hot.keyIterator();
        const page = it.next().?.*;
        const i = find(page) orelse {
            dropHot(page, page + PAGE);
            continue;
        };
        _ = cool(page, regions.items[i].prot);
    }
}

pub fn forkUnlock() void {
    unlock();
}

const ForkHead = extern struct { nregion: u64, ndirty: u64, nrunning: u64, ntrap: u64, nsharedx: u64, nfrozen: u64, nremote: u64 };
const FrozenRec = extern struct { page: u64, obj: u32, pad: u32 = 0, off: u64, prot: u64 };
const Running = extern struct { page: u64, pc: u64, traps: u32, svc: u32 };

pub fn forkSave(buf: *std.ArrayList(u8)) bool {
    const h = ForkHead{ .nregion = regions.items.len, .ndirty = dirty_.items.len, .nrunning = running.count(), .ntrap = traps.count(), .nsharedx = sharedx.items.len, .nfrozen = frozen.count(), .nremote = remote_hot.count() };
    buf.appendSlice(std.mem.asBytes(&h)) catch return false;
    buf.appendSlice(std.mem.sliceAsBytes(regions.items)) catch return false;
    buf.appendSlice(std.mem.sliceAsBytes(dirty_.items)) catch return false;
    buf.appendSlice(std.mem.sliceAsBytes(sharedx.items)) catch return false;
    var it = running.iterator();
    while (it.next()) |kv| {
        const v = kv.value_ptr.*;
        const r = Running{ .page = kv.key_ptr.*, .pc = v.pc, .traps = v.traps, .svc = @intFromBool(v.svc) };
        buf.appendSlice(std.mem.asBytes(&r)) catch return false;
    }
    var t = traps.keyIterator();
    while (t.next()) |a| buf.appendSlice(std.mem.asBytes(a)) catch return false;
    // Its mappings frozen for another process's hot page stay so in the child,
    // with what they are frozen for.
    var ft = frozen.iterator();
    while (ft.next()) |kv| {
        const r = FrozenRec{ .page = kv.key_ptr.*, .obj = kv.value_ptr.id.obj, .off = kv.value_ptr.id.off, .prot = kv.value_ptr.prot };
        buf.appendSlice(std.mem.asBytes(&r)) catch return false;
    }
    var rt = remote_hot.keyIterator();
    while (rt.next()) |id| {
        const r = service.Page{ .obj = id.obj, .off = id.off };
        buf.appendSlice(std.mem.asBytes(&r)) catch return false;
    }
    return true;
}

// forkLoad takes over the tables forkSave wrote; b is advanced past them.
pub fn forkLoad(b: *[]const u8) bool {
    if (b.len < @sizeOf(ForkHead)) return false;
    const h = std.mem.bytesToValue(ForkHead, b.*[0..@sizeOf(ForkHead)]);
    b.* = b.*[@sizeOf(ForkHead)..];
    const nr = h.nregion * @sizeOf(Region);
    const nd = h.ndirty * @sizeOf(Region);
    const ns = h.nsharedx * @sizeOf(Region);
    const nu = h.nrunning * @sizeOf(Running);
    const nt = h.ntrap * 8;
    const nf = h.nfrozen * @sizeOf(FrozenRec);
    const nm = h.nremote * @sizeOf(service.Page);
    if (b.len < nr + nd + ns + nu + nt + nf + nm) return false;
    lock();
    defer unlock();
    clear(); // what the service thread heard (remote_hot) stays
    var rest = b.*;
    for (std.mem.bytesAsSlice(Region, @as([]align(1) const u8, rest[0..nr]))) |r| regions.append(gpa, r) catch return false;
    rest = rest[nr..];
    for (std.mem.bytesAsSlice(Region, @as([]align(1) const u8, rest[0..nd]))) |r| dirty_.append(gpa, r) catch return false;
    rest = rest[nd..];
    for (std.mem.bytesAsSlice(Region, @as([]align(1) const u8, rest[0..ns]))) |r| sharedx.append(gpa, r) catch return false;
    rest = rest[ns..];
    // The child's supervisor knows nothing of these pages yet: every one is
    // handed over before a page with svcs is analyzed.
    for (std.mem.bytesAsSlice(Running, @as([]align(1) const u8, rest[0..nu]))) |r| {
        running.put(gpa, r.page, .{ .pc = r.pc, .traps = r.traps, .svc = r.svc != 0 }) catch return false;
        if (r.svc != 0) with_svc += 1;
        unlearned.put(gpa, r.page, r.pc) catch return false;
    }
    rest = rest[nu..];
    for (std.mem.bytesAsSlice(u64, @as([]align(1) const u8, rest[0..nt]))) |a| traps.put(gpa, a, {}) catch return false;
    rest = rest[nt..];
    for (std.mem.bytesAsSlice(FrozenRec, @as([]align(1) const u8, rest[0..nf]))) |r| frozen.put(gpa, r.page, .{ .id = .{ .obj = r.obj, .off = r.off }, .prot = r.prot }) catch return false;
    rest = rest[nf..];
    for (std.mem.bytesAsSlice(service.Page, @as([]align(1) const u8, rest[0..nm]))) |r| remote_hot.put(gpa, .{ .obj = r.obj, .off = r.off }, {}) catch return false;
    b.* = rest[nm..];
    // Mappings of memory held elsewhere since the parent's walk freeze now.
    var it = remote_hot.keyIterator();
    while (it.next()) |id| freezeViews(id.*);
    return true;
}

// ---- shared code ---------------------------------------------------------------

fn inIn(l: *List, addr: u64) bool {
    for (l.items) |r| {
        if (addr >= r.lo and addr < r.hi) return true;
    }
    return false;
}

// vm_region_basic_info_64 is 4-byte packed (its u64 offset sits at 20).
const BasicInfo = extern struct { prot: i32, maxprot: i32, inherit: u32, shared: i32, reserved: i32, offset: [2]u32, behavior: i32, wired: u16, pad: u16 };
const TopInfo = extern struct { obj_id: u32, ref_count: u32, private_resident: u32, shared_resident: u32, share_mode: u8, pad: [3]u8 };

// Region0 is the host region at or above an address: its range, protection,
// inheritance, VM object and offset in it.
const Region0 = struct { lo: u64, hi: u64, prot: u64, inherit: u32, obj: u32, off: u64 };

fn regionAt(addr: u64) ?Region0 {
    const task = mach_task_self();
    var a = addr;
    var size: u64 = 0;
    var bi: BasicInfo = undefined;
    var count: c_uint = @sizeOf(BasicInfo) / 4;
    var obj: c_uint = 0;
    if (mach_vm_region(task, &a, &size, VM_REGION_BASIC_INFO_64, &bi, &count, &obj) != 0) return null;
    if (obj != 0) _ = mach_port_deallocate(task, obj);
    var t = a;
    var tsize: u64 = 0;
    var ti: TopInfo = undefined;
    var tcount: c_uint = @sizeOf(TopInfo) / 4;
    if (mach_vm_region(task, &t, &tsize, VM_REGION_TOP_INFO, &ti, &tcount, &obj) != 0) return null;
    if (obj != 0) _ = mach_port_deallocate(task, obj);
    return .{ .lo = a, .hi = a + size, .prot = @intCast(bi.prot & 7), .inherit = bi.inherit, .obj = ti.obj_id, .off = @as(u64, bi.offset[1]) << 32 | bi.offset[0] };
}

// eachView calls f with every page of a shared mapping in [lo, hi) that maps
// memory of id, and the host region it lies in.
fn eachView(lo: u64, hi: u64, id: ObjPage, f: *const fn (u64, Region0, ObjPage) void) void {
    var a = lo;
    while (a < hi) {
        const r = regionAt(a) orelse return;
        if (r.lo >= hi) return;
        if (r.inherit == VM_INHERIT_SHARE and r.obj == id.obj and id.off >= r.off and id.off < r.off + (r.hi - r.lo)) {
            const v = r.lo + (id.off - r.off);
            if (v >= lo and v < hi) f(v, r, id);
        }
        a = r.hi;
    }
}

// freeze makes page v, a writable mapping of memory id runs as a shadow,
// read-only while it does.
fn freeze(v: u64, r: Region0, id: ObjPage) void {
    if (v == heating or hot.contains(v) or frozen.contains(v) or r.prot & PROT_WRITE == 0) return;
    const prot: u64 = if (find(v)) |j| regions.items[j].prot else r.prot;
    frozen.put(gpa, v, .{ .id = id, .prot = prot }) catch return;
    if (!setProt(v, PAGE, PROT_READ)) _ = frozen.remove(v);
}

// freezeViews freezes every writable mapping of memory id the guest has.
fn freezeViews(id: ObjPage) void {
    mem.eachShared(id, freezeIn);
}

fn freezeIn(id: ObjPage, lo: u64, hi: u64) void {
    eachView(lo, hi, id, freeze);
}

// bornFrozen freezes the pages of [lo, hi), just mapped or made writable,
// whose memory has a hot page.
fn bornFrozen(lo: u64, hi: u64) void {
    if (hot.count() == 0 and remote_hot.count() == 0) return;
    var a = lo;
    while (a < hi) {
        const r = regionAt(a) orelse return;
        if (r.lo >= hi) return;
        if (r.inherit == VM_INHERIT_SHARE and r.prot & PROT_WRITE != 0) {
            var it = hot.valueIterator();
            while (it.next()) |h| viewIn(r, lo, hi, h.id);
            var rt = remote_hot.keyIterator();
            while (rt.next()) |id| viewIn(r, lo, hi, id.*);
        }
        a = r.hi;
    }
}

// viewIn freezes the page of host region r, in [lo, hi), that maps memory id.
fn viewIn(r: Region0, lo: u64, hi: u64, id: ObjPage) void {
    if (r.obj != id.obj or id.off < r.off or id.off >= r.off + (r.hi - r.lo)) return;
    const v = r.lo + (id.off - r.off);
    if (v >= lo and v < hi) freeze(v, r, id);
}

// heat makes page, of a shared mapping with guest protection p, a shadow of
// its memory: the writable mappings of that memory frozen, a keeper holding
// it, and a private copy of its bytes in its place.
fn heat(page: u64, p: u64) bool {
    if (hot.contains(page)) return true;
    const r = regionAt(page) orelse return false;
    if (page < r.lo) return false;
    const id = ObjPage{ .obj = r.obj, .off = r.off + (page - r.lo) };
    // No store reaches the memory through this mapping while it is copied:
    // it would be missing from the copy.
    if (!setProt(page, PAGE, PROT_READ)) return false;
    heating = page;
    freezeViews(id);
    heating = 0;
    const task = mach_task_self();
    var keeper: u64 = 0;
    var cur: c_int = 0;
    var max: c_int = 0;
    if (mach_vm_remap(task, &keeper, PAGE, 0, VM_FLAGS_ANYWHERE, task, page, 0, &cur, &max, VM_INHERIT_NONE) != 0) return fail(page, p);
    hot.ensureUnusedCapacity(gpa, 1) catch {
        _ = mach_vm_deallocate(task, keeper, PAGE);
        return fail(page, p);
    };
    // The copy is made aside and takes the page's place whole and read-only,
    // so no store lands in it half made, to be lost. It stands in for a
    // shared mapping, as which mem.zig knows it by its inheritance (a fork
    // cools it first).
    const tmp = mmap(null, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (tmp == null or @intFromPtr(tmp) == std.math.maxInt(usize)) {
        _ = mach_vm_deallocate(task, keeper, PAGE);
        return fail(page, p);
    }
    @memcpy(@as([*]u8, @ptrCast(tmp))[0..PAGE], @as([*]const u8, @ptrFromInt(keeper))[0..PAGE]);
    var dst = page;
    const ok = mprotect(tmp.?, PAGE, PROT_READ) == 0 and
        mach_vm_remap(task, &dst, PAGE, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, task, @intFromPtr(tmp), 0, &cur, &max, VM_INHERIT_SHARE) == 0;
    _ = mach_vm_deallocate(task, @intFromPtr(tmp), PAGE);
    if (!ok) {
        _ = mach_vm_deallocate(task, keeper, PAGE);
        return fail(page, p);
    }
    sys_icache_invalidate(@ptrFromInt(page), PAGE);
    hot.putAssumeCapacity(page, .{ .id = id, .keeper = keeper });
    return true;
}

// cool takes hot page, of guest protection p, out of execution: it maps its
// memory again, from its keeper, with the host protection of p, and the
// mappings frozen for it thaw.
fn cool(page: u64, p: u64) bool {
    const kv = hot.fetchRemove(page) orelse return false;
    if (running.fetchRemove(page)) |rk| {
        if (rk.value.svc) with_svc -= 1;
    }
    _ = unlearned.remove(page);
    dropTraps(page, page + PAGE);
    dropAddrs(&xtraps, page, page + PAGE);
    const task = mach_task_self();
    var dst = page;
    var cur: c_int = 0;
    var max: c_int = 0;
    const ok = mach_vm_remap(task, &dst, PAGE, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, task, kv.value.keeper, 0, &cur, &max, VM_INHERIT_SHARE) == 0;
    _ = mach_vm_deallocate(task, kv.value.keeper, PAGE);
    thawId(kv.value.id);
    return ok and setProt(page, PAGE, hostProt(p));
}

// thaw cools the hot pages of memory id, for a write through a mapping
// frozen for them; with none left, the mappings thaw.
fn thaw(id: ObjPage) bool {
    var ok = true;
    while (true) {
        var page: ?u64 = null;
        var it = hot.iterator();
        while (it.next()) |kv| {
            if (std.meta.eql(kv.value_ptr.id, id)) page = kv.key_ptr.*;
        }
        const pg = page orelse break;
        const i = find(pg) orelse {
            dropHot(pg, pg + PAGE);
            continue;
        };
        ok = cool(pg, regions.items[i].prot) and ok;
    }
    thawId(id);
    return ok;
}

// thawId gives the mappings frozen for memory id their protection back.
fn thawId(id: ObjPage) void {
    var gone: [64]u64 = undefined;
    while (true) {
        var n: usize = 0;
        var it = frozen.iterator();
        while (it.next()) |kv| {
            if (std.meta.eql(kv.value_ptr.id, id) and n < gone.len) {
                gone[n] = kv.key_ptr.*;
                n += 1;
            }
        }
        for (gone[0..n]) |v| {
            const f = frozen.fetchRemove(v).?.value;
            _ = setProt(v, PAGE, if (find(v) != null) hostProt(f.prot) else @intCast(f.prot));
        }
        if (n < gone.len) break;
    }
}

// thawIn gives the frozen pages of [lo, hi) their protection back, before
// their mapping moves or changes.
fn thawIn(lo: u64, hi: u64) void {
    var gone: [64]u64 = undefined;
    while (frozen.count() > 0) {
        var n: usize = 0;
        var it = frozen.keyIterator();
        while (it.next()) |k| {
            if (k.* >= lo and k.* < hi and n < gone.len) {
                gone[n] = k.*;
                n += 1;
            }
        }
        for (gone[0..n]) |v| {
            const f = frozen.fetchRemove(v).?.value;
            _ = setProt(v, PAGE, if (find(v) != null) hostProt(f.prot) else @intCast(f.prot));
        }
        if (n < gone.len) break;
    }
}

// ---- stores into the page that runs them ---------------------------------------

// selfStore serves a store hot page's own code makes into it, from pc: the
// page cools and the store runs out of line. A store exclusive no trapped
// load exclusive ran the window of fails, and its window is learned.
fn selfStore(page: u64, p: u64, pc: u64, st: *Step) Verdict {
    const w = @as(*const u32, @ptrFromInt(pc)).*;
    if (ool.storeExclusive(w)) {
        learnExcl(page, pc, w);
        st.fail = ool.statusReg(w);
        return .step;
    }
    st.words[0] = w;
    st.n = 1;
    st.start = pc;
    const id = memOf(page);
    if (!cool(page, p)) return .real;
    st.hold = holdMem(id);
    return .step;
}

// learnExcl records the window store exclusive w at pc, of hot page page,
// closes: from the nearest load exclusive before it on the page, if that one
// takes the same base, size and pairing. Its load exclusive is trapped now.
fn learnExcl(page: u64, pc: u64, w: u32) void {
    const h = hot.get(page) orelse return;
    var at = pc;
    var n: u32 = 1;
    while (at > page and n < ool.MAX) {
        at -= 4;
        n += 1;
        const l = @as(*const u32, @ptrFromInt(at)).*;
        if (!ool.loadExclusive(l)) continue;
        if (!ool.pairOf(l, w)) return;
        const key = ExclKey{ .obj = h.id.obj, .off = h.id.off, .at = @intCast(at - page) };
        excl.put(gpa, key, .{ .n = n, .ldx = l }) catch return;
        trapExcl(page, key, l);
        return;
    }
}

// placeExcl traps the load exclusives of the windows learned for memory id
// in hot page page, just rewritten.
fn placeExcl(page: u64, id: ObjPage) void {
    var it = excl.iterator();
    while (it.next()) |kv| {
        if (kv.key_ptr.obj == id.obj and kv.key_ptr.off == id.off) trapExcl(page, kv.key_ptr.*, kv.value_ptr.ldx);
    }
}

// trapExcl traps load exclusive l at its window's place in hot page page,
// if it is still there.
fn trapExcl(page: u64, key: ExclKey, l: u32) void {
    const at = page + key.at;
    if (@as(*const u32, @ptrFromInt(at)).* != l) return;
    xtraps.put(gpa, at, key) catch return;
    const tmp = alias(page) orelse {
        _ = xtraps.remove(at);
        return;
    };
    @as(*u32, @ptrFromInt(tmp + key.at)).* = TRAP;
    _ = mach_vm_deallocate(mach_task_self(), tmp, PAGE);
    sys_icache_invalidate(@ptrFromInt(at), 4);
}

// exclTrap serves the trapped load exclusive at pc: its page cools and its
// window runs out of line (st), from the load exclusive.
pub fn exclTrap(pc: u64, st: *Step) Verdict {
    lock();
    defer unlock();
    const key = xtraps.get(pc) orelse return .handled; // cooled meanwhile: it runs anew
    const page = pc & ~(PAGE - 1);
    const e = excl.get(key) orelse return .real;
    const i = find(page) orelse return .real;
    const w: [*]const u32 = @ptrFromInt(pc);
    st.words[0] = e.ldx;
    st.n = 1;
    while (st.n < e.n and pc + 4 * st.n < page + PAGE) : (st.n += 1) st.words[st.n] = w[st.n];
    st.start = pc;
    const id = memOf(page);
    if (!cool(page, regions.items[i].prot)) return .real;
    st.hold = holdMem(id); // 0, none left: run unheld, its store may fail
    return .step;
}

fn wake() void {
    _ = @atomicRmw(u32, &wake_gen, .Add, 1, .release);
    _ = __ulock_wake(UL_COMPARE_AND_WAIT | ULF_WAKE_ALL | ULF_NO_ERRNO, &wake_gen, 0);
}

// waitWindow waits, for a thread that would run a page, for what keeps it
// from running since gen to end: a window held, or a stop.
pub fn waitWindow(gen: u32) void {
    while (@atomicLoad(u32, &wake_gen, .acquire) == gen) _ = __ulock_wait(UL_COMPARE_AND_WAIT | ULF_NO_ERRNO, &wake_gen, gen, 0);
}

// ---- shared code across processes ---------------------------------------------

// alone reports whether this process is the run's only one: none other can
// map its memory.
fn alone() bool {
    return sig.runProcs() <= 1;
}

// remote reports whether memory id is, for all this process knows, run as a
// hot page in another.
fn remote(id: ObjPage) bool {
    return remote_hot.contains(id) and !alone();
}

fn coolAsk(id: ObjPage, st: *Step) Verdict {
    st.id = .{ .obj = id.obj, .off = id.off };
    st.gen = freezes;
    return .cool;
}

// holdAsk is what running shared page page waits for: the broker's HOT, when
// this process does not hold its memory there yet and is not the run's only
// one; null if it may run now.
fn holdAsk(page: u64, st: *Step) ?Verdict {
    if (alone()) return null;
    const r = regionAt(page) orelse return null;
    if (page < r.lo) return null;
    const id = ObjPage{ .obj = r.obj, .off = r.off + (page - r.lo) };
    if (registered.contains(id)) return null;
    st.id = .{ .obj = id.obj, .off = id.off };
    return .hot;
}

// holding records that the broker has made this process a holder of p (HOT):
// its pages of that memory may run.
pub fn holding(p: service.Page) void {
    lock();
    defer unlock();
    registered.put(gpa, .{ .obj = p.obj, .off = p.off }, {}) catch {};
}

// cooled follows the broker's COOL of p, asked when freezes stood at gen:
// the page is cool everywhere else, so it cools here and the mappings thaw,
// unless a FREEZE has come since (a HOT after the COOL), when the write
// faults and asks again.
pub fn cooled(p: service.Page, gen: u32) void {
    lock();
    defer unlock();
    if (freezes != gen) return;
    const id = ObjPage{ .obj = p.obj, .off = p.off };
    _ = thaw(id);
    _ = remote_hot.remove(id);
}

// The broker's requests, which the service thread serves (service.zig).
pub const code = service.Code{ .held = svcHeld, .freeze = svcFreeze, .cool = svcCool, .coolFile = svcCoolFile, .stop = svcStop, .go = svcGo };

fn svcHeld(pages: []const service.Page) void {
    for (pages) |p| svcFreeze(p);
}

fn svcFreeze(p: service.Page) void {
    lock();
    defer unlock();
    const id = ObjPage{ .obj = p.obj, .off = p.off };
    while (heldMem(id)) { // once what is held of it lands
        const gen = @atomicLoad(u32, &wake_gen, .acquire);
        unlock();
        waitWindow(gen);
        lock();
    }
    freezes +%= 1;
    remote_hot.put(gpa, id, {}) catch {};
    freezeViews(id);
}

fn svcCool(p: service.Page) void {
    lock();
    defer unlock();
    const id = ObjPage{ .obj = p.obj, .off = p.off };
    _ = registered.remove(id);
    _ = thaw(id);
}

// svcCoolFile cools the hot pages of the file with inode ino, which the
// supervisor wrote.
fn svcCoolFile(ino: u64) void {
    lock();
    defer unlock();
    while (true) {
        var gone: [64]u64 = undefined;
        var n: usize = 0;
        var it = hot.keyIterator();
        while (it.next()) |k| {
            const f = mem.fileOf(k.*) orelse continue;
            if (f[1] == ino and n < gone.len) {
                gone[n] = k.*;
                n += 1;
            }
        }
        for (gone[0..n]) |page| {
            if (find(page)) |i| _ = cool(page, regions.items[i].prot) else dropHot(page, page + PAGE);
        }
        if (n < gone.len) return;
    }
}

// svcStop readies the process for a host stop: its hot pages cool, and it
// heats none until svcGo, so it holds none while it cannot answer.
fn svcStop() void {
    lock();
    defer unlock();
    stopped = true;
    registered.clearRetainingCapacity();
    while (hot.count() > 0) {
        var it = hot.keyIterator();
        const page = it.next().?.*;
        const i = find(page) orelse {
            dropHot(page, page + PAGE);
            continue;
        };
        _ = cool(page, regions.items[i].prot);
    }
}

fn svcGo() void {
    lock();
    defer unlock();
    stopped = false;
    wake();
}
