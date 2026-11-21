// mem.zig — the guest's memory syscalls, served in-stub: the guest shares this
// task's address space, so mmap, munmap, mremap, brk, madvise, msync, mincore
// and the mlock family need no supervisor round trip. A file mapping asks the
// supervisor for the host fd behind the guest fd (LC_MMAPFD; it arrives over
// fdlink) and then maps it here directly.
//
// Darwin arm64 pages are 16 KiB and AT_PAGESZ says so; a file offset that is
// only 4 KiB-aligned cannot be mapped directly, so a private mapping of it is
// copied in instead (as is an executable one, whose svc/tpidr/ctr sites must
// be rewritten before it becomes executable).

const std = @import("std");
const root = @import("root");
const fdlink = @import("fdlink.zig");
const jit = @import("jit.zig");
const procinfo = @import("procinfo.zig");
const sig = @import("sig.zig");
const wx = @import("wx.zig");
const tstate = @import("tstate.zig");

pub const PAGE: u64 = tstate.page;

// GUEST_BASE is where the guest's memory goes when it names no address. A
// stub's own mappings all lie below it (its malloc's nano zone far above), so
// a fresh stub, as a fork child is, finds the parent's guest ranges free;
// Darwin places a hinted mapping first-fit upward from the hint.
pub const GUEST_BASE: u64 = 1 << 40;

// The guest's layout is a 47-bit Linux one, as an arm64 kernel with 16 KiB
// pages (or an x86-64 one) lays a process out: the stack's top at the task
// size moved down by a random part of STACK_RND, though no higher than
// Darwin maps (HOST_TOP); below it the mmap area, whose top (mmap_base)
// leaves the stack's rlimit and a random offset between them, filled
// top-down -- bottom-up from TASK_SIZE / UNMAPPED_DIV with the legacy layout
// (ADDR_COMPAT_LAYOUT, or an unlimited stack on arm64); a program with an
// interpreter at two thirds of the task size, again moved by a random offset,
// one without in the mmap area; and the break a random part of 1 GiB past the
// program's end. Each is drawn anew at an exec (drawLayout) and kept across a
// fork; ADDR_NO_RANDOMIZE leaves them all at their bases.
const X86 = @import("builtin").cpu.arch == .x86_64;
pub const TASK_SIZE: u64 = 1 << 47;
const HOST_TOP: u64 = 0x7fff_fe00_0000;
// TOP_LO starts the guest's window under the task size, above the stub's
// malloc nano zone (GUEST_TOP).
pub const TOP_LO: u64 = 0x7000_0000_0000;
const STACK_RND: u64 = if (X86) 16 << 30 else 1 << 30;
const MMAP_RND_PAGES: u64 = if (X86) 1 << 28 else 1 << 18;
pub const ET_DYN_BASE: u64 = TASK_SIZE / 3 * 2 & ~(PAGE - 1);
const UNMAPPED_DIV: u64 = if (X86) 3 else 4;
// HUGE is the PMD size transparent huge pages align to.
const HUGE: u64 = PAGE * (PAGE / 8);
const LAYOUT_COMPAT: u32 = 2; // sandbox/exec_darwin.go layoutCompat
const LAYOUT_RLIM_INF: u32 = 0xffffff;

// guest_top is where the guest's address space ends: HOST_TOP, but under Rosetta
// the host keeps the window's highest gigabytes (the x86-64 shared region,
// Rosetta's runtime and dyld's stack below it), so an x86-64 guest ends under
// them, as on a kernel with a smaller task size (noteHost).
pub var guest_top: u64 = HOST_TOP;
pub var hint_exe: u64 = ET_DYN_BASE;
pub var stack_top: u64 = HOST_TOP;
var mmap_base: u64 = TASK_SIZE - (128 << 20);
var legacy_base: u64 = TASK_SIZE / UNMAPPED_DIV;
var legacy = false;
var brk_hint: u64 = 0;
var brk_gap: u64 = 0;

extern "c" fn arc4random_buf(buf: *anyopaque, n: usize) void;

fn randBelow(n: u64) u64 {
    var v: u64 = 0;
    arc4random_buf(&v, @sizeOf(u64));
    return v % n;
}

// drawLayout draws the layout for an exec from the supervisor's flags
// (chan.LAYOUT_NORAND, LAYOUT_COMPAT, and the stack's rlimit in MiB from bit 8).
pub fn drawLayout(flags: u32) void {
    const norand = flags & 1 != 0;
    const mib = flags >> 8;
    const rlim: u64 = if (mib == LAYOUT_RLIM_INF) std.math.maxInt(u64) else @as(u64, mib) << 20;
    legacy = flags & LAYOUT_COMPAT != 0 or (!X86 and mib == LAYOUT_RLIM_INF);
    var rnd: u64 = 0;
    var pad: u64 = 256 * PAGE;
    if (!norand) {
        rnd = randBelow(MMAP_RND_PAGES) * PAGE;
        pad += STACK_RND;
    }
    const tsize: u64 = if (X86) guest_top else TASK_SIZE;
    var gap = rlim;
    if (gap +% pad > gap) gap += pad;
    gap = std.math.clamp(gap, 128 << 20, tsize / 6 * 5);
    mmap_base = (tsize - gap - rnd) & ~(PAGE - 1);
    legacy_base = rdUp(TASK_SIZE / UNMAPPED_DIV) + rnd;
    if (norand) {
        stack_top = guest_top;
        hint_exe = ET_DYN_BASE;
        brk_gap = 0;
    } else {
        stack_top = guest_top - randBelow((STACK_RND - (tsize - guest_top)) / PAGE) * PAGE;
        hint_exe = ET_DYN_BASE + randBelow(MMAP_RND_PAGES) * PAGE;
        brk_gap = randBelow((1 << 30) / PAGE) * PAGE;
    }
    lock.lock();
    taken.clearRetainingCapacity();
    takeHost();
    lock.unlock();
}

// placeBreak sets where the break goes: past hi, the program's end (or
// ELF_ET_DYN_BASE for one in the mmap area), by the layout's random gap.
pub fn placeBreak(hi: u64) void {
    brk_hint = rdUp(hi) + brk_gap;
}

const NR_BRK: u64 = 214;
const NR_MUNMAP: u64 = 215;
const NR_MREMAP: u64 = 216;
const NR_MMAP: u64 = 222;
const NR_MPROTECT: u64 = 226;
const NR_MSYNC: u64 = 227;
const NR_MLOCK: u64 = 228;
const NR_MUNLOCK: u64 = 229;
const NR_MLOCKALL: u64 = 230;
const NR_MUNLOCKALL: u64 = 231;
const NR_MINCORE: u64 = 232;
const NR_MADVISE: u64 = 233;
const NR_MLOCK2: u64 = 284;
const NR_SHMAT: u64 = 196;
const NR_SHMDT: u64 = 197;
const NR_EPOLL_PWAIT: u64 = 22;
const NR_READ: u64 = 63;
const NR_READV: u64 = 65;
const NR_PREAD64: u64 = 67;
const NR_PREADV: u64 = 69;
const NR_PREADV2: u64 = 286;
const NR_EPOLL_PWAIT2: u64 = 441;

// Supervisor services the stub calls like syscalls (sandbox/mem_darwin.go).
pub const LC_MMAPFD: u64 = 0x4c430001; // (guest fd, shared writable, shared executable) -> stub fd | kind << 32
const LC_CODEFILE: u64 = 0x4c430006; // (open-file id): this stub maps that file shared and executable
const LC_SYNCFILE: u64 = 0x4c430007; // (open-file id): msync of its MAP_SHARED mapping; write the backing back to the file
const LC_UNMAPFILE: u64 = 0x4c430008; // (open-file id): this stub's last MAP_SHARED mapping of that non-host file is gone
pub const LC_REWRITE: u64 = 0x4c430002; // (base, len, file off, guest fd, count only): rewrite, or count, a text range's sites
const LC_SHMAT: u64 = 0x4c430003; // (shmid) -> stub fd | pages << 32
const LC_SHMATTACHED: u64 = 0x4c430004; // (shmid) -> attachment cookie
const LC_SHMGONE: u64 = 0x4c430005; // (cookie): its last range is unmapped
const LC_RWX: u64 = 0x4c430030; // -> 0, or -EACCES when the run refuses W+X memory
const KIND_ZERO: u64 = 1; // /dev/zero: an anonymous mapping

// Linux errnos, returned negated.
const EPERM: i64 = 1;
const EACCES: i64 = 13;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const EOPNOTSUPP: i64 = 95;

// Linux mmap flags.
const L_SHARED: u64 = 0x01;
const L_PRIVATE: u64 = 0x02;
const L_SHARED_VALIDATE: u64 = 0x03;
const L_TYPE: u64 = 0x0f;
const L_FIXED: u64 = 0x10;
const L_ANON: u64 = 0x20;
const L_32BIT: u64 = 0x40; // x86-64 only
const L_GROWSDOWN: u64 = 0x100;
const L_DENYWRITE: u64 = 0x800;
const L_EXECUTABLE: u64 = 0x1000;
const L_LOCKED: u64 = 0x2000;
const L_NORESERVE: u64 = 0x4000;
const L_POPULATE: u64 = 0x8000;
const L_NONBLOCK: u64 = 0x10000;
const L_STACK: u64 = 0x20000;
const L_HUGETLB: u64 = 0x40000;
const L_SYNC: u64 = 0x80000;
const L_FIXED_NOREPLACE: u64 = 0x100000;
const L_HUGE_MASK: u64 = 0x3f << 26;
// Flags MAP_SHARED_VALIDATE accepts. MAP_SYNC needs DAX storage, which a host
// file never is, so it is left out and refused as on a non-DAX Linux file.
const L_KNOWN: u64 = L_TYPE | L_FIXED | L_ANON | L_GROWSDOWN | L_DENYWRITE | L_EXECUTABLE |
    L_LOCKED | L_NORESERVE | L_POPULATE | L_NONBLOCK | L_STACK | L_HUGETLB |
    L_FIXED_NOREPLACE | L_HUGE_MASK;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const PROT_RW: u64 = 3;

// Darwin.
const SYS_msync: u64 = 65;
const SYS_munmap: u64 = 73;
const SYS_mprotect: u64 = 74;
const SYS_madvise: u64 = 75;
const SYS_mincore: u64 = 78;
const SYS_pread: u64 = 153;
const SYS_mmap: u64 = 197;
const SYS_minherit: u64 = 250;
const SYS_fstat64: u64 = 339;
const D_SHARED: u64 = 0x1;
const D_PRIVATE: u64 = 0x2;
const D_FIXED: u64 = 0x10;
const D_NORESERVE: u64 = 0x40;
const D_JIT: u64 = 0x800;
const D_ANON: u64 = 0x1000;
const D_MS_ASYNC: u64 = 0x1;
const D_MS_SYNC: u64 = 0x10;
const D_MADV_WILLNEED: u64 = 3;
const D_MADV_DONTNEED: u64 = 4;
const D_MADV_FREE: u64 = 5;
const D_MADV_ZERO: u64 = 11;
const VM_INHERIT_SHARE: u32 = 0;
const VM_INHERIT_COPY: u32 = 1;
const VM_INHERIT_NONE: u32 = 2;

extern "c" fn mach_task_self() c_uint;
extern "c" fn mach_vm_region(task: c_uint, addr: *u64, size: *u64, flavor: c_int, info: *anyopaque, count: *c_uint, obj: *c_uint) c_int;
extern "c" fn mach_vm_remap(task: c_uint, dst: *u64, size: u64, mask: u64, flags: c_int, src_task: c_uint, src: u64, copy: c_int, cur: *c_int, max: *c_int, inherit: c_uint) c_int;
extern "c" fn mach_port_deallocate(task: c_uint, name: c_uint) c_int;

const VM_REGION_BASIC_INFO_64: c_int = 9;
const VM_FLAGS_FIXED: c_int = 0;
const VM_FLAGS_ANYWHERE: c_int = 1;
const VM_FLAGS_OVERWRITE: c_int = 0x4000;

// vm_region_basic_info_64 is 4-byte packed (its u64 offset sits at 20).
const BasicInfo = extern struct {
    prot: i32,
    maxprot: i32,
    inherit: u32,
    shared: i32,
    reserved: i32,
    offset: [2]u32,
    behavior: i32,
    wired: u16,
    pad: u16,
};

fn neg(e: i64) u64 {
    return @bitCast(-e);
}

fn rdUp(x: u64) u64 {
    return (x + PAGE - 1) & ~(PAGE - 1);
}

// freeNear returns where n free bytes of the address space lie closest to pc
// with all of them within reach of it, or null: the stub's island arenas, which
// a site's b must reach.
pub fn freeNear(pc: u64, n: u64, reach: u64) ?u64 {
    const first = if (pc > reach) rdUp(pc - reach) else PAGE;
    const last = (pc + reach - n) & ~(PAGE - 1); // the highest start in reach
    var best: ?u64 = null;
    var dist: u64 = std.math.maxInt(u64);
    var cur = first;
    while (cur <= last) {
        var a = cur;
        var size: u64 = 0;
        var info: BasicInfo = undefined;
        var count: c_uint = @sizeOf(BasicInfo) / 4;
        var obj: c_uint = 0;
        const found = mach_vm_region(task, &a, &size, VM_REGION_BASIC_INFO_64, &info, &count, &obj) == 0;
        if (found and obj != 0) _ = mach_port_deallocate(task, obj);
        // [cur, end) is free: up to the next region, or the top of the space.
        const end = if (found) a else std.math.maxInt(u64);
        if (end > cur and end - cur >= n) {
            const top = @min((end - n) & ~(PAGE - 1), last);
            const at = @max(cur, @min(pc & ~(PAGE - 1), top));
            const d = if (at > pc) at - pc else pc - at;
            if (d < dist) {
                dist = d;
                best = at;
            }
        }
        if (!found) break;
        cur = a + size;
    }
    return best;
}

fn sys(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) i64 {
    return fdlink.sys(nr, a0, a1, a2, a3, a4, a5);
}

// lx turns a raw Darwin result (-errno on failure) into the Linux one.
fn lx(r: i64) u64 {
    if (r >= 0) return @bitCast(r);
    const e = -r;
    return neg(switch (e) {
        1...34 => e,
        35 => EAGAIN,
        45, 102 => EOPNOTSUPP,
        84 => 75, // EOVERFLOW
        else => 5, // EIO
    });
}

fn isErr(r: u64) bool {
    return r > std.math.maxInt(u64) - 4095;
}

var lock: std.Thread.Mutex = .{};

// task is this task's port, cached.
var task: c_uint = 0;

pub fn init() void {
    task = mach_task_self();
}

pub fn handle(nr: u64, a: [*]const u64) ?u64 {
    if (overCap(growth(nr, a))) return if (nr == NR_BRK) brk_cur else neg(ENOMEM);
    const r = serve(nr, a);
    switch (nr) {
        NR_MUNMAP, NR_MPROTECT, NR_MREMAP, NR_BRK, NR_SHMAT, NR_SHMDT => wroteMaps(),
        NR_MMAP => if (a[3] & L_FIXED != 0) wroteMaps(),
        else => {},
    }
    switch (nr) {
        NR_MMAP, NR_MUNMAP, NR_MREMAP, NR_BRK, NR_SHMAT, NR_SHMDT => publish(),
        else => {},
    }
    return r;
}

// ---- memory cap ---------------------------------------------------------------

// The run's memory cap (Config.MaxBytes) bounds what all its processes have
// mapped together. Each stub process publishes its total in the signal record
// of the slot it leads (acct); a request that would take the sum past the cap
// fails with ENOMEM, as an address-space limit does on Linux.
var acct: usize = 0;

// account makes slot the one this stub process publishes its total in: its
// image's or its fork child's, once that is in place.
pub fn account(slot: usize) void {
    acct = slot;
    publish();
}

fn publish() void {
    if (sig.runMemCap() == 0) return;
    lock.lock();
    const n = usedIn(0, std.math.maxInt(u64));
    lock.unlock();
    sig.setProcMem(acct, n);
}

// growth is how much more a call asks to map, at most.
fn growth(nr: u64, a: [*]const u64) u64 {
    if (sig.runMemCap() == 0) return 0;
    switch (nr) {
        NR_MMAP => {
            const n = rdUp(a[1]);
            if (a[3] & L_FIXED == 0) return n;
            lock.lock();
            defer lock.unlock();
            return n -| usedIn(a[0], a[0] +| n);
        },
        NR_MREMAP => return if (a[3] & MREMAP_DONTUNMAP != 0) rdUp(a[2]) else rdUp(a[2]) -| rdUp(a[1]),
        NR_BRK => {
            lock.lock();
            defer lock.unlock();
            return if (brk_base != 0 and a[0] > brk_end) rdUp(a[0]) - brk_end else 0;
        },
        else => return 0,
    }
}

fn overCap(more: u64) bool {
    if (more == 0) return false;
    const cap = sig.runMemCap();
    if (cap == 0) return false;
    lock.lock();
    const own = usedIn(0, std.math.maxInt(u64));
    lock.unlock();
    return own +| more +| sig.othersMem(acct) > cap;
}

// usedIn is how much of [lo, hi) the guest has mapped: the union of its
// mappings there, each counted once. Under lock.
fn usedIn(lo: u64, hi: u64) u64 {
    const pi = procinfo.info;
    const fixed = [_]Range{
        .{ .lo = brk_base, .hi = brk_end },
        .{ .lo = pi.main_lo, .hi = pi.main_hi },
        .{ .lo = pi.interp_lo, .hi = pi.interp_hi },
        .{ .lo = pi.stack_lo, .hi = pi.stack_hi },
    };
    const all = gpa.alloc(Range, anons.items.len + vmas.items.len + fixed.len) catch return 0;
    defer gpa.free(all);
    var n: usize = 0;
    for (anons.items) |e| {
        all[n] = .{ .lo = e.lo, .hi = e.hi };
        n += 1;
    }
    for (vmas.items) |e| {
        if (e.kind == .nofork) continue;
        all[n] = .{ .lo = e.lo, .hi = e.hi };
        n += 1;
    }
    for (fixed) |e| {
        all[n] = e;
        n += 1;
    }
    std.mem.sort(Range, all[0..n], {}, rangeLess);
    var used: u64 = 0;
    var done = lo;
    for (all[0..n]) |e| {
        const a = @max(e.lo, done);
        const b = @min(e.hi, hi);
        if (b > a) {
            used += b - a;
            done = b;
        }
    }
    return used;
}

fn serve(nr: u64, a: [*]const u64) ?u64 {
    return switch (nr) {
        NR_MMAP => mmap(a[0], a[1], a[2], a[3], a[4], a[5]),
        NR_MUNMAP => munmap(a[0], a[1]),
        NR_MPROTECT => mprotect(a[0], a[1], a[2]),
        NR_MREMAP => mremap(a[0], a[1], a[2], a[3], a[4]),
        NR_BRK => brk(a[0]),
        NR_MADVISE => madvise(a[0], a[1], a[2]),
        NR_MSYNC => msync(a[0], a[1], a[2]),
        NR_MINCORE => mincore(a[0], a[1], a[2]),
        NR_MLOCK, NR_MUNLOCK => lockRange(a[0], a[1]),
        NR_MUNLOCKALL => 0,
        NR_MLOCKALL => if (a[0] == 0 or a[0] & ~@as(u64, 7) != 0 or a[0] == 4) neg(EINVAL) else 0,
        NR_MLOCK2 => if (a[2] & ~@as(u64, 1) != 0) neg(EINVAL) else lockRange(a[0], a[1]),
        NR_SHMAT => shmat(a[0], a[1], a[2]),
        NR_SHMDT => shmdt(a[0]),
        else => null,
    };
}

// ---- writable prefix ----------------------------------------------------------

// A read the supervisor serves stops where the guest's buffer stops being
// writable, as Linux's copy does, but the supervisor cannot see this task's
// memory: outPrefix measures it at the call's entry, for the request's ret.
// Each thread keeps the writable span it last found, good while wgen stands;
// what can take write access away bumps it once done (wroteMaps): munmap,
// mprotect, mremap, a fixed mapping, brk, SysV attach and detach, an exec,
// and the supervisor's own host calls.
pub const OUT_TAG: u64 = 2 << 62;
const MAX_RW: u64 = 0x7ffff000;
const EP_EVENT: u64 = if (X86) 12 else 16; // x86-64's struct epoll_event is packed
var wgen = std.atomic.Value(u64).init(0);
threadlocal var w_lo: u64 = 0;
threadlocal var w_hi: u64 = 0;
threadlocal var w_gen: u64 = std.math.maxInt(u64);

pub fn wroteMaps() void {
    _ = wgen.fetchAdd(1, .release);
}

// outPrefix is OUT_TAG with how much of guest syscall nr's output vector the
// guest can write from its start, for a read the supervisor serves into guest
// memory; 0 for any other call, or one the supervisor fails before reading.
pub fn outPrefix(nr: u64, a: [*]const u64) u64 {
    const p = switch (nr) {
        NR_READ, NR_PREAD64 => writablePrefix(a[1], @min(a[2], MAX_RW)),
        NR_READV, NR_PREADV, NR_PREADV2 => vecPrefix(a[1], a[2]) orelse return 0,
        NR_EPOLL_PWAIT, NR_EPOLL_PWAIT2 => blk: {
            const m: i32 = @bitCast(@as(u32, @truncate(a[2])));
            if (m <= 0) return 0;
            break :blk writablePrefix(a[1], @as(u64, @intCast(m)) * EP_EVENT);
        },
        else => return 0,
    };
    return OUT_TAG | p;
}

// vecPrefix is how much of the cnt iovecs at iov the guest can write from the
// start, or null when the vector itself is bad.
fn vecPrefix(iov: u64, cnt: u64) ?u64 {
    if (cnt > 1024) return null;
    var v: [16][2]u64 = undefined;
    var total: u64 = 0;
    var i: u64 = 0;
    while (i < cnt) : (i += v.len) {
        const k: u64 = @min(cnt - i, v.len);
        if (!sig.copyGuest(@intFromPtr(&v), iov + i * 16, k * 16)) return null;
        for (v[0..k]) |x| {
            if (x[1] > std.math.maxInt(i64)) return null;
            const l = @min(x[1], MAX_RW - total);
            if (l == 0) continue;
            const p = writablePrefix(x[0], l);
            total += p;
            if (p < l or total == MAX_RW) return total;
        }
    }
    return total;
}

// writablePrefix is how much of [addr, addr+n) the guest can write from its
// start.
fn writablePrefix(addr: u64, n: u64) u64 {
    const end = addr +| n;
    const g = wgen.load(.acquire);
    if (g == w_gen and addr >= w_lo and end <= w_hi) return n;
    var at = addr;
    var lo = addr;
    while (at < end) {
        const r = regionAt(at) orelse break;
        var hi = r.hi;
        var prot: u64 = @intCast(r.info.prot & 7);
        // Memory that runs only once rewritten writes as the guest gave it,
        // and so does a page frozen while it runs.
        if (wx.protAt(at)) |x| {
            hi = @min(hi, x.hi);
            prot = x.prot;
        } else if (wx.frozenProt(at)) |p| {
            hi = @min(hi, (at & ~(PAGE - 1)) + PAGE);
            prot = p;
        } else hi = @min(hi, wx.nextAt(at));
        if (prot & PROT_WRITE == 0) break;
        if (at == addr and hi == r.hi) lo = r.lo;
        at = hi;
    }
    if (at > addr) {
        w_lo = lo;
        w_hi = at;
        w_gen = g;
    }
    return @min(at, end) - addr;
}

// ---- ranges -------------------------------------------------------------------

// Vma records what the host's regions cannot tell. A file entry is a file
// mapping, direct or copied in, with its file and offset, so mremap can grow it
// with more of the file and a DONTNEED can bring the file's bytes back; it
// holds a reference on its fdlink entry, so the file outlives a guest close as
// on Linux. shm names the SysV attachment the range belongs to. A nofork entry
// is a shared range that MADV_DONTFORK took out of fork inheritance.
const Kind = enum(u8) { file, nofork, vdso };
const Vma = struct {
    lo: u64,
    hi: u64,
    kind: Kind = .file,
    id: u64 = 0,
    off: u64 = 0,
    shared: bool = false,
    copy: bool = false, // filled by pread, not mapped from the file
    exec: bool = false, // a copied executable segment, its sites rewritten
    shm: u64 = 0,
};
const gpa = std.heap.page_allocator;
var vmas: std.ArrayListUnmanaged(Vma) = .{};
// SysV attachments whose last range went away, for flushGone to report.
var shm_gone: std.ArrayListUnmanaged(u64) = .{};

// The functions below run under lock.

fn vmaAdd(v: Vma) bool {
    vmas.append(gpa, v) catch return false;
    if (v.kind == .file) fdlink.ref(v.id);
    return true;
}

fn vmaDel(i: usize) Vma {
    const v = vmas.swapRemove(i);
    if (v.kind == .file) fdlink.unref(v.id);
    return v;
}

// vmaPunch forgets [lo, hi) (only entries of kind `only`, if given): entries
// inside go, overlapping ones are trimmed or split. An attachment left with no
// range is queued for flushGone.
fn vmaPunch(lo: u64, hi: u64, only: ?Kind) void {
    const gone = shm_gone.items.len;
    var i: usize = 0;
    while (i < vmas.items.len) {
        const e = vmas.items[i];
        if (e.hi <= lo or e.lo >= hi or (only != null and e.kind != only.?)) {
            i += 1;
            continue;
        }
        if (e.lo < lo) {
            var l = e;
            l.hi = lo;
            _ = vmaAdd(l);
        }
        if (e.hi > hi) {
            var r = e;
            r.lo = hi;
            if (r.kind == .file) r.off += hi - e.lo;
            _ = vmaAdd(r);
        }
        const v = vmaDel(i);
        if (v.shm != 0 and std.mem.indexOfScalar(u64, shm_gone.items, v.shm) == null) shm_gone.append(gpa, v.shm) catch {};
    }
    var j = gone;
    while (j < shm_gone.items.len) {
        if (hasShm(shm_gone.items[j])) {
            _ = shm_gone.swapRemove(j);
        } else j += 1;
    }
}

fn hasShm(c: u64) bool {
    for (vmas.items) |e| {
        if (e.shm == c) return true;
    }
    return false;
}

fn vmaAt(addr: u64) ?Vma {
    for (vmas.items) |e| {
        if (e.kind == .file and addr >= e.lo and addr < e.hi) return e;
    }
    return null;
}

// vmaNext is the start of the first file entry inside (addr, hi), or hi.
fn vmaNext(addr: u64, hi: u64) u64 {
    var n = hi;
    for (vmas.items) |e| {
        if (e.kind == .file and e.lo > addr and e.lo < n) n = e.lo;
    }
    return n;
}

fn anyVma(lo: u64, hi: u64) bool {
    for (vmas.items) |e| {
        if (e.kind == .file and e.hi > lo and e.lo < hi) return true;
    }
    return false;
}

fn noforkAt(addr: u64) bool {
    for (vmas.items) |e| {
        if (e.kind == .nofork and addr >= e.lo and addr < e.hi) return true;
    }
    return false;
}

fn vmaMove(lo: u64, hi: u64, to: u64) void {
    for (vmas.items) |*e| {
        if (e.lo >= lo and e.hi <= hi) {
            e.lo = e.lo - lo + to;
            e.hi = e.hi - lo + to;
        }
    }
}

// anons lists the guest's anonymous mappings, for /proc/<pid>/maps: the host's
// regions include the stub's own memory, so only this says which are the
// guest's. Neighbours of the same kind are merged.
const Anon = struct { lo: u64, hi: u64, shared: bool };
var anons: std.ArrayListUnmanaged(Anon) = .{};

fn anonPunch(lo: u64, hi: u64) void {
    var i: usize = 0;
    while (i < anons.items.len) {
        const e = anons.items[i];
        if (e.hi <= lo or e.lo >= hi) {
            i += 1;
            continue;
        }
        if (e.lo < lo and e.hi > hi) {
            anons.items[i].hi = lo;
            anons.append(gpa, .{ .lo = hi, .hi = e.hi, .shared = e.shared }) catch {};
            return;
        }
        if (e.lo < lo) {
            anons.items[i].hi = lo;
            i += 1;
        } else if (e.hi > hi) {
            anons.items[i].lo = hi;
            i += 1;
        } else {
            _ = anons.swapRemove(i);
        }
    }
}

fn anonAdd(lo: u64, hi: u64, shared: bool) void {
    anonPunch(lo, hi);
    var l = lo;
    var h = hi;
    var i: usize = 0;
    while (i < anons.items.len) {
        const e = anons.items[i];
        if (e.shared == shared and (e.hi == l or e.lo == h)) {
            l = @min(l, e.lo);
            h = @max(h, e.hi);
            _ = anons.swapRemove(i);
        } else i += 1;
    }
    anons.append(gpa, .{ .lo = l, .hi = h, .shared = shared }) catch {};
}

// anonMove moves the parts of [lo, hi) to start at `to`.
fn anonMove(lo: u64, hi: u64, to: u64) void {
    var moved: [64]Anon = undefined;
    var n: usize = 0;
    for (anons.items) |e| {
        if (e.hi <= lo or e.lo >= hi or n == moved.len) continue;
        moved[n] = .{ .lo = @max(e.lo, lo) - lo + to, .hi = @min(e.hi, hi) - lo + to, .shared = e.shared };
        n += 1;
    }
    anonPunch(lo, hi);
    for (moved[0..n]) |e| anonAdd(e.lo, e.hi, e.shared);
}

fn anonShared(lo: u64, hi: u64, to: u64) void {
    var add: [64]Anon = undefined;
    var n: usize = 0;
    for (anons.items) |e| {
        if (e.hi <= lo or e.lo >= hi or n == add.len) continue;
        add[n] = .{ .lo = @max(e.lo, lo) - lo + to, .hi = @min(e.hi, hi) - lo + to, .shared = true };
        n += 1;
    }
    for (add[0..n]) |e| anonAdd(e.lo, e.hi, true);
}

// ---- /proc/<pid>/maps ----------------------------------------------------------------

// A maps entry as the supervisor reads it (sandbox/procmaps_darwin.go):
// aux is the open-file id of a file mapping or the SysV attachment cookie.
pub const MapEnt = extern struct { lo: u64, hi: u64, off: u64, aux: u64, attr: u64 };
const M_ANON: u64 = 1;
const M_FILE: u64 = 2;
const M_SHM: u64 = 3;
const M_HEAP: u64 = 4;
const M_MAIN: u64 = 5;
const M_INTERP: u64 = 6;
const M_STACK: u64 = 7;
const M_VDSO: u64 = 8;

// entLess orders by address; the heap goes first among equals, as it is
// labelled over the guest's own mappings inside it (malloc's guard page).
fn entLess(_: void, a: MapEnt, b: MapEnt) bool {
    if (a.lo != b.lo) return a.lo < b.lo;
    return a.attr >> 8 == M_HEAP and b.attr >> 8 != M_HEAP;
}

// maps writes the guest's mappings that end above `from`, in address order and
// split where the host protection changes, as up to cap entries into out. It
// returns the count and sets next to where the following call resumes (0 when
// done).
pub fn maps(out: [*]MapEnt, cap: usize, from: u64, next: *u64) u64 {
    next.* = 0;
    wx.hold();
    defer wx.release();
    lock.lock();
    defer lock.unlock();
    const all = gpa.alloc(MapEnt, anons.items.len + vmas.items.len + 4) catch return 0;
    defer gpa.free(all);
    var n: usize = 0;
    for (anons.items) |e| {
        all[n] = .{ .lo = e.lo, .hi = e.hi, .off = 0, .aux = 0, .attr = M_ANON << 8 | @as(u64, @intFromBool(e.shared)) << 3 };
        n += 1;
    }
    for (vmas.items) |e| {
        const k = switch (e.kind) {
            .file => if (e.shm != 0) M_SHM else M_FILE,
            .vdso => M_VDSO,
            .nofork => continue,
        };
        all[n] = .{ .lo = e.lo, .hi = e.hi, .off = e.off, .aux = if (e.shm != 0) e.shm else e.id, .attr = k << 8 | @as(u64, @intFromBool(e.shared)) << 3 };
        n += 1;
    }
    const pi = procinfo.info;
    const fixed = [_]MapEnt{
        .{ .lo = brk_base, .hi = brk_end, .off = 0, .aux = 0, .attr = M_HEAP << 8 },
        .{ .lo = pi.main_lo, .hi = pi.main_hi, .off = 0, .aux = 0, .attr = M_MAIN << 8 },
        .{ .lo = pi.interp_lo, .hi = pi.interp_hi, .off = 0, .aux = 0, .attr = M_INTERP << 8 },
        .{ .lo = pi.stack_lo, .hi = pi.stack_hi, .off = 0, .aux = 0, .attr = M_STACK << 8 },
    };
    for (fixed) |e| {
        if (e.hi <= e.lo) continue;
        all[n] = e;
        n += 1;
    }
    std.mem.sort(MapEnt, all[0..n], {}, entLess);
    var w: usize = 0;
    var done = from;
    for (all[0..n]) |e| {
        var a = @max(e.lo, done);
        while (a < e.hi) {
            var ra = a;
            var size: u64 = 0;
            var info: BasicInfo = undefined;
            var count: c_uint = @sizeOf(BasicInfo) / 4;
            var obj: c_uint = 0;
            if (mach_vm_region(task, &ra, &size, VM_REGION_BASIC_INFO_64, &info, &count, &obj) != 0) break;
            if (obj != 0) _ = mach_port_deallocate(task, obj);
            if (ra >= e.hi) break;
            const lo = @max(ra, a);
            var hi = @min(ra + size, e.hi);
            // Memory that runs only once rewritten has the guest's protection.
            var prot: u64 = @intCast(info.prot & 7);
            if (wx.protAt(lo)) |x| {
                hi = @min(hi, x.hi);
                prot = x.prot;
            } else hi = @min(hi, wx.nextAt(lo));
            // Host regions split where Linux would keep one mapping.
            const pa = prot | e.attr;
            const k = e.attr >> 8;
            const filed = k == M_FILE or k == M_SHM or k == M_MAIN or k == M_INTERP;
            const off = if (filed) e.off + (lo - e.lo) else 0;
            if (w > 0) {
                const l = &out[w - 1];
                if (l.hi == lo and l.attr == pa and l.aux == e.aux and (!filed or l.off + (l.hi - l.lo) == off)) {
                    l.hi = hi;
                    a = hi;
                    done = hi;
                    continue;
                }
            }
            if (w == cap) {
                next.* = lo;
                return w;
            }
            out[w] = .{ .lo = lo, .hi = hi, .off = off, .aux = e.aux, .attr = pa };
            w += 1;
            a = hi;
            done = hi;
        }
    }
    return w;
}

// flushGone tells the supervisor which SysV attachments are gone, after lock
// is released.
fn flushGone() void {
    while (true) {
        lock.lock();
        const c = shm_gone.popOrNull();
        lock.unlock();
        _ = root.hostCall(LC_SHMGONE, .{ c orelse return, 0, 0, 0, 0, 0 });
    }
}

// noteVdso records the vDSO the stub mapped at [lo, hi): /proc/<pid>/maps
// names it [vdso], and unmapping, mapping over or moving it takes it along as
// it does any mapping.
pub fn noteVdso(lo: u64, hi: u64) void {
    lock.lock();
    defer lock.unlock();
    _ = vmaAdd(.{ .lo = lo, .hi = hi, .kind = .vdso, .exec = true });
}

// reset forgets the old image's mappings at exec; its SysV attachments are
// detached (the supervisor drops its side at the same point).
pub fn reset() void {
    wx.clear();
    lock.lock();
    defer lock.unlock();
    for (vmas.items) |e| {
        if (e.shm != 0) _ = sys(SYS_munmap, e.lo, e.hi - e.lo, 0, 0, 0, 0);
    }
    while (vmas.items.len > 0) _ = vmaDel(vmas.items.len - 1);
    anons.clearRetainingCapacity();
    shm_gone.clearRetainingCapacity();
    if (brk_base != 0) _ = sys(SYS_munmap, brk_base, BRK_RESERVE, 0, 0, 0, 0);
    brk_base = 0;
    wroteMaps();
}

// ---- mmap / munmap -------------------------------------------------------------

// place maps at addr as the caller asked: MAP_FIXED replaces, a NOREPLACE
// request must land exactly on addr (Darwin takes it as a hint) or EEXIST, and
// otherwise addr is a hint, an unaligned one naming the page it falls in as
// Linux takes it, used when free; where an unfixed mapping goes is pick's.
// Darwin maps a hint that is free exactly there: one that is not names
// something taken has not recorded, which is learned and the pick redone.
fn place(addr: u64, n: u64, prot: u64, dw: u64, fd: i64, off: u64, noreplace: bool) u64 {
    return placeAt(addr, n, prot, dw, fd, off, noreplace, false);
}

// placeAt is place with lock held already when held.
fn placeAt(addr: u64, n: u64, prot: u64, dw: u64, fd: i64, off: u64, noreplace: bool, held: bool) u64 {
    if (dw & D_FIXED != 0 or noreplace) {
        const r = sys(SYS_mmap, addr & ~(PAGE - 1), n, prot, dw, @bitCast(fd), off);
        if (r < 0) return lx(r);
        const got: u64 = @bitCast(r);
        if (noreplace and got != addr) {
            _ = sys(SYS_munmap, got, n, 0, 0, 0, 0);
            return neg(EEXIST);
        }
        noteTaken(got, n, held);
        return got;
    }
    const anon = fd < 0 and dw & D_SHARED == 0;
    var tries: u32 = 0;
    while (tries < 64) : (tries += 1) {
        if (!held) lock.lock();
        const at = pick(addr & ~(PAGE - 1), n, anon);
        if (!held) lock.unlock();
        const want = at orelse return neg(ENOMEM);
        const r = sys(SYS_mmap, want, n, prot, dw | (if (inLow(want, want + n)) D_FIXED else 0), @bitCast(fd), off);
        if (r < 0) return lx(r);
        const got: u64 = @bitCast(r);
        if (got == want) {
            noteTaken(got, n, held);
            return got;
        }
        _ = sys(SYS_munmap, got, n, 0, 0, 0, 0);
        const there = regionFrom(want) orelse return neg(ENOMEM);
        noteTaken(there.lo, there.hi - there.lo, held);
    }
    return neg(ENOMEM);
}

// ---- placement -------------------------------------------------------------------

// taken is what the guest's address space holds, sorted and disjoint, which
// pick places around: every mapping the guest makes and the program's images,
// stack and break, less what it unmaps. Something it misses is learned when a
// mapping meant for a free place lands elsewhere (place).
const Run = struct { lo: u64, hi: u64 };
var taken: std.ArrayListUnmanaged(Run) = .{};

fn noteTaken(lo: u64, n: u64, held: bool) void {
    if (!held) lock.lock();
    defer if (!held) lock.unlock();
    takenAdd(lo, lo + n);
}

// takenAdd and takenDel run under lock.
fn takenAdd(lo_in: u64, hi_in: u64) void {
    var lo = lo_in;
    var hi = hi_in;
    var i: usize = 0;
    while (i < taken.items.len and taken.items[i].hi < lo) i += 1;
    var j = i;
    while (j < taken.items.len and taken.items[j].lo <= hi) : (j += 1) {
        lo = @min(lo, taken.items[j].lo);
        hi = @max(hi, taken.items[j].hi);
    }
    taken.replaceRange(gpa, i, j - i, &.{.{ .lo = lo, .hi = hi }}) catch {};
}

fn takenDel(lo: u64, hi: u64) void {
    var i: usize = 0;
    while (i < taken.items.len) {
        const e = taken.items[i];
        if (e.hi <= lo or e.lo >= hi) {
            i += 1;
            continue;
        }
        if (e.lo < lo and e.hi > hi) {
            taken.items[i].hi = lo;
            taken.insert(gpa, i + 1, .{ .lo = hi, .hi = e.hi }) catch {};
            return;
        }
        if (e.lo < lo) {
            taken.items[i].hi = lo;
            i += 1;
        } else if (e.hi > hi) {
            taken.items[i].lo = hi;
            i += 1;
        } else _ = taken.orderedRemove(i);
    }
}

fn clear(lo: u64, hi: u64) bool {
    for (taken.items) |e| {
        if (e.lo < hi and e.hi > lo) return false;
    }
    return true;
}

// pick is where n bytes the guest leaves unplaced go, as get_unmapped_area
// puts them: at the hint when it is free, else by the layout's search, a
// private anonymous mapping a whole number of huge pages long on a huge-page
// boundary (thp_get_unmapped_area). lock held.
fn pick(hint: u64, n: u64, anon: bool) ?u64 {
    if (n == 0 or n > TASK_SIZE) return null;
    if (hint != 0 and hint >= PAGE and hint <= guest_top - n and clear(hint, hint + n)) return hint;
    if (anon and hint == 0 and n % HUGE == 0) {
        if (search(n + HUGE)) |a| {
            const skip = (HUGE - a % HUGE) % HUGE;
            return if (skip == 0 and !legacy) a + HUGE else a + skip;
        }
    }
    return search(n);
}

// search is top-down below mmap_base falling back to bottom-up from the
// legacy base, or bottom-up alone with the legacy layout.
fn search(n: u64) ?u64 {
    if (!legacy) {
        if (topDown(n, GUEST_BASE, mmap_base)) |a| return a;
    }
    return bottomUp(n, legacy_base, guest_top);
}

// topDown finds the highest a in [low, high-n] with [a, a+n) clear, as
// unmapped_area_topdown does.
fn topDown(n: u64, low: u64, high: u64) ?u64 {
    var end = high;
    var i = taken.items.len;
    while (i > 0 and taken.items[i - 1].lo >= end) i -= 1;
    while (true) {
        const gap_lo = if (i > 0) @max(taken.items[i - 1].hi, low) else low;
        if (end >= n and end - n >= gap_lo) return (end - n) & ~(PAGE - 1);
        if (i == 0) return null;
        i -= 1;
        end = @min(end, taken.items[i].lo);
        if (end <= low) return null;
    }
}

// bottomUp finds the lowest a in [low, high-n] with [a, a+n) clear, as
// unmapped_area does.
fn bottomUp(n: u64, low: u64, high: u64) ?u64 {
    var start = rdUp(low);
    for (taken.items) |e| {
        if (e.hi <= start) continue;
        if (e.lo >= start and e.lo - start >= n) break;
        start = @max(start, rdUp(e.hi));
        if (start >= high) return null;
    }
    return if (high >= start and high - start >= n) start else null;
}

// regionFrom is the host mapping at or above addr.
fn regionFrom(addr: u64) ?Run {
    var a = addr;
    var size: u64 = 0;
    var info: BasicInfo = undefined;
    var count: c_uint = @sizeOf(BasicInfo) / 4;
    var obj: c_uint = 0;
    if (mach_vm_region(task, &a, &size, VM_REGION_BASIC_INFO_64, &info, &count, &obj) != 0) return null;
    if (obj != 0) _ = mach_port_deallocate(task, obj);
    return .{ .lo = a, .hi = a + size };
}

// pickFree is where the loader puts an image or the stack the layout leaves
// unplaced (0 when the address space has no room).
pub fn pickFree(n: u64) u64 {
    lock.lock();
    defer lock.unlock();
    return pick(0, n, false) orelse 0;
}

// mapStack maps the initial stack of n bytes, ending at the layout's top of
// stack when that is free.
pub fn mapStack(n: u64) u64 {
    return place(stack_top - n, n, PROT_RW, D_PRIVATE | D_ANON, -1, 0, false);
}

pub fn noteImage(lo: u64, hi: u64) void {
    noteTaken(lo, hi - lo, false);
}

// rwx_state caches the supervisor's answer to LC_RWX: 0 not asked yet, 1
// allowed, 2 refused.
var rwx_state = std.atomic.Value(u8).init(0);

fn rwxAllowed() bool {
    switch (rwx_state.load(.monotonic)) {
        1 => return true,
        2 => return false,
        else => {},
    }
    const ok = !isErr(root.hostCall(LC_RWX, .{ 0, 0, 0, 0, 0, 0 }));
    rwx_state.store(if (ok) 1 else 2, .monotonic);
    return ok;
}

fn mmap(addr: u64, len: u64, prot_in: u64, flags: u64, fd: u64, off: u64) u64 {
    const typ = flags & L_TYPE;
    if (typ != L_SHARED and typ != L_PRIVATE and typ != L_SHARED_VALIDATE) return neg(EINVAL);
    if (typ == L_SHARED_VALIDATE and flags & ~L_KNOWN != 0) return neg(EOPNOTSUPP);
    if (len == 0 or off & 0xfff != 0) return neg(EINVAL);
    if (len > 1 << 47) return neg(ENOMEM);
    const n = rdUp(len);
    const prot = prot_in & 7;
    if (prot & 6 == 6 and !rwxAllowed()) return neg(EACCES);
    const noreplace = flags & L_FIXED_NOREPLACE != 0;
    const fixed = !noreplace and flags & L_FIXED != 0;
    if ((fixed or noreplace) and addr & (PAGE - 1) != 0) return neg(EINVAL);
    if ((fixed or noreplace) and (addr > guest_top or n > guest_top - addr)) return neg(ENOMEM);
    var hint = addr;
    if (X86 and flags & L_32BIT != 0 and !fixed and !noreplace) {
        lock.lock();
        const at = bottomUp(n, LOW32_LO, LOW32_TOP);
        lock.unlock();
        hint = at orelse return neg(ENOMEM);
    }
    const shared = typ != L_PRIVATE;
    var r: u64 = undefined;
    var file = false;
    // wx learns of the mapping before another thread can act on what it
    // replaced (see munmap).
    wx.hold();
    defer wx.release();
    if (flags & L_ANON != 0) {
        r = mapAnon(hint, n, prot, flags, shared, fixed, noreplace);
    } else {
        const wshared: u64 = @intFromBool(shared and prot & PROT_WRITE != 0);
        // A file mapped shared and executable: the supervisor's writes to it
        // reach the shadows of its pages (wx.zig).
        const code: u64 = @intFromBool(shared and prot & PROT_EXEC != 0);
        const k = root.hostCall(LC_MMAPFD, .{ fd, wshared, code, 0, 0, 0 });
        if (isErr(k)) return k;
        if (k >> 32 == KIND_ZERO) {
            r = mapAnon(hint, n, prot, flags, shared, fixed, noreplace);
        } else {
            file = true;
            r = mapFile(hint, n, prot, shared, fixed, noreplace, @intCast(k & 0xffffffff), fd, off);
        }
    }
    if (!isErr(r)) {
        if (file and !shared and prot & 6 == 6) {
            // File code the guest may write runs only once rewritten (wx.zig).
            const p = wx.protect(r, n, prot, true, false);
            if (isErr(p)) {
                _ = munmap(r, n);
                return p;
            }
        } else wx.mapped(r, n, prot, (!file or shared) and prot & PROT_EXEC != 0, shared);
    }
    if (!isErr(r) and flags & L_POPULATE != 0) _ = sys(SYS_madvise, r, n, D_MADV_WILLNEED, 0, 0, 0);
    flushGone();
    return r;
}

fn mapAnon(addr: u64, n: u64, prot_in: u64, flags: u64, shared: bool, fixed_in: bool, noreplace_in: bool) u64 {
    var fixed = fixed_in;
    var noreplace = noreplace_in;
    var dw: u64 = D_ANON | (if (shared) D_SHARED else D_PRIVATE);
    if (flags & L_NORESERVE != 0) dw |= D_NORESERVE;
    // Memory the guest makes executable is mapped without execute until it
    // runs (wx.zig).
    const prot = if (prot_in & PROT_EXEC != 0) wx.hostProtOf(prot_in) else prot_in;
    // RWX is only possible in a MAP_JIT region (see jit.zig), which cannot be
    // MAP_FIXED: a fixed one unmaps the range and must land back on it.
    if (prot & 6 == 6) {
        if (fixed) {
            _ = sys(SYS_munmap, addr, n, 0, 0, 0, 0);
            fixed = false;
            noreplace = true;
        }
        dw |= D_JIT;
    }
    if (fixed) dw |= D_FIXED;
    const r = place(addr, n, prot, dw, -1, 0, noreplace);
    if (!isErr(r)) {
        lock.lock();
        if (fixed_in or noreplace_in) vmaPunch(r, r + n, null);
        anonAdd(r, r + n, shared);
        lock.unlock();
    }
    return r;
}

// mapFile maps a regular file. A page-aligned private mapping and any shared
// one map the file itself; a shared executable one runs only once rewritten,
// as a shadow of its pages (wx.zig), and maps without execute. A private executable one
// is mapped writable first, for its sites to be rewritten copy-on-write (a
// shared one's cannot be without writing the file). One that is 4K-aligned or
// runs past the end of the file is copied in.
fn mapFile(addr: u64, n: u64, prot: u64, shared: bool, fixed_in: bool, noreplace: bool, sfd: i32, gfd: u64, off: u64) u64 {
    const id = fdlink.idOf(sfd) orelse return neg(EBADF);
    var at = addr;
    var fixed = fixed_in;
    const room: ?*Room = if (!shared and !fixed and !noreplace) roomFor(addr, n, gfd, off) else null;
    if (room) |rm| {
        at = rm.lo;
        fixed = true;
    }
    const r = mapFileAt(at, n, prot, shared, fixed, noreplace, sfd, gfd, off, id);
    if (isErr(r)) {
        if (room) |rm| dropRoom(rm);
    }
    return r;
}

fn mapFileAt(addr: u64, n: u64, prot: u64, shared: bool, fixed: bool, noreplace: bool, sfd: i32, gfd: u64, off: u64, id: u64) u64 {
    if (shared or (off % PAGE == 0 and prot & PROT_EXEC == 0)) {
        if (off % PAGE != 0) return neg(EINVAL);
        const dw: u64 = (if (shared) D_SHARED else D_PRIVATE) | (if (fixed) D_FIXED else 0);
        const r = place(addr, n, if (prot & PROT_EXEC != 0) wx.hostProtOf(prot) else prot, dw, sfd, off, noreplace);
        if (isErr(r)) return r;
        return record(r, n, .{ .lo = r, .hi = r + n, .id = id, .off = off, .shared = shared });
    }
    if (off % PAGE == 0 and off + n <= rdUp(fileSize(sfd) orelse 0)) {
        const r = place(addr, n, PROT_RW, D_PRIVATE | (if (fixed) D_FIXED else 0), sfd, off, noreplace);
        if (isErr(r)) return r;
        rewrite(r, n, off, gfd);
        const p = jit.protect(r, n, prot);
        if (isErr(p)) {
            _ = sys(SYS_munmap, r, n, 0, 0, 0, 0);
            return p;
        }
        return record(r, n, .{ .lo = r, .hi = r + n, .id = id, .off = off, .exec = true });
    }
    const dw: u64 = D_PRIVATE | D_ANON | (if (fixed) D_FIXED else 0);
    const r = place(addr, n, PROT_RW, dw, -1, 0, noreplace);
    if (isErr(r)) return r;
    const k = fill(r, n, sfd, off);
    if (k < 0) {
        _ = sys(SYS_munmap, r, n, 0, 0, 0, 0);
        return lx(k);
    }
    if (prot & PROT_EXEC != 0) rewrite(r, n, off, gfd);
    if (prot != PROT_RW) {
        const p = jit.protect(r, n, prot);
        if (isErr(p)) {
            _ = sys(SYS_munmap, r, n, 0, 0, 0, 0);
            return p;
        }
    }
    return record(r, n, .{ .lo = r, .hi = r + n, .id = id, .off = off, .copy = true, .exec = prot & PROT_EXEC != 0 });
}

// ---- island rooms -------------------------------------------------------------
//
// A rewritten site branches to its island, which must lie within b's
// +-128 MiB. A private file mapping the kernel places, of a range that has
// sites, is placed with room for all their islands on each side, so every site
// reaches one however full the address space around it is (an area beside a
// library wider than b reaches serves the sites at that end). glibc maps a
// library's whole span first, without execute, and its text inside that span
// later: the room is kept by span and found again when the text is rewritten.

pub const Room = struct {
    lo: u64, // the span: the low area ends at lo, the high one starts at hi
    hi: u64,
    size: u64, // of each area; 0 once dropped
    used: [2]u64 = .{ 0, 0 }, // what islands took of each area
    busy: bool = false, // a rewrite is placing islands in it

    pub fn area(self: *const Room, i: usize) u64 {
        return if (i == 0) self.lo - self.size else self.hi;
    }
};

var rooms: [512]Room = undefined; // guarded by lock
var nrooms: usize = 0;

// cur_room is the room of the text this thread is rewriting, for lcRewrite.
pub threadlocal var cur_room: ?*Room = null;

// roomFor reserves n bytes for a mapping of file gfd at off, with room for
// its sites' islands, near addr; null when the range has no sites or no room
// can be had, for the mapping to go where the kernel puts it.
fn roomFor(addr: u64, n: u64, gfd: u64, off: u64) ?*Room {
    const k = root.hostCall(LC_REWRITE, .{ 0, n, off, gfd, 1, 0 });
    if (isErr(k) or k == 0) return null;
    const g = rdUp(k * root.ISLAND_SIZE) + PAGE;
    const r = place(if (addr > g) addr - g else addr, n + 2 * g, PROT_RW, D_PRIVATE | D_ANON, -1, 0, false);
    if (isErr(r)) return null;
    lock.lock();
    defer lock.unlock();
    if (nrooms == rooms.len) {
        _ = sys(SYS_munmap, r, n + 2 * g, 0, 0, 0, 0);
        return null;
    }
    rooms[nrooms] = .{ .lo = r + g, .hi = r + g + n, .size = g };
    nrooms += 1;
    return &rooms[nrooms - 1];
}

// dropRoom gives back the room of a mapping that failed.
fn dropRoom(rm: *Room) void {
    _ = sys(SYS_munmap, rm.area(0), rm.hi + rm.size - rm.area(0), 0, 0, 0, 0);
    lock.lock();
    rm.size = 0;
    lock.unlock();
}

// rewrite has the supervisor rewrite the sites of the text just mapped at r,
// with the islands in the room of its span when it has one; the pages they
// took are sealed executable after, and a later rewrite starts past them.
fn rewrite(r: u64, n: u64, off: u64, gfd: u64) void {
    var room: ?*Room = null;
    lock.lock();
    for (rooms[0..nrooms]) |*rm| {
        if (rm.size != 0 and !rm.busy and rm.lo <= r and r + n <= rm.hi) {
            rm.busy = true;
            room = rm;
            break;
        }
    }
    lock.unlock();
    const from: [2]u64 = if (room) |rm| rm.used else .{ 0, 0 };
    cur_room = room;
    _ = root.hostCall(LC_REWRITE, .{ r, n, off, gfd, 0, 0 });
    cur_room = null;
    const rm = room orelse return;
    for (0..2) |i| {
        const done = rdUp(rm.used[i]);
        if (done > from[i]) _ = sys(SYS_mprotect, rm.area(i) + from[i], done - from[i], PROT_READ | PROT_EXEC, 0, 0, 0);
        rm.used[i] = done;
    }
    lock.lock();
    rm.busy = false;
    lock.unlock();
}

// record notes a new file mapping at r, undoing it if there is no room.
fn record(r: u64, n: u64, v: Vma) u64 {
    lock.lock();
    defer lock.unlock();
    vmaPunch(r, r + n, null);
    anonPunch(r, r + n);
    if (!vmaAdd(v)) {
        _ = sys(SYS_munmap, r, n, 0, 0, 0, 0);
        return neg(ENOMEM);
    }
    return r;
}

// fileSize returns the size of the file open at fd.
fn fileSize(fd: i32) ?u64 {
    var st: [144]u8 align(8) = undefined;
    if (sys(SYS_fstat64, @intCast(fd), @intFromPtr(&st), 0, 0, 0, 0) < 0) return null;
    return std.mem.readInt(u64, st[96..104], .little);
}

// fill reads up to n bytes of fd at off into dst; past EOF stays as it was.
fn fill(dst: u64, n: u64, fd: i32, off: u64) i64 {
    var got: u64 = 0;
    while (got < n) {
        const k = sys(SYS_pread, @intCast(fd), dst + got, n - got, off + got, 0, 0);
        if (k < 0) return k;
        if (k == 0) break;
        got += @intCast(k);
    }
    return 0;
}

// mprotect goes through jit.zig: RWX lives in MAP_JIT regions, whose
// protection only the stub can manage. PROT_BTI is accepted and has no effect
// (the guest's branch targets are not enforced here).
fn mprotect(addr: u64, len: u64, prot: u64) u64 {
    const PROT_BTI: u64 = 0x10;
    const PROT_GROWSDOWN: u64 = 0x01000000;
    const PROT_GROWSUP: u64 = 0x02000000;
    if (addr & (PAGE - 1) != 0) return neg(EINVAL);
    if (prot & ~(7 | PROT_BTI | PROT_GROWSDOWN | PROT_GROWSUP) != 0) return neg(EINVAL);
    if (prot & PROT_GROWSDOWN != 0 and prot & PROT_GROWSUP != 0) return neg(EINVAL);
    if (len > 1 << 47) return neg(ENOMEM);
    const n = rdUp(len);
    if (n == 0) return 0;
    if (prot & 6 == 6 and !rwxAllowed()) return neg(EACCES);
    const p = prot & 7;
    if (p & PROT_WRITE != 0 and anyText(addr, addr + n)) wx.dirty(addr, addr + n);
    const shared = anyShared(addr, addr + n);
    const emulate = p & PROT_EXEC != 0 and (shared or !cleanText(addr, addr + n, p));
    if (shared and p & PROT_EXEC != 0) markCode(addr, addr + n);
    return wx.protect(addr, n, p, emulate, shared);
}

// markCode tells the supervisor the files [lo, hi) maps shared are mapped
// executable: its writes to them reach the shadows of their pages (wx.zig).
fn markCode(lo: u64, hi: u64) void {
    var ids: [8]u64 = undefined;
    var n: usize = 0;
    lock.lock();
    for (vmas.items) |e| {
        if (e.kind != .file or !e.shared or e.hi <= lo or e.lo >= hi) continue;
        if (std.mem.indexOfScalar(u64, ids[0..n], e.id) != null) continue;
        if (n == ids.len) break;
        ids[n] = e.id;
        n += 1;
    }
    lock.unlock();
    for (ids[0..n]) |id| _ = root.hostCall(LC_CODEFILE, .{ id, 0, 0, 0, 0, 0 });
}

// syncFiles tells the supervisor to write each non-host file this stub maps
// shared in [lo, hi) back to its backend. The stub has already flushed its own
// pages to the host temp file (SYS_msync); the supervisor copies that to the
// file. A non-host file shared mapping that the supervisor does not back is
// ignored there, so host-file mappings in the range cost only the call.
fn syncFiles(lo: u64, hi: u64) void {
    var ids: [8]u64 = undefined;
    var n: usize = 0;
    lock.lock();
    for (vmas.items) |e| {
        if (e.kind != .file or !e.shared or e.hi <= lo or e.lo >= hi) continue;
        if (std.mem.indexOfScalar(u64, ids[0..n], e.id) != null) continue;
        if (n == ids.len) break;
        ids[n] = e.id;
        n += 1;
    }
    lock.unlock();
    for (ids[0..n]) |id| _ = root.hostCall(LC_SYNCFILE, .{ id, 0, 0, 0, 0, 0 });
}

// sharedIds collects into ids the shared file ids [lo, hi) maps, returning how
// many; used by munmap to notice when a file's last mapping is gone.
fn sharedIds(lo: u64, hi: u64, ids: *[8]u64) usize {
    var n: usize = 0;
    lock.lock();
    defer lock.unlock();
    for (vmas.items) |e| {
        if (e.kind != .file or !e.shared or e.hi <= lo or e.lo >= hi) continue;
        if (std.mem.indexOfScalar(u64, ids[0..n], e.id) != null) continue;
        if (n == ids.len) break;
        ids[n] = e.id;
        n += 1;
    }
    return n;
}

// mapsId reports whether any mapping of file id survives.
fn mapsId(id: u64) bool {
    lock.lock();
    defer lock.unlock();
    for (vmas.items) |e| if (e.kind == .file and e.id == id) return true;
    return false;
}

// fileOf is the host file (device, inode) whose shared mapping page is, if
// it is one.
pub fn fileOf(page: u64) ?[2]u64 {
    lock.lock();
    const v = vmaAt(page);
    lock.unlock();
    const e = v orelse return null;
    if (e.kind != .file or !e.shared) return null;
    const fd = fdlink.lookup(e.id) orelse return null;
    var st: [144]u8 align(8) = undefined;
    if (sys(SYS_fstat64, @intCast(fd), @intFromPtr(&st), 0, 0, 0, 0) < 0) return null;
    return .{ std.mem.readInt(u32, st[0..4], .little), std.mem.readInt(u64, st[8..16], .little) };
}

// eachShared calls f with each of the guest's shared mappings, the tables
// held still meanwhile.
pub fn eachShared(ctx: anytype, f: fn (@TypeOf(ctx), u64, u64) void) void {
    lock.lock();
    defer lock.unlock();
    for (anons.items) |e| {
        if (e.shared) f(ctx, e.lo, e.hi);
    }
    for (vmas.items) |e| {
        if (e.shared) f(ctx, e.lo, e.hi);
    }
}

// anyText reports whether part of [lo, hi) is file code cleanText may find.
fn anyText(lo: u64, hi: u64) bool {
    const pi = procinfo.info;
    if (lo < pi.main_hi and pi.main_lo < hi) return true;
    if (lo < pi.interp_hi and pi.interp_lo < hi) return true;
    lock.lock();
    defer lock.unlock();
    for (vmas.items) |e| {
        if (e.exec and e.lo < hi and lo < e.hi) return true;
    }
    return false;
}

// cleanText reports whether [lo, hi) is code from a file the stub mapped and
// rewrote, which the guest has never been able to write since: its own and
// its interpreter's text, and executable file mappings. Anything else made
// executable runs only once rewritten (wx.zig).
fn cleanText(lo: u64, hi: u64, prot: u64) bool {
    if (prot & PROT_WRITE != 0 or wx.dirtyIn(lo, hi)) return false;
    const pi = procinfo.info;
    var a = lo;
    while (a < hi) {
        const r = regionAt(a) orelse return false;
        if (r.info.prot & 2 != 0) return false;
        const end = @min(r.hi, hi);
        const image = (a >= pi.main_lo and end <= pi.main_hi) or (a >= pi.interp_lo and end <= pi.interp_hi);
        if (!image) {
            lock.lock();
            const v = vmaAt(a);
            lock.unlock();
            if (v == null or !v.?.exec or v.?.hi < end) return false;
        }
        a = end;
    }
    return true;
}

fn munmap(addr: u64, len: u64) u64 {
    if (addr & (PAGE - 1) != 0 or len == 0) return neg(EINVAL);
    const n = rdUp(len);
    // wx learns of the unmap before another thread's mapping can land there.
    wx.hold();
    defer wx.release();
    const r = if (inLow(addr, addr + n))
        sys(SYS_mmap, addr, n, 0, D_PRIVATE | D_ANON | D_FIXED | D_NORESERVE, @bitCast(@as(i64, -1)), 0)
    else
        sys(SYS_munmap, addr, n, 0, 0, 0, 0);
    if (r < 0) return lx(r);
    dropped(addr, addr + n);
    flushGone();
    return 0;
}

// dropped forgets [lo, hi), unmapped or mapped over, and tells the supervisor
// of the non-host files it mapped shared that no mapping holds any more (so it
// releases their backings). wx is held.
fn dropped(lo: u64, hi: u64) void {
    var ids: [8]u64 = undefined;
    const nid = sharedIds(lo, hi, &ids);
    lock.lock();
    vmaPunch(lo, hi, null);
    anonPunch(lo, hi);
    takenDel(lo, hi);
    lock.unlock();
    wx.unmapped(lo, hi);
    for (ids[0..nid]) |id| {
        if (!mapsId(id)) _ = root.hostCall(LC_UNMAPFILE, .{ id, 0, 0, 0, 0, 0 });
    }
}

// ---- region queries --------------------------------------------------------------

const Region = struct { lo: u64, hi: u64, info: BasicInfo };

// regionAt returns the mapping containing addr, or null if addr is unmapped.
fn regionAt(addr: u64) ?Region {
    var a = addr;
    var size: u64 = 0;
    var info: BasicInfo = undefined;
    var count: c_uint = @sizeOf(BasicInfo) / 4;
    var obj: c_uint = 0;
    if (mach_vm_region(task, &a, &size, VM_REGION_BASIC_INFO_64, &info, &count, &obj) != 0) return null;
    if (obj != 0) _ = mach_port_deallocate(task, obj);
    if (a > addr) return null;
    return .{ .lo = a, .hi = a + size, .info = info };
}

// writable reports whether addr is mapped with write permission: a MAP_JIT
// region is, whichever view this thread has of it.
pub fn writable(addr: u64) bool {
    const r = regionAt(addr) orelse return false;
    return r.info.prot & 2 != 0;
}

// protAt is the protection addr is mapped with, if it is mapped.
pub fn protAt(addr: u64) ?u32 {
    const r = regionAt(addr) orelse return null;
    return @intCast(r.info.prot);
}

// pastEnd reports whether addr is in a page of a shared file mapping that
// lies wholly past the file's end, which has no page to give.
pub fn pastEnd(addr: u64) bool {
    lock.lock();
    defer lock.unlock();
    for (vmas.items) |e| {
        if (e.kind != .file or !e.shared or e.copy or addr < e.lo or addr >= e.hi) continue;
        const fd = fdlink.lookup(e.id) orelse return false;
        const size = fileSize(fd) orelse return false;
        return e.off + (addr & ~(PAGE - 1)) - e.lo >= rdUp(size);
    }
    return false;
}

// isShared reports whether addr is in a MAP_SHARED mapping.
pub fn isShared(addr: u64) bool {
    const r = regionAt(addr) orelse return false;
    if (r.info.inherit == VM_INHERIT_SHARE) return true;
    if (r.info.inherit != VM_INHERIT_NONE) return false;
    lock.lock();
    defer lock.unlock();
    return noforkAt(addr);
}

// isJit reports whether addr is in a MAP_JIT region, the only kind that can
// be read+write+execute.
pub fn isJit(addr: u64) bool {
    const r = regionAt(addr) orelse return false;
    return r.info.prot & 7 == 7;
}

// mapped reports whether all of [lo, hi) is mapped.
pub fn mapped(lo: u64, hi: u64) bool {
    var a = lo;
    while (a < hi) {
        const r = regionAt(a) orelse return false;
        a = r.hi;
    }
    return true;
}

// ---- mremap ------------------------------------------------------------------------

const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;

// Darwin has no mremap. Pages move with mach_vm_remap (no copy: the new range
// takes over the same memory objects, so shared mappings stay shared and file
// mappings stay file-backed) and a grown tail is mapped fresh to match the
// old range's last mapping. A MAP_JIT (RWX) range is copied instead.
fn mremap(old: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64) u64 {
    const r = if (old & (PAGE - 1) == 0 and isVdso(old, rdUp(old_len)))
        moveVdso(old, rdUp(old_len), rdUp(new_len), flags, new_addr)
    else
        remapCode(old, old_len, new_len, flags, new_addr);
    if (!isErr(r)) noteTaken(r, rdUp(new_len), false);
    flushGone();
    return r;
}

fn isVdso(lo: u64, n: u64) bool {
    lock.lock();
    defer lock.unlock();
    for (vmas.items) |e| {
        if (e.kind == .vdso and e.lo == lo and e.hi == lo + n) return true;
    }
    return false;
}

// moveVdso moves the vDSO, as Linux lets CRIU, whole and to its own size: a
// fresh copy at dst (remapVdso), so it still runs where it went.
fn moveVdso(old: u64, n: u64, nn: u64, flags: u64, dst: u64) u64 {
    if (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED) != 0 or nn != n) return neg(EINVAL);
    if (flags & MREMAP_FIXED == 0) return old;
    if (flags & MREMAP_MAYMOVE == 0 or dst & (PAGE - 1) != 0) return neg(EINVAL);
    if (dst < old + n and old < dst + n) return neg(EINVAL);
    wx.hold();
    defer wx.release();
    if (!root.remapVdso(dst, n)) return neg(ENOMEM);
    dropped(dst, dst + n);
    _ = sys(SYS_munmap, old, n, 0, 0, 0, 0);
    dropped(old, old + n);
    noteVdso(dst, dst + n);
    return dst;
}

// remapCode moves what wx.zig knows of the range along with it, its pages
// stopped first so the traps in them stay behind.
fn remapCode(old: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64) u64 {
    wx.hold();
    defer wx.release();
    const on = rdUp(old_len);
    if (old & (PAGE - 1) == 0) wx.reset(old, old + (if (on != 0) on else rdUp(new_len)));
    const r = remap(old, old_len, new_len, flags, new_addr);
    if (isErr(r)) return r;
    if (on == 0) {
        wx.aliased(old, r, rdUp(new_len)); // a second mapping of shared memory
    } else {
        wx.moved(old, on, r, rdUp(new_len), flags & MREMAP_DONTUNMAP != 0);
    }
    return r;
}

fn remap(old: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64) u64 {
    if (old & (PAGE - 1) != 0) return neg(EINVAL);
    if (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0) return neg(EINVAL);
    if (flags & MREMAP_FIXED != 0 and flags & MREMAP_MAYMOVE == 0) return neg(EINVAL);
    if (flags & MREMAP_DONTUNMAP != 0 and (flags & MREMAP_MAYMOVE == 0 or old_len != new_len)) return neg(EINVAL);
    const on = rdUp(old_len);
    const nn = rdUp(new_len);
    if (nn == 0) return neg(EINVAL);
    if (on == 0) return dup(old, nn, flags, new_addr);
    if (!mapped(old, old + on)) return neg(EFAULT);
    lock.lock();
    defer lock.unlock();
    const last = regionAt(old + on - 1) orelse return neg(EFAULT);
    const first = regionAt(old) orelse return neg(EFAULT);

    if (flags & MREMAP_FIXED != 0) {
        if (new_addr & (PAGE - 1) != 0) return neg(EINVAL);
        if (new_addr < old + on and old < new_addr + nn) return neg(EINVAL);
        _ = sys(SYS_munmap, new_addr, nn, 0, 0, 0, 0);
        vmaPunch(new_addr, new_addr + nn, null);
        anonPunch(new_addr, new_addr + nn);
        return moveTo(old, on, nn, new_addr, flags, first, last);
    }
    if (flags & MREMAP_DONTUNMAP == 0) {
        if (nn <= on) {
            if (nn < on) {
                _ = sys(SYS_munmap, old + nn, on - nn, 0, 0, 0, 0);
                vmaPunch(old + nn, old + on, null);
                anonPunch(old + nn, old + on);
            }
            return old;
        }
        if (extend(old, on, nn - on, last, false)) return old;
    }
    if (flags & MREMAP_MAYMOVE == 0) return neg(ENOMEM);
    const r: i64 = @bitCast(placeAt(0, nn, 0, D_PRIVATE | D_ANON, -1, 0, false, true));
    if (r < 0) return neg(ENOMEM);
    return moveTo(old, on, nn, @bitCast(r), flags, first, last);
}

// moveTo moves [old, old+on) to dst (whose nn bytes are free or reserved),
// mapping any grown tail and releasing the old range.
fn moveTo(old: u64, on_in: u64, nn: u64, dst: u64, flags: u64, first: Region, last: Region) u64 {
    var on = on_in;
    if (nn < on) {
        _ = sys(SYS_munmap, old + nn, on - nn, 0, 0, 0, 0);
        vmaPunch(old + nn, old + on, null);
        anonPunch(old + nn, old + on);
        on = nn;
    }
    if (!move(old, dst, on, first.info)) {
        _ = sys(SYS_munmap, dst, nn, 0, 0, 0, 0);
        return neg(ENOMEM);
    }
    vmaPunch(dst, dst + nn, null);
    vmaMove(old, old + on, dst);
    anonPunch(dst, dst + nn);
    anonMove(old, old + on, dst);
    if (nn > on and !extend(dst, on, nn - on, last, true)) {
        _ = sys(SYS_munmap, dst, nn, 0, 0, 0, 0);
        return neg(ENOMEM);
    }
    if (flags & MREMAP_DONTUNMAP != 0) {
        // The old range stays mapped but empty, as a fresh private mapping.
        _ = sys(SYS_mmap, old, on, @intCast(first.info.prot & 7), D_PRIVATE | D_ANON | D_FIXED, @bitCast(@as(i64, -1)), 0);
        anonAdd(old, old + on, false);
    } else {
        _ = sys(SYS_munmap, old, on, 0, 0, 0, 0);
    }
    return dst;
}

fn move(src: u64, dst: u64, n: u64, info: BasicInfo) bool {
    if (info.prot & 7 == 7) {
        _ = sys(SYS_munmap, dst, n, 0, 0, 0, 0);
        const r = sys(SYS_mmap, dst, n, 7, D_PRIVATE | D_ANON | D_JIT, @bitCast(@as(i64, -1)), 0);
        if (r < 0) return false;
        if (@as(u64, @bitCast(r)) != dst) {
            _ = sys(SYS_munmap, @bitCast(r), n, 0, 0, 0, 0);
            return false;
        }
        jit.copyIn(dst, src, n);
        return true;
    }
    var d = dst;
    var cur: c_int = 0;
    var max: c_int = 0;
    return mach_vm_remap(task, &d, n, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, task, src, 0, &cur, &max, info.inherit) == 0;
}

// extend maps len more bytes after [base, base+on) like the mapping `last`
// that ended the old range: more of the same file, or fresh anonymous memory,
// shared if it was shared. Without `fixed` the bytes must be free.
fn extend(base: u64, on: u64, len: u64, last: Region, fixed: bool) bool {
    const at = base + on;
    const prot: u64 = @intCast(last.info.prot & 7);
    const shared = last.info.inherit == VM_INHERIT_SHARE;
    var dw: u64 = if (shared) D_SHARED else D_PRIVATE;
    if (fixed) dw |= D_FIXED;
    var fd: i64 = -1;
    var off: u64 = 0;
    if (vmaAt(at - 1)) |v| {
        fd = fdlink.lookup(v.id) orelse return false;
        off = v.off + (at - v.lo);
    } else if (prot == 7) {
        // MAP_JIT cannot be MAP_FIXED: free the range and map at it as a hint.
        if (fixed) _ = sys(SYS_munmap, at, len, 0, 0, 0, 0);
        dw = D_PRIVATE | D_ANON | D_JIT;
    } else {
        dw |= D_ANON;
    }
    const r = sys(SYS_mmap, at, len, prot, dw, @bitCast(fd), off);
    if (r < 0) return false;
    if (@as(u64, @bitCast(r)) != at) {
        _ = sys(SYS_munmap, @bitCast(r), len, 0, 0, 0, 0);
        return false;
    }
    if (vmaAt(at - 1)) |v| {
        // Widen the entry that ends at the old end.
        for (vmas.items) |*e| {
            if (e.kind == .file and e.hi == v.hi and e.lo == v.lo) e.hi = at + len;
        }
    } else {
        anonAdd(at, at + len, shared);
    }
    return true;
}

// dup serves mremap with old_len 0: a second mapping of the same pages, which
// Linux allows only for a shared mapping.
fn dup(old: u64, nn: u64, flags: u64, new_addr: u64) u64 {
    if (flags & MREMAP_MAYMOVE == 0) return neg(ENOMEM);
    if (flags & MREMAP_DONTUNMAP != 0) return neg(EINVAL);
    const first = regionAt(old) orelse return neg(EFAULT);
    if (first.info.inherit != VM_INHERIT_SHARE) return neg(EINVAL);
    if (!mapped(old, old + nn)) return neg(EFAULT);
    var d: u64 = 0;
    var vf: c_int = VM_FLAGS_ANYWHERE;
    if (flags & MREMAP_FIXED != 0) {
        if (new_addr & (PAGE - 1) != 0) return neg(EINVAL);
        d = new_addr;
        vf = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
    }
    lock.lock();
    defer lock.unlock();
    var cur: c_int = 0;
    var max: c_int = 0;
    if (mach_vm_remap(task, &d, nn, 0, vf, task, old, 0, &cur, &max, VM_INHERIT_SHARE) != 0) return neg(ENOMEM);
    vmaPunch(d, d + nn, null);
    anonPunch(d, d + nn);
    anonShared(old, old + nn, d);
    var i: usize = 0;
    const n = vmas.items.len;
    while (i < n) : (i += 1) {
        const e = vmas.items[i];
        if (e.kind != .file or e.hi <= old or e.lo >= old + nn) continue;
        const lo = @max(e.lo, old);
        const hi = @min(e.hi, old + nn);
        _ = vmaAdd(.{ .lo = lo - old + d, .hi = hi - old + d, .id = e.id, .off = e.off + (lo - e.lo), .shared = e.shared });
    }
    return d;
}

// ---- brk ---------------------------------------------------------------------------

// ---- fork --------------------------------------------------------------------------

// A fork child is a fresh stub (sfork.zig) that maps its parent's guest memory
// at the same addresses: the parent lists it region by region, copy-on-write
// or shared as Linux's fork would leave it, and hands over its tables.

// GUEST_TOP is malloc's nano zone, the stub's: the guest's memory lies below,
// from GUEST_BASE, and above it from TOP_LO.
pub const GUEST_TOP: u64 = 0x6000_0000_0000;

// LOW_LO and LOW_TOP bound the x86-64 stub's low reserve, the guest's own
// (sandbox patchStub).
const LOW_LO: u64 = 0x10000;
// MAP_32BIT goes in the second gigabyte, as x86-64 Linux puts it.
const LOW32_LO: u64 = 1 << 30;
const LOW32_TOP: u64 = 2 << 30;
const LOW_TOP: u64 = 4 << 30;

// inLow reports [lo, hi) inside the low reserve: what the guest leaves there
// goes back to the reserve rather than to Darwin.
fn inLow(lo: u64, hi: u64) bool {
    return X86 and lo >= LOW_LO and hi <= LOW_TOP;
}

pub fn inWindow(lo: u64, hi: u64) bool {
    return lo >= GUEST_BASE and hi <= GUEST_TOP or lo >= TOP_LO and hi <= HOST_TOP or
        inLow(lo, hi);
}

pub const RegionKind = enum(u32) { copy, share, empty, jit };
pub const ForkRegion = extern struct { addr: u64, size: u64, cur: i32, max: i32, inherit: u32, kind: RegionKind };

const VM_REGION_EXTENDED_INFO: c_int = 13;
const SM_EMPTY: u8 = 3;
const ExtInfo = extern struct {
    prot: i32,
    user_tag: u32,
    resident: u32,
    shared_now_private: u32,
    swapped_out: u32,
    dirtied: u32,
    ref_count: u32,
    shadow_depth: u16,
    external_pager: u8,
    share_mode: u8,
    reusable: u32,
};

// hostRegion is Darwin's own memory inside the guest's window, which every
// process has of its own; on x86-64 the window holds much of it. The shared
// region is a submap; malloc's zones, thread stacks and Rosetta's allocations
// carry their VM tags; and what lay there before the stub ran (Rosetta's
// runtime, the first zones) noteHost recorded.
fn hostRegion(info: BasicInfo, ext: ExtInfo, lo: u64, hi: u64) bool {
    if (info.reserved != 0) return true;
    switch (ext.user_tag) {
        1...13, 30, 230...239 => return true,
        else => {},
    }
    for (host_at_start[0..nhost]) |r| {
        if (r.lo < hi and lo < r.hi) return true;
    }
    return false;
}

var host_at_start: [64]Range = undefined;
var nhost: usize = 0;

// noteHost records what lies in the guest's upper window when the stub
// starts, before any guest memory: the host's.
pub fn noteHost() void {
    const t = mach_task_self();
    var a: u64 = TOP_LO;
    while (a < HOST_TOP and nhost < host_at_start.len) {
        var ra = a;
        var size: u64 = 0;
        var info: BasicInfo = undefined;
        var count: c_uint = @sizeOf(BasicInfo) / 4;
        var obj: c_uint = 0;
        if (mach_vm_region(t, &ra, &size, VM_REGION_BASIC_INFO_64, &info, &count, &obj) != 0) break;
        if (obj != 0) _ = mach_port_deallocate(t, obj);
        if (ra >= HOST_TOP) break;
        host_at_start[nhost] = .{ .lo = ra, .hi = ra + size };
        nhost += 1;
        a = ra + size;
    }
    if (X86) {
        var floor: u64 = HOST_TOP;
        for (host_at_start[0..nhost]) |r| {
            if (r.lo >= HOST_BLOCK) floor = @min(floor, r.lo);
        }
        guest_top = floor & ~@as(u64, (1 << 30) - 1);
    }
}

// HOST_BLOCK bounds from below where the host's own high block starts.
const HOST_BLOCK: u64 = 0x7ff0_0000_0000;

// takeHost marks the host's memory in the guest's upper window taken, so no
// placement lands on it (lock held).
fn takeHost() void {
    const t = mach_task_self();
    var a: u64 = TOP_LO;
    while (a < HOST_TOP) {
        var ra = a;
        var size: u64 = 0;
        var info: BasicInfo = undefined;
        var count: c_uint = @sizeOf(BasicInfo) / 4;
        var obj: c_uint = 0;
        if (mach_vm_region(t, &ra, &size, VM_REGION_BASIC_INFO_64, &info, &count, &obj) != 0) break;
        if (obj != 0) _ = mach_port_deallocate(t, obj);
        if (ra >= HOST_TOP) break;
        var ea = ra;
        var esize: u64 = 0;
        var ext: ExtInfo = undefined;
        var ecount: c_uint = @sizeOf(ExtInfo) / 4;
        if (mach_vm_region(t, &ea, &esize, VM_REGION_EXTENDED_INFO, &ext, &ecount, &obj) != 0) break;
        if (obj != 0) _ = mach_port_deallocate(t, obj);
        if (hostRegion(info, ext, ra, ra + size)) takenAdd(ra, ra + size);
        a = ra + size;
    }
    if (guest_top < HOST_TOP) takenAdd(guest_top, HOST_TOP);
}

const Range = struct { lo: u64, hi: u64 };

fn rangeLess(_: void, a: Range, b: Range) bool {
    return a.lo < b.lo;
}

// forkRegions lists the guest's memory into out and leaves the tables locked
// for forkSave (forkUnlock releases them): every host region in
// [GUEST_BASE, GUEST_TOP) and in any mapping the guest fixed outside it, but
// not one MADV_DONTFORK took out of inheritance. A region never written
// (empty) carries no memory, only its place and protections.
pub fn forkRegions(out: *std.ArrayList(ForkRegion)) bool {
    wx.forkLock();
    lock.lock();
    var ranges = std.ArrayList(Range).init(gpa);
    defer ranges.deinit();
    ranges.append(.{ .lo = GUEST_BASE, .hi = GUEST_TOP }) catch return false;
    ranges.append(.{ .lo = TOP_LO, .hi = HOST_TOP }) catch return false;
    for (anons.items) |e| ranges.append(.{ .lo = e.lo, .hi = e.hi }) catch return false;
    for (vmas.items) |e| ranges.append(.{ .lo = e.lo, .hi = e.hi }) catch return false;
    if (brk_base != 0) ranges.append(.{ .lo = brk_base, .hi = brk_base + BRK_RESERVE }) catch return false;
    const pi = procinfo.info;
    for ([_]Range{ .{ .lo = pi.main_lo, .hi = pi.main_hi }, .{ .lo = pi.interp_lo, .hi = pi.interp_hi }, .{ .lo = pi.stack_lo, .hi = pi.stack_hi } }) |r| {
        if (r.hi > r.lo) ranges.append(r) catch return false;
    }
    std.mem.sort(Range, ranges.items, {}, rangeLess);
    var done: u64 = 0;
    for (ranges.items) |g| {
        var a = @max(g.lo, done);
        while (a < g.hi) {
            var ra = a;
            var size: u64 = 0;
            var info: BasicInfo = undefined;
            var count: c_uint = @sizeOf(BasicInfo) / 4;
            var obj: c_uint = 0;
            if (mach_vm_region(task, &ra, &size, VM_REGION_BASIC_INFO_64, &info, &count, &obj) != 0) break;
            if (obj != 0) _ = mach_port_deallocate(task, obj);
            if (ra >= g.hi) break;
            const lo = @max(ra, a);
            const hi = @min(ra + size, g.hi);
            var ea = ra;
            var esize: u64 = 0;
            var ext: ExtInfo = undefined;
            var ecount: c_uint = @sizeOf(ExtInfo) / 4;
            if (mach_vm_region(task, &ea, &esize, VM_REGION_EXTENDED_INFO, &ext, &ecount, &obj) != 0) break;
            if (info.inherit != VM_INHERIT_NONE and !hostRegion(info, ext, lo, hi)) {
                // A shared region stays shared even before anything is
                // written to it; a private one never written is only a place.
                const kind: RegionKind = if (info.inherit == VM_INHERIT_SHARE)
                    .share
                else if (ext.share_mode == SM_EMPTY)
                    .empty
                else if (info.prot & 7 == 7)
                    .jit
                else
                    .copy;
                out.append(.{ .addr = lo, .size = hi - lo, .cur = info.prot, .max = info.maxprot, .inherit = info.inherit, .kind = kind }) catch return false;
            }
            a = hi;
            done = hi;
        }
    }
    return true;
}

// ForkState heads the tables a fork child takes over.
pub const ForkState = extern struct { brk_base: u64, brk_cur: u64, brk_end: u64, brk_hint: u64, hint_exe: u64, stack_top: u64, mmap_base: u64, legacy_base: u64, legacy: u8, rwx: u8, nvma: u32, nanon: u32, nroom: u32, ntaken: u32 };

// forkSave appends the tables to buf, after forkRegions; the child is the
// same binary, so the entries go as they are.
pub fn forkSave(buf: *std.ArrayList(u8)) bool {
    const st = ForkState{ .brk_base = brk_base, .brk_cur = brk_cur, .brk_end = brk_end, .brk_hint = brk_hint, .hint_exe = hint_exe, .stack_top = stack_top, .mmap_base = mmap_base, .legacy_base = legacy_base, .legacy = @intFromBool(legacy), .rwx = rwx_state.load(.monotonic), .nvma = @intCast(vmas.items.len), .nanon = @intCast(anons.items.len), .nroom = @intCast(nrooms), .ntaken = @intCast(taken.items.len) };
    buf.appendSlice(std.mem.asBytes(&st)) catch return false;
    buf.appendSlice(std.mem.sliceAsBytes(vmas.items)) catch return false;
    buf.appendSlice(std.mem.sliceAsBytes(anons.items)) catch return false;
    for (rooms[0..nrooms]) |rm| {
        var r = rm;
        r.busy = false;
        buf.appendSlice(std.mem.asBytes(&r)) catch return false;
    }
    buf.appendSlice(std.mem.sliceAsBytes(taken.items)) catch return false;
    return wx.forkSave(buf);
}

pub fn forkUnlock() void {
    lock.unlock();
    wx.forkUnlock();
}

// forkLoad takes over the tables forkSave wrote; b is advanced past them.
// fdlink's entries must be in place first: each file range takes a hold.
pub fn forkLoad(b: *[]const u8) bool {
    if (b.len < @sizeOf(ForkState)) return false;
    const st = std.mem.bytesToValue(ForkState, b.*[0..@sizeOf(ForkState)]);
    b.* = b.*[@sizeOf(ForkState)..];
    lock.lock();
    defer lock.unlock();
    brk_base = st.brk_base;
    brk_cur = st.brk_cur;
    brk_end = st.brk_end;
    brk_hint = st.brk_hint;
    hint_exe = st.hint_exe;
    stack_top = st.stack_top;
    mmap_base = st.mmap_base;
    legacy_base = st.legacy_base;
    legacy = st.legacy != 0;
    rwx_state.store(st.rwx, .monotonic);
    const nv = st.nvma * @sizeOf(Vma);
    const na = st.nanon * @sizeOf(Anon);
    const nr = st.nroom * @sizeOf(Room);
    const nt = st.ntaken * @sizeOf(Run);
    if (b.len < nv + na + nr + nt or st.nroom > rooms.len) return false;
    for (std.mem.bytesAsSlice(Vma, @as([]align(1) const u8, b.*[0..nv]))) |v| {
        if (!vmaAdd(v)) return false;
    }
    anons.clearRetainingCapacity();
    for (std.mem.bytesAsSlice(Anon, @as([]align(1) const u8, b.*[nv .. nv + na]))) |e| anons.append(gpa, e) catch return false;
    for (std.mem.bytesAsSlice(Room, @as([]align(1) const u8, b.*[nv + na .. nv + na + nr])), 0..) |r, i| rooms[i] = r;
    nrooms = st.nroom;
    taken.clearRetainingCapacity();
    for (std.mem.bytesAsSlice(Run, @as([]align(1) const u8, b.*[nv + na + nr .. nv + na + nr + nt]))) |e| taken.append(gpa, e) catch return false;
    takeHost();
    b.* = b.*[nv + na + nr + nt ..];
    return true;
}

// The break lives in a reservation made on first use; it grows by making pages
// of it accessible and shrinks by replacing pages with fresh inaccessible ones,
// so memory below a lowered break reads back as zero when raised again.
const BRK_RESERVE: u64 = 1 << 30;
var brk_base: u64 = 0;
var brk_cur: u64 = 0;
var brk_end: u64 = 0; // end of the accessible pages

fn brk(addr: u64) u64 {
    var gone_lo: u64 = 0;
    var gone_hi: u64 = 0;
    wx.hold();
    defer wx.release();
    defer if (gone_hi > gone_lo) wx.unmapped(gone_lo, gone_hi);
    lock.lock();
    defer lock.unlock();
    if (brk_base == 0) {
        const at = if (brk_hint != 0) brk_hint else GUEST_BASE;
        const own = inLow(at, at + BRK_RESERVE) and clear(at, at + BRK_RESERVE);
        const r = sys(SYS_mmap, at, BRK_RESERVE, 0, D_PRIVATE | D_ANON | D_NORESERVE | (if (own) D_FIXED else 0), @bitCast(@as(i64, -1)), 0);
        if (r < 0) return 0;
        brk_base = @bitCast(r);
        takenAdd(brk_base, brk_base + BRK_RESERVE);
        brk_cur = brk_base;
        brk_end = brk_base;
    }
    if (addr < brk_base or addr > brk_base + BRK_RESERVE) return brk_cur;
    const end = rdUp(addr);
    if (end > brk_end) {
        if (jit.protect(brk_end, end - brk_end, PROT_RW) != 0) return brk_cur;
    } else if (end < brk_end) {
        _ = sys(SYS_mmap, end, brk_end - end, 0, D_PRIVATE | D_ANON | D_FIXED, @bitCast(@as(i64, -1)), 0);
        gone_lo = end;
        gone_hi = brk_end;
    }
    brk_end = end;
    brk_cur = addr;
    return brk_cur;
}

// ---- advice, sync, residency ----------------------------------------------------------

fn madvise(addr: u64, len: u64, advice: u64) u64 {
    if (addr & (PAGE - 1) != 0) return neg(EINVAL);
    const n = rdUp(len);
    if (n == 0) return 0;
    // The pages that run stop, their own bytes back, before the memory is
    // given up.
    if (advice == 4 or advice == 8 or advice == 9 or advice == 24) wx.reset(addr, addr + n);
    defer if (advice == 4 or advice == 8 or advice == 9 or advice == 24) wx.settle(addr, addr + n);
    return switch (advice) {
        0, 1, 2, 3 => if (mapped(addr, addr + n)) lx(sys(SYS_madvise, addr, n, advice, 0, 0, 0)) else neg(ENOMEM), // NORMAL RANDOM SEQUENTIAL WILLNEED
        4, 9, 24 => discard(addr, n), // DONTNEED REMOVE DONTNEED_LOCKED
        8 => blk: { // FREE: private anonymous memory only
            const r = regionAt(addr) orelse break :blk neg(ENOMEM);
            if (r.info.inherit == VM_INHERIT_SHARE or r.info.prot & 7 == 7) break :blk neg(EINVAL);
            break :blk lx(sys(SYS_madvise, addr, n, D_MADV_FREE, 0, 0, 0));
        },
        10 => dontfork(addr, n),
        11 => dofork(addr, n),
        // WIPEONFORK has no Darwin counterpart; refusing it lets a caller (an
        // RNG guarding against fork) fall back to its own fork detection.
        18 => neg(EINVAL),
        // MERGEABLE UNMERGEABLE HUGEPAGE NOHUGEPAGE DONTDUMP DODUMP KEEPONFORK
        // COLD PAGEOUT POPULATE_READ POPULATE_WRITE COLLAPSE: hints with no
        // effect the guest can observe.
        12, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 25 => if (mapped(addr, addr + n)) 0 else neg(ENOMEM),
        100, 101 => neg(EPERM), // HWPOISON SOFT_OFFLINE
        else => neg(EINVAL),
    };
}

// dontfork keeps [addr, addr+n) out of forked children. Shared parts are
// remembered, so DOFORK can make them shared again rather than copied.
fn dontfork(addr: u64, n: u64) u64 {
    if (!mapped(addr, addr + n)) return neg(ENOMEM);
    lock.lock();
    defer lock.unlock();
    var a = addr;
    while (a < addr + n) {
        const r = regionAt(a) orelse return neg(ENOMEM);
        const hi = @min(r.hi, addr + n);
        if (r.info.inherit == VM_INHERIT_SHARE) {
            vmaPunch(a, hi, .nofork);
            if (!vmaAdd(.{ .lo = a, .hi = hi, .kind = .nofork })) return neg(ENOMEM);
        }
        a = hi;
    }
    return lx(sys(SYS_minherit, addr, n, VM_INHERIT_NONE, 0, 0, 0));
}

fn dofork(addr: u64, n: u64) u64 {
    if (!mapped(addr, addr + n)) return neg(ENOMEM);
    lock.lock();
    defer lock.unlock();
    var a = addr;
    while (a < addr + n) {
        const r = regionAt(a) orelse return neg(ENOMEM);
        const hi = @min(r.hi, addr + n);
        if (r.info.inherit == VM_INHERIT_NONE) _ = sys(SYS_minherit, a, hi - a, VM_INHERIT_COPY, 0, 0, 0);
        a = hi;
    }
    for (vmas.items) |e| {
        if (e.kind != .nofork or e.hi <= addr or e.lo >= addr + n) continue;
        const lo = @max(e.lo, addr);
        _ = sys(SYS_minherit, lo, @min(e.hi, addr + n) - lo, VM_INHERIT_SHARE, 0, 0, 0);
    }
    vmaPunch(addr, addr + n, .nofork);
    return 0;
}

// discard gives MADV_DONTNEED its Linux meaning per mapping: private anonymous
// memory reads back as zero, a private file mapping reads back the file, and a
// shared mapping keeps its contents (they live in the shared object). A copied
// executable segment keeps its bytes: reading the file back would undo its
// rewritten svc sites.
fn discard(addr: u64, n: u64) u64 {
    lock.lock();
    const files = anyVma(addr, addr + n);
    lock.unlock();
    if (!files and !anyShared(addr, addr + n) and sys(SYS_madvise, addr, n, D_MADV_ZERO, 0, 0, 0) == 0) return 0;
    var a = addr;
    while (a < addr + n) {
        const r = regionAt(a) orelse return neg(ENOMEM);
        var hi = @min(r.hi, addr + n);
        const prot: u64 = @intCast(r.info.prot & 7);
        lock.lock();
        const v = vmaAt(a);
        hi = if (v) |x| @min(hi, x.hi) else vmaNext(a, hi);
        const fd: i32 = if (v) |x| fdlink.lookup(x.id) orelse -1 else -1;
        lock.unlock();
        if (r.info.inherit == VM_INHERIT_SHARE or (v != null and v.?.shared)) {
            _ = sys(SYS_madvise, a, hi - a, D_MADV_DONTNEED, 0, 0, 0);
        } else if (v != null and fd >= 0) {
            if (!v.?.exec) reload(a, hi - a, prot, fd, v.?.off + (a - v.?.lo), v.?.copy);
        } else if (prot == 7) {
            jit.zero(a, hi - a);
        } else if (sys(SYS_madvise, a, hi - a, D_MADV_ZERO, 0, 0, 0) != 0) {
            _ = sys(SYS_mmap, a, hi - a, prot, D_PRIVATE | D_ANON | D_FIXED, @bitCast(@as(i64, -1)), 0);
        }
        a = hi;
    }
    return 0;
}

// reload puts a private file mapping's pages back to the file's bytes: mapped
// afresh from the file, or for a copied-in range (or one made RWX) read in
// again.
fn reload(a: u64, n: u64, prot: u64, fd: i32, off: u64, copy: bool) void {
    if (prot == 7) {
        const t = sys(SYS_mmap, 0, n, PROT_RW, D_PRIVATE | D_ANON, @bitCast(@as(i64, -1)), 0);
        if (t < 0) return;
        const tmp: u64 = @bitCast(t);
        _ = fill(tmp, n, fd, off);
        jit.copyIn(a, tmp, n);
        _ = sys(SYS_munmap, tmp, n, 0, 0, 0, 0);
        return;
    }
    if (!copy) {
        if (sys(SYS_mmap, a, n, prot & ~PROT_EXEC, D_PRIVATE | D_FIXED, @intCast(fd), off) >= 0 and prot & PROT_EXEC != 0)
            _ = sys(SYS_mprotect, a, n, prot, 0, 0, 0);
        return;
    }
    if (sys(SYS_mmap, a, n, PROT_RW, D_PRIVATE | D_ANON | D_FIXED, @bitCast(@as(i64, -1)), 0) < 0) return;
    _ = fill(a, n, fd, off);
    if (prot != PROT_RW) _ = sys(SYS_mprotect, a, n, prot, 0, 0, 0);
}

fn anyShared(lo: u64, hi: u64) bool {
    var a = lo;
    while (a < hi) {
        const r = regionAt(a) orelse return false;
        if (r.info.inherit == VM_INHERIT_SHARE) return true;
        a = r.hi;
    }
    return false;
}

fn msync(addr: u64, len: u64, flags: u64) u64 {
    const MS_ASYNC: u64 = 1;
    const MS_INVALIDATE: u64 = 2;
    const MS_SYNC: u64 = 4;
    if (addr & (PAGE - 1) != 0 or flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0) return neg(EINVAL);
    if (flags & MS_ASYNC != 0 and flags & MS_SYNC != 0) return neg(EINVAL);
    const n = rdUp(len);
    if (n == 0) return 0;
    if (!mapped(addr, addr + n)) return neg(ENOMEM);
    // MS_INVALIDATE is a no-op on Linux's unified page cache; Darwin's would
    // throw away dirty private pages, so it is not passed on.
    const r = lx(sys(SYS_msync, addr, n, if (flags & MS_SYNC != 0) D_MS_SYNC else D_MS_ASYNC, 0, 0, 0));
    if (!isErr(r)) syncFiles(addr, addr + n); // flush any non-host backing to its file
    return r;
}

fn mincore(addr: u64, len: u64, vec: u64) u64 {
    if (addr & (PAGE - 1) != 0) return neg(EINVAL);
    const n = rdUp(len);
    if (n == 0) return 0;
    if (!mapped(addr, addr + n)) return neg(ENOMEM);
    const r = sys(SYS_mincore, addr, n, vec, 0, 0, 0);
    if (r < 0) return lx(r);
    // Linux defines only bit 0 (resident); Darwin also reports referenced,
    // modified and sharing bits.
    const v: [*]u8 = @ptrFromInt(vec);
    for (v[0 .. n / PAGE]) |*b| b.* &= 1;
    return 0;
}

// lockRange checks an mlock/munlock range. Pages are not pinned (the host
// decides residency), but an unmapped range fails as on Linux.
fn lockRange(addr: u64, len: u64) u64 {
    const lo = addr & ~(PAGE - 1);
    const hi = rdUp(addr +% len);
    if (hi < lo) return neg(EINVAL);
    if (hi == lo) return 0;
    return if (mapped(lo, hi)) 0 else neg(ENOMEM);
}

// ---- SysV shared memory ------------------------------------------------------------

// The supervisor owns segments and their accounting (sandbox/sysvipc_darwin.go);
// attaching maps the segment's file here like any shared file mapping, tagged
// with the attachment so shmdt finds it and an munmap of it detaches.
fn shmat(shmid: u64, addr_in: u64, flg: u64) u64 {
    const SHM_RDONLY: u64 = 0o10000;
    const SHM_RND: u64 = 0o20000;
    const SHM_REMAP: u64 = 0o40000;
    const SHM_EXEC: u64 = 0o100000;
    if (flg & SHM_EXEC != 0 and flg & SHM_RDONLY == 0 and !rwxAllowed()) return neg(EACCES);
    var addr = addr_in;
    if (addr != 0) {
        if (flg & SHM_RND != 0) {
            addr &= ~(PAGE - 1);
        } else if (addr & (PAGE - 1) != 0) return neg(EINVAL);
    }
    const k = root.hostCall(LC_SHMAT, .{ shmid, 0, 0, 0, 0, 0 });
    if (isErr(k)) return k;
    const sfd: i32 = @intCast(k & 0xffffffff);
    const n = (k >> 32) * PAGE;
    if (overCap(n)) return neg(ENOMEM);
    var prot: u64 = if (flg & SHM_RDONLY != 0) PROT_READ else PROT_RW;
    if (flg & SHM_EXEC != 0) prot |= PROT_EXEC;
    const fixed = addr != 0 and flg & SHM_REMAP != 0;
    wx.hold();
    defer wx.release();
    const r = mapFile(addr, n, prot, true, fixed, addr != 0 and !fixed, sfd, 0, 0);
    if (r == neg(EEXIST)) return neg(EINVAL);
    if (isErr(r)) return r;
    const c = root.hostCall(LC_SHMATTACHED, .{ shmid, 0, 0, 0, 0, 0 });
    lock.lock();
    if (isErr(c)) {
        _ = sys(SYS_munmap, r, n, 0, 0, 0, 0);
        vmaPunch(r, r + n, null);
    } else {
        for (vmas.items) |*e| {
            if (e.kind == .file and e.lo == r) e.shm = c;
        }
    }
    lock.unlock();
    if (!isErr(c)) wx.mapped(r, n, prot, prot & PROT_EXEC != 0, true);
    if (!isErr(c) and prot & PROT_EXEC != 0) markCode(r, r + n);
    flushGone();
    return if (isErr(c)) c else r;
}

// shmdt unmaps the attachment that starts at addr, all of it.
fn shmdt(addr: u64) u64 {
    wx.hold();
    defer wx.release();
    lock.lock();
    var c: u64 = 0;
    for (vmas.items) |e| {
        if (e.shm != 0 and e.lo -% e.off == addr) c = e.shm;
    }
    if (c == 0) {
        lock.unlock();
        return neg(EINVAL);
    }
    while (true) {
        var found: ?Vma = null;
        for (vmas.items) |e| {
            if (e.shm == c) found = e;
        }
        const e = found orelse break;
        _ = sys(SYS_munmap, e.lo, e.hi - e.lo, 0, 0, 0, 0);
        vmaPunch(e.lo, e.hi, null);
        wx.unmapped(e.lo, e.hi); // held already, so taken here without waiting
    }
    lock.unlock();
    flushGone();
    return 0;
}
