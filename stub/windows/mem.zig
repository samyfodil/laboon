// Guest memory, owned by the stub: mmap, munmap, mprotect, mremap, msync,
// madvise and brk are served here without a supervisor round trip, except for the file
// contents of a file mapping.
//
// The mmap areas are placeholder reservations (NtAllocateVirtualMemoryEx with
// MEM_RESERVE_PLACEHOLDER), split and replaced at 4 KiB granularity: one made
// at start, one for each mapping asked for at an address outside them that the
// host has nothing at, as Linux maps any free address it is asked for (a JVM
// tries hint after hint for its class space), and one wherever the host has
// room for a mapping none of them has room for. Every part of an
// area is a region: a free placeholder, an anonymous allocation that replaced
// one, or a section view that replaced one. Adjacent free placeholders of an
// area are coalesced before a span is carved out of them; those of two areas
// cannot be. A mapping the stub places itself leaves a free page above it,
// which no mapping fills (each asks for its own page more): the arm64 stub
// resumes the guest by a branch from a page within 128 MiB of the resume pc
// (stubPage), and reservations packed together (a JVM's heap, code cache and
// arenas) would leave the code among them out of every free page's reach.
//
// - Anonymous memory is committed when it is mapped, except PROT_NONE, which
//   is only reserved until mprotect gives it access.
// - A private file mapping is anonymous memory the supervisor fills from the
//   file; a shared one is a view of a section the supervisor makes for the
//   file and duplicates into this process. A view cannot be partly unmapped,
//   so a partial munmap unmaps it whole and maps the surviving pieces again.
// - A shared file mapping may run past the end of the file, as on Linux: the
//   view holds the pages the file reaches into, and the rest is an eof region,
//   reserved, where an access raises SIGBUS. Unlike Linux, a file that grows
//   afterwards does not bring its new pages into the mappings already made.
// - An executable private file mapping is the same, except that the
//   supervisor rewrites the code it copies in and writes its trampolines and
//   %fs islands to a second region in branch range, which lives as long as
//   some part of the code does.
// - Anonymous private memory may be executable, writable and executable at
//   once, or flipped between the two by mprotect, as a JIT (V8) needs. It is
//   executable only once its syscall sites are traps, a page at a time (see
//   "code made executable at run time" below).
// - brk grows by committing pages of a reservation the supervisor made right
//   after the image (REP_START args 4 and 5).
// - A shared mapping may be executable too, as on Linux, but its traps cannot
//   go into its section, which its other views, other processes and the file
//   see. A page of one runs as a shadow ("hot", see "code in shared memory"
//   below): a view of a one-page section of its own, holding a copy of the
//   page, rewritten, while every writable view of that memory in the process
//   is frozen read-only, and in the run's other processes too, through the
//   supervisor (sandbox/codereg.go).
const std = @import("std");
const win = std.os.windows;
const root = @import("root");
const ool = @import("ool.zig");

const NTSTATUS = i32;
const HANDLE = usize;
const SELF = root.SELF;

extern "ntdll" fn NtAllocateVirtualMemoryEx(proc: HANDLE, base: *usize, size: *usize, typ: u32, prot: u32, params: ?*anyopaque, n: u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtAllocateVirtualMemory(proc: HANDLE, base: *usize, zero_bits: usize, size: *usize, typ: u32, prot: u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtFreeVirtualMemory(proc: HANDLE, base: *usize, size: *usize, typ: u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtProtectVirtualMemory(proc: HANDLE, base: *usize, size: *usize, prot: u32, old: *u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtMapViewOfSectionEx(sec: HANDLE, proc: HANDLE, base: *usize, off: ?*i64, size: *usize, typ: u32, prot: u32, params: ?*anyopaque, n: u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtUnmapViewOfSectionEx(proc: HANDLE, base: usize, flags: u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtClose(h: HANDLE) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtQueryVirtualMemory(proc: HANDLE, base: usize, class: u32, info: *MemInfo, len: usize, ret: ?*usize) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtFlushVirtualMemory(proc: HANDLE, base: *usize, size: *usize, iosb: *[2]usize) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtFlushInstructionCache(proc: HANDLE, base: usize, size: usize) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtCreateSection(sec: *HANDLE, access: u32, attrs: ?*anyopaque, size: ?*i64, prot: u32, attr: u32, file: HANDLE) callconv(win.WINAPI) NTSTATUS;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u32 = 0x4000;
const MEM_REPLACE_PLACEHOLDER: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_RESERVE_PLACEHOLDER: u32 = 0x40000;
const MEM_PRESERVE_PLACEHOLDER: u32 = 0x2;
const MEM_COALESCE_PLACEHOLDERS: u32 = 0x1;

const PAGE: u64 = 0x1000;
const AREA_SIZE: usize = 1 << 40;
const MAXREG = 8192;

// Linux mmap/mremap/madvise bits.
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE: u64 = 2;
const MAP_TYPE: u64 = 0xf;
const MAP_FIXED: u64 = 0x10;
const MAP_ANON: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x100000;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MADV_DONTNEED: u64 = 4;

const ENOMEM: u64 = 12;
const EACCES: u64 = 13;
const ENOEXEC: u64 = 8;
const EEXIST: u64 = 17;
const EINVAL: u64 = 22;

// The supervisor's side of a file mapping (sandbox/mem_windows.go): fill
// private anonymous memory from a file, or make a section for a shared one.
pub const LC_MAP_FILL: u64 = 0x4c430020;
// -> 0, or -EACCES when the run refuses writable+executable memory.
const LC_RWX: u64 = 0x4c430030;
pub const LC_MAP_SECTION: u64 = 0x4c430021;
// An executable file mapping: the trampoline bytes its rewrite needs, then
// the rewritten fill (fd, off, len, addr, tramp, tramp len).
pub const LC_CODE_SIZE: u64 = 0x4c430023;
pub const LC_MAP_CODE: u64 = 0x4c430024;
// (pc) -> the length of the x86-64 instruction there | where its RIP-relative
// displacement starts << 8 (0: none); 0 when it decodes as none.
const LC_INSN: u64 = 0x4c43002c;
// Shared code across processes (sandbox/codereg_windows.go): (key, off) of a
// page of memory to hold (run as a hot page), or to have cooled where others
// run it; (key) of a file mapped shared and executable.
pub const LC_HOT: u64 = 0x4c43002f;
pub const LC_COOL: u64 = 0x4c430032;
const LC_CODEFILE: u64 = 0x4c430033;
const LC_SYNCBACKING: u64 = 0x4c430036; // (key): msync of a non-host file's MAP_SHARED mapping; write its backing back to the file
const LC_DROPBACKING: u64 = 0x4c430037; // (key): a MAP_SHARED mapping of a non-host file is unmapped; release its backing
// SysV shmat: (shmid) -> duplicated section handle | pages << 32; args[0] the
// futex key. LC_SHMATTACHED (shmid) -> attachment cookie; LC_SHMGONE (cookie)
// when a segment's last mapping is dropped.
const LC_SHMAT: u64 = 0x4c430003;
const LC_SHMATTACHED: u64 = 0x4c430004;
const LC_SHMGONE: u64 = 0x4c430005;

// How far a patched site may be from its trampoline: rel32 on x86-64, B on
// arm64.
const REACH: u64 = switch (@import("builtin").cpu.arch) {
    .aarch64 => (1 << 27) - PAGE,
    else => (1 << 31) - PAGE,
};

const Kind = enum(u8) { free, anon, view, eof };

const Region = struct {
    lo: u64,
    hi: u64,
    kind: Kind,
    prot: u64, // Linux PROT_* of an anon or view region
    sec: HANDLE, // a view's section, kept to map surviving pieces again
    key: u64 = 0, // a view's identity for shared futexes (the supervisor's)
    off: u64, // a view's file offset at lo
    size: u64 = 0, // a view's section size: no view of it reaches past
    code: bool = false, // rewritten file code: may be made executable
    tramp: u64 = 0, // code: the lo of its trampoline region, 0 if none
    tramp2: u64 = 0, // code: a second one, for code wider than a branch reaches
    is_tramp: bool = false,
    pinned: bool = false, // the stub's own (stubPage): the guest never unmaps or changes it
    file: bool = false, // a view of a file, not of shared anonymous memory
    shm: u64 = 0, // a SysV attachment cookie, for shmdt and exit accounting
    hot: bool = false, // a shadow of a view's page (anon, its view's fields kept): see "code in shared memory"
    vdso: bool = false, // the guest's vDSO (mapVdso)
};

var regs: [MAXREG]Region = undefined;
var nreg: usize = 0;
var area_starts: [64]u64 = undefined;
var nareas: usize = 0;
var brk_base: u64 = 0;
var brk_limit: u64 = 0;
var brk_cur: u64 = 0;
var lock: u32 = 0;

fn neg(e: u64) u64 {
    return @bitCast(-@as(i64, @intCast(e)));
}

fn up(v: u64) u64 {
    return (v + PAGE - 1) & ~(PAGE - 1);
}

fn winProt(p: u64) u32 {
    const x = p & PROT_EXEC != 0;
    const w = p & PROT_WRITE != 0;
    const r = p & PROT_READ != 0;
    if (x) return if (w) 0x40 else if (r) 0x20 else 0x10;
    if (w) return 0x04;
    if (r) return 0x02;
    return 0x01;
}

// hostProt is the host protection of guest protection p on anonymous region
// i: p's own, but for code made executable at run time, which the host maps
// without execute until its pages are rewritten (wxFault).
fn hostProt(i: usize, p: u64) u32 {
    return winProt(if (ownCode(i, p)) p & ~PROT_EXEC else p);
}

// ownCode reports whether region i, with protection p, is anonymous memory
// the guest makes executable itself: not rewritten file code, a trampoline
// area or the stub's own page.
fn ownCode(i: usize, p: u64) bool {
    const r = regs[i];
    return r.kind == .anon and p & PROT_EXEC != 0 and !r.code and !r.is_tramp and !r.pinned;
}

// emulated reports whether region i is such memory now.
fn emulated(i: usize) bool {
    return ownCode(i, regs[i].prot);
}

fn viewProt(p: u64) u32 {
    return if (p & PROT_WRITE != 0) 0x04 else if (p & PROT_READ != 0) 0x02 else 0x01;
}

pub fn init(base: u64, limit: u64) void {
    var b: usize = 0;
    var s: usize = AREA_SIZE;
    if (NtAllocateVirtualMemoryEx(SELF, &b, &s, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, 0x01, null, 0) < 0) root.die(0xE0000010);
    area_starts[0] = b;
    nareas = 1;
    regs[0] = .{ .lo = b, .hi = b + s, .kind = .free, .prot = 0, .sec = 0, .off = 0 };
    nreg = 1;
    brk_base = base;
    brk_cur = base;
    brk_limit = limit;
}

fn insertAt(i: usize, r: Region) bool {
    if (nreg == MAXREG) return false;
    var j = nreg;
    while (j > i) : (j -= 1) regs[j] = regs[j - 1];
    regs[i] = r;
    nreg += 1;
    return true;
}

fn removeAt(i: usize) void {
    var j = i;
    while (j + 1 < nreg) : (j += 1) regs[j] = regs[j + 1];
    nreg -= 1;
}

// find returns the index of the region holding a, or nreg.
fn find(a: u64) usize {
    var i: usize = 0;
    while (i < nreg) : (i += 1) {
        if (a >= regs[i].lo and a < regs[i].hi) return i;
    }
    return nreg;
}

// region returns the [lo, hi) of the mapping holding addr, for a new thread's
// TEB stack fields. null when addr is outside the guest mmap area.
pub fn region(addr: u64) ?[2]u64 {
    acquire();
    defer releaseLock();
    const i = find(addr);
    if (i == nreg) return null;
    return .{ regs[i].lo, regs[i].hi };
}

// splitAt makes a a region boundary (a lies in the area), splitting the
// region's bookkeeping. The host objects are split by the callers.
fn splitAt(a: u64) bool {
    const i = find(a);
    if (i == nreg or regs[i].lo == a) return true;
    var r = regs[i];
    r.off += a - r.lo;
    r.lo = a;
    if (!insertAt(i + 1, r)) return false;
    regs[i].hi = a;
    return true;
}

// splitFree splits the free placeholder region i at a.
fn splitFree(i: usize, a: u64) bool {
    var b: usize = regs[i].lo;
    var s: usize = a - regs[i].lo;
    if (NtFreeVirtualMemory(SELF, &b, &s, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) < 0) return false;
    return splitAt(a);
}

// carve makes [lo, hi), which must be all free, exactly one placeholder
// region and returns its index.
fn carve(lo: u64, hi: u64) ?usize {
    var i = find(lo);
    if (i == nreg) return null;
    var j = i;
    while (regs[j].hi < hi) : (j += 1) {
        if (j + 1 >= nreg or regs[j + 1].lo != regs[j].hi or regs[j + 1].kind != .free or areaStart(regs[j + 1].lo)) return null;
    }
    if (regs[i].kind != .free) return null;
    if (j > i) {
        var b: usize = regs[i].lo;
        var s: usize = regs[j].hi - regs[i].lo;
        if (NtFreeVirtualMemory(SELF, &b, &s, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS) < 0) return null;
        regs[i].hi = regs[j].hi;
        var k = j;
        while (k > i) : (k -= 1) removeAt(i + 1);
    }
    if (regs[i].lo < lo) {
        if (!splitFree(i, lo)) return null;
        i += 1;
    }
    if (regs[i].hi > hi and !splitFree(i, hi)) return null;
    return i;
}

// freeSpan finds the highest span of len free bytes.
fn freeSpan(len: u64) ?u64 {
    var i = nreg;
    while (i > 0) {
        i -= 1;
        if (regs[i].kind != .free) continue;
        const hi = regs[i].hi;
        var lo = regs[i].lo;
        var k = i;
        while (hi - lo < len and k > 0 and regs[k - 1].kind == .free and regs[k - 1].hi == lo and !areaStart(lo)) {
            k -= 1;
            lo = regs[k].lo;
        }
        if (hi - lo >= len) return hi - len;
        i = k;
    }
    return null;
}

fn allocAnon(i: usize, prot: u64) bool {
    var b: usize = regs[i].lo;
    var s: usize = regs[i].hi - regs[i].lo;
    const typ: u32 = if (prot == 0) MEM_RESERVE | MEM_REPLACE_PLACEHOLDER else MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER;
    regs[i].kind = .anon;
    if (NtAllocateVirtualMemoryEx(SELF, &b, &s, typ, hostProt(i, prot), null, 0) < 0) {
        regs[i].kind = .free;
        return false;
    }
    regs[i].prot = prot;
    regs[i].file = false;
    return true;
}

fn mapView(i: usize, sec: HANDLE, off: u64, prot: u64, key: u64, size: u64) bool {
    var b: usize = regs[i].lo;
    var s: usize = @min(regs[i].hi - regs[i].lo, size - off);
    var o: i64 = @intCast(off);
    if (NtMapViewOfSectionEx(sec, SELF, &b, &o, &s, MEM_REPLACE_PLACEHOLDER, viewProt(prot), null, 0) < 0) return false;
    regs[i].kind = .view;
    regs[i].file = false;
    regs[i].prot = prot;
    regs[i].sec = sec;
    regs[i].key = key;
    regs[i].off = off;
    regs[i].size = size;
    return true;
}

// release turns the part [lo, hi) of region i back into a free placeholder.
fn release(i: usize, lo: u64, hi: u64) bool {
    if (regs[i].hot and !cool(i)) return false;
    thawIn(lo, hi);
    const r = regs[i];
    switch (r.kind) {
        .free => return true,
        .anon, .eof => {
            dropOwn(lo, hi, false);
            var b: usize = lo;
            var s: usize = hi - lo;
            if (NtFreeVirtualMemory(SELF, &b, &s, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) < 0) return false;
            if (!splitAt(lo) or !splitAt(hi)) return false;
            const k = find(lo);
            if (regs[k].code) code_freed = true;
            regs[k] = .{ .lo = regs[k].lo, .hi = regs[k].hi, .kind = .free, .prot = 0, .sec = 0, .off = 0 };
            return true;
        },
        .view => {
            if (NtUnmapViewOfSectionEx(SELF, r.lo, MEM_PRESERVE_PLACEHOLDER) < 0) return false;
            regs[i].kind = .free;
            var ok = true;
            if (r.lo < lo) {
                if (carve(r.lo, lo)) |k| {
                    ok = mapView(k, r.sec, r.off, r.prot, r.key, r.size) and ok;
                    regs[k].file = r.file;
                    regs[k].shm = r.shm;
                } else ok = false;
            }
            if (hi < r.hi) {
                if (carve(hi, r.hi)) |k| {
                    ok = mapView(k, r.sec, r.off + (hi - r.lo), r.prot, r.key, r.size) and ok;
                    regs[k].file = r.file;
                    regs[k].shm = r.shm;
                } else ok = false;
            }
            closeIfUnused(r.sec);
            return ok;
        },
    }
}

fn closeIfUnused(sec: HANDLE) void {
    var i: usize = 0;
    while (i < nreg) : (i += 1) {
        if (regs[i].kind == .view and regs[i].sec == sec) return;
    }
    _ = NtClose(sec);
}

var code_freed = false;

// unmapRange frees whatever is mapped in [lo, hi) of the areas, and the
// trampoline regions no code refers to any more.
fn unmapRange(lo: u64, hi: u64) bool {
    var a = lo;
    var ok = true;
    while (a < hi) {
        var i: usize = 0;
        while (i < nreg and regs[i].hi <= a) : (i += 1) {}
        if (i == nreg or regs[i].lo >= hi) break;
        const s = @max(a, regs[i].lo);
        const end = @min(hi, regs[i].hi);
        if (regs[i].pinned) {
            a = end;
            continue;
        }
        // A file view is unmapped whole: tell the supervisor so it releases the
        // backing this mapping held (a non-backing key is ignored there).
        const drop = regs[i].kind == .view and regs[i].file;
        const key = regs[i].key;
        if (!release(i, s, end)) {
            ok = false;
            break;
        }
        if (drop) _ = root.request(LC_DROPBACKING, .{ key, 0, 0, 0, 0, 0 });
        a = end;
    }
    if (code_freed) sweepTramps();
    return ok;
}

fn sweepTramps() void {
    code_freed = false;
    var i: usize = 0;
    while (i < nreg) : (i += 1) {
        if (!regs[i].is_tramp) continue;
        const t = regs[i].lo;
        var used = false;
        for (regs[0..nreg]) |r| {
            if (r.code and (r.tramp == t or r.tramp2 == t)) {
                used = true;
                break;
            }
        }
        if (!used) _ = release(i, t, regs[i].hi);
    }
}

// nearSpan finds len free bytes in branch range of all of [lo, hi), as close
// to it as there is room.
fn nearSpan(lo: u64, hi: u64, len: u64) ?u64 {
    return spanWithin(lo, hi, len, REACH);
}

// spanWithin finds len free bytes within reach of all of [lo, hi), as close
// to it as there is room.
fn spanWithin(lo: u64, hi: u64, len: u64, reach: u64) ?u64 {
    var best: ?u64 = null;
    var dist: u64 = reach;
    var i: usize = 0;
    while (i < nreg) {
        if (regs[i].kind != .free) {
            i += 1;
            continue;
        }
        const a = regs[i].lo;
        var b = regs[i].hi;
        i += 1;
        while (i < nreg and regs[i].kind == .free and regs[i].lo == b and !areaStart(b)) : (i += 1) b = regs[i].hi;
        if (b - a < len) continue;
        const t = if (b <= lo) b - len else if (a >= hi) a else continue;
        const span = @max(hi, t + len) - @min(lo, t);
        if (span < dist) {
            dist = span;
            best = t;
        }
    }
    return best;
}

// mark records [lo, hi) as rewritten code with trampolines at tramp.
fn mark(lo: u64, hi: u64, tramp: u64, tramp2: u64) void {
    if (!splitAt(lo) or !splitAt(hi)) return;
    var i = find(lo);
    while (i < nreg and regs[i].lo < hi) : (i += 1) {
        regs[i].code = true;
        regs[i].tramp = tramp;
        regs[i].tramp2 = tramp2;
    }
}

// allMapped reports whether [lo, hi) is all memory a JIT may make
// executable: private (rewritten file code, trampolines, anonymous memory)
// or shared views.
fn allMapped(lo: u64, hi: u64) bool {
    var a = lo;
    while (a < hi) {
        const i = find(a);
        if (i == nreg or (regs[i].kind != .anon and regs[i].kind != .view)) return false;
        a = regs[i].hi;
    }
    return true;
}

// mapCode fills the anonymous region [lo, lo+len) with the rewritten code of
// a file mapping and makes it executable. Its trampolines go in branch range
// of it: in one area, or, for code wider than a branch reaches, in one for
// each half, each with room for all of them (need, when the caller sized
// them already). With no room in range, every site takes the trap path.
fn mapCode(lo: u64, len: u64, prot: u64, fd: u64, off: u64, sized: ?u64) u64 {
    const need = sized orelse root.request(LC_CODE_SIZE, .{ fd, off, len, lo, 0, 0 });
    if (need == neg(ENOEXEC)) return mapData(lo, len, prot, fd, off);
    if (@as(i64, @bitCast(need)) < 0) {
        _ = unmapRange(lo, lo + len);
        return need;
    }
    const tlen = up(need);
    var areas = [2]u64{ 0, 0 };
    var n: usize = 0;
    if (tlen != 0) {
        const halves: u64 = if (len + tlen <= REACH) 1 else 2;
        var h: u64 = 0;
        while (h < halves) : (h += 1) {
            const c = nearSpan(lo + len * h / halves, lo + len * (h + 1) / halves, tlen) orelse continue;
            const k = carve(c, c + tlen) orelse continue;
            if (!allocAnon(k, PROT_READ | PROT_WRITE)) continue;
            regs[k].is_tramp = true;
            areas[n] = c;
            n += 1;
        }
    }
    const sc: [*]u64 = @ptrFromInt(@intFromPtr(root.scratch()));
    for (areas[0..n], 0..) |c, i| {
        sc[2 * i] = c;
        sc[2 * i + 1] = tlen;
    }
    const r = root.request(LC_MAP_CODE, .{ fd, off, len, lo, n, 0 });
    if (@as(i64, @bitCast(r)) < 0) {
        _ = unmapRange(lo, lo + len);
        for (areas[0..n]) |c| _ = unmapRange(c, c + tlen);
        return r;
    }
    for (areas[0..n]) |c| _ = protect(c, c + tlen, PROT_READ | PROT_EXEC);
    mark(lo, lo + len, areas[0], areas[1]); // rewritten already: executable as it is
    _ = protect(lo, lo + len, prot);
    return lo;
}

// mapData fills the private region [lo, lo+len), mapped writable, with the
// file's bytes and gives it prot. A file that is not an image of ours is data
// even when mapped executable: like a JIT's code it runs only once rewritten
// (wxFault).
fn mapData(lo: u64, len: u64, prot: u64, fd: u64, off: u64) u64 {
    const r = root.request(LC_MAP_FILL, .{ fd, off, len, lo, 0, 0 });
    if (@as(i64, @bitCast(r)) < 0) {
        _ = unmapRange(lo, lo + len);
        return r;
    }
    if (prot != PROT_READ | PROT_WRITE) _ = protect(lo, lo + len, prot);
    return lo;
}

// inArea reports whether all of [lo, hi) lies in the areas.
fn inArea(lo: u64, hi: u64) bool {
    if (lo >= hi) return false;
    var i = find(lo);
    if (i == nreg) return false;
    while (regs[i].hi < hi) : (i += 1) {
        if (i + 1 == nreg or regs[i + 1].lo != regs[i].hi) return false;
    }
    return true;
}

fn areaStart(a: u64) bool {
    for (area_starts[0..nareas]) |s| {
        if (s == a) return true;
    }
    return false;
}

// A reservation's granularity.
const GRAN: u64 = 0x10000;

// reserveAt makes an area of [lo, hi) when the host has nothing there and no
// area reaches into it.
fn reserveAt(lo: u64, hi: u64) bool {
    const b0 = lo & ~(GRAN - 1);
    const e0 = (hi +% (GRAN - 1)) & ~(GRAN - 1);
    if (lo >= hi or e0 < hi or nareas == area_starts.len) return false;
    for (regs[0..nreg]) |r| {
        if (r.lo < e0 and b0 < r.hi) return false;
    }
    var b: usize = b0;
    var s: usize = e0 - b0;
    if (NtAllocateVirtualMemoryEx(SELF, &b, &s, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, 0x01, null, 0) < 0) return false;
    var i: usize = 0;
    while (i < nreg and regs[i].lo < b0) : (i += 1) {}
    if (!insertAt(i, .{ .lo = b0, .hi = e0, .kind = .free, .prot = 0, .sec = 0, .off = 0 })) {
        b = b0;
        s = 0;
        _ = NtFreeVirtualMemory(SELF, &b, &s, MEM_RELEASE);
        return false;
    }
    area_starts[nareas] = b0;
    nareas += 1;
    return true;
}

fn anyMapped(lo: u64, hi: u64) bool {
    var i: usize = 0;
    while (i < nreg) : (i += 1) {
        if (regs[i].kind != .free and regs[i].lo < hi and lo < regs[i].hi) return true;
    }
    return false;
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
    const ok = @as(i64, @bitCast(root.request(LC_RWX, .{ 0, 0, 0, 0, 0, 0 }))) >= 0;
    rwx_state.store(if (ok) 1 else 2, .monotonic);
    return ok;
}

// newArea makes an area of at least len bytes wherever the host has room, for a
// mapping no area has room for (MariaDB reserves 8 TiB for its buffer pool's
// largest size), and returns its start.
fn newArea(len: u64) ?u64 {
    if (nareas == area_starts.len) return null;
    var b: usize = 0;
    var s: usize = (len + GRAN - 1) & ~(GRAN - 1);
    if (s < len or NtAllocateVirtualMemoryEx(SELF, &b, &s, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, 0x01, null, 0) < 0) return null;
    var i: usize = 0;
    while (i < nreg and regs[i].lo < b) : (i += 1) {}
    if (!insertAt(i, .{ .lo = b, .hi = b + s, .kind = .free, .prot = 0, .sec = 0, .off = 0 })) {
        s = 0;
        _ = NtFreeVirtualMemory(SELF, &b, &s, MEM_RELEASE);
        return null;
    }
    area_starts[nareas] = b;
    nareas += 1;
    return b;
}

// hinted returns the hint addr when nothing is mapped in [addr, addr+len):
// Linux places a mapping at its hint then.
fn hinted(addr: u64, len: u64) ?u64 {
    if (addr == 0) return null;
    const hi = addr +% len;
    if (inArea(addr, hi)) return if (anyMapped(addr, hi)) null else addr;
    return if (reserveAt(addr, hi)) addr else null;
}

fn mmap(hint: u64, len0: u64, prot: u64, flags: u64, fd: u64, off: u64) u64 {
    const fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    if (len0 == 0 or off & (PAGE - 1) != 0 or (fixed and hint & (PAGE - 1) != 0)) return neg(EINVAL);
    const addr = hint & ~(PAGE - 1);
    if (prot & 6 == 6 and !rwxAllowed()) return neg(EACCES);
    const len = up(len0);
    if (len < len0) return neg(ENOMEM);
    const typ = flags & MAP_TYPE;
    if (typ != MAP_SHARED and typ != MAP_PRIVATE and typ != 3) return neg(EINVAL);
    const anon = flags & MAP_ANON != 0;
    // Private file code is rewritten as it is copied in; anonymous code, and
    // a shared mapping's, run only once rewritten (wxFault).
    var code = prot & PROT_EXEC != 0 and !anon and typ == MAP_PRIVATE;
    var sized: ?u64 = null;
    if (code and !fixed) {
        const need = root.request(LC_CODE_SIZE, .{ fd, off, len, 0, 0, 0 });
        if (need == neg(ENOEXEC)) {
            code = false;
        } else if (@as(i64, @bitCast(need)) < 0) {
            return need;
        } else {
            sized = need;
        }
    }
    var lo: u64 = 0;
    if (fixed) {
        lo = addr;
        if (!inArea(lo, lo + len) and !reserveAt(lo, lo + len)) return neg(ENOMEM);
        if (anyMapped(lo, lo + len)) {
            if (flags & MAP_FIXED == 0) return neg(EEXIST);
            if (!unmapRange(lo, lo + len)) return neg(ENOMEM);
        }
    } else if (sized) |need| {
        // Code wider than a branch reaches takes a trampoline area on each
        // side (mapCode): leave room for both.
        const pad: u64 = if (len + up(need) <= REACH) 0 else up(need);
        const span = len + 2 * pad + PAGE;
        lo = hinted(addr, len) orelse (freeSpan(span) orelse newArea(span) orelse return neg(ENOMEM)) + pad;
    } else {
        lo = hinted(addr, len) orelse freeSpan(len + PAGE) orelse newArea(len + PAGE) orelse return neg(ENOMEM);
    }
    const i = carve(lo, lo + len) orelse return neg(ENOMEM);
    // Shared anonymous memory is a view of a section the supervisor makes,
    // so it stays shared with a fork child.
    if (typ == MAP_PRIVATE or (anon and typ != MAP_SHARED)) {
        const p = if (anon) prot else PROT_READ | PROT_WRITE;
        if (!allocAnon(i, p)) return neg(ENOMEM);
        if (code) return mapCode(lo, len, prot, fd, off, sized);
        if (!anon) return mapData(lo, len, prot, fd, off);
        return lo;
    }
    const r = root.request(LC_MAP_SECTION, .{ if (anon) ~@as(u64, 0) else fd, if (anon) 0 else off, len, prot, 0, 0 });
    if (@as(i64, @bitCast(r)) < 0) {
        _ = release(i, lo, lo + len);
        return r;
    }
    const key = root.slot().args[0];
    const size = root.slot().args[1];
    const voff = if (anon) 0 else off;
    const vlen = @min(len, up(size -| voff));
    if (vlen < len) {
        if (vlen != 0 and !splitFree(i, lo + vlen)) {
            _ = NtClose(r);
            return neg(ENOMEM);
        }
        const t = if (vlen != 0) i + 1 else i;
        if (!allocAnon(t, 0)) {
            if (r != 0) _ = NtClose(r);
            return neg(ENOMEM);
        }
        regs[t].kind = .eof;
        regs[t].prot = prot;
        regs[t].file = true;
        regs[t].off = voff + vlen;
    }
    if (r == 0) return lo; // none of the file is in range
    if (!mapView(i, r, voff, prot, key, size)) {
        _ = NtClose(r);
        _ = unmapRange(lo, lo + len);
        return neg(EACCES);
    }
    regs[i].file = !anon;
    bornFrozen(i);
    root.ensureService(); // a shared view: the registry may owe this process a freeze
    return lo;
}

fn protect(lo: u64, hi: u64, prot: u64) bool {
    stopPages(lo, hi);
    var a = lo;
    while (a < hi) {
        const i = find(a);
        if (i == nreg or regs[i].kind == .free) return false;
        const end = @min(hi, regs[i].hi);
        if (regs[i].pinned) {
            a = end;
            continue;
        }
        if (regs[i].kind == .eof) {
            if (!splitAt(a) or !splitAt(end)) return false;
            regs[find(a)].prot = prot;
            a = end;
            continue;
        }
        var b: usize = a;
        var s: usize = end - a;
        var old: u32 = 0;
        if (regs[i].kind == .anon and prot != 0) {
            if (NtAllocateVirtualMemory(SELF, &b, 0, &s, MEM_COMMIT, hostProt(i, prot)) < 0) return false;
            b = a;
            s = end - a;
        }
        if (regs[i].kind == .view) {
            // A view keeps one record (it is unmapped whole): a change to
            // part of it maps that part as a view of its own.
            var k = i;
            if (a != regs[i].lo or end != regs[i].hi) {
                const r = regs[i];
                const m = splitView(i, a, end) orelse return false;
                if (!mapPiece(m, r, r.off + (a - r.lo))) return false;
                refreeze(r.lo, r.hi);
                k = m;
            }
            b = a;
            s = end - a;
            if (NtProtectVirtualMemory(SELF, &b, &s, viewProt(prot), &old) < 0) return false;
            regs[k].prot = prot;
            refreeze(a, end);
            bornFrozen(k);
            // A file mapped executable: the supervisor's writes to it reach
            // the shadows of its pages.
            if (prot & PROT_EXEC != 0 and regs[k].file) _ = root.request(LC_CODEFILE, .{ regs[k].key, 0, 0, 0, 0, 0 });
            a = end;
            continue;
        }
        const st = NtProtectVirtualMemory(SELF, &b, &s, if (regs[i].kind == .anon) hostProt(i, prot) else winProt(prot), &old);
        if (st < 0 and prot != 0) return false;
        if (!splitAt(a) or !splitAt(end)) return false;
        regs[find(a)].prot = prot;
        a = end;
    }
    return true;
}

fn mprotect(addr: u64, len0: u64, prot: u64) u64 {
    if (addr & (PAGE - 1) != 0) return neg(EINVAL);
    const hi = addr + up(len0);
    if (hi == addr) return 0;
    if (prot & 6 == 6 and !rwxAllowed()) return neg(EACCES);
    if (prot & PROT_EXEC != 0 and !(inArea(addr, hi) and allMapped(addr, hi))) return neg(EACCES);
    if (!inArea(addr, hi)) {
        // The image and the stack, which the supervisor allocated.
        var b: usize = addr;
        var s: usize = hi - addr;
        var old: u32 = 0;
        return if (NtProtectVirtualMemory(SELF, &b, &s, winProt(prot), &old) < 0) neg(ENOMEM) else 0;
    }
    return if (protect(addr, hi, prot)) 0 else neg(ENOMEM);
}

fn munmap(addr: u64, len0: u64) u64 {
    if (addr & (PAGE - 1) != 0 or len0 == 0) return neg(EINVAL);
    return if (unmapRange(addr, addr + up(len0))) 0 else neg(EINVAL);
}

fn mremap(old: u64, oldlen0: u64, newlen0: u64, flags: u64, newaddr: u64) u64 {
    if (old & (PAGE - 1) != 0 or newlen0 == 0) return neg(EINVAL);
    const oldlen = up(oldlen0);
    const newlen = up(newlen0);
    if (oldlen == 0) return aliasView(old, newlen, flags, newaddr);
    if (!inArea(old, old + oldlen)) return neg(EINVAL);
    coolIn(old, old + oldlen);
    const i = find(old);
    if (i == nreg or regs[i].kind != .anon or regs[i].hi < old + oldlen) return neg(EINVAL);
    if (regs[i].vdso) return moveVdso(i, old, oldlen, newlen, flags, newaddr);
    if (regs[i].code or regs[i].is_tramp or regs[i].pinned) return neg(EINVAL); // its sites branch to fixed trampolines
    const prot = regs[i].prot;
    if (flags & MREMAP_FIXED == 0) {
        if (newlen <= oldlen) {
            if (newlen < oldlen and !unmapRange(old + newlen, old + oldlen)) return neg(ENOMEM);
            return old;
        }
        if (inArea(old + oldlen, old + newlen) and !anyMapped(old + oldlen, old + newlen)) {
            if (carve(old + oldlen, old + newlen)) |k| {
                if (allocAnon(k, prot)) return old;
            }
        }
        if (flags & MREMAP_MAYMOVE == 0) return neg(ENOMEM);
    } else if (flags & MREMAP_MAYMOVE == 0 or newaddr & (PAGE - 1) != 0) return neg(EINVAL);
    var dst: u64 = undefined;
    if (flags & MREMAP_FIXED != 0) {
        dst = mmap(newaddr, newlen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
    } else {
        dst = mmap(0, newlen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0, 0);
    }
    if (@as(i64, @bitCast(dst)) < 0) return dst;
    stopPages(old, old + oldlen); // their traps stay behind
    if (prot & PROT_READ == 0) _ = protect(old, old + oldlen, PROT_READ);
    const n = @min(oldlen, newlen);
    @memcpy(@as([*]u8, @ptrFromInt(dst))[0..n], @as([*]const u8, @ptrFromInt(old))[0..n]);
    _ = unmapRange(old, old + oldlen);
    if (prot != PROT_READ | PROT_WRITE) _ = protect(dst, dst + newlen, prot);
    return dst;
}

// moveVdso moves the vDSO, as Linux lets CRIU do, whole and to its own size:
// a fresh copy at newaddr, rewritten for where it is, so it still runs.
fn moveVdso(i: usize, old: u64, oldlen: u64, newlen: u64, flags: u64, newaddr: u64) u64 {
    if (regs[i].lo != old or regs[i].hi != old + oldlen or newlen != oldlen) return neg(EINVAL);
    if (flags & MREMAP_FIXED == 0) return old;
    if (flags & MREMAP_MAYMOVE == 0 or newaddr & (PAGE - 1) != 0) return neg(EINVAL);
    if (newaddr < old + oldlen and old < newaddr + newlen) return neg(EINVAL);
    const dst = mmap(newaddr, newlen, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, VDSO_FD, 0);
    if (@as(i64, @bitCast(dst)) < 0) return dst;
    markVdso(dst, dst + newlen);
    _ = unmapRange(old, old + oldlen);
    return dst;
}

// VDSO_FD names the vDSO to the supervisor's code mapping (sandbox vdsoFD),
// which fills it from its image; a guest fd, an int, never is.
const VDSO_FD: u64 = 1 << 32;

// mapVdso maps the guest's vDSO, which fits a page, and returns where, or 0.
pub fn mapVdso() u64 {
    acquire();
    defer releaseLock();
    const lo = mmap(0, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE, VDSO_FD, 0);
    if (@as(i64, @bitCast(lo)) < 0) return 0;
    markVdso(lo, lo + PAGE);
    return lo;
}

fn markVdso(lo: u64, hi: u64) void {
    if (!splitAt(lo) or !splitAt(hi)) return;
    var i = find(lo);
    while (i < nreg and regs[i].lo < hi) : (i += 1) regs[i].vdso = true;
}

// aliasView maps the shared memory at old a second time, newlen bytes of it
// from there, as mremap with no old size does (Linux takes it only of shared
// memory, and only to move): a view of the same section, where the caller
// asks or anywhere.
fn aliasView(old: u64, newlen: u64, flags: u64, newaddr: u64) u64 {
    if (flags & MREMAP_MAYMOVE == 0) return neg(EINVAL);
    const i = find(old);
    if (i == nreg or (regs[i].kind != .view and !regs[i].hot)) return neg(EINVAL);
    const r = regs[i];
    var lo: u64 = undefined;
    if (flags & MREMAP_FIXED != 0) {
        if (newaddr & (PAGE - 1) != 0) return neg(EINVAL);
        lo = newaddr;
        if (!inArea(lo, lo + newlen) and !reserveAt(lo, lo + newlen)) return neg(ENOMEM);
        if (anyMapped(lo, lo + newlen) and !unmapRange(lo, lo + newlen)) return neg(ENOMEM);
    } else {
        lo = freeSpan(newlen + PAGE) orelse newArea(newlen + PAGE) orelse return neg(ENOMEM);
    }
    const k = carve(lo, lo + newlen) orelse return neg(ENOMEM);
    if (!mapView(k, r.sec, r.off + (old - r.lo), r.prot, r.key, r.size)) {
        _ = release(k, lo, lo + newlen);
        return neg(ENOMEM);
    }
    regs[k].file = r.file;
    regs[k].shm = r.shm;
    bornFrozen(k);
    return lo;
}

fn madvise(addr: u64, len0: u64, advice: u64) u64 {
    if (addr & (PAGE - 1) != 0) return neg(EINVAL);
    if (advice != MADV_DONTNEED) return 0;
    const hi = addr + up(len0);
    var a = addr;
    while (a < hi) {
        const i = find(a);
        if (i == nreg) break;
        const end = @min(hi, regs[i].hi);
        if (regs[i].kind == .anon and regs[i].prot != 0 and !regs[i].code and !regs[i].is_tramp and !regs[i].pinned and !regs[i].hot) {
            // Linux refills dropped anonymous pages with zeros; code made
            // executable at run time runs only once rewritten again.
            dropOwn(a, end, false);
            var b: usize = a;
            var s: usize = end - a;
            _ = NtFreeVirtualMemory(SELF, &b, &s, MEM_DECOMMIT);
            b = a;
            s = end - a;
            _ = NtAllocateVirtualMemory(SELF, &b, 0, &s, MEM_COMMIT, hostProt(i, regs[i].prot));
        }
        a = end;
    }
    return 0;
}

// msync writes a shared mapping's dirty pages to its file.
fn msync(addr: u64, len0: u64) u64 {
    if (addr & (PAGE - 1) != 0) return neg(EINVAL);
    const hi = addr + up(len0);
    var a = addr;
    while (a < hi) {
        const i = find(a);
        if (i == nreg) break;
        const end = @min(hi, regs[i].hi);
        if (regs[i].kind == .view) {
            var b: usize = a;
            var s: usize = end - a;
            var iosb: [2]usize = .{ 0, 0 };
            _ = NtFlushVirtualMemory(SELF, &b, &s, &iosb);
            // A file view: its dirty pages are now in the backing file; have the
            // supervisor write that file back to the backend (a non-backing key
            // is ignored there).
            if (regs[i].file) _ = root.request(LC_SYNCBACKING, .{ regs[i].key, 0, 0, 0, 0, 0 });
        }
        a = end;
    }
    return 0;
}

fn brk(want: u64) u64 {
    if (want < brk_base or want > brk_limit) return brk_cur;
    const have = up(brk_cur);
    const need = up(want);
    var b: usize = undefined;
    var s: usize = undefined;
    if (need > have) {
        b = have;
        s = need - have;
        if (NtAllocateVirtualMemory(SELF, &b, 0, &s, MEM_COMMIT, 0x04) < 0) return brk_cur;
    } else if (need < have) {
        b = need;
        s = have - need;
        _ = NtFreeVirtualMemory(SELF, &b, &s, MEM_DECOMMIT);
    }
    brk_cur = want;
    return want;
}

// stubPage commits a page of the areas with prot, in branch range of addr, for
// the stub itself: for an addr deep inside them, where the host has nothing
// free in range. The guest never unmaps or changes it.
pub fn stubPage(addr: u64, prot: u32) ?u64 {
    return stubPageWithin(addr, prot, REACH);
}

// stubPageAny is stubPage's page, from anywhere in the areas.
pub fn stubPageAny(prot: u32) ?u64 {
    return stubPageWithin(0, prot, std.math.maxInt(u64));
}

fn stubPageWithin(addr: u64, prot: u32, reach: u64) ?u64 {
    acquire();
    defer releaseLock();
    const c = spanWithin(addr, addr + 4, PAGE, reach) orelse return null;
    const k = carve(c, c + PAGE) orelse return null;
    var b: usize = c;
    var s: usize = PAGE;
    if (NtAllocateVirtualMemoryEx(SELF, &b, &s, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, prot, null, 0) < 0) return null;
    regs[k].kind = .anon;
    regs[k].prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs[k].pinned = true;
    return c;
}

// pastEof reports whether a faulting access at addr (of Windows' kind: 0
// read, 1 write, 8 execute) lies past the end of the file a shared mapping
// holds, with a protection that allows it: Linux raises SIGBUS there, not
// SIGSEGV.
pub fn pastEof(addr: u64, access: u64) bool {
    acquire();
    defer releaseLock();
    const i = find(addr);
    if (i == nreg or regs[i].kind != .eof) return false;
    const need: u64 = switch (access) {
        1 => PROT_WRITE,
        8 => PROT_EXEC,
        else => PROT_READ,
    };
    return regs[i].prot & need != 0;
}

// sharedKey names the futex word at addr for the supervisor when it lies in a
// shared view: the view's key and the word's offset in its section.
pub fn sharedKey(addr: u64) ?[2]u64 {
    acquire();
    defer releaseLock();
    const i = find(addr);
    if (i == nreg or (regs[i].kind != .view and !regs[i].hot) or regs[i].key == 0) return null;
    return .{ regs[i].key, regs[i].off + (addr - regs[i].lo) };
}

// MapEnt is one guest mapping for /proc/<pid>/maps, as the darwin stub
// reports it: attr packs the Linux protection (bits 0-2), MAP_SHARED (bit 3)
// and the kind (bits 8+: 1 anonymous, 2 file, 4 heap). The supervisor adds
// the images and the main stack, which it placed.
pub const MapEnt = extern struct { lo: u64, hi: u64, off: u64, aux: u64, attr: u64 };

// maps writes the regions that end above from, in address order, as up to
// cap entries into out, and sets next to where the following call resumes
// (0 when done).
pub fn maps(out: [*]MapEnt, cap: usize, from: u64, next: *u64) u64 {
    acquire();
    defer releaseLock();
    next.* = 0;
    var n: usize = 0;
    if (brk_cur > brk_base and brk_base >= from) {
        out[n] = .{ .lo = brk_base, .hi = up(brk_cur), .off = 0, .aux = 0, .attr = 4 << 8 | PROT_READ | PROT_WRITE };
        n += 1;
    }
    for (regs[0..nreg]) |r| {
        if (r.kind == .free or r.pinned or r.hi <= from) continue;
        if (n == cap) {
            next.* = r.lo;
            break;
        }
        const view = r.kind == .view or r.kind == .eof or r.hot;
        const shared: u64 = if (view and (r.prot & PROT_WRITE != 0 or !r.file)) 8 else 0;
        const kind: u64 = if (r.vdso) 8 else if (r.file) 2 else 1;
        out[n] = .{ .lo = r.lo, .hi = r.hi, .off = if (view) r.off else 0, .aux = 0, .attr = kind << 8 | shared | (r.prot & 7) };
        n += 1;
    }
    return n;
}

// lockAll and unlockAll hold the region table across a fork, so the child's
// copy is not caught mid-update by another thread. The hot pages cool first:
// the child shares their memory, not a copy of their shadows.
pub fn lockAll() void {
    acquire();
    registered.n = 0; // the child shares the memory: what is held is held anew, the child told
    var i: usize = 0;
    while (i < nreg) : (i += 1) {
        if (regs[i].hot) _ = cool(i);
    }
}

pub fn unlockAll() void {
    releaseLock();
}

// iovLen sums the lengths of the cnt iovecs at iov, for a write the stub
// serves itself. It reads them under the lock, so no munmap pulls them away,
// and only from readable guest memory; null leaves the call to the
// supervisor, which reports the fault. As on Linux, a length past ssize_t is
// EINVAL and the total stops at MAX_RW_COUNT.
pub const MAX_RW_COUNT: u64 = 0x7ffff000;

pub fn iovLen(iov: u64, cnt: u64) ?u64 {
    if (cnt > 1024) return neg(EINVAL);
    const n = cnt * 16;
    if (n == 0) return 0;
    acquire();
    defer releaseLock();
    if (!readable(iov, n)) return null;
    const v: [*]const u64 = @ptrFromInt(iov);
    var total: u64 = 0;
    var i: usize = 0;
    while (i < cnt) : (i += 1) {
        const len = v[2 * i + 1];
        if (len > std.math.maxInt(i64)) return neg(EINVAL);
        total += @min(len, MAX_RW_COUNT - total);
    }
    return total;
}

// ---- code made executable at run time -------------------------------------
//
// Anonymous memory the guest maps or protects executable -- a JIT's code, a
// loader's -- runs only once its syscall sites are traps, as file code runs
// only rewritten: the host keeps it unexecutable (hostProt), and an
// instruction fetch from one of its pages faults into wxFault, which freezes
// the page, has the supervisor find its sites (LC_ANON_SITES: descent from
// where the thread was about to run and from where other pages' code branches
// in, and a sweep), turns each into a trap and makes the page executable. A
// write to a page made executable faults and makes it writable again, so what
// is written there runs only once rewritten. A page whose own code writes into
// it can never run so -- no one protection both runs that instruction and lets
// it write -- so it becomes writable and executable at once, unrewritten:
// self-modifying code, which gets the RWX it asked for.
const LC_ANON_SITES: u64 = 0x4c430029; // (page, pc) -> n; the n u32 site offsets in the slot scratch, then a u32 count and the u64 pages to rewrite again
const LC_IS_TRAP: u64 = 0x4c43002b; // (pc) -> 1 if a trap there is the rewriter's
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// Verdict is what a fault wxFault looked at needs: nothing more (handled,
// the access runs again), the same but noted, a store that may lose to a
// thread running its page (retry, ool.tried), the store in st run out of line
// (step), the hold in st kept by the run out of line the store is part of
// (attach), or none of its business.
pub const Verdict = enum { none, handled, retry, step, attach, hot, cool, wait, fail };

fn done(ok: bool) Verdict {
    return if (ok) .handled else .none;
}

// wxFault serves a fault at addr of the given kind (0 a read, 8 an
// instruction fetch, 1 a write), from an instruction at pc, on memory this
// file runs code from: code made executable at run time, and shared code
// (its views frozen, its hot pages). What it sees, it sees under one hold of
// the lock, so another thread's change cannot slip between two looks; and a
// fault the host's protection allows by then is one a change made meanwhile,
// which runs again (a view mapped again in pieces, a page made to run).
pub fn wxFault(addr: u64, kind: u64, pc: u64, st: *Step) Verdict {
    acquire();
    defer releaseLock();
    const page = addr & ~(PAGE - 1);
    if (kind == 1) {
        if (frozenAt(page)) |f| {
            if (remote(frozen[f].key, frozen[f].soff)) return ask(.cool, frozen[f].key, frozen[f].soff, st);
            return writeHeld(frozen[f].key, frozen[f].soff, addr, pc, st);
        }
    }
    const i = find(addr);
    if (i != nreg and (kind == 8 or kind == 1)) {
        if (kind == 8 and regs[i].kind == .view and regs[i].prot & PROT_EXEC != 0) {
            const soff = regs[i].off + (page - regs[i].lo);
            if (stopped or heldMem(regs[i].key, soff)) {
                st.gen = @atomicLoad(u32, &wake_gen, .acquire);
                return .wait;
            }
            if (!alone() and !registered.has(.{ .key = regs[i].key, .soff = soff })) return ask(.hot, regs[i].key, soff, st);
            return done(heat(i, page, pc));
        }
        if (regs[i].hot) {
            if (kind == 1 and regs[i].prot & PROT_WRITE != 0) {
                // In another process too, the page cools first. From its own
                // code it cannot run in place (see "code in shared memory").
                if (remote(regs[i].key, regs[i].off)) return ask(.cool, regs[i].key, regs[i].off, st);
                if (pc & ~(PAGE - 1) == page and !st.from_slot) return selfStore(i, pc, st);
                return writeHeld(regs[i].key, regs[i].off, addr, pc, st);
            }
        } else if (emulated(i)) {
            const host = pageProt(page) orelse return .none;
            const exec = host & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE) != 0;
            if (kind == 8) {
                if (exec) return .handled;
                if (heldMem(0, page)) {
                    st.gen = @atomicLoad(u32, &wake_gen, .acquire);
                    return .wait;
                }
                return done(rewritePage(page, pc));
            }
            if (regs[i].prot & PROT_WRITE == 0) return .none;
            if (!exec) return .handled; // made writable meanwhile
            if (pc & ~(PAGE - 1) == page and !st.from_slot) return done(setProt(page, PAGE_EXECUTE_READWRITE)); // self-modifying, its traps kept
            if (!stopPage(page, winProt(regs[i].prot & ~PROT_EXEC))) return .none;
            return storeHeld(0, page, addr, pc, st);
        }
    }
    const p = pageProt(page) orelse return .none;
    const now = switch (kind) {
        0 => p == 0x02 or p == 0x04 or p == 0x08 or p == 0x20 or p == 0x40 or p == 0x80,
        1 => p == 0x04 or p == 0x08 or p == 0x40 or p == 0x80,
        8 => p == 0x10 or p == 0x20 or p == 0x40 or p == 0x80,
        else => false,
    };
    return done(now);
}

// ---- code in shared memory --------------------------------------------------
//
// A page of a view the guest made executable runs as a shadow ("hot"): a view
// of a one-page section of its own, holding a copy of the page, rewritten as
// code made executable at run time is. The copy is made while every writable
// view of the same memory (its section key and offset) in the process is
// frozen read-only, and is mapped in the page's place read-only and whole,
// its traps written through a second view of it, so no store lands in it. A
// write through a frozen view, or into the hot page, cools it: the page maps
// its view again, without execute, the frozen views thaw, and the next
// instruction fetch takes a fresh copy. Splitting a view around a page maps
// it again in pieces: a thread touching it meanwhile faults, and once the
// lock is free its access is retried (transient).

// A writable view page frozen read-only for a hot page of its memory: the
// section's key and the offset in it, and the guest's protection of it.
const Frozen = struct { page: u64, key: u64, soff: u64, prot: u64 };
const MAXFROZEN = 1024;
var frozen: [MAXFROZEN]Frozen = undefined;
var nfrozen: usize = 0;

fn frozenAt(page: u64) ?usize {
    for (frozen[0..nfrozen], 0..) |f, k| {
        if (f.page == page) return k;
    }
    return null;
}

// mapPiece maps k, a free placeholder region, as the part of view r from its
// section offset off.
fn mapPiece(k: usize, r: Region, off: u64) bool {
    if (!mapView(k, r.sec, off, r.prot, r.key, r.size)) return false;
    regs[k].file = r.file;
    regs[k].shm = r.shm;
    bornFrozen(k);
    return true;
}

// bornFrozen freezes the pages of view region k, writable, whose memory a
// hot page runs.
fn bornFrozen(k: usize) void {
    const r = regs[k];
    if (r.kind != .view or r.prot & PROT_WRITE == 0) return;
    for (regs[0..nreg]) |h| {
        if (h.hot and h.key == r.key) freezeIn(k, h.off);
    }
    for (remote_hot.items[0..remote_hot.n]) |p| {
        if (p.key == r.key) freezeIn(k, p.soff);
    }
}

// freezeIn freezes the page of view region k that maps section offset soff,
// if it has one.
fn freezeIn(k: usize, soff: u64) void {
    const r = regs[k];
    if (soff < r.off or soff >= r.off + (r.hi - r.lo)) return;
    const v = r.lo + (soff - r.off);
    if (frozenAt(v) != null or nfrozen == MAXFROZEN or !setProt(v, PAGE_READONLY)) return;
    frozen[nfrozen] = .{ .page = v, .key = r.key, .soff = soff, .prot = r.prot };
    nfrozen += 1;
}

// splitView unmaps view region i and maps it again, but for [lo, hi), which
// it leaves a free placeholder region and returns the index of. The pieces
// keep its section, offsets and protection.
fn splitView(i: usize, lo: u64, hi: u64) ?usize {
    const r = regs[i];
    if (NtUnmapViewOfSectionEx(SELF, r.lo, MEM_PRESERVE_PLACEHOLDER) < 0) return null;
    regs[i] = .{ .lo = r.lo, .hi = r.hi, .kind = .free, .prot = 0, .sec = 0, .off = 0 };
    var ok = true;
    if (r.lo < lo) {
        if (carve(r.lo, lo)) |k| ok = mapPiece(k, r, r.off) and ok else ok = false;
    }
    if (hi < r.hi) {
        if (carve(hi, r.hi)) |k| ok = mapPiece(k, r, r.off + (hi - r.lo)) and ok else ok = false;
    }
    const m = carve(lo, hi) orelse return null;
    return if (ok) m else null;
}

// refreeze makes the frozen pages of [lo, hi), mapped again, read-only again.
fn refreeze(lo: u64, hi: u64) void {
    for (frozen[0..nfrozen]) |f| {
        if (f.page >= lo and f.page < hi) _ = setProt(f.page, PAGE_READONLY);
    }
}

// freezeViews freezes every writable view page of memory (key, soff) but
// except.
fn freezeViews(key: u64, soff: u64, except: u64) void {
    for (regs[0..nreg]) |r| {
        if (r.kind != .view or r.key != key or r.prot & PROT_WRITE == 0) continue;
        if (soff < r.off or soff >= r.off + (r.hi - r.lo)) continue;
        const v = r.lo + (soff - r.off);
        if (v == except or frozenAt(v) != null or nfrozen == MAXFROZEN) continue;
        if (!setProt(v, PAGE_READONLY)) continue;
        frozen[nfrozen] = .{ .page = v, .key = key, .soff = soff, .prot = r.prot };
        nfrozen += 1;
    }
}

// thawKey gives the views frozen for memory (key, soff) their protection back.
fn thawKey(key: u64, soff: u64) void {
    var k: usize = 0;
    while (k < nfrozen) {
        const f = frozen[k];
        if (f.key == key and f.soff == soff) {
            _ = setProt(f.page, viewProt(f.prot));
            nfrozen -= 1;
            frozen[k] = frozen[nfrozen];
        } else k += 1;
    }
}

// thawIn gives the frozen pages of [lo, hi) their protection back, before
// they change or go.
fn thawIn(lo: u64, hi: u64) void {
    var k: usize = 0;
    while (k < nfrozen) {
        const f = frozen[k];
        if (f.page >= lo and f.page < hi) {
            _ = setProt(f.page, viewProt(f.prot));
            nfrozen -= 1;
            frozen[k] = frozen[nfrozen];
        } else k += 1;
    }
}

// thaw cools the hot pages of memory (key, soff) and thaws the views frozen
// for them, for a write.
fn thaw(key: u64, soff: u64) bool {
    var ok = true;
    var i: usize = 0;
    while (i < nreg) : (i += 1) {
        if (regs[i].hot and regs[i].key == key and regs[i].off == soff) ok = cool(i) and ok;
    }
    thawKey(key, soff);
    return ok;
}

// coolIn cools the hot pages of [lo, hi), before they change or go.
fn coolIn(lo: u64, hi: u64) void {
    var i: usize = 0;
    while (i < nreg) : (i += 1) {
        if (regs[i].hot and regs[i].lo < hi and regs[i].hi > lo) _ = cool(i);
    }
}

// Step is how a store a hot page's own code makes into it runs out of line
// (ool.zig), the guest's code at start: arm64 instructions, or an x86-64
// one's bytes and where its RIP-relative displacement starts.
pub const Step = struct {
    code: [ool.MAX * 4]u8 = undefined,
    n: u32 = 0,
    at: u32 = 0,
    start: u64 = 0,
    // .hot, .cool: the page of memory the registry is asked about, and
    // the freezes served when asked (cooled); .wait: what wakes it.
    key: u64 = 0,
    soff: u64 = 0,
    gen: u32 = 0,
    hold: u64 = 0, // .step, .attach: the hold on the memory while it runs (holds)
    again: bool = false, // .step: the access may run again in place instead
    call: bool = false, // .step: the store is a near call's push (ool.runCall)
    rs: u5 = 0, // .fail: the store exclusive's status register, which takes 1
    from_slot: bool = false, // in: the access is the thread's run out of line
    lost: bool = false, // in: the store ran again in place and lost (ool.lost)
};

// selfStore readies the write hot region i's own code at pc makes into it
// to run out of line: the page cools, and st holds the store. The lock is
// held.
fn selfStore(i: usize, pc: u64, st: *Step) Verdict {
    const key = regs[i].key;
    const soff = regs[i].off;
    st.start = pc;
    switch (@import("builtin").cpu.arch) {
        .aarch64 => {
            const w = @as(*const u32, @ptrFromInt(pc)).*;
            if (ool.storeExclusive(w)) {
                // Its monitor is lost to the fault: it fails, as the
                // architecture lets one fail at any time, and its window is
                // learned, its load exclusive trapped from the next heat on.
                learnExcl(i, pc, w);
                st.rs = ool.statusReg(w);
                _ = cool(i);
                return .fail;
            }
            std.mem.writeInt(u32, st.code[0..4], w, .little);
            st.n = 1;
        },
        else => if (!storeAt(pc, st)) return .none,
    }
    if (!cool(i)) return .none;
    st.hold = hold(key, soff);
    return .step;
}

// writeHeld readies a write at pc into memory (key, soff) at addr, which
// runs as a hot page or a view of which is frozen for one, from code
// elsewhere: the memory cools and the store runs again in place (retry). One
// that lost to a thread that ran the memory again before it landed runs out
// of line, the memory held (st), so none can before it lands: a store
// exclusive, whose monitor the fault lost, with its window from its load
// exclusive, when that runs the same again (ool.rerunnable). A store already
// run out of line keeps the hold until its run ends (attach); the stub's own,
// and one that cannot run out of line, runs again in place. The lock is held.
fn writeHeld(key: u64, soff: u64, addr: u64, pc: u64, st: *Step) Verdict {
    if (!thaw(key, soff)) return .none;
    return storeHeld(key, soff, addr, pc, st);
}

// storeHeld runs the write at pc into memory (key, soff), out of execution
// now, out of line and held (writeHeld). Code made executable at run time is
// held by its address (key 0).
fn storeHeld(key: u64, soff: u64, addr: u64, pc: u64, st: *Step) Verdict {
    if (root.ownCode(pc)) return .handled;
    if (st.from_slot) {
        st.hold = hold(key, soff);
        return .attach;
    }
    if (!st.lost) return .retry;
    st.start = pc;
    switch (@import("builtin").cpu.arch) {
        .aarch64 => {
            const w = @as(*const u32, @ptrFromInt(pc)).*;
            if (ool.storeExclusive(w)) {
                const cp = pc & ~(PAGE - 1);
                const n = ool.window(@ptrFromInt(cp), cp, pc, w) orelse return .handled;
                const words: [*]u32 = @ptrCast(@alignCast(&st.code));
                @memcpy(words[0..n], @as([*]const u32, @ptrFromInt(pc - 4 * (n - 1)))[0..n]);
                if (!ool.rerunnable(words[0..n])) return .handled;
                st.n = n;
                st.start = pc - 4 * (n - 1);
                touch(addr);
            } else {
                std.mem.writeInt(u32, st.code[0..4], w, .little);
                st.n = 1;
            }
        },
        else => if (!storeAt(pc, st)) return .handled,
    }
    st.hold = hold(key, soff);
    st.again = true;
    return .step;
}

// storeAt puts the x86-64 instruction at pc in st, to run out of line, and
// reports whether it can: a near call runs as its push (call), as no copy of
// it pushes where it was.
fn storeAt(pc: u64, st: *Step) bool {
    const d = insnAt(pc) orelse return false;
    const code = @as([*]const u8, @ptrFromInt(pc))[0..d.n];
    st.call = ool.nearCall(code);
    if (!st.call and !ool.relocatable(code)) return false;
    @memcpy(st.code[0..d.n], code);
    st.n = d.n;
    st.at = d.at;
    return true;
}

// The x86-64 instructions decoded (LC_INSN), by where they ran: an
// instruction's bytes decide its length and where its displacement starts,
// so one that holds the same bytes decodes the same. The lock guards it.
const Insn = struct { pc: u64 = 0, n: u8 = 0, at: u8 = 0, b: [15]u8 = undefined };
var insns: [64]Insn = [_]Insn{.{}} ** 64;

fn insnAt(pc: u64) ?struct { n: u32, at: u32 } {
    const e = &insns[(pc ^ pc >> 6) % insns.len];
    const at: [*]const u8 = @ptrFromInt(pc);
    if (e.pc == pc and std.mem.eql(u8, e.b[0..e.n], at[0..e.n])) return .{ .n = e.n, .at = e.at };
    const r = root.request(LC_INSN, .{ pc, 0, 0, 0, 0, 0 });
    const n: u8 = @truncate(r & 0xff);
    if (n == 0 or n > 15) return null;
    const a: u8 = @truncate((r >> 8) & 0xff);
    if (pc % PAGE + n <= PAGE) { // read back from its page alone
        e.* = .{ .pc = pc, .n = n, .at = a };
        @memcpy(e.b[0..n], at[0..n]);
    }
    return .{ .n = n, .at = a };
}

var heat_buf: [PAGE]u8 = undefined; // the lock guards these
var heat_traps: [PAGE / 2]u32 = undefined;
var heat_xtraps: [64]u32 = undefined;

// heat makes page, of view region i that the guest made executable, run as a
// shadow, entered at pc.
fn heat(i: usize, page: u64, pc: u64) bool {
    const r = regs[i];
    const soff = r.off + (page - r.lo);
    // No store reaches the memory through this view while it is copied. A
    // view frozen for another hot page of it is frozen no more: it runs.
    if (!setProt(page, PAGE_READONLY)) return false;
    if (frozenAt(page)) |f| {
        nfrozen -= 1;
        frozen[f] = frozen[nfrozen];
    }
    freezeViews(r.key, soff, page);
    @memcpy(&heat_buf, @as([*]const u8, @ptrFromInt(page))[0..PAGE]);
    var sec: HANDLE = 0;
    var size: i64 = PAGE;
    if (NtCreateSection(&sec, 0xf001f, null, &size, PAGE_EXECUTE_READWRITE, 0x8000000, 0) < 0) return false; // SECTION_ALL_ACCESS, SEC_COMMIT
    defer _ = NtClose(sec);
    // The copy, analyzed and with its traps, is made through a view of its
    // own, and only then takes the page's place, executable.
    var aside: usize = 0;
    var vs: usize = PAGE;
    if (NtMapViewOfSectionEx(sec, SELF, &aside, null, &vs, 0, PAGE_READWRITE, null, 0) < 0) return false;
    defer _ = NtUnmapViewOfSectionEx(SELF, aside, 0);
    @memcpy(@as([*]u8, @ptrFromInt(aside))[0..PAGE], &heat_buf);
    const rr = root.request(LC_ANON_SITES, .{ page, pc, aside, 0, 0, 0 });
    if (@as(i64, @bitCast(rr)) < 0) return false;
    const nsites: usize = @intCast(rr);
    const sc: [*]const u32 = @ptrFromInt(@intFromPtr(root.scratch()));
    var nt: usize = 0;
    for (sc[0..nsites]) |off| {
        if (!trapAside(aside, page, off)) continue;
        heat_traps[nt] = off;
        nt += 1;
    }
    const nx = placeExcl(aside, r.key, soff);
    const m = splitView(i, page, page + PAGE) orelse return false;
    var b: usize = page;
    var s: usize = PAGE;
    var o: i64 = 0;
    if (NtMapViewOfSectionEx(sec, SELF, &b, &o, &s, MEM_REPLACE_PLACEHOLDER, PAGE_EXECUTE_READ, null, 0) < 0) {
        _ = mapPiece(m, r, soff);
        return false;
    }
    regs[m] = r;
    regs[m].lo = page;
    regs[m].hi = page + PAGE;
    regs[m].off = soff;
    regs[m].kind = .anon;
    regs[m].hot = true;
    refreeze(r.lo, r.hi);
    for (heat_traps[0..nt]) |off| {
        if (!addOwn(page + off)) {
            _ = cool(m);
            return false;
        }
        @atomicStore(u64, &trap_cache[cacheSlot(page + off)], page + off, .release);
    }
    for (heat_xtraps[0..nx]) |off| xtraps.add(.{ .key = page + off, .soff = 0 });
    _ = NtFlushInstructionCache(SELF, page, PAGE);
    stopMore(sc, nsites, page);
    return true;
}

// trapAside turns the syscall at off in a page held aside, to run at page,
// into the stub's way in (on arm64 its island, see jitSiteWord), if it is one,
// and reports whether it did.
fn trapAside(aside: u64, page: u64, off: u32) bool {
    switch (@import("builtin").cpu.arch) {
        .aarch64 => {
            if (off % 4 != 0 or off + 4 > PAGE) return false;
            const w: [*]u32 = @ptrFromInt(aside + off);
            if (w[0] != 0xd4000001) return false;
            w[0] = root.arch.jitSiteWord(page + off, if (off >= 4) (w - 1)[0] else null);
        },
        else => {
            if (off + 2 > PAGE) return false;
            const b: [*]u8 = @ptrFromInt(aside + off);
            if (b[0] != 0x0f or b[1] != 0x05) return false;
            b[1] = 0x0b;
        },
    }
    return true;
}

// stopMore stops the pages a sites reply at sc names after its r sites, but
// page: they ran, and have a new entry to be analyzed with the next time they
// run.
fn stopMore(sc: [*]const u32, r: usize, page: u64) void {
    const more = sc[r];
    const pages: [*]align(4) const u64 = @ptrCast(@alignCast(&sc[r + 1]));
    for (pages[0..more]) |q| {
        if (q == page) continue;
        const k = find(q);
        if (k == nreg or !emulated(k)) continue;
        const host = pageProt(q) orelse continue;
        if (host == PAGE_EXECUTE_READ) _ = stopPage(q, winProt(regs[k].prot & ~PROT_EXEC));
    }
}

// cool takes hot region m out of execution: its page maps its view again,
// without execute, and the views frozen for it thaw.
fn cool(m: usize) bool {
    const r = regs[m];
    if (!r.hot) return true;
    dropOwn(r.lo, r.hi, false);
    dropXtraps(r.lo, r.hi);
    if (NtUnmapViewOfSectionEx(SELF, r.lo, MEM_PRESERVE_PLACEHOLDER) < 0) return false;
    regs[m] = .{ .lo = r.lo, .hi = r.hi, .kind = .free, .prot = 0, .sec = 0, .off = 0 };
    if (!mapPiece(m, r, r.off)) return false;
    refreeze(r.lo, r.hi);
    thawKey(r.key, r.off);
    return true;
}

// unshade cools the hot pages and thaws the frozen ones of [a, a+n), for a
// write the stub makes, and reports whether it could: one frozen for memory
// another process runs needs the supervisor. The lock is held.
fn unshade(a: u64, n: u64) bool {
    var page = a & ~(PAGE - 1);
    while (page < a + n) : (page += PAGE) {
        const i = find(page);
        const f = frozenAt(page);
        const key = if (f) |k| frozen[k].key else if (i != nreg and regs[i].hot) regs[i].key else continue;
        const soff = if (f) |k| frozen[k].soff else regs[i].off;
        if (remote(key, soff) or !thaw(key, soff)) return false;
    }
    return true;
}

// ---- exclusive windows (arm64) ---------------------------------------------------
//
// A store exclusive from a hot page's own code into it cannot run alone: its
// monitor is lost to the fault. Its window, from the load exclusive that
// opens it, runs out of line instead, the page held cool meanwhile (holds), so
// the load and the store reach the same memory, a thread that would run the
// page waiting. The first time, the store fails and the window is learned
// (excl), its load exclusive trapped (XTRAP) in every shadow of the page from
// then on.

pub const XTRAP: u32 = 0x5e; // udf #0x5e
pub const Excl = struct { key: u64, soff: u64, at: u32, n: u32, ldx: u32 };
const MAXEXCL = 256;
var excl: [MAXEXCL]Excl = undefined;
var nexcl: usize = 0;
var xtraps: PageSet = .{}; // the trapped load exclusives in hot pages, by address (key)

// learnExcl records the window store exclusive w at pc, of hot region i,
// closes: from the nearest load exclusive before it on the page that takes
// the same base, size and pairing.
fn learnExcl(i: usize, pc: u64, w: u32) void {
    const page = pc & ~(PAGE - 1);
    var at = pc;
    var n: u32 = 1;
    while (at > page and n < ool.MAX) {
        at -= 4;
        n += 1;
        const l = @as(*const u32, @ptrFromInt(at)).*;
        if (!ool.loadExclusive(l)) continue;
        if (!ool.pairOf(l, w)) return;
        const e = Excl{ .key = regs[i].key, .soff = regs[i].off, .at = @intCast(at - page), .n = n, .ldx = l };
        for (excl[0..nexcl]) |x| {
            if (x.key == e.key and x.soff == e.soff and x.at == e.at) return;
        }
        if (nexcl == MAXEXCL) return;
        excl[nexcl] = e;
        nexcl += 1;
        return;
    }
}

// placeExcl traps, in a page of memory (key, soff) held aside for a heat,
// the load exclusives of the windows learned for it, and returns how many;
// their offsets are in heat_xtraps.
fn placeExcl(aside: u64, key: u64, soff: u64) usize {
    if (@import("builtin").cpu.arch != .aarch64) return 0;
    var n: usize = 0;
    for (excl[0..nexcl]) |e| {
        if (e.key != key or e.soff != soff or n == heat_xtraps.len) continue;
        const w: *u32 = @ptrFromInt(aside + e.at);
        if (w.* != e.ldx) continue;
        w.* = XTRAP;
        heat_xtraps[n] = e.at;
        n += 1;
    }
    return n;
}

fn dropXtraps(lo: u64, hi: u64) void {
    var k: usize = 0;
    while (k < xtraps.n) {
        if (xtraps.items[k].key >= lo and xtraps.items[k].key < hi) {
            xtraps.n -= 1;
            xtraps.items[k] = xtraps.items[xtraps.n];
        } else k += 1;
    }
}

// exclTrap serves the trapped load exclusive at pc (an XTRAP, or one taken
// back since), the thread's registers xr and sp: its page cools and is
// held, and its window runs out of line from the load exclusive (st).
pub fn exclTrap(pc: u64, xr: []const u64, sp: u64, st: *Step) Verdict {
    acquire();
    defer releaseLock();
    const page = pc & ~(PAGE - 1);
    const i = find(page);
    if (!xtraps.has(.{ .key = pc, .soff = 0 })) {
        // Cooled since it was fetched: it runs anew.
        return if (i != nreg and ool.loadExclusive(@as(*const u32, @ptrFromInt(pc)).*)) .handled else .none;
    }
    if (i == nreg or !regs[i].hot) return .none;
    const key = regs[i].key;
    const soff = regs[i].off;
    const e = for (excl[0..nexcl]) |x| {
        if (x.key == regs[i].key and x.soff == regs[i].off and x.at == pc - page) break x;
    } else return .none;
    const w: [*]const u32 = @ptrFromInt(pc);
    const words: [*]u32 = @ptrCast(@alignCast(&st.code));
    words[0] = e.ldx;
    st.n = 1;
    while (st.n < e.n and pc + 4 * st.n < page + PAGE) : (st.n += 1) words[st.n] = w[st.n];
    st.start = pc;
    if (!cool(i)) return .none;
    const rn = (e.ldx >> 5) & 31;
    touch(if (rn == 31) sp else xr[rn]);
    st.hold = hold(key, soff);
    return .step;
}

// touch has the memory at a, if the guest may write it, mapped writable
// before the window runs: a fault inside it would lose its monitor, the
// pages just mapped again taking one on their first write.
fn touch(a: u64) void {
    const j = find(a);
    if (j == nreg or regs[j].hot or regs[j].prot & PROT_WRITE == 0 or frozenAt(a & ~(PAGE - 1)) != null) return;
    _ = @atomicRmw(u8, @as(*u8, @ptrFromInt(a)), .Add, 0, .monotonic);
}

// ---- holds ---------------------------------------------------------------------
//
// Memory a store or an exclusive window runs out of line on is held cool
// until the run ends: no thread heats a page of it, or runs it rewritten,
// meanwhile (it waits), nor does another process (its freeze waits,
// serveCode), so what runs lands. A thread holds nothing while it waits on
// another, or on the registry. A hold is named by its place + 1; 0 is none.

const Hold = struct { key: u64 = 0, soff: u64 = 0, used: bool = false };
var holds: [64]Hold = [_]Hold{.{}} ** 64;

fn hold(key: u64, soff: u64) u64 {
    for (&holds, 0..) |*h, k| {
        if (h.used) continue;
        h.* = .{ .key = key, .soff = soff, .used = true };
        return k + 1;
    }
    return 0;
}

fn heldMem(key: u64, soff: u64) bool {
    for (holds) |h| {
        if (h.used and h.key == key and h.soff == soff) return true;
    }
    return false;
}

// letGo ends hold id.
pub fn letGo(id: u64) void {
    if (id == 0) return;
    acquire();
    defer releaseLock();
    holds[id - 1].used = false;
    wake();
}

// ---- shared code across processes ---------------------------------------------
//
// Through the supervisor's registry (sandbox/codereg.go): memory another
// process runs as a hot page, whose writable views here stay frozen, a write
// through one having it cooled there first (LC_COOL); the pages this process
// holds there (LC_HOT); how many freezes the service thread has served, for a
// cool's thaw to know none came since it asked; and whether the host is about
// to stop the process, which then heats nothing. The service thread
// (thread.zig) serves the registry's requests (serveCode). No thread waits on
// the registry holding the lock.

const MemPage = struct { key: u64, soff: u64 };

// PageSet is a set of pages of memory, grown as it fills. The lock guards it.
const PageSet = struct {
    items: [*]MemPage = undefined,
    n: usize = 0,
    cap: usize = 0,

    fn has(s: *const PageSet, p: MemPage) bool {
        for (s.items[0..s.n]) |q| {
            if (q.key == p.key and q.soff == p.soff) return true;
        }
        return false;
    }

    fn add(s: *PageSet, p: MemPage) void {
        if (s.has(p)) return;
        if (s.n == s.cap) {
            const c = @max(s.cap * 2, PAGE / @sizeOf(MemPage));
            var b: usize = 0;
            var z: usize = c * @sizeOf(MemPage);
            if (NtAllocateVirtualMemory(SELF, &b, 0, &z, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0) return;
            const fresh: [*]MemPage = @ptrFromInt(b);
            @memcpy(fresh[0..s.n], s.items[0..s.n]);
            if (s.cap > 0) {
                var o: usize = @intFromPtr(s.items);
                var zz: usize = 0;
                _ = NtFreeVirtualMemory(SELF, &o, &zz, MEM_RELEASE);
            }
            s.items = fresh;
            s.cap = c;
        }
        s.items[s.n] = p;
        s.n += 1;
    }

    fn remove(s: *PageSet, p: MemPage) void {
        for (s.items[0..s.n], 0..) |q, k| {
            if (q.key == p.key and q.soff == p.soff) {
                s.n -= 1;
                s.items[k] = s.items[s.n];
                return;
            }
        }
    }
};

var remote_hot: PageSet = .{};
var registered: PageSet = .{};
var freezes: u32 = 0;
var stopped = false;
var wake_gen: u32 = 0;

extern "ntdll" fn RtlWaitOnAddress(addr: *const anyopaque, cmp: *const anyopaque, size: usize, timeout: ?*const i64) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn RtlWakeAddressAll(addr: *const anyopaque) callconv(win.WINAPI) void;

// alone reports whether this process is the run's only one: none other can
// map its memory.
fn alone() bool {
    return root.sigRunProcs() <= 1;
}

// remote reports whether memory (key, soff) is, for all this process knows,
// run as a hot page in another.
fn remote(key: u64, soff: u64) bool {
    return remote_hot.has(.{ .key = key, .soff = soff }) and !alone();
}

fn ask(v: Verdict, key: u64, soff: u64, st: *Step) Verdict {
    st.key = key;
    st.soff = soff;
    st.gen = freezes;
    return v;
}

// holding records that the registry has made this process a holder of
// (key, soff): its pages of that memory may run.
pub fn holding(key: u64, soff: u64) void {
    acquire();
    defer releaseLock();
    registered.add(.{ .key = key, .soff = soff });
}

// cooled follows the registry's cool of (key, soff), asked when freezes stood
// at gen: the page is cool everywhere else, so it cools here and its views
// thaw, unless a freeze has come since, when the write faults and asks again.
pub fn cooled(key: u64, soff: u64, gen: u32) void {
    acquire();
    defer releaseLock();
    cooledLocked(key, soff, gen);
}

fn cooledLocked(key: u64, soff: u64, gen: u32) void {
    if (freezes != gen) return;
    _ = thaw(key, soff);
    remote_hot.remove(.{ .key = key, .soff = soff });
}

// settle does what a fault's verdict v asks of the thread, the lock not held,
// before the access runs again: has the registry hold or cool a page, or
// waits for a stop to end.
pub fn settle(v: Verdict, st: *const Step) void {
    switch (v) {
        .hot => {
            _ = root.request(LC_HOT, .{ st.key, st.soff, 0, 0, 0, 0 });
            holding(st.key, st.soff);
        },
        .cool => {
            _ = root.request(LC_COOL, .{ st.key, st.soff, 0, 0, 0, 0 });
            cooled(st.key, st.soff, st.gen);
        },
        .wait => waitGen(st.gen),
        else => {},
    }
}

// waitGen waits for what keeps a page from running since gen to end.
pub fn waitGen(gen: u32) void {
    while (@atomicLoad(u32, &wake_gen, .acquire) == gen) _ = RtlWaitOnAddress(&wake_gen, &gen, 4, null);
}

fn wake() void {
    _ = @atomicRmw(u32, &wake_gen, .Add, 1, .release);
    RtlWakeAddressAll(&wake_gen);
}

// serveCode serves the registry's request on ch, the service thread's slot
// (sandbox/codereg_windows.go's repCode): args[0] the op, its body after.
pub fn serveCode(ch: *root.Chan) u64 {
    acquire();
    defer releaseLock();
    const a = ch.args;
    switch (a[0]) {
        0 => { // codeFreeze, once what is held of it lands
            while (heldMem(a[1], a[2])) {
                const gen = @atomicLoad(u32, &wake_gen, .acquire);
                releaseLock();
                waitGen(gen);
                acquire();
            }
            freezeRemote(a[1], a[2]);
        },
        1 => { // codeCool
            registered.remove(.{ .key = a[1], .soff = a[2] });
            _ = thaw(a[1], a[2]);
        },
        2 => { // codeCoolFile
            var i: usize = 0;
            while (i < nreg) : (i += 1) {
                if (regs[i].hot and regs[i].key == a[1]) _ = cool(i);
            }
        },
        3 => { // codeStop
            stopped = true;
            registered.n = 0;
            var i: usize = 0;
            while (i < nreg) : (i += 1) {
                if (regs[i].hot) _ = cool(i);
            }
        },
        4 => { // codeGo
            stopped = false;
            wake();
        },
        else => {},
    }
    return 0;
}

// heldIn freezes the n pages of memory at at, which other processes ran as
// this one joined the registry.
pub fn heldIn(at: u64, n: u64) void {
    acquire();
    defer releaseLock();
    const pages: [*]const [2]u64 = @ptrFromInt(at);
    for (pages[0..n]) |p| freezeRemote(p[0], p[1]);
}

// freezeRemote freezes this process's writable views of memory (key, soff),
// which another process runs. The lock is held.
fn freezeRemote(key: u64, soff: u64) void {
    freezes +%= 1;
    remote_hot.add(.{ .key = key, .soff = soff });
    freezeViews(key, soff, 0);
}

// stopPage takes a page of code made executable at run time out of
// execution, with its syscalls back where its traps were, and gives it host
// protection prot. The lock is held.
fn stopPage(page: u64, prot: u32) bool {
    const i = find(page);
    if (i != nreg and regs[i].hot) return cool(i); // its copy goes, traps and all
    if (!setProt(page, PAGE_READWRITE)) return false;
    untrapPage(page);
    return setProt(page, prot);
}

// stopPages stops the pages of [lo, hi) that run, before their protection
// changes or their bytes move. The lock is held.
fn stopPages(lo: u64, hi: u64) void {
    coolIn(lo, hi);
    var page = lo & ~(PAGE - 1);
    while (page < hi) : (page += PAGE) {
        const i = find(page);
        if (i == nreg or !emulated(i)) continue;
        const host = pageProt(page) orelse continue;
        if (host & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE) == 0) continue;
        _ = stopPage(page, winProt(regs[i].prot & ~PROT_EXEC));
    }
}

// The traps of code made executable at run time are the stub's own, in own
// (it puts them back with no call: a page may stop while the stub serves the
// supervisor); the rewriter's, in file code, the supervisor knows. trap_cache
// holds traps found to be either, by a hash of their address.
var trap_cache: [4096]u64 = [_]u64{0} ** 4096;
var own: [*]u64 = undefined;
var nown: usize = 0;
var capown: usize = 0;

fn cacheSlot(pc: u64) usize {
    return @intCast((pc *% 0x9e3779b97f4a7c15) >> 52);
}

// isTrap reports whether a trap instruction at pc is one the rewriter or the
// stub placed for a syscall; any other is the guest's own.
pub fn isTrap(pc: u64) bool {
    if (@atomicLoad(u64, &trap_cache[cacheSlot(pc)], .acquire) == pc) return true;
    acquire();
    const mine = for (own[0..nown]) |t| {
        if (t == pc) break true;
    } else false;
    releaseLock();
    if (!mine and root.request(LC_IS_TRAP, .{ pc, 0, 0, 0, 0, 0 }) != 1) return false;
    @atomicStore(u64, &trap_cache[cacheSlot(pc)], pc, .release);
    return true;
}

// forgetTraps drops what trap_cache knows of [lo, hi), whose code changed.
fn forgetTraps(lo: u64, hi: u64) void {
    for (&trap_cache) |*e| {
        const v = @atomicLoad(u64, e, .monotonic);
        if (v >= lo and v < hi) @atomicStore(u64, e, 0, .monotonic);
    }
}

// ownTrap records a trap the stub placed outside the guest's memory.
pub fn ownTrap(pc: u64) bool {
    acquire();
    defer releaseLock();
    return addOwn(pc);
}

// addOwn records a trap the stub placed. The lock is held.
fn addOwn(pc: u64) bool {
    if (nown == capown) {
        const n = @max(capown * 2, PAGE / 8);
        var b: usize = 0;
        var s: usize = n * 8;
        if (NtAllocateVirtualMemory(SELF, &b, 0, &s, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0) return false;
        const fresh: [*]u64 = @ptrFromInt(b);
        @memcpy(fresh[0..nown], own[0..nown]);
        if (capown > 0) {
            var o: usize = @intFromPtr(own);
            var z: usize = 0;
            _ = NtFreeVirtualMemory(SELF, &o, &z, MEM_RELEASE);
        }
        own = fresh;
        capown = n;
    }
    own[nown] = pc;
    nown += 1;
    return true;
}

// dropOwn forgets the stub's traps in [lo, hi), putting the syscalls back
// when untrap (the page is writable). The lock is held.
fn dropOwn(lo: u64, hi: u64, untrap: bool) void {
    forgetTraps(lo, hi);
    var k: usize = 0;
    while (k < nown) {
        const t = own[k];
        if (t >= lo and t < hi) {
            if (untrap) untrapSite(t & ~(PAGE - 1), @intCast(t & (PAGE - 1)));
            nown -= 1;
            own[k] = own[nown];
        } else k += 1;
    }
}

// untrapPage puts the syscalls of the writable page back where the stub's
// traps are. The lock is held.
fn untrapPage(page: u64) void {
    dropOwn(page, page + PAGE, true);
}

fn untrapSite(page: u64, off: u32) void {
    switch (@import("builtin").cpu.arch) {
        .aarch64 => {
            if (off % 4 != 0 or off + 4 > PAGE) return;
            const w: *u32 = @ptrFromInt(page + off);
            const cur = @atomicLoad(u32, w, .seq_cst);
            if (cur == 0 or root.arch.isJitBranch(page + off, cur)) _ = @cmpxchgStrong(u32, w, cur, 0xd4000001, .seq_cst, .seq_cst);
        },
        else => {
            if (off + 2 > PAGE) return;
            const b: [*]u8 = @ptrFromInt(page + off);
            if (b[0] == 0x0f) _ = @cmpxchgStrong(u8, &b[1], 0x0b, 0x05, .seq_cst, .seq_cst);
        },
    }
}

// makeWritable makes the executable pages of code made executable at run time
// in [a, a+n) writable again, for the supervisor to write into, and reports
// whether all of the range is memory the guest may write.
pub fn makeWritable(a: u64, n: u64, ch: *root.Chan) u64 {
    acquire();
    defer releaseLock();
    // The supervisor has had memory another process runs cooled there, as
    // the last answer asked: the page thaws here too.
    if (ch.args[3] != 0) cooledLocked(ch.args[3], ch.args[4], @truncate(ch.args[5]));
    if (!accessible(a, n, true)) return 1;
    var page = a & ~(PAGE - 1);
    while (page < a + n) : (page += PAGE) {
        const i = find(page);
        const f = frozenAt(page);
        const key = if (f) |k| frozen[k].key else if (i != nreg and regs[i].hot) regs[i].key else continue;
        const soff = if (f) |k| frozen[k].soff else regs[i].off;
        if (remote(key, soff)) {
            ch.args = .{ key, soff, freezes, 0, 0, 0 };
            return 2;
        }
        _ = thaw(key, soff);
    }
    return @intFromBool(!unexecute(a, n));
}

// unexecute makes the pages of code made executable at run time in [a, a+n)
// that are executable writable again (the guest may write them: accessible
// said so), so a write lands without a fault and runs only once rewritten.
// The lock is held.
fn unexecute(a: u64, n: u64) bool {
    var page = a & ~(PAGE - 1);
    while (page < a + n) : (page += PAGE) {
        const i = find(page);
        if (i == nreg or !emulated(i)) continue;
        const host = pageProt(page) orelse return false;
        if (host == PAGE_EXECUTE_READ and !stopPage(page, winProt(regs[i].prot & ~PROT_EXEC))) return false;
    }
    return true;
}

// rewritePage makes page, of an emulated region, executable with its syscall
// sites traps, and stops the executable pages the analysis found more entries
// of, to be analyzed again when they next run. The page is read-only while
// its sites are found, so a write meanwhile faults and waits; one landing in
// the moment it is writable for the patches changes what was analyzed, which
// the comparison after catches: its traps are taken back and it is done
// again. The lock is held.
// snap is a page being rewritten as analyzed, then as patched (the lock
// guards it).
var snap: [PAGE]u8 = undefined;

fn rewritePage(page: u64, pc: u64) bool {
    const j = find(page);
    if (j == nreg or !emulated(j)) return false;
    while (true) {
        if (!setProt(page, PAGE_READONLY)) return false;
        const src: [*]const u8 = @ptrFromInt(page);
        @memcpy(&snap, src[0..PAGE]);
        const rr = root.request(LC_ANON_SITES, .{ page, pc, 0, 0, 0, 0 });
        if (@as(i64, @bitCast(rr)) < 0) {
            _ = setProt(page, winProt(regs[j].prot & ~PROT_EXEC));
            return false;
        }
        const r: usize = @intCast(rr);
        const sc: [*]const u32 = @ptrFromInt(@intFromPtr(root.scratch()));
        if (!setProt(page, PAGE_READWRITE)) return false;
        var any = false;
        for (sc[0..r]) |off| any = trapSite(page, off, &snap) or any;
        if (!setProt(page, PAGE_EXECUTE_READ)) return false;
        if (std.mem.eql(u8, snap[0..], src[0..PAGE])) {
            _ = NtFlushInstructionCache(SELF, page, PAGE);
            stopMore(sc, r, page);
            return true;
        }
        _ = setProt(page, PAGE_READWRITE);
        if (any) dropOwn(page, page + PAGE, true);
    }
}

// trapSite turns the syscall at off in page into the stub's way in (on arm64
// its island, see jitSiteWord; a trap otherwise), if it is still the syscall,
// makes img what the page then holds, and reports whether it did.
fn trapSite(page: u64, off: u32, img: *[PAGE]u8) bool {
    switch (@import("builtin").cpu.arch) {
        .aarch64 => {
            if (off % 4 != 0 or off + 4 > PAGE) return false;
            const w: *u32 = @ptrFromInt(page + off);
            const to = root.arch.jitSiteWord(page + off, if (off >= 4) std.mem.readInt(u32, img[off - 4 ..][0..4], .little) else null);
            if (!addOwn(page + off)) return false;
            if (@cmpxchgStrong(u32, w, 0xd4000001, to, .seq_cst, .seq_cst) != null) {
                nown -= 1;
                return false;
            }
            std.mem.writeInt(u32, img[off..][0..4], to, .little);
        },
        else => {
            if (off + 2 > PAGE) return false; // a syscall across the page's end is left for the next page to own
            const b: [*]u8 = @ptrFromInt(page + off);
            if (b[0] != 0x0f or !addOwn(page + off)) return false;
            if (@cmpxchgStrong(u8, &b[1], 0x05, 0x0b, .seq_cst, .seq_cst) != null) {
                nown -= 1;
                return false;
            }
            img[off + 1] = 0x0b;
        },
    }
    @atomicStore(u64, &trap_cache[cacheSlot(page + off)], page + off, .release);
    return true;
}

// pageProt is the host protection of page, or null when it is not committed.
fn pageProt(page: u64) ?u32 {
    var mi: MemInfo = undefined;
    if (NtQueryVirtualMemory(SELF, page, 0, &mi, @sizeOf(MemInfo), null) < 0 or mi.state != MEM_COMMIT_STATE) return null;
    return mi.protect & 0xff;
}

fn setProt(page: u64, prot: u32) bool {
    var b: usize = page;
    var s: usize = PAGE;
    var old: u32 = 0;
    return NtProtectVirtualMemory(SELF, &b, &s, prot, &old) >= 0;
}

// readable reports whether [a, a+n) is readable guest memory: one region
// mapped with PROT_READ, or the heap below the break. The lock is held.
fn readable(a: u64, n: u64) bool {
    const end, const o = @addWithOverflow(a, n);
    if (o != 0) return false;
    if (a >= brk_base and end <= brk_cur) return true;
    const i = find(a);
    if (i == nreg) return false;
    const r = regs[i];
    return r.kind != .free and r.kind != .eof and r.prot & PROT_READ != 0 and end <= r.hi;
}

// copyGuest copies n bytes between guest memory at a and the stub's buffer
// buf, into the guest when poke. It holds the lock, so no munmap or mprotect
// changes the range under the copy, and copies only when all of it is
// committed guest memory that allows the access; false leaves the copy to the
// supervisor, which reports the bad address.
pub fn copyGuest(a: u64, buf: usize, n: u64, poke: bool) bool {
    if (n == 0) return true;
    acquire();
    defer releaseLock();
    if (!accessible(a, n, poke)) return false;
    if (poke and !unshade(a, n)) return false; // left to the supervisor (makeWritable)
    if (poke and !unexecute(a, n)) return false; // a write the stub makes never faults
    const g: [*]u8 = @ptrFromInt(a);
    const b: [*]u8 = @ptrFromInt(buf);
    if (poke) @memcpy(g[0..n], b[0..n]) else @memcpy(b[0..n], g[0..n]);
    return true;
}

// load64 reads the guest's u64 at addr, or null when it is not committed
// guest memory that allows reading.
pub fn load64(addr: u64) ?u64 {
    acquire();
    defer releaseLock();
    if (!accessible(addr, 8, false)) return null;
    return std.mem.readInt(u64, @as(*const [8]u8, @ptrFromInt(addr)), .little);
}

// load32 reads the aligned guest word at addr in one load (a futex word), or
// null when it is not committed guest memory that allows reading.
pub fn load32(addr: u64) ?u32 {
    acquire();
    defer releaseLock();
    if (!accessible(addr, 4, false)) return null;
    return @atomicLoad(u32, @as(*const u32, @ptrFromInt(addr)), .seq_cst);
}

const MemInfo = extern struct {
    base: usize,
    alloc_base: usize,
    alloc_protect: u32,
    partition: u16,
    _pad: u16,
    size: usize,
    state: u32,
    protect: u32,
    typ: u32,
    _pad2: u32,
};

const MEM_COMMIT_STATE: u32 = 0x1000;
const PAGE_GUARD: u32 = 0x100;

// accessible reports whether [a, a+n) may be read, or written when write:
// the heap below the break, regions of the mmap area by their Linux
// protection, and anything else (the image, the stack) by what Windows says
// of its pages. The lock is held.
fn accessible(a: u64, n: u64, write: bool) bool {
    const end, const o = @addWithOverflow(a, n);
    if (o != 0) return false;
    const need: u64 = if (write) PROT_WRITE else PROT_READ;
    var p = a;
    while (p < end) {
        if (p >= brk_base and p < brk_cur) {
            p = brk_cur;
            continue;
        }
        const i = find(p);
        if (i != nreg) {
            if (regs[i].kind == .free or regs[i].kind == .eof or regs[i].prot & need == 0) return false;
            p = regs[i].hi;
            continue;
        }
        var mi: MemInfo = undefined;
        if (NtQueryVirtualMemory(SELF, p, 0, &mi, @sizeOf(MemInfo), null) < 0) return false;
        if (mi.state != MEM_COMMIT_STATE or mi.protect & PAGE_GUARD != 0) return false;
        const ok = switch (mi.protect & 0xff) {
            0x04, 0x08, 0x40, 0x80 => true,
            0x02, 0x20 => !write,
            else => false,
        };
        if (!ok) return false;
        p = mi.base + mi.size;
    }
    return true;
}

// The lock is the thread's again when it holds it already: a copy into guest
// memory, under the lock, can fault into wxFault on the same thread.
var lock_owner: u32 = 0;
var lock_depth: u32 = 0;

fn acquire() void {
    const me: u32 = @truncate(root.arch.tebLoad(0x48)); // the thread id
    if (@atomicLoad(u32, &lock_owner, .monotonic) == me) {
        lock_depth += 1;
        return;
    }
    while (@cmpxchgWeak(u32, &lock, 0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    @atomicStore(u32, &lock_owner, me, .monotonic);
    lock_depth = 1;
}

fn releaseLock() void {
    lock_depth -= 1;
    if (lock_depth != 0) return;
    @atomicStore(u32, &lock_owner, 0, .monotonic);
    @atomicStore(u32, &lock, 0, .release);
}

// The memory syscalls' numbers: x86-64's own, or asm-generic on arm64.
const NR = switch (@import("builtin").cpu.arch) {
    .aarch64 => .{ .mmap = 222, .mprotect = 226, .munmap = 215, .brk = 214, .mremap = 216, .msync = 227, .madvise = 233, .shmat = 196, .shmdt = 197 },
    else => .{ .mmap = 9, .mprotect = 10, .munmap = 11, .brk = 12, .mremap = 25, .msync = 26, .madvise = 28, .shmat = 30, .shmdt = 67 },
};

// The reads the supervisor serves into guest memory, and the size of the
// struct epoll_event they fill (packed on x86-64). arm64 has no epoll_wait.
const RD = switch (@import("builtin").cpu.arch) {
    .aarch64 => .{ .read = 63, .pread64 = 67, .readv = 65, .preadv = 69, .preadv2 = 286, .epoll_wait = ~@as(u64, 0), .epoll_pwait = 22, .epoll_pwait2 = 441, .event = 16 },
    else => .{ .read = 0, .pread64 = 17, .readv = 19, .preadv = 295, .preadv2 = 327, .epoll_wait = 232, .epoll_pwait = 281, .epoll_pwait2 = 441, .event = 12 },
};

// A read the supervisor serves stops where the guest's buffer stops being
// writable, as Linux's copy does, but the supervisor cannot see this
// process's memory: outPrefix measures it at the call's entry, for the
// request's ret. Each slot (thread) keeps the writable span it last found,
// good while wgen stands; what can take write access away bumps it once done
// (wroteMaps): munmap, mprotect, mremap, a fixed mapping, brk, SysV attach
// and detach.
pub const OUT_TAG: u64 = 2 << 62;
const Span = struct { lo: u64 = 0, hi: u64 = 0, gen: u64 = std.math.maxInt(u64) };
var wspan: [root.MAX_SLOTS]Span = [_]Span{.{}} ** root.MAX_SLOTS;
var wgen: u64 = 0;

fn wroteMaps() void {
    _ = @atomicRmw(u64, &wgen, .Add, 1, .release);
}

// outPrefix is OUT_TAG with how much of guest syscall nr's output vector the
// guest can write from its start, for a read the supervisor serves into guest
// memory; 0 for any other call, or one the supervisor fails before reading.
pub fn outPrefix(nr: u64, a: [6]u64) u64 {
    const p = if (nr == RD.read or nr == RD.pread64)
        writablePrefix(a[1], @min(a[2], MAX_RW_COUNT))
    else if (nr == RD.readv or nr == RD.preadv or nr == RD.preadv2)
        vecPrefix(a[1], a[2]) orelse return 0
    else if (nr == RD.epoll_wait or nr == RD.epoll_pwait or nr == RD.epoll_pwait2) blk: {
        const m: i32 = @bitCast(@as(u32, @truncate(a[2])));
        if (m <= 0) return 0;
        break :blk writablePrefix(a[1], @as(u64, @intCast(m)) * RD.event);
    } else return 0;
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
        if (!copyGuest(iov + i * 16, @intFromPtr(&v), k * 16, false)) return null;
        for (v[0..k]) |x| {
            if (x[1] > std.math.maxInt(i64)) return null;
            const l = @min(x[1], MAX_RW_COUNT - total);
            if (l == 0) continue;
            const p = writablePrefix(x[0], l);
            total += p;
            if (p < l or total == MAX_RW_COUNT) return total;
        }
    }
    return total;
}

// writablePrefix is how much of [a, a+n) the guest can write from its start:
// the heap below the break, regions of the mmap area by their Linux
// protection, and anything else (the image, the stack) by what Windows says
// of its pages.
fn writablePrefix(a: u64, n: u64) u64 {
    const end = a +| n;
    const s = &wspan[root.curSlot()];
    const g = @atomicLoad(u64, &wgen, .acquire);
    if (g == s.gen and a >= s.lo and end <= s.hi) return n;
    acquire();
    defer releaseLock();
    var p = a;
    var lo = a;
    while (p < end) {
        var from = p;
        var to: u64 = undefined;
        const i = find(p);
        if (p >= brk_base and p < brk_cur) {
            from, to = .{ brk_base, brk_cur };
        } else if (i != nreg) {
            const r = &regs[i];
            if (r.kind == .free or r.kind == .eof or r.prot & PROT_WRITE == 0) break;
            from, to = .{ r.lo, r.hi };
        } else {
            var mi: MemInfo = undefined;
            if (NtQueryVirtualMemory(SELF, p, 0, &mi, @sizeOf(MemInfo), null) < 0) break;
            if (mi.state != MEM_COMMIT_STATE or mi.protect & PAGE_GUARD != 0) break;
            switch (mi.protect & 0xff) {
                0x04, 0x08, 0x40, 0x80 => {},
                else => break,
            }
            from, to = .{ mi.base, mi.base + mi.size };
        }
        if (p == a) lo = from;
        p = to;
    }
    if (p > a) s.* = .{ .lo = lo, .hi = p, .gen = g };
    return @min(p, end) - a;
}

// serve answers the memory syscalls; null for any other.
pub fn serve(nr: u64, a: [6]u64) ?u64 {
    switch (nr) {
        NR.mmap, NR.mprotect, NR.munmap, NR.brk, NR.mremap, NR.msync, NR.madvise, NR.shmat, NR.shmdt => {},
        else => return null,
    }
    acquire();
    defer releaseLock();
    defer switch (nr) {
        NR.mprotect, NR.munmap, NR.brk, NR.mremap, NR.shmat, NR.shmdt => wroteMaps(),
        NR.mmap => if (a[3] & MAP_FIXED != 0) wroteMaps(),
        else => {},
    };
    return switch (nr) {
        NR.mmap => mmap(a[0], a[1], a[2], a[3], a[4] & 0xffffffff, a[5]),
        NR.mprotect => mprotect(a[0], a[1], a[2]),
        NR.munmap => munmap(a[0], a[1]),
        NR.brk => brk(a[0]),
        NR.mremap => mremap(a[0], a[1], a[2], a[3], a[4]),
        NR.msync => msync(a[0], a[1]),
        NR.madvise => madvise(a[0], a[1], a[2]),
        NR.shmat => shmat(a[0], a[1], a[2]),
        NR.shmdt => shmdt(a[0]),
        else => unreachable,
    };
}

// shmat attaches a SysV segment: the supervisor makes a section for it, the
// stub maps it into the guest address space and records the attachment cookie
// so shmdt can drop every piece.
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
    const k = root.request(LC_SHMAT, .{ shmid, 0, 0, 0, 0, 0 });
    if (@as(i64, @bitCast(k)) < 0) return k;
    const sec: HANDLE = @intCast(k & 0xffffffff);
    const key = root.slot().args[0];
    const n = (k >> 32) * PAGE;
    var prot: u64 = if (flg & SHM_RDONLY != 0) PROT_READ else PROT_READ | PROT_WRITE;
    if (flg & SHM_EXEC != 0) prot |= PROT_EXEC;
    var lo: u64 = 0;
    if (addr != 0) {
        lo = addr;
        if (!inArea(lo, lo + n) and !reserveAt(lo, lo + n)) {
            _ = NtClose(sec);
            return neg(ENOMEM);
        }
        if (anyMapped(lo, lo + n)) {
            if (flg & SHM_REMAP == 0 or !unmapRange(lo, lo + n)) {
                _ = NtClose(sec);
                return neg(EINVAL);
            }
        }
    } else {
        lo = freeSpan(n) orelse {
            _ = NtClose(sec);
            return neg(ENOMEM);
        };
    }
    const i = carve(lo, lo + n) orelse {
        _ = NtClose(sec);
        return neg(ENOMEM);
    };
    if (!mapView(i, sec, 0, prot, key, n)) {
        _ = NtClose(sec);
        return neg(EACCES);
    }
    regs[i].file = true;
    bornFrozen(i);
    root.ensureService(); // a shared view: the registry may owe this process a freeze
    const c = root.request(LC_SHMATTACHED, .{ shmid, 0, 0, 0, 0, 0 });
    if (@as(i64, @bitCast(c)) < 0) {
        _ = release(i, lo, lo + n);
        return c;
    }
    regs[find(lo)].shm = c;
    return lo;
}

// shmdt detaches the segment attached at addr: drop every region that carries
// its cookie, then tell the supervisor the attachment is gone.
fn shmdt(addr: u64) u64 {
    var c: u64 = 0;
    for (regs[0..nreg]) |r| {
        if (r.shm != 0 and r.lo == addr) c = r.shm;
    }
    if (c == 0) return neg(EINVAL);
    var i: usize = 0;
    while (i < nreg) {
        if (regs[i].shm == c) {
            const lo = regs[i].lo;
            const hi = regs[i].hi;
            regs[i].shm = 0; // clear first: release leaves a freed region in place
            _ = release(i, lo, hi);
            i = 0; // release may compact the table; rescan
        } else {
            i += 1;
        }
    }
    _ = root.request(LC_SHMGONE, .{ c, 0, 0, 0, 0, 0 });
    return 0;
}
