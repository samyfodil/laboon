// smaps.zig — the counts /proc/<pid>/smaps has for a mapping
// (sandbox/lx_smaps.go), from the host's view of the memory behind it: its
// pages' residency, dirtiness, reference and swap state as the kernel
// reports them (mincore; the task port is denied mach_vm_page_range_query),
// and whether another map shares them, from the region's share mode.

extern "c" fn mach_task_self() c_uint;
extern "c" fn mach_vm_region(task: c_uint, addr: *u64, size: *u64, flavor: c_int, info: *anyopaque, count: *c_uint, obj: *c_uint) c_int;
extern "c" fn mincore(addr: *anyopaque, len: usize, vec: [*]u8) c_int;
extern "c" fn mach_port_deallocate(task: c_uint, name: c_uint) c_int;

// MapEnt is a mapping as the supervisor renders it (mem.zig's, vmm.zig's).
pub const MapEnt = extern struct { lo: u64, hi: u64, off: u64, aux: u64, attr: u64 };
// Counts are a mapping's, in bytes, as smaps names them.
pub const Counts = extern struct { rss: u64 = 0, pss: u64 = 0, pss_dirty: u64 = 0, shared_clean: u64 = 0, shared_dirty: u64 = 0, private_clean: u64 = 0, private_dirty: u64 = 0, referenced: u64 = 0, swap: u64 = 0 };
// SmapEnt is a mapping with its counts.
pub const SmapEnt = extern struct { e: MapEnt, c: Counts };

// The page mincore reports by: Darwin's 16 KiB, or 4 KiB in a Rosetta task.
const HOST_PAGE: u64 = if (@import("builtin").cpu.arch == .x86_64) 0x1000 else 0x4000;
const VM_REGION_EXTENDED_INFO: c_int = 13;
const SM_COW: u8 = 1;
const SM_SHARED: u8 = 4;
const SM_TRUESHARED: u8 = 5;
const SM_SHARED_ALIASED: u8 = 7;
const INCORE: u8 = 0x1;
const REFERENCED: u8 = 0x2 | 0x8; // by this map, or by another
const MODIFIED: u8 = 0x4 | 0x10;
const PAGED_OUT: u8 = 0x20;
const COPIED: u8 = 0x40;

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

// count counts the pages of [lo, hi), page bytes each, whose memory lies at
// host address lo+off on (a guest page within a host page takes that page's
// state). A resident page is in Rss, referenced or dirty as the kernel says;
// one swapped out is in Swap. One a copy-on-write region has not copied, or
// of a shared region more than one map holds, is shared, its Pss divided by
// the region's references; the rest are private. With anon, the memory is a
// guest's private memory the host cannot see written (the hypervisor's
// RAM, written through the VM's own tables): a resident page is private and
// dirty, as Linux holds anonymous memory.
pub fn count(lo: u64, hi: u64, off: u64, page: u64, anon: bool) Counts {
    var c = Counts{};
    const task = mach_task_self();
    var disp: [256]u8 = undefined;
    var a = lo;
    while (a < hi) {
        var ea = a + off;
        var esize: u64 = 0;
        var ext: ExtInfo = undefined;
        var ecount: c_uint = @sizeOf(ExtInfo) / 4;
        var obj: c_uint = 0;
        if (mach_vm_region(task, &ea, &esize, VM_REGION_EXTENDED_INFO, &ext, &ecount, &obj) != 0) break;
        if (obj != 0) _ = mach_port_deallocate(task, obj);
        if (ea > a + off) {
            a = (ea - off + page - 1) & ~(page - 1); // nothing mapped before the next region
            continue;
        }
        const rhi = @min(ea + esize - off, hi);
        const shared = !anon and (ext.share_mode == SM_COW or ((ext.share_mode == SM_SHARED or ext.share_mode == SM_TRUESHARED or ext.share_mode == SM_SHARED_ALIASED) and ext.ref_count > 1));
        const refs: u64 = @max(ext.ref_count, 2);
        while (a < rhi) {
            const hp = (a + off) & ~(HOST_PAGE - 1);
            const hend = @min((rhi + off + HOST_PAGE - 1) & ~(HOST_PAGE - 1), hp + disp.len * HOST_PAGE);
            var n: u64 = (hend - hp) / HOST_PAGE;
            if (mincore(@ptrFromInt(hp), hend - hp, &disp) != 0) n = 0;
            const end = @min(rhi, hend - off);
            while (a < end) : (a += page) {
                const i = (a + off - hp) / HOST_PAGE;
                const d: u8 = if (i < n) disp[i] else 0;
                if (d & PAGED_OUT != 0) c.swap += page;
                if (d & INCORE == 0) continue;
                c.rss += page;
                if (d & REFERENCED != 0) c.referenced += page;
                const dirty = anon or d & MODIFIED != 0;
                const pss = if (shared and d & COPIED == 0) page / refs else page;
                if (pss != page) {
                    if (dirty) c.shared_dirty += page else c.shared_clean += page;
                } else {
                    if (dirty) c.private_dirty += page else c.private_clean += page;
                }
                c.pss += pss;
                if (dirty) c.pss_dirty += pss;
            }
        }
    }
    return c;
}

// with lists the mappings maps lists, each with its counts; vm for the
// hypervisor's RAM, whose private mappings count as count's anon.
pub fn with(out: [*]SmapEnt, cap: usize, from: u64, next: *u64, maps: *const fn ([*]MapEnt, usize, u64, *u64) u64, off: u64, page: u64, vm: bool) u64 {
    const std = @import("std");
    const tmp = std.heap.page_allocator.alloc(MapEnt, cap) catch return 0;
    defer std.heap.page_allocator.free(tmp);
    const n = maps(tmp.ptr, cap, from, next);
    for (tmp[0..n], 0..) |e, i| out[i] = .{ .e = e, .c = count(e.lo, e.hi, off, page, vm and e.attr & 8 == 0) };
    return n;
}
