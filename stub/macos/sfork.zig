// sfork.zig — a fork whose child is a fresh stub. Darwin keeps a process's x18
// only for an image it execs from the (legacy-marked) stub binary, never in a
// fork() child, and code GCC builds for Linux uses x18 as a scratch register:
// a forked guest must run in a stub that was started, not forked.
//
// Every stub registers a mailbox (a Mach receive right) with the supervisor's
// broker before it sandboxes itself (register). For a fork the supervisor
// adopts a pooled stub as the child and sends the parent a send right to the
// child's mailbox; the parent sends the child its guest memory as Mach memory
// entries (copy-on-write, or shared where Linux's fork would share), its
// cached files as fileports and its state, and the child maps the memory at
// the same addresses, takes the state over and resumes the guest at the
// fork's return with 0. Stubs start without ASLR, so the islands the guest's
// code branches to reach the same stub code in the child.

const std = @import("std");
const root = @import("root");
const chan = @import("chan.zig");
const mem = @import("mem.zig");
const fdlink = @import("fdlink.zig");
const procinfo = @import("procinfo.zig");
const sig = @import("sig.zig");
const proc = @import("proc.zig");
const tstate = @import("tstate.zig");

extern "c" fn mach_task_self() u32;
extern "c" fn mach_reply_port() u32;
extern "c" fn mach_port_allocate(task: u32, right: u32, name: *u32) c_int;
extern "c" fn mach_port_deallocate(task: u32, name: u32) c_int;
extern "c" fn mach_msg(msg: *anyopaque, option: c_int, send_size: u32, rcv_size: u32, rcv_name: u32, timeout: u32, notify: u32) c_int;
extern "c" fn task_get_special_port(task: u32, which: c_int, port: *u32) c_int;
extern "c" fn mach_make_memory_entry_64(task: u32, size: *u64, offset: u64, permission: c_int, entry: *u32, parent: u32) c_int;
extern "c" fn mach_vm_map(task: u32, addr: *u64, size: u64, mask: u64, flags: c_int, object: u32, offset: u64, copy: c_int, cur: c_int, max: c_int, inherit: u32) c_int;
extern "c" fn mach_vm_deallocate(task: u32, addr: u64, size: u64) c_int;
extern "c" fn mach_vm_remap(task: u32, dst: *u64, size: u64, mask: u64, flags: c_int, src_task: u32, src: u64, copy: c_int, cur: *c_int, max: *c_int, inherit: u32) c_int;
extern "c" fn mach_vm_protect(task: u32, addr: u64, size: u64, set_max: c_int, prot: c_int) c_int;
extern "c" fn fileport_makeport(fd: c_int, port: *u32) c_int;
extern "c" fn getppid() c_int;
extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) ?*anyopaque;
extern "c" fn munmap(addr: *anyopaque, len: usize) c_int;
extern "c" fn pthread_jit_write_protect_np(enabled: c_int) void;

const TASK_BOOTSTRAP_PORT: c_int = 4;
const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
const MOVE_SEND: u8 = 17;
const MOVE_SEND_ONCE: u8 = 18;
const COPY_SEND: u8 = 19;
const MAKE_SEND: u8 = 20;
const MAKE_SEND_ONCE: u8 = 21;
const COMPLEX: u32 = 0x80000000;
const SEND_MSG: c_int = 1;
const RCV_MSG: c_int = 2;
const RCV_AUDIT: c_int = 3 << 24; // MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT)
const PORT_DESC: u8 = 0;
const OOL_DESC: u8 = 1;
const OOL_PORTS_DESC: u8 = 2;
const VIRTUAL_COPY: u8 = 1;
const MAP_MEM_VM_COPY: c_int = 0x200000;
const MAP_MEM_VM_SHARE: c_int = 0x400000;
const VM_FLAGS_FIXED: c_int = 0;
const VM_FLAGS_ANYWHERE: c_int = 1;
const VM_FLAGS_OVERWRITE: c_int = 0x4000;

// Message ids; the broker's must match sandbox/broker_darwin.go.
const ID_REGISTER: i32 = 0x4c430100; // stub -> broker: its mailbox
const ID_CHILD: i32 = 0x4c430101; // supervisor -> parent: the child's mailbox and pid
const ID_FORK: i32 = 0x4c430102; // parent -> child: memory, files, state
const ID_OK: i32 = 0x4c430103; // child -> parent: taken over
const ID_FAIL: i32 = 0x4c430104; // child -> parent: could not

const Header = extern struct { bits: u32, size: u32, remote: u32, local: u32 = 0, voucher: u32 = 0, id: i32 };
const PortDesc = extern struct { name: u32, pad1: u32 = 0, pad2: u16 = 0, disposition: u8, typ: u8 = PORT_DESC };
const OolDesc = extern struct { address: u64 align(4), deallocate: u8 = 0, copy: u8 = VIRTUAL_COPY, pad1: u8 = 0, typ: u8 = OOL_DESC, size: u32 };
const OolPortsDesc = extern struct { address: u64 align(4), deallocate: u8 = 0, copy: u8 = VIRTUAL_COPY, disposition: u8, typ: u8 = OOL_PORTS_DESC, count: u32 };

// A one-port message: a stub's registration, or a child's mailbox.
const PortMsg = extern struct { h: Header, n: u32, port: PortDesc, pid: i32 };
// The audit trailer the kernel appends on request: the sender's pid is audit[5].
const Trailer = extern struct { typ: u32, size: u32, seqno: u32, sender: [2]u32, audit: [8]u32 };

const ForkMsg = extern struct { h: Header, n: u32, regions: OolPortsDesc, files: OolPortsDesc, blob: OolDesc, reply: PortDesc };

// Blob heads the state the parent sends; the region list, the file list and
// mem.zig's tables follow.
const Blob = extern struct {
    magic: u64,
    tramp: u64, // the stub's trampoline: the child must have it at the same address
    tp_key: u64, // the guest thread pointer's TSD slot, baked into islands
    frame: u64,
    stack: u64,
    flags: u64,
    tls: u64,
    ctid: u64,
    tp: u64, // the forking thread's guest thread pointer
    restorer: u64,
    nregion: u64,
    nfile: u64,
    info: procinfo.Info,
    // The forking guest's full register image. The frame is on a stack of the
    // parent stub's own (the thread's, or on x86-64 the signal stack serveTrap
    // runs on), which the child does not have, so the image travels here and
    // the child resumes from its own copy.
    regs: [proc.FRAME_BYTES / 8]u64,
};
const MAGIC: u64 = 0x6b726f666e6f626c; // "lbonfork"

// g_fork_regs holds the child's copy of the forking register image, outliving
// the (freed) blob that carried it, for resumeIsland to read.
var g_fork_regs: [proc.FRAME_BYTES / 8]u64 align(16) = undefined;

// mailbox is this stub's receive right for fork messages; supervisor is the
// pid only the supervisor's messages come from.
pub var mailbox: u32 = 0;
var supervisor: u32 = 0;

// register makes the mailbox and sends a send right to it to the broker,
// this task's bootstrap port. It runs before Seatbelt.
pub fn register() void {
    const task = mach_task_self();
    supervisor = @bitCast(getppid());
    var broker: u32 = 0;
    if (task_get_special_port(task, TASK_BOOTSTRAP_PORT, &broker) != 0 or broker == 0) return;
    defer _ = mach_port_deallocate(task, broker);
    if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &mailbox) != 0) return;
    var m = PortMsg{
        .h = .{ .bits = COPY_SEND | COMPLEX, .size = @sizeOf(PortMsg), .remote = broker, .id = ID_REGISTER },
        .n = 1,
        .port = .{ .name = mailbox, .disposition = MAKE_SEND },
        .pid = 0,
    };
    _ = mach_msg(&m, SEND_MSG, @sizeOf(PortMsg), 0, 0, 0, 0);
}

fn send(m: anytype) bool {
    return mach_msg(m, SEND_MSG, @sizeOf(@TypeOf(m.*)), 0, 0, 0, 0) == 0;
}

fn reply(port: u32, id: i32) void {
    var h = Header{ .bits = MOVE_SEND_ONCE, .size = @sizeOf(Header), .remote = port, .id = id };
    _ = send(&h);
}

const gpa = std.heap.page_allocator;

// parent does the parent's part of a fork once the supervisor has sent it the
// child's mailbox: it describes and sends this process's guest memory, files
// and state, and waits for the child to take them over. It returns the
// child's host pid, or 0 if there is no child.
pub fn parent(frame: u64, flags: u64, stack: u64, tls: u64, ctid: u64, tp: u64) i32 {
    const task = mach_task_self();
    var in: extern struct { m: PortMsg, t: Trailer } = undefined;
    if (mach_msg(&in, RCV_MSG | RCV_AUDIT, 0, @sizeOf(@TypeOf(in)), mailbox, 0, 0) != 0) return 0;
    if (in.m.h.id != ID_CHILD or in.m.h.bits & COMPLEX == 0 or in.t.audit[5] != supervisor) {
        if (in.m.h.bits & COMPLEX != 0 and in.m.port.name != 0) _ = mach_port_deallocate(task, in.m.port.name);
        return 0;
    }
    const box = in.m.port.name;
    if (box == 0) return 0; // the child stub ended before it could be told
    defer _ = mach_port_deallocate(task, box);

    var regions = std.ArrayList(mem.ForkRegion).init(gpa);
    defer regions.deinit();
    var entries = std.ArrayList(u32).init(gpa);
    defer entries.deinit();
    var files = std.ArrayList(fdlink.ForkEnt).init(gpa);
    defer files.deinit();
    var fports = std.ArrayList(u32).init(gpa);
    defer fports.deinit();
    var blob = std.ArrayList(u8).init(gpa);
    defer blob.deinit();

    const ok = collect(task, &regions, &entries, &files, &fports, &blob, .{
        .magic = MAGIC,
        .tramp = @intFromPtr(&root.tramp_common),
        .tp_key = root.g_tp_key,
        .frame = frame,
        .stack = stack,
        .flags = flags,
        .tls = tls,
        .ctid = ctid,
        .tp = tp,
        .restorer = sig.g_restorer,
        .nregion = 0,
        .nfile = 0,
        .info = procinfo.info,
        .regs = @as(*const [proc.FRAME_BYTES / 8]u64, @ptrFromInt(frame)).*,
    });
    if (!ok) {
        for (entries.items) |e| _ = mach_port_deallocate(task, e);
        for (fports.items) |p| _ = mach_port_deallocate(task, p);
        var h = Header{ .bits = COPY_SEND, .size = @sizeOf(Header), .remote = box, .id = ID_FAIL };
        _ = send(&h);
        return 0;
    }

    const rp = mach_reply_port();
    defer _ = mach_port_deallocate(task, rp);
    var m = ForkMsg{
        .h = .{ .bits = COPY_SEND | COMPLEX, .size = @sizeOf(ForkMsg), .remote = box, .id = ID_FORK },
        .n = 4,
        .regions = .{ .address = @intFromPtr(entries.items.ptr), .disposition = MOVE_SEND, .count = @intCast(entries.items.len) },
        .files = .{ .address = @intFromPtr(fports.items.ptr), .disposition = MOVE_SEND, .count = @intCast(fports.items.len) },
        .blob = .{ .address = @intFromPtr(blob.items.ptr), .size = @intCast(blob.items.len) },
        .reply = .{ .name = rp, .disposition = MAKE_SEND_ONCE },
    };
    if (!send(&m)) {
        for (entries.items) |e| _ = mach_port_deallocate(task, e);
        for (fports.items) |p| _ = mach_port_deallocate(task, p);
        return 0;
    }
    // The child answers on the reply port; if it dies first, the kernel's
    // send-once notification arrives there instead.
    var ack: extern struct { h: Header, t: Trailer } = undefined;
    if (mach_msg(&ack, RCV_MSG, 0, @sizeOf(@TypeOf(ack)), rp, 0, 0) != 0 or ack.h.id != ID_OK) return 0;
    return @bitCast(in.m.pid);
}

// collect fills the region and file lists with their ports and the blob, the
// memory tables locked from the region walk to the blob's end so the guest's
// map holds still meanwhile.
fn collect(task: u32, regions: *std.ArrayList(mem.ForkRegion), entries: *std.ArrayList(u32), files: *std.ArrayList(fdlink.ForkEnt), fports: *std.ArrayList(u32), blob: *std.ArrayList(u8), head: Blob) bool {
    var raw = std.ArrayList(mem.ForkRegion).init(gpa);
    defer raw.deinit();
    const listed = mem.forkRegions(&raw);
    defer mem.forkUnlock();
    if (!listed) return false;
    for (raw.items) |r| {
        if (r.kind == .empty) {
            regions.append(r) catch return false;
            entries.append(0) catch return false;
            continue;
        }
        // An entry may cover less than the region asks: the rest takes more.
        var off: u64 = 0;
        while (off < r.size) {
            var size = r.size - off;
            var e: u32 = 0;
            // A shared entry may not be writable and executable both: the
            // child's mapping of one is at most read-write.
            const limit: c_int = if (r.kind == .share) r.max & 3 else r.max & 7;
            const perm: c_int = if (r.kind == .jit) 1 else limit | (if (r.kind == .share) MAP_MEM_VM_SHARE else MAP_MEM_VM_COPY);
            // An entry is only made of readable memory, and a shared one of
            // memory as writable as it lets the child map it. Memory the
            // guest made otherwise is first mapped again elsewhere, a copy
            // (or for a shared region the same memory), so there: its own
            // protection does not change while the guest's threads run.
            var src = r.addr + off;
            const left = r.size - off;
            var tmp: u64 = 0;
            defer if (tmp != 0) {
                _ = mach_vm_deallocate(task, tmp, left);
            };
            const need: c_int = if (r.kind == .share) limit | 1 else 1;
            if (r.cur & need != need) {
                var cur: c_int = 0;
                var max: c_int = 0;
                if (mach_vm_remap(task, &tmp, left, 0, VM_FLAGS_ANYWHERE, task, src, @intFromBool(r.kind != .share), &cur, &max, r.inherit) != 0) {
                    tmp = 0;
                    return false;
                }
                if (mach_vm_protect(task, tmp, left, 0, need) != 0) return false;
                src = tmp;
            }
            if (mach_make_memory_entry_64(task, &size, src, perm, &e, 0) != 0 or size == 0) return false;
            size = @min(size, r.size - off);
            var part = r;
            part.addr += off;
            part.size = size;
            if (r.kind != .jit) {
                part.max = limit;
                part.cur &= limit;
            }
            regions.append(part) catch return false;
            entries.append(e) catch return false;
            off += size;
        }
    }
    const listedf = fdlink.forkList(files);
    defer fdlink.forkListEnd();
    if (!listedf) return false;
    for (files.items) |f| {
        var p: u32 = 0;
        if (fileport_makeport(f.fd, &p) != 0) return false;
        fports.append(p) catch return false;
    }
    var h = head;
    h.nregion = regions.items.len;
    h.nfile = files.items.len;
    blob.appendSlice(std.mem.asBytes(&h)) catch return false;
    blob.appendSlice(std.mem.sliceAsBytes(regions.items)) catch return false;
    blob.appendSlice(std.mem.sliceAsBytes(files.items)) catch return false;
    return mem.forkSave(blob);
}

// Taken is what a fork child resumes from.
pub const Taken = struct { frame: u64, stack: u64, flags: u64, tls: u64, ctid: u64, tp: u64 };

// child takes over the guest of the stub parent_pid sent: maps its memory at
// the same addresses, installs its files and tables, and acknowledges. The
// pooled stub had mapped nothing of a guest but its restorer page, which the
// parent's memory replaces. null if it could not; the parent is told so.
pub fn child(parent_pid: u64) ?Taken {
    const task = mach_task_self();
    var in: extern struct { m: ForkMsg, t: Trailer } = undefined;
    if (mach_msg(&in, RCV_MSG | RCV_AUDIT, 0, @sizeOf(@TypeOf(in)), mailbox, 0, 0) != 0) return null;
    const m = &in.m;
    if (m.h.id != ID_FORK or m.h.bits & COMPLEX == 0 or m.n != 4 or in.t.audit[5] != @as(u32, @truncate(parent_pid))) return null;
    const rp = m.reply.name;
    const t = take(task, m) orelse {
        reply(rp, ID_FAIL);
        return null;
    };
    reply(rp, ID_OK);
    return t;
}

fn take(task: u32, m: *const ForkMsg) ?Taken {
    const raw: [*]const u8 = @ptrFromInt(m.blob.address);
    defer _ = mach_vm_deallocate(task, m.blob.address, m.blob.size);
    const ents: [*]const u32 = @ptrFromInt(m.regions.address);
    defer _ = mach_vm_deallocate(task, m.regions.address, @as(u64, m.regions.count) * 4);
    const fps: [*]const u32 = @ptrFromInt(m.files.address);
    defer _ = mach_vm_deallocate(task, m.files.address, @as(u64, m.files.count) * 4);
    defer drop(task, ents[0..m.regions.count]);
    defer drop(task, fps[0..m.files.count]);

    var b: []const u8 = raw[0..m.blob.size];
    if (b.len < @sizeOf(Blob)) return null;
    const h = std.mem.bytesToValue(Blob, b[0..@sizeOf(Blob)]);
    b = b[@sizeOf(Blob)..];
    if (h.magic != MAGIC or h.tramp != @intFromPtr(&root.tramp_common) or h.tp_key != root.g_tp_key) return null;
    if (h.nregion != m.regions.count or h.nfile != m.files.count) return null;
    const rl = h.nregion * @sizeOf(mem.ForkRegion);
    const fl = h.nfile * @sizeOf(fdlink.ForkEnt);
    if (b.len < rl + fl) return null;
    const regions = std.mem.bytesAsSlice(mem.ForkRegion, @as([]align(1) const u8, b[0..rl]));
    const files = std.mem.bytesAsSlice(fdlink.ForkEnt, @as([]align(1) const u8, b[rl .. rl + fl]));
    b = b[rl + fl ..];

    // The pooled stub's own restorer page is where the parent's lies.
    _ = munmap(@ptrFromInt(sig.g_restorer & ~@as(u64, mem.PAGE - 1)), mem.PAGE);
    for (regions, 0..) |r, i| {
        if (!place(task, r, ents[i])) return null;
    }
    if (!fdlink.forkAdopt(files, fps[0..m.files.count])) return null;
    if (!mem.forkLoad(&b) or !@import("wx.zig").forkLoad(&b)) return null;
    procinfo.info = h.info;
    sig.g_restorer = h.restorer;
    // The frame was on a stack of the parent stub's own: resume from the image
    // the blob carried, kept past it.
    g_fork_regs = h.regs;
    return .{ .frame = @intFromPtr(&g_fork_regs), .stack = h.stack, .flags = h.flags, .tls = h.tls, .ctid = h.ctid, .tp = h.tp };
}

fn drop(task: u32, ports: []const u32) void {
    for (ports) |p| {
        if (p != 0) _ = mach_port_deallocate(task, p);
    }
}

// place maps region r at its address: inside the guest window over whatever
// is there (only the guest's own lies there), elsewhere only where nothing is.
fn place(task: u32, r: mem.ForkRegion, entry: u32) bool {
    const in_window = r.addr >= mem.GUEST_BASE and r.addr + r.size <= mem.GUEST_TOP;
    const fl: c_int = VM_FLAGS_FIXED | (if (in_window) VM_FLAGS_OVERWRITE else 0);
    var at = r.addr;
    switch (r.kind) {
        .empty => return mach_vm_map(task, &at, r.size, 0, fl, 0, 0, 0, r.cur, r.max, r.inherit) == 0,
        .copy, .share => {
            // Executable memory is mapped without execute and then given it,
            // as the parent's was (by the mprotect that sealed its code):
            // XNU marks code made executable that way, and a child whose
            // mapping of the same pages lacked the mark would have the page
            // monitor retype each page whenever the two take turns faulting
            // on it, each retype unmapping it from the other.
            const exec = r.cur & 4 != 0;
            if (mach_vm_map(task, &at, r.size, 0, fl, entry, 0, 0, if (exec) r.cur & ~@as(c_int, 4) else r.cur, r.max, r.inherit) != 0) return false;
            return !exec or mach_vm_protect(task, r.addr, r.size, 0, r.cur) == 0;
        },
        .jit => {
            // MAP_JIT memory cannot be mapped from an entry, nor fixed: a
            // fresh JIT region at the address, filled from a view of the
            // parent's bytes.
            if (in_window) _ = mach_vm_deallocate(task, r.addr, r.size);
            const MAP_JIT_RWX: c_int = 0x0802 | 0x1000; // MAP_PRIVATE | MAP_JIT | MAP_ANON
            const p = mmap(@ptrFromInt(r.addr), r.size, 7, MAP_JIT_RWX, -1, 0) orelse return false;
            if (@intFromPtr(p) != r.addr) {
                if (@intFromPtr(p) != std.math.maxInt(usize)) _ = munmap(p, r.size);
                return false;
            }
            var src: u64 = 0;
            if (mach_vm_map(task, &src, r.size, 0, VM_FLAGS_ANYWHERE, entry, 0, 0, 1, 1, 1) != 0) return false;
            defer _ = mach_vm_deallocate(task, src, r.size);
            pthread_jit_write_protect_np(0);
            @memcpy(@as([*]u8, @ptrFromInt(r.addr))[0..r.size], @as([*]const u8, @ptrFromInt(src))[0..r.size]);
            pthread_jit_write_protect_np(1);
            return true;
        },
    }
}
