// fdlink.zig — host fds handed from the supervisor to the stub. Every guest fd
// is the supervisor's; when the stub needs the real host file behind one (to
// mmap it), the supervisor sends a copy with SCM_RIGHTS over a datagram
// socketpair inherited as `sock`, then asks the stub to collect it (REP_FDSYNC).
// Received fds are cached here keyed by the supervisor's open-file id, and
// dropped once the supervisor reports that description closed and no mapping
// still needs the file.
//
// Each process has its own pairing, so two processes never read one socket; a
// fork child takes its parent's cached files over on its own (forkAdopt).

const std = @import("std");
const tstate = @import("tstate.zig");

pub const OP_INSTALL: u64 = 1;

// This process's end of its pairing, set up by the supervisor before exec.
pub var sock: i32 = 3;

// An entry lives while the supervisor's description is open or a mapping
// still needs the file (refs, held by mem.zig's file ranges), as Linux keeps a
// file referenced by its mappings after close. Ids are never reused.
const Entry = struct { fd: i32, refs: u32 = 0, open: bool = true };
const gpa = std.heap.page_allocator;
var by_id: std.AutoHashMapUnmanaged(u64, Entry) = .{};
var by_fd: std.AutoHashMapUnmanaged(i32, u64) = .{};
// lock guards the tables: one thread collects fds while others look them up.
pub var lock: std.Thread.Mutex = .{};

const SYS_close: u64 = 6;
const SYS_recvmsg: u64 = 27;

// sys issues a raw Darwin BSD syscall, -errno on failure. The kernel writes a
// second result into x1, so x1..x5 are clobbers loaded inside the asm.
pub fn sys(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) i64 {
    if (tstate.arm64) {
        return asm volatile (
            \\ mov x1, %[a1]
            \\ mov x2, %[a2]
            \\ mov x3, %[a3]
            \\ mov x4, %[a4]
            \\ mov x5, %[a5]
            \\ mov x16, %[nr]
            \\ svc #0x80
            \\ b.cc 1f
            \\ neg x0, x0
            \\ 1:
            : [ret] "={x0}" (-> i64),
            : [nr] "r" (nr),
              [a0] "{x0}" (a0),
              [a1] "r" (a1),
              [a2] "r" (a2),
              [a3] "r" (a3),
              [a4] "r" (a4),
              [a5] "r" (a5),
            : "x1", "x2", "x3", "x4", "x5", "x16", "cc", "memory"
        );
    } else {
        // The arg registers are also clobbers (the kernel writes a second result
        // into rdx for some calls), so the args ride flexible regs and are moved
        // into the syscall ABI registers here.
        return asm volatile (
            \\ movq %[a0], %%rdi
            \\ movq %[a1], %%rsi
            \\ movq %[a2], %%rdx
            \\ movq %[a3], %%r10
            \\ movq %[a4], %%r8
            \\ movq %[a5], %%r9
            \\ movq %[nr], %%rax
            \\ orq $0x2000000, %%rax
            \\ syscall
            \\ jnc 1f
            \\ negq %%rax
            \\ 1:
            : [ret] "={rax}" (-> i64),
            : [nr] "r" (nr),
              [a0] "r" (a0),
              [a1] "r" (a1),
              [a2] "r" (a2),
              [a3] "r" (a3),
              [a4] "r" (a4),
              [a5] "r" (a5),
            : "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx", "r11", "cc", "memory"
        );
    }
}

pub fn close(fd: i32) void {
    _ = sys(SYS_close, @intCast(fd), 0, 0, 0, 0, 0);
}

pub fn lookup(id: u64) ?i32 {
    lock.lock();
    defer lock.unlock();
    const e = by_id.get(id) orelse return null;
    return e.fd;
}

pub fn idOf(fd: i32) ?u64 {
    lock.lock();
    defer lock.unlock();
    return by_fd.get(fd);
}

// ref and unref count a mapping's hold on id's file.
pub fn ref(id: u64) void {
    lock.lock();
    defer lock.unlock();
    if (by_id.getPtr(id)) |e| e.refs += 1;
}

pub fn unref(id: u64) void {
    lock.lock();
    defer lock.unlock();
    const e = by_id.getPtr(id) orelse return;
    e.refs -|= 1;
    if (e.refs == 0 and !e.open) remove(id, e.fd);
}

fn remove(id: u64, fd: i32) void {
    close(fd);
    _ = by_fd.remove(fd);
    _ = by_id.remove(id);
}

fn install(id: u64, fd: i32) bool {
    by_id.ensureUnusedCapacity(gpa, 1) catch return false;
    by_fd.ensureUnusedCapacity(gpa, 1) catch return false;
    if (by_id.getPtr(id)) |e| {
        // A resend of a description: the new fd is the same open file.
        close(e.fd);
        _ = by_fd.remove(e.fd);
        e.fd = fd;
        e.open = true;
    } else {
        by_id.putAssumeCapacity(id, .{ .fd = fd });
    }
    by_fd.putAssumeCapacity(fd, id);
    return true;
}

// drop forgets a description the supervisor closed, keeping the fd while a
// mapping still holds it.
fn drop(id: u64) void {
    const e = by_id.getPtr(id) orelse return;
    e.open = false;
    if (e.refs == 0) remove(id, e.fd);
}

const Iovec = extern struct { base: [*]u8, len: usize };
const Msghdr = extern struct {
    name: ?*anyopaque,
    namelen: u32,
    iov: *Iovec,
    iovlen: c_int,
    control: [*]u8,
    controllen: u32,
    flags: c_int,
};
const SOL_SOCKET: i32 = 0xffff;
const EMSGSIZE: i64 = 40;
const ENFILE: i64 = 23;
const SCM_RIGHTS: i32 = 1;

// recvOne takes one datagram {op, id} and the fd riding it.
fn recvOne() i64 {
    var msg: [2]u64 = undefined;
    var iov = Iovec{ .base = @ptrCast(&msg), .len = 16 };
    var ctl: [32]u8 align(8) = undefined;
    var h = Msghdr{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &ctl, .controllen = ctl.len, .flags = 0 };
    const n = sys(SYS_recvmsg, @intCast(sock), @intFromPtr(&h), 0, 0, 0, 0);
    // Out of descriptors the kernel discards the fd (EMSGSIZE, or a truncated
    // control message): the file table is full.
    if (n == -EMSGSIZE) return -ENFILE;
    if (n < 0) return n;
    // Darwin cmsghdr: len u32, level i32, type i32, then the fd (4-aligned).
    if (n == 16 and h.controllen < 16) return -ENFILE;
    if (n != 16) return -5;
    const level = std.mem.readInt(i32, ctl[4..8], .little);
    const typ = std.mem.readInt(i32, ctl[8..12], .little);
    if (level != SOL_SOCKET or typ != SCM_RIGHTS) return -5;
    const fd = std.mem.readInt(i32, ctl[12..16], .little);
    switch (msg[0]) {
        OP_INSTALL => if (!install(msg[1], fd)) {
            close(fd);
            return -ENFILE;
        },
        else => close(fd),
    }
    return 0;
}

// sync serves REP_FDSYNC: drop the `ncl` closed ids packed as u64s in `ids`,
// collect `nrecv` queued datagrams, and return the stub fd now cached for
// `want` (-EBADF if none, 0 when want is 0).
pub fn sync(ids: [*]const u64, ncl: u64, nrecv: u64, want: u64) u64 {
    lock.lock();
    defer lock.unlock();
    var i: u64 = 0;
    while (i < ncl) : (i += 1) drop(ids[i]);
    i = 0;
    while (i < nrecv) : (i += 1) {
        const r = recvOne();
        if (r < 0) return @bitCast(r);
    }
    if (want == 0) return 0;
    if (by_id.get(want)) |e| {
        if (e.open) return @intCast(e.fd);
    }
    return @bitCast(@as(i64, -9));
}

// ForkEnt is a cached file a fork child takes over: the supervisor's id for
// it, whether that description is still open, and the fd it is on, which the
// child keeps (the supervisor names a stub's files by fd). The file itself goes
// as a fileport.
pub const ForkEnt = extern struct { id: u64, fd: i32, open: u32 };

// forkList lists the cache for a fork child, leaving it locked until
// forkListEnd.
pub fn forkList(out: *std.ArrayList(ForkEnt)) bool {
    lock.lock();
    var it = by_id.iterator();
    while (it.next()) |kv| {
        out.append(.{ .id = kv.key_ptr.*, .fd = kv.value_ptr.fd, .open = @intFromBool(kv.value_ptr.open) }) catch return false;
    }
    return true;
}

pub fn forkListEnd() void {
    lock.unlock();
}

const SYS_dup2: u64 = 90;
const SYS_fstat64: u64 = 339;

extern "c" fn fileport_makefd(port: u32) c_int;

// forkAdopt installs a fork child's cache from its parent's list, each file
// (ports[i] carries entry i's) on the fd it had there; false if that fd is
// taken. Each is made an fd and moved before the next, so a fresh fd never
// sits on a number a later entry needs. Mappings take their holds after
// (mem.forkLoad).
pub fn forkAdopt(ents: []align(1) const ForkEnt, ports: []const u32) bool {
    lock.lock();
    defer lock.unlock();
    var st: [144]u8 align(8) = undefined;
    for (ents, ports) |e, port| {
        const fd = fileport_makefd(port);
        if (fd < 0) return false;
        if (fd != e.fd) {
            if (sys(SYS_fstat64, @intCast(e.fd), @intFromPtr(&st), 0, 0, 0, 0) == 0 or
                sys(SYS_dup2, @intCast(fd), @intCast(e.fd), 0, 0, 0, 0) < 0)
            {
                close(fd);
                return false;
            }
            close(fd);
        }
        if (!install(e.id, e.fd)) return false;
        if (e.open == 0) by_id.getPtr(e.id).?.open = false;
    }
    return true;
}

extern "c" fn getrlimit(res: c_int, rl: *[2]u64) c_int;
extern "c" fn setrlimit(res: c_int, rl: *const [2]u64) c_int;
extern "c" fn sysctlbyname(name: [*:0]const u8, old: ?*anyopaque, oldlen: ?*usize, new: ?*anyopaque, newlen: usize) c_int;

// init lifts the stub's descriptor limit (launchd's default soft limit is 256)
// as far as the host allows, so the cache holds as many files as the guest
// maps. It must run before Seatbelt.
pub fn init() void {
    const RLIMIT_NOFILE: c_int = 8;
    var rl: [2]u64 = undefined;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return;
    var per: c_int = 10240;
    var len: usize = @sizeOf(c_int);
    _ = sysctlbyname("kern.maxfilesperproc", &per, &len, null, 0);
    rl[0] = @min(rl[1], @as(u64, @intCast(@max(per, 256))));
    _ = setrlimit(RLIMIT_NOFILE, &rl);
}
