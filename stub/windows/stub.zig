// Windows stub: the process a Linux guest runs in. It imports only ntdll (a
// process cloned with RtlCloneUserProcess cannot load DLLs) and runs inside an
// LPAC AppContainer, so everything it touches is handed in by the supervisor:
// the channel section and its two events arrive as inherited handles named on
// the command line.
//
// The supervisor loads and rewrites the guest image from outside (it holds a
// full-access process handle) and starts it with REP_START. Guest syscalls
// reach lc_syscall_entry through a rewriter trampoline, or trap on the
// instruction the rewriter left (ud2 on x86-64, udf on arm64) and arrive
// through the vectored exception handler; either way they are posted to the
// channel slot (sandbox/chanabi.go) and served by the supervisor. What is
// per architecture (register files, entry code, the TEB register) lives in
// x86_64.zig and aarch64.zig.
//
// Per-thread state lives in TEB TLS slots:
//   SLOT_CHAN  this thread's channel slot
//   SLOT_AUX   arm64: the guest's x18 while an exception resumes
//   SLOT_TP    the guest thread pointer: the Linux FS base on x86-64, the
//              guest's tpidr_el0 on arm64 (see aarch64.zig)
//   SLOT_STK   x86-64: the top of this thread's stub stack, which exit sites
//              switch to before anything is written
//   SLOT_CONT  pointer to this thread's canonical sig.Return, consumed by
//              lc_guest_return on both architectures

const std = @import("std");
const builtin = @import("builtin");
const win = std.os.windows;
pub const mem = @import("mem.zig");

// ensureService starts this process's shared-code service thread on its first
// shared view (thread.zig); mem.zig calls it.
pub fn ensureService() void {
    thread.ensureService();
}
const sig = @import("sig.zig");
const thread = @import("thread.zig");

pub const arch = switch (builtin.cpu.arch) {
    .x86_64 => @import("x86_64.zig"),
    .aarch64 => @import("aarch64.zig"),
    else => @compileError("unsupported architecture"),
};

// instrcb is the x86-64 syscall backstop (the seccomp analog). arm64's
// callback-entry ABI differs and has no thunk yet, so it stays strict-rewrite.
const instrcb = if (builtin.cpu.arch == .x86_64) @import("instrcb.zig") else struct {
    pub fn install() void {}
};

pub const SLOT_CONT = 0x1480 + 59 * 8;
pub const SLOT_STK = 0x1480 + 60 * 8;
pub const SLOT_CHAN = 0x1480 + 61 * 8;
pub const SLOT_AUX = 0x1480 + 62 * 8;
pub const SLOT_TP = 0x1480 + 63 * 8;

pub const SLOT_SIZE: usize = 4096;

// Each slot's copy window, past the slots and the signal records
// (sandbox/chanwin.go).
const WIN_OFF: usize = MAX_SLOTS * SLOT_SIZE + MAX_SLOTS * 0x4000;
const WIN_SIZE: usize = 256 << 10;

const MSG_READY: u64 = 1;
const MSG_SYSCALL: u64 = 2;
const MSG_TRACE_LOCAL: u64 = 5; // an in-guest-served syscall, posted only for its ptrace stops
const MSG_SECCOMP: u64 = 7; // a call to run past the guest's seccomp filters before it is served
// Set by the supervisor in the low-bit alive word (null_fds) when the thread is
// ptrace-traced: gates MSG_TRACE_LOCAL so an untraced thread posts nothing extra.
pub const WIN_TRACED: u32 = 1 << 31;
// Set beside WIN_TRACED when the thread's process has a seccomp filter: each
// call is posted for the filters' verdict (MSG_SECCOMP) before it is served.
pub const WIN_SECCOMP: u32 = 1 << 30;
const REP_RESULT: u64 = 1;
const REP_START: u64 = 3;
const AT_IGNORE: u64 = 1;
const AT_SYSINFO_EHDR: u64 = 33;
const REP_PEEK: u64 = 7; // copy guest memory into the slot window, reply MSG_HOSTRET
const REP_POKE: u64 = 8; // copy the slot window into guest memory, reply MSG_HOSTRET
const REP_THREAD_END: u64 = 11;
const REP_MAPS: u64 = 12; // list the mappings into the scratch, reply MSG_HOSTRET
const REP_ADOPT: u64 = 13; // a pooled stub moves to the slot at offset args[0]
const REP_WRITABLE: u64 = 15; // make [args[0], +args[1]) writable for the supervisor's write, reply MSG_HOSTRET: ret 1 when the guest may not write all of it, 2 when a page of it is frozen for memory another process runs (mem.makeWritable)
const REP_CODE: u64 = 23; // the service thread: serve the shared-code registry's request (mem.serveCode)
const MSG_HOSTRET: u64 = 3;
const SCRATCH_OFF: u64 = 128;
const ST_REQ: u32 = 1;
const ST_REP: u32 = 2;
const SPIN = 20000;

// LC_FAULT reports a guest fault the guest cannot handle yet (signo, address,
// pc); the supervisor ends the process as killed by that signal.
const LC_FAULT: u64 = 0x4c430022;
const LC_IDREGS: u64 = 0x4c430035; // () -> the guest ID_AA64ISAR0/1/2 in args[0..2] (arm64)
pub const SIGILL: u64 = 4;
pub const SIGTRAP: u64 = 5;
pub const SIGBUS: u64 = 7;
pub const SIGFPE: u64 = 8;
pub const SIGSEGV: u64 = 11;

pub const Chan = extern struct {
    self: u64,
    state: u32,
    null_fds: u32, // bit i: guest fd i is the run's null device (nullStdio)
    kind: u64,
    nr: u64,
    args: [6]u64,
    rip: u64,
    ret: u64,
    stub_sleep: u32,
    sup_sleep: u32,
    guest_rip: u64,
    stdio: u64,
    pinfo: u64,
};

comptime {
    std.debug.assert(@offsetOf(Chan, "guest_rip") == 104);
    std.debug.assert(@sizeOf(Chan) == 128);
}

pub const NTSTATUS = i32;
pub const HANDLE = usize;
pub const SELF: HANDLE = ~@as(usize, 0);

extern "ntdll" fn NtClose(h: HANDLE) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtMapViewOfSection(section: HANDLE, process: HANDLE, base: *usize, zero_bits: usize, commit: usize, offset: ?*i64, size: *usize, inherit: u32, alloc: u32, protect: u32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtWaitForSingleObject(h: HANDLE, alertable: u8, timeout: ?*const i64) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtSetEvent(h: HANDLE, prev: ?*i32) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn NtTerminateProcess(h: HANDLE, status: NTSTATUS) callconv(win.WINAPI) NTSTATUS;
extern "ntdll" fn RtlAddVectoredExceptionHandler(first: u32, handler: *const fn (*win.EXCEPTION_POINTERS) callconv(win.WINAPI) i32) callconv(win.WINAPI) ?*anyopaque;
extern "ntdll" fn NtAllocateVirtualMemory(proc: HANDLE, base: *usize, zero_bits: usize, size: *usize, typ: u32, prot: u32) callconv(win.WINAPI) NTSTATUS;

pub fn curSlot() usize {
    return (arch.tebLoad(SLOT_CHAN) - chan_base) / SLOT_SIZE;
}

// allocRWX reserves and commits one RWX page (for the sigreturn restorer).
pub fn allocRWX(base: *usize, size: *usize) ?usize {
    base.* = 0;
    size.* = 0x1000;
    if (NtAllocateVirtualMemory(SELF, base, 0, size, 0x3000, 0x40) < 0) return null;
    return base.*;
}

// The linker is always told to keep _tls_index; the stub has no TLS directory.
export var _tls_index: u32 = 0;

// One auto-reset event pair per channel slot: a shared pair would lose a
// wakeup when more than one guest thread waits. The supervisor wakes the stub
// thread of a slot by its evStub, the stub wakes the supervisor by its evSup.
pub const MAX_SLOTS = 256;
var ev_stub: [MAX_SLOTS]HANDLE = [_]HANDLE{0} ** MAX_SLOTS;
var ev_sup: [MAX_SLOTS]HANDLE = [_]HANDLE{0} ** MAX_SLOTS;
pub var chan_base: usize = 0;

// window is ch's slot window, in the stub.
pub fn window(ch: *Chan) u64 {
    return chan_base + WIN_OFF + slotIdx(ch) * WIN_SIZE;
}

// sigRunProcs is how many processes the run has (sandbox/lx_signal.go's
// sigRunOff, in slot 0's signal stride).
pub fn sigRunProcs() u32 {
    return @atomicLoad(u32, @as(*const u32, @ptrFromInt(chan_base + sig.AREA_OFF + 0x2000)), .acquire);
}

fn slotIdx(ch: *Chan) usize {
    return (@intFromPtr(ch) - chan_base) / SLOT_SIZE;
}

// setSlotEvents records a newly created thread's channel events (the arch half
// reads them from the slot and calls this before the thread's first exchange).
pub fn setSlotEvents(idx: usize, es: HANDLE, ep: HANDLE) void {
    ev_stub[idx] = es;
    ev_sup[idx] = ep;
}
var image_lo: usize = 0;
var image_hi: usize = 0;

pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    die(0xE00000FF);
}

pub fn die(code: u32) noreturn {
    _ = NtTerminateProcess(SELF, @bitCast(code));
    unreachable;
}

pub fn slot() *Chan {
    return @ptrFromInt(arch.tebLoad(SLOT_CHAN));
}

// exchange posts the slot to the supervisor and waits for its reply: spin,
// then sleep on this side's event once the sleep flag is visible. Waits are
// alertable so a signal APC can break them. When the post had to wake the
// supervisor, the reply is at least that wakeup away, so the spin goes on for
// about as long as wakeups take (see wait in sandbox/chan_windows.go) rather
// than sleep and need a wakeup back.
//
// The supervisor may answer with copies between guest memory and the slot
// window before its reply; those are served here and the exchange goes on.
fn exchange(ch: *Chan) void {
    while (true) {
        exchangeOnce(ch);
        switch (ch.kind) {
            REP_PEEK, REP_POKE => ch.ret = copyWin(ch),
            REP_WRITABLE => ch.ret = mem.makeWritable(ch.args[0], ch.args[1], ch),
            REP_CODE => ch.ret = mem.serveCode(ch),
            else => return,
        }
        ch.kind = MSG_HOSTRET;
    }
}

// copyWin copies args[1] bytes between guest memory at args[0] and the slot
// window at args[2]. 1 copies nothing and leaves it to the supervisor, for a
// range the stub cannot vouch for.
fn copyWin(ch: *Chan) u64 {
    const n = ch.args[1];
    const off = ch.args[2];
    if (off > WIN_SIZE or n > WIN_SIZE - off) return 1;
    const w = chan_base + WIN_OFF + slotIdx(ch) * WIN_SIZE + off;
    return if (mem.copyGuest(ch.args[0], w, n, ch.kind == REP_POKE)) 0 else 1;
}

fn exchangeOnce(ch: *Chan) void {
    const idx = slotIdx(ch);
    @atomicStore(u32, &ch.state, ST_REQ, .seq_cst);
    var woke: i64 = 0;
    if (@atomicLoad(u32, &ch.sup_sleep, .seq_cst) != 0) {
        _ = NtSetEvent(ev_sup[idx], null);
        woke = sig.nowNs();
    }
    defer if (woke != 0) noteWake(sig.nowNs() - woke);
    if (spinFor(ch)) return;
    if (woke != 0) {
        const end = woke + @min(2 * @atomicLoad(i64, &wake_ns, .monotonic), MAX_WAKE_SPIN);
        while (sig.nowNs() < end) if (spinFor(ch)) return;
    }
    while (true) {
        @atomicStore(u32, &ch.stub_sleep, 1, .seq_cst);
        if (@atomicLoad(u32, &ch.state, .seq_cst) == ST_REP) break;
        _ = NtWaitForSingleObject(ev_stub[idx], 1, null);
    }
    @atomicStore(u32, &ch.stub_sleep, 0, .seq_cst);
}

fn spinFor(ch: *Chan) bool {
    var i: u32 = 0;
    while (i < SPIN) : (i += 1) {
        if (@atomicLoad(u32, &ch.state, .seq_cst) == ST_REP) return true;
        std.atomic.spinLoopHint();
    }
    return false;
}

const MAX_WAKE_SPIN: i64 = 2 * std.time.ns_per_ms;
var wake_ns: i64 = 0;

// noteWake folds a wakeup's duration into wake_ns: down at once to a faster
// one, up slowly.
fn noteWake(d: i64) void {
    while (true) {
        const old = @atomicLoad(i64, &wake_ns, .monotonic);
        const n = if (old != 0 and d > old) old + @divTrunc(d - old, 16) else d;
        if (@cmpxchgWeak(i64, &wake_ns, old, n, .monotonic, .monotonic) == null) return;
    }
}

// handle serves guest syscall nr: in the stub when it is per thread or a
// memory call, else by the supervisor. site is the syscall's address (0 when
// a trampoline does not know it), resume_at where the guest goes on.
pub fn handle(nr: u64, args: [6]u64, site: u64, resume_at: u64) u64 {
    if (nullStdio(nr, args)) |r| return localTraced(nr, args, resume_at, r);
    if (arch.local(nr, args)) |r| return localTraced(nr, args, resume_at, r);
    if (mem.serve(nr, args)) |r| return localTraced(nr, args, resume_at, r);
    const ch = slot();
    ch.rip = site;
    ch.guest_rip = resume_at;
    ch.ret = mem.outPrefix(nr, args);
    return request(nr, args);
}

// localTraced reports a syscall the stub served in-guest to the supervisor so a
// traced thread's ptrace stops still fire for it. Untraced (the common case) it
// is a single-branch no-op. Otherwise it posts MSG_TRACE_LOCAL -- the frame is
// already published by the trampoline -- and the supervisor runs the entry and
// exit stops and replies the (possibly tracer-edited) result. The call has
// already run, so a tracer observes it and may rewrite the result but cannot
// edit the arguments or suppress it.
pub fn localTraced(nr: u64, args: [6]u64, resume_at: u64, r: u64) u64 {
    const ch = slot();
    if (ch.null_fds & WIN_TRACED == 0) return r;
    ch.kind = MSG_TRACE_LOCAL;
    ch.nr = nr;
    ch.args = args;
    ch.guest_rip = resume_at;
    ch.ret = r;
    exchange(ch);
    if (ch.kind != REP_RESULT) die(0xE0000001);
    return ch.ret;
}

// seccompCheck posts call nr for the verdict of its process's seccomp filters
// before it is served: the result when they decided it, null to serve it.
pub fn seccompCheck(nr: u64, args: [6]u64, resume_at: u64) ?u64 {
    const ch = slot();
    if (@atomicLoad(u32, &ch.null_fds, .monotonic) & WIN_SECCOMP == 0) return null;
    ch.kind = MSG_SECCOMP;
    ch.nr = nr;
    ch.args = args;
    ch.guest_rip = resume_at;
    exchange(ch);
    if (ch.kind != REP_RESULT) die(0xE0000001);
    return if (ch.args[0] != 0) ch.ret else null;
}

// nullStdio serves read, write and writev on a guest fd 0-2 that the
// supervisor marks as the run's null device (discarded stdio): a write of n
// bytes returns n, a read is end of file. The mark follows the open-file
// description, so it is gone once the fd is closed or redirected.
fn nullStdio(nr: u64, a: [6]u64) ?u64 {
    if (a[0] > 2) return null;
    const ch = slot();
    if (@atomicLoad(u32, &ch.null_fds, .monotonic) >> @intCast(a[0]) & 1 == 0) return null;
    return switch (nr) {
        arch.NR.read => 0,
        arch.NR.write => @min(a[2], mem.MAX_RW_COUNT),
        arch.NR.writev => mem.iovLen(a[1], a[2]),
        else => null,
    };
}

// scratch is this thread's slot scratch, where the supervisor puts the
// larger replies and the stub a request's larger arguments.
pub fn scratch() [*]const u8 {
    return @ptrFromInt(@intFromPtr(slot()) + SCRATCH_OFF);
}

// request posts call nr with args to the supervisor and returns its result.
pub fn request(nr: u64, args: [6]u64) u64 {
    const ch = slot();
    ch.kind = MSG_SYSCALL;
    ch.nr = nr;
    ch.args = args;
    exchange(ch);
    while (ch.kind == REP_MAPS) {
        const cap = (SLOT_SIZE - SCRATCH_OFF) / @sizeOf(mem.MapEnt);
        ch.ret = mem.maps(@ptrFromInt(@intFromPtr(ch) + SCRATCH_OFF), cap, ch.args[0], &ch.args[1]);
        ch.kind = MSG_HOSTRET;
        exchange(ch);
    }
    if (ch.kind == REP_THREAD_END) arch.endThread(0);
    if (ch.kind != REP_RESULT) die(0xE0000001);
    return ch.ret;
}

// exchangePub lets the architecture half run its own reply loop (clone's
// REP_CLONE); postReq posts without waiting (a thread's final exit notice).
pub fn exchangePub(ch: *Chan) void {
    exchange(ch);
}

pub fn postReq(ch: *Chan) void {
    @atomicStore(u32, &ch.state, ST_REQ, .seq_cst);
    if (@atomicLoad(u32, &ch.sup_sleep, .seq_cst) != 0) _ = NtSetEvent(ev_sup[slotIdx(ch)], null);
}

// ownCode reports whether pc is the stub's own.
pub fn ownCode(pc: u64) bool {
    return pc >= image_lo and pc < image_hi;
}

// fault ends the guest for a fault at pc that it has no handler for (signals
// arrive with M3); access is an access violation's kind (sig.accessKind). It
// returns false, leaving the exception to Windows, when pc is in the stub
// itself: that is a stub bug, not a guest fault.
pub fn fault(signo: u64, addr: u64, pc: u64, access: u64) bool {
    if (ownCode(pc)) return false;
    const s = if (signo == SIGSEGV and mem.pastEof(addr, access)) SIGBUS else signo;
    _ = request(LC_FAULT, .{ s, addr, pc, 0, 0, 0 });
    die(0xE0000006);
}

pub fn peb() usize {
    return arch.tebLoad(0x60);
}

// cmdArgs parses the command line: <stub path> <section> <ev_stub> <ev_sup>
// <slot offset>, in hex. Only the last four tokens are read, so the path may
// be quoted and hold spaces.
fn cmdArgs(out: *[4]usize) void {
    const params = @as(*const usize, @ptrFromInt(peb() + 0x20)).*;
    const len = @as(*const u16, @ptrFromInt(params + 0x70)).* / 2;
    const buf: [*]const u16 = @ptrFromInt(@as(*const usize, @ptrFromInt(params + 0x78)).*);
    var ntok: usize = 0;
    var in_tok = false;
    var v: usize = 0;
    var i: usize = 0;
    while (i <= len) : (i += 1) {
        const c: u16 = if (i < len) buf[i] else ' ';
        if (c == ' ') {
            if (in_tok) {
                out[0] = out[1];
                out[1] = out[2];
                out[2] = out[3];
                out[3] = v;
                ntok += 1;
                in_tok = false;
                v = 0;
            }
            continue;
        }
        in_tok = true;
        const d: usize = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => 0,
        };
        v = v *% 16 +% d;
    }
    if (ntok < 5) die(0xE0000002);
}

// claimTls marks the four TEB TLS slots as allocated in the PEB bitmap, so a
// TlsAlloc in loaded system code never hands them out.
fn claimTls() void {
    const bits: *u32 = @ptrFromInt(peb() + 0x84);
    bits.* |= 0xF8000000; // reserve TLS slots 59..63, so TlsAlloc never hands one out
}

// imageRange records the stub's own image (PEB ImageBaseAddress, SizeOfImage
// from its PE header).
fn imageRange() void {
    image_lo = @as(*const usize, @ptrFromInt(peb() + 0x10)).*;
    const nt = image_lo + @as(*const u32, @ptrFromInt(image_lo + 0x3c)).*;
    image_hi = image_lo + @as(*const u32, @ptrFromInt(nt + 0x50)).*;
}

var veh_entry: usize = 0;

// vehUnlock frees, in a fork child, the lock ntdll's exception dispatch
// takes around the vectored handler list (exclusively on Windows 11 24H2).
// Another thread of the parent may have held it at the clone, and that thread
// does not exist here: the child's first trap would wait forever. The list
// is {lock pointer, LIST_ENTRY head}; ours is its only entry, so the entry's
// Flink is the head. Nothing is changed unless that shape holds.
pub fn vehUnlock() void {
    if (veh_entry == 0) return;
    const e: [*]const usize = @ptrFromInt(veh_entry);
    const head = e[0];
    if (head == 0 or head != e[1]) return;
    const h: [*]const usize = @ptrFromInt(head);
    if (h[0] != veh_entry or h[1] != veh_entry) return;
    const lockp = @as(*const usize, @ptrFromInt(head - 8)).*;
    const near = if (lockp > head) lockp - head else head - lockp;
    if (lockp == 0 or lockp & 7 != 0 or near > 16 << 20) return;
    @atomicStore(usize, @as(*usize, @ptrFromInt(lockp)), 0, .release);
}

// forkReset gives a fork child's only thread its slot idx and the slot's
// events (inherited); the parent's other events are not the child's.
pub fn forkReset(idx: usize, es: HANDLE, ep: HANDLE) void {
    @memset(&ev_stub, 0);
    @memset(&ev_sup, 0);
    ev_stub[idx] = es;
    ev_sup[idx] = ep;
}

pub export fn wWinMainCRTStartup() callconv(win.WINAPI) noreturn {
    var h: [4]usize = undefined;
    cmdArgs(&h);
    const off = h[3];
    const idx = off / SLOT_SIZE;
    if (idx >= MAX_SLOTS) die(0xE0000002);
    ev_stub[idx] = h[1];
    ev_sup[idx] = h[2];
    imageRange();
    var base: usize = 0;
    var size: usize = 0;
    // ViewShare: a fork child keeps the channel at the same address.
    if (NtMapViewOfSection(h[0], SELF, &base, 0, 0, null, &size, 1, 0, 0x04) < 0) die(0xE0000003);
    chan_base = base;
    claimTls();
    arch.tebStore(SLOT_CHAN, base + off);
    arch.tebStore(SLOT_TP, 0);
    arch.init();
    veh_entry = @intFromPtr(RtlAddVectoredExceptionHandler(1, &arch.onException) orelse die(0xE0000004));

    var ch: *Chan = @ptrFromInt(base + off);
    var si = idx;
    while (true) {
        ch.kind = MSG_READY;
        ch.args = .{ @intFromPtr(&arch.lc_syscall_entry), base, 0, 0, 0, 0 };
        arch.readyAux(&ch.args);
        exchange(ch);
        if (ch.kind != REP_ADOPT) break;
        // A pooled stub, started ahead on a spare si, is claimed for
        // another: it takes that si's events (left in its stdio and pinfo
        // fields) and reports ready there.
        const noff = ch.args[0];
        const ni = noff / SLOT_SIZE;
        if (noff % SLOT_SIZE != 0 or ni >= MAX_SLOTS) die(0xE0000006);
        _ = NtClose(ev_stub[si]);
        _ = NtClose(ev_sup[si]);
        ev_stub[si] = 0;
        ev_sup[si] = 0;
        ch = @ptrFromInt(base + noff);
        ev_stub[ni] = ch.stdio;
        ev_sup[ni] = ch.pinfo;
        si = ni;
        arch.tebStore(SLOT_CHAN, base + noff);
    }
    if (ch.kind != REP_START) die(0xE0000005);
    // args: entry, sp, stack top, stack bottom, brk base, brk limit. The TEB
    // describes the guest stack from here on, so exception dispatch and stack
    // probes in the handlers (which run on it) see a valid stack.
    if (@hasDecl(arch, "prefaultStack")) arch.prefaultStack();
    sig.keepWinStack();
    arch.tebStore(0x08, ch.args[2]);
    arch.tebStore(0x10, ch.args[3]);
    arch.tebStore(0x1478, ch.args[3]);
    mem.init(ch.args[4], ch.args[5]);
    const entry = ch.args[0];
    const sp = ch.args[1];
    setVdso(sp, mem.mapVdso());
    if (@hasDecl(arch, "setIdregs")) {
        _ = request(LC_IDREGS, .{ 0, 0, 0, 0, 0, 0 });
        const ia = slot().args;
        arch.setIdregs(ia[0], ia[1], ia[2]);
    }
    instrcb.install(); // syscall backstop on, just before guest code runs
    arch.start(entry, si);
    arch.enter(entry, sp);
}

// setVdso puts the vDSO's address in the AT_SYSINFO_EHDR entry the supervisor
// leaves first in the auxv of the initial stack at sp.
fn setVdso(sp: u64, at: u64) void {
    if (at == 0) die(0xE0000008);
    const v: [*]u64 = @ptrFromInt(sp);
    var i: usize = v[0] + 2;
    while (v[i] != 0) : (i += 1) {}
    i += 1;
    if (v[i] == AT_SYSINFO_EHDR) v[i + 1] = at;
}
