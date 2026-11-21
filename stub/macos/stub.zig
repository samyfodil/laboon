// stub.zig — the macOS (arm64) stub process a Linux guest runs in. It is the
// Darwin counterpart of stub/csrc/stub.c: it maps the shared channel, resolves
// the os_sync primitives, applies the Seatbelt syscall-allowlist backstop,
// loads the guest ELF, rewrites every `svc #0` into a trampoline branch, and
// enters the guest. Each rewritten syscall posts over the channel to the Go
// supervisor (the hot path); an un-rewritten `svc` that reaches Darwin is
// denied by Seatbelt, as the Linux build's seccomp does.
//
// Loading happens in-stub (the guest shares this task's address space; the
// supervisor has no writable view of it until the mach_vm path lands), so the
// supervisor passes the guest ELF's host path as argv[2]. This is the shape
// proven end to end in macos/m7-run/; see macos/README.md.
//
// Unlike the freestanding Linux stub, this one links libSystem: macOS has no
// stable raw-syscall ABI and the Mach / os_sync primitives live there. Every
// libSystem call the stub makes before entering the guest must therefore be in
// the Seatbelt allowlist (see `seatbelt_profile`).

const std = @import("std");
const chan = @import("chan.zig");
const futex = @import("futex.zig");
const jit = @import("jit.zig");
const hwcap = @import("hwcap.zig");
const local = @import("local.zig");
const mem = @import("mem.zig");
const fdlink = @import("fdlink.zig");
const stdio = @import("stdio.zig");
const procinfo = @import("procinfo.zig");
const proc = @import("proc.zig");
const sbcache = @import("sbcache.zig");
const builtin = @import("builtin");
const sig = @import("sig.zig");
const tstate = @import("tstate.zig");
const life = @import("life.zig");

// Rosetta's translation of the x86-64 stub mistranslates the code at the very
// start of __text (Zig's linker metadata about it is wrong), so a trap fills
// that spot and no function starts there.
comptime {
    if (!tstate.arm64) asm (
        \\ .text
        \\ .p2align 4
        \\ .globl _lc_text_head
        \\ .no_dead_strip _lc_text_head
        \\_lc_text_head:
        \\ ud2
    );
}

// The guest syscall instruction the rewriter traps: arm64 `svc` is 4 bytes and
// is branch-rewritten to an island; x86-64 `syscall` is 2 bytes (too small for a
// branch) and is overwritten with `ud2` (0f 0b) in place, serviced from the
// SIGILL mcontext. SITE_DELTA is that instruction's length, so the resume pc
// minus it is the syscall site (for restart).
const SITE_DELTA: u64 = if (tstate.arm64) 4 else 2;
const sfork = @import("sfork.zig");
const service = @import("service.zig");
const smaps = @import("smaps.zig");

// g_chan is thread-local: each guest thread runs on its own OS thread with its
// own channel slot. A Zig thread-local rides libSystem's TLS (tpidrro_el0 on
// this Darwin), which is per-thread and separate from the guest's tpidr_el0, so
// the guest owning tpidr_el0 does not disturb it (see m15-threads/tlsprobe).
threadlocal var g_chan: *chan.Chan = undefined;
// g_exit_key is a pthread TSD slot holding a guest thread's own (libc-allocated)
// stack pointer, saved before it switches to the guest stack; 0 on the main
// thread, whose stack no joiner frees. A thread's exit runs there from its
// island on (buildExitIsland), and pthread_exit with it, never on the guest
// stack, which the guest frees as soon as it is done with it.
pub var g_exit_key: c_ulong = 0;

// g_stk_key holds the stack a thread serves the guest's syscalls on, set as
// it first enters the guest: the rest of its own, below where the guest took
// over (an exec, which enters again from deep in it, keeps it). The guest's
// stack has only the room Linux promises below its sp, which the stub's own
// frame and calls would overrun into whatever lies below it.
pub var g_stk_key: c_ulong = 0;
export var lc_stk_tsd: u64 = 0;

inline fn ownStack() void {
    if (pthread_getspecific(g_stk_key) != null) return;
    const sp = asm volatile (if (tstate.arm64) "mov %[o], sp" else "movq %%rsp, %[o]"
        : [o] "=r" (-> u64),
    );
    _ = pthread_setspecific(g_stk_key, @ptrFromInt(sp & ~@as(u64, 15)));
}

pub fn exitSp() u64 {
    return @intFromPtr(pthread_getspecific(g_exit_key));
}
// Guest thread state the stub owns end to end: a clone(CLONE_VM) child, whose
// exit ends only itself, and its CLONE_CHILD_CLEARTID / set_tid_address word,
// cleared and futex-woken on that exit so a joiner wakes.
threadlocal var g_is_thread: bool = false;
threadlocal var g_ctid: u64 = 0;
// A detached thread's last act (musl's __unmapself) unmaps the guest stack it
// runs on, which the stub's handler is running on too. That unmap is held
// here and done once exit has moved to the thread's own libc stack.
threadlocal var g_unmap: [2]u64 = .{ 0, 0 };
var g_base: [*]u8 = undefined; // channel mapping base; shared across threads
// g_tp_key is a pthread TSD slot holding the GUEST's thread pointer. musl keeps
// its thread pointer in tpidr_el0, but Darwin's kernel overwrites tpidr_el0 with
// CPU info on every context switch, so the guest's tpidr_el0 cannot survive
// scheduling. The guest's every `mrs/msr tpidr_el0` is rewritten (like a svc
// site) to read/write this slot instead. The slot is reachable from the rewrite
// islands as tpidrro_el0 + g_tp_key*8 (Darwin's pthread_getspecific fast path),
// and tpidrro_el0 IS kept per-thread by the kernel. Created once at startup.
pub var g_tp_key: c_ulong = 0;
// g_threads counts this process's live guest threads, so an exit (not
// exit_group) from the main thread while others run ends only that thread.
var g_threads = std.atomic.Value(u32).init(1);

const PAGE: u64 = tstate.page; // arm64 16 KiB; x86-64 4 KiB under Rosetta
const ET_EXEC: u16 = 2;
// LOW_TOP ends the low reserve the x86-64 stub holds for ET_EXEC programs.
const LOW_TOP: u64 = 4 << 30;
const SVC0: u32 = 0xd4000001;

// Linux arm64 syscalls and clone flags the stub serves itself.
const NR_EXIT: u64 = 93;
const NR_SET_TID_ADDRESS: u64 = 96;
const NR_FUTEX: u64 = 98;
const NR_GETTID: u64 = 178;
const NR_MUNMAP: u64 = 215;
// x86-64 arch_prctl subfunctions. On x86-64 glibc keeps its thread pointer in
// %fs, which the stub virtualizes (wrfsbase faults under Rosetta), so the stub
// serves arch_prctl itself rather than forwarding it.
const X64_ARCH_PRCTL: u64 = 158;
const X64_GETTID: u64 = 186;
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;
// NO_LOCAL is x64gen's answer for a call the stub does not serve in-guest: it
// matches no local handler, so the call forwards to the supervisor by its raw
// x86-64 number.
const NO_LOCAL: u64 = ~@as(u64, 0);
const STDIO_TRACED: u64 = 1 << 63; // the supervisor set this thread as ptrace-traced
const STDIO_SECCOMP: u64 = 1 << 61; // its process has a seccomp filter: each call is checked first
const NR_GETCPU: u64 = 168;
const STDIO_AFFINITY: u64 = 1 << 60; // its process's affinity leaves out a CPU, maybe the one it runs on: getcpu is the supervisor's
const NR_VFORK_WAIT: u64 = 0x1_0000_0001; // stub->supervisor only, not a Linux number
const NR_THREAD_GONE: u64 = 0x1_0000_0002; // a thread ended; no reply expected
const NR_FORKED: u64 = 0x1_0000_0003; // the child's host pid (0: none), right after a fork
const NR_CHILD_STOP: u64 = 0x1_0000_0004; // a traced new thread, before its first instruction
const CLONE_VFORK: u64 = 0x4000;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;
const EAGAIN: i64 = 11;

fn neg(e: i64) u64 {
    return @bitCast(-e);
}

// ---- libSystem imports (BSD + Mach + Seatbelt) --------------------------------

const kern_return_t = c_int;
const mach_port_t = c_uint;

extern "c" fn mach_task_self() mach_port_t;
extern "c" fn arc4random_buf(buf: *anyopaque, n: usize) void;

const TASK_BOOTSTRAP_PORT: c_int = 4;

extern "c" fn task_set_special_port(task: mach_port_t, which: c_int, port: mach_port_t) kern_return_t;
extern "c" fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) kern_return_t;
extern "c" var bootstrap_port: mach_port_t;

extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) ?*anyopaque;
extern "c" fn mprotect(addr: *anyopaque, len: usize, prot: c_int) c_int;
extern "c" fn munmap(addr: *anyopaque, len: usize) c_int;
extern "c" fn _exit(code: c_int) noreturn;
extern "c" fn setrlimit(res: c_int, rl: *const [2]u64) c_int;
extern "c" fn signal(sig: c_int, handler: usize) usize;
extern "c" fn pthread_create(t: *usize, attr: ?*anyopaque, start: *const fn (?*anyopaque) callconv(.C) ?*anyopaque, arg: ?*anyopaque) c_int;
extern "c" fn pthread_exit(value: ?*anyopaque) noreturn;
extern "c" fn pthread_key_create(key: *c_ulong, destructor: ?*const anyopaque) c_int;
extern "c" fn pthread_getspecific(key: c_ulong) ?*anyopaque;
extern "c" fn pthread_setspecific(key: c_ulong, value: ?*const anyopaque) c_int;
extern "c" fn pthread_sigmask(how: c_int, set: ?*const u32, old: ?*u32) c_int;
const SIG_UNBLOCK: c_int = 2;
// The Darwin signals the stub handles (install): SIGILL(4) SIGTRAP(5) SIGFPE(8)
// SIGBUS(10) SIGSEGV(11) SIGUSR1(30) SIGUSR2(31), as a sigset bitmask (bit n-1).
const stubSignals: u32 = (1 << 3) | (1 << 4) | (1 << 7) | (1 << 9) | (1 << 10) | (1 << 29) | (1 << 30);

const SIGCHLD: c_int = 20;
const SIG_IGN: usize = 1; // auto-reap exited children (no zombies) on BSD/macOS

// rawGetpid issues the Darwin getpid syscall directly: libc's getpid caches
// the pid, and the forked child reports its own to the supervisor.
fn rawGetpid() u64 {
    if (tstate.arm64) {
        return asm volatile (
            \\ mov x16, #20
            \\ svc #0x80
            : [ret] "={x0}" (-> u64),
            :
            : "x16", "memory"
        );
    } else {
        return asm volatile (
            \\ movl $0x2000014, %%eax
            \\ syscall
            : [ret] "={rax}" (-> u64),
            :
            : "rcx", "r11", "memory"
        );
    }
}

const O_RDWR: c_int = 0x0002;
const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const PROT_EXEC: c_int = 0x4;
const MAP_SHARED: c_int = 0x0001;
const MAP_PRIVATE: c_int = 0x0002;
const MAP_ANON: c_int = 0x1000;
const MAP_FIXED: c_int = 0x0010;
const MAP_FAILED: ?*anyopaque = @ptrFromInt(std.math.maxInt(usize));

// ---- Seatbelt backstop --------------------------------------------------------

// Deny-by-default. The stub reads only the run's root filesystem and its temp
// directory (the ROOT and TMP parameters, see sbcache.zig), neither forks nor
// execs (a fork child is a stub the supervisor started), signals only its own process group, the run's stubs (life.zig), and
// reaches no network, Mach service, sysctl or other process. Each BSD syscall,
// Mach trap and kernel MIG routine it issues after this point is listed (the
// MIG ones it does not call itself are libSystem's fork-child setup and the
// kernel raising the EXC_BAD_INSTRUCTION backstop); any other call, including a
// missed guest `svc` that reaches Darwin, is denied. The denial is graceful in
// a release build -- the call returns EPERM (BSD) or a Mach error and the stub
// keeps running -- so a gap in the list degrades one operation instead of
// silently killing the program; a debug build instead SIGKILLs on denial (see
// sb_kill), to surface a missed rewrite or an out-of-policy stub call loudly.
// This is the Seatbelt analog of the Linux seccomp allowlist. It bounds what
// the whole process may ask of the kernel: the guest shares this address space,
// so it can reach these same calls through the stub's own instructions -- the
// boundary is this capability set, not any property of the guest's own code.
const sb_kill = if (builtin.mode == .Debug) " (with send-signal SIGKILL)" else "";
const seatbelt_profile: [*:0]const u8 =
    \\(version 1)
    \\(deny default)
    \\(allow signal (target pgrp))
    \\(allow file-read* (subpath (param "ROOT")) (subpath (param "TMP")))
    \\(disable-syscall-inference)
    ++ "\n(deny syscall-unix" ++ sb_kill ++ ")\n" ++
    \\(allow syscall-unix
    \\  (syscall-number SYS_exit SYS_read SYS_write SYS_open SYS_close)
    \\  (syscall-number SYS_getpid SYS_recvmsg SYS_sigprocmask SYS_sigaltstack)
    \\  (syscall-number SYS_msync SYS_munmap SYS_mprotect SYS_madvise SYS_mincore)
    \\  (syscall-number SYS_kill SYS_gettimeofday SYS_readv SYS_writev SYS_pread)
    \\  (syscall-number SYS_sigreturn SYS_getrlimit SYS_mmap SYS_lseek)
    \\  (syscall-number SYS_minherit SYS_issetugid SYS___pthread_kill)
    \\  (syscall-number SYS___pthread_sigmask SYS___disable_threadsignal)
    \\  (syscall-number SYS___pthread_markcancel SYS___pthread_canceled)
    \\  (syscall-number SYS___semwait_signal SYS_fstat64 SYS_fstatat64)
    \\  (syscall-number SYS_bsdthread_create SYS_bsdthread_terminate SYS_bsdthread_register)
    \\  (syscall-number SYS_thread_selfid SYS_bsdthread_ctl SYS_read_nocancel SYS_write_nocancel)
    \\  (syscall-number SYS_open_nocancel SYS_close_nocancel SYS_recvmsg_nocancel)
    \\  (syscall-number SYS_pread_nocancel SYS_openat SYS_openat_nocancel)
    \\  (syscall-number SYS_getentropy SYS_terminate_with_payload SYS_abort_with_payload)
    \\  (syscall-number SYS_psynch_mutexwait SYS_psynch_mutexdrop SYS_psynch_cvbroad)
    \\  (syscall-number SYS_psynch_cvsignal SYS_psynch_cvwait SYS_psynch_cvclrprepost)
    \\  (syscall-number SYS_ulock_wait SYS_ulock_wake SYS_ulock_wait2)
    \\  (syscall-number SYS_fileport_makeport SYS_fileport_makefd SYS_dup2))
    ++ mach_profile;

// The Mach allowlist is per-arch. arm64 traps the guest's missed `svc` as the
// kernel's EXC_BAD_INSTRUCTION backstop and needs only the Mach calls the stub
// itself makes. x86-64 runs under Rosetta on Apple Silicon, and Rosetta's own
// exception server delivers the guest's `ud2` trap -- to do so it suspends the
// faulting thread, reads/writes its state and allocates reply ports, a set an
// arm64-tuned allowlist omits (the failure is "failed to suspend thread that
// generated exception" / "failed to allocate runtime msg port"). Allow the Mach
// layer there; the deny-default and the BSD allowlist still bound file, network,
// signal and process reach. A native x86-64 mac (no Rosetta) can later use the
// tight arm64-style list.
const mach_profile = if (tstate.arm64)
    "\n(deny syscall-mach" ++ sb_kill ++ ")\n" ++
    \\(allow syscall-mach
    \\  (machtrap-number MSC__kernelrpc_mach_vm_allocate_trap MSC__kernelrpc_mach_vm_deallocate_trap)
    \\  (machtrap-number MSC__kernelrpc_mach_vm_protect_trap MSC__kernelrpc_mach_vm_map_trap)
    \\  (machtrap-number MSC__kernelrpc_mach_port_deallocate_trap MSC__kernelrpc_mach_port_mod_refs_trap)
    \\  (machtrap-number MSC__kernelrpc_mach_port_construct_trap MSC__kernelrpc_mach_port_destruct_trap)
    \\  (machtrap-number MSC_mach_reply_port MSC_thread_self_trap MSC_task_self_trap MSC_host_self_trap)
    \\  (machtrap-number MSC_mach_msg2_trap MSC_thread_get_special_reply_port MSC_swtch_pri))
    ++ "\n(deny syscall-mig" ++ sb_kill ++ ")\n" ++
    \\(allow syscall-mig
    \\  (kernel-mig-routine mach_vm_region mach_vm_remap_external task_threads_from_user)
    \\  (kernel-mig-routine thread_get_state_to_user thread_info mach_exception_raise)
    \\  (kernel-mig-routine host_get_clock_service semaphore_create mach_ports_register)
    \\  (kernel-mig-routine mach_ports_lookup task_get_special_port_from_user task_set_special_port)
    \\  (kernel-mig-routine _mach_make_memory_entry mach_vm_map_external))
else
    \\
    \\(allow syscall-mach)
    \\(allow syscall-mig)
;

// noCore drops the core-size limit, soft and hard, to 0: a crashing stub
// never dumps the guest's memory to disk.
fn noCore() void {
    const RLIMIT_CORE: c_int = 4;
    _ = setrlimit(RLIMIT_CORE, &[2]u64{ 0, 0 });
}

// dropBootstrap gives up the task's send right to launchd: guest code could
// mach_msg it, and nothing in the stub looks up a service once sandboxed. A
// fork child's libSystem then finds no bootstrap port either.
fn dropBootstrap() void {
    _ = task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, 0);
    _ = mach_port_deallocate(mach_task_self(), bootstrap_port);
    bootstrap_port = 0;
}

// ---- Channel map --------------------------------------------------------------

// Each slot's bounce window, past the signal area: peek and poke move guest
// memory through it, up to WIN_SIZE bytes a round trip. Must match
// chan_darwin.go.
const WIN_OFF: usize = chan.SLOT_SIZE * chan.MAX_SLOTS + sig.AREA_LEN;
const WIN_SIZE: usize = 256 * 1024;
const CHAN_LEN: usize = WIN_OFF + WIN_SIZE * chan.MAX_SLOTS;

fn mapChannel(path: [*:0]const u8) [*]u8 {
    const fd = open(path, O_RDWR);
    if (fd < 0) _exit(123);
    const p = mmap(null, CHAN_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED or p == null) _exit(123);
    fdlink.close(fd);
    return @ptrCast(p.?);
}

fn slotAt(base: [*]u8, idx: usize) *chan.Chan {
    return @ptrCast(@alignCast(base + idx * chan.SLOT_SIZE));
}

// scratch returns the slot's small scratch buffer (the bytes after the header).
fn serviceMaps(out: [*]service.MapEnt, cap: usize, from: u64, next: *u64) u64 {
    return mem.maps(@ptrCast(out), cap, from, next);
}

fn memMaps(out: [*]smaps.MapEnt, cap: usize, from: u64, next: *u64) u64 {
    return mem.maps(@ptrCast(out), cap, from, next);
}

fn serviceSmaps(out: [*]smaps.SmapEnt, cap: usize, from: u64, next: *u64) u64 {
    return smaps.with(out, cap, from, next, memMaps, 0, mem.PAGE, false);
}

fn scratch(ch: *chan.Chan) [*]u8 {
    return @ptrFromInt(@intFromPtr(ch) + chan.SCRATCH_OFF);
}

// window returns the slot's peek/poke window.
fn window(ch: *chan.Chan) [*]u8 {
    return g_base + WIN_OFF + slotIndex(ch) * WIN_SIZE;
}

// ---- Trap path: handler + trampoline ------------------------------------------

// svc6 issues a raw Darwin BSD syscall. arm64 ABI: x16 = number, x0..x5 = args,
// `svc #0x80`; carry set on error with errno in x0.
fn svc6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) u64 {
    // Darwin reports a BSD syscall error by setting the carry flag with the
    // positive errno in x0/rax; Linux returns a negative errno. Negate on carry
    // so the guest (which expects the Linux convention) detects failures. The
    // errno numbering mostly matches for the calls we forward (EINVAL/ENOMEM/
    // EACCES); a full Darwin->Linux errno map is a later refinement.
    if (tstate.arm64) {
        return asm volatile (
            \\ mov x16, %[nr]
            \\ svc #0x80
            \\ b.cc 1f
            \\ neg x0, x0
            \\ 1:
            : [ret] "={x0}" (-> u64),
            : [nr] "r" (nr),
              [a0] "{x0}" (a0),
              [a1] "{x1}" (a1),
              [a2] "{x2}" (a2),
              [a3] "{x3}" (a3),
              [a4] "{x4}" (a4),
              [a5] "{x5}" (a5),
            : "x16", "cc", "memory"
        );
    } else {
        // x86-64 Darwin BSD syscall: rax = 0x2000000 | nr, args in
        // rdi/rsi/rdx/r10/r8/r9, result in rax, carry set on error.
        return asm volatile (
            \\ orq $0x2000000, %%rax
            \\ syscall
            \\ jnc 1f
            \\ negq %%rax
            \\ 1:
            : [ret] "={rax}" (-> u64),
            : [nr] "{rax}" (nr),
              [a0] "{rdi}" (a0),
              [a1] "{rsi}" (a1),
              [a2] "{rdx}" (a2),
              [a3] "{r10}" (a3),
              [a4] "{r8}" (a4),
              [a5] "{r9}" (a5),
            : "rcx", "r11", "cc", "memory"
        );
    }
}

// tramp_handler posts the trapped Linux syscall over the channel and services
// the supervisor's REP_HOST requests (a translated Darwin syscall performed
// in-stub) until it replies the final result, exactly like the Linux stub's
// lc_handle. An exit is handled by the supervisor replying REP_HOST with the
// Darwin exit syscall, which terminates the process here.
export fn tramp_handler(frame: [*]u64) callconv(.C) u64 {
    sig.enter();
    while (true) {
        const r = serveSyscall(frame);
        if (sig.afterSyscall(frame, r)) |v| return v; // null: a signal restarts it
    }
}

// serveTrap is the x86-64 equivalent of the arm64 island -> tramp_common ->
// tramp_handler path. There is no saved-register frame or island: the SIGILL
// from a rewritten `syscall` (now `ud2`) already carried the full guest context
// in the signal's mcontext. onFault calls this with that mcontext. It projects
// the registers into the arm64-shaped `frame` the dispatch reads -- args at
// 0..5, the number at 8, the resume pc at 33 -- serves the syscall, then writes
// the result into rax and advances past the 2-byte ud2.
pub fn serveTrap(mc: *std.c.mcontext_t, avx: bool) void {
    var frame = std.mem.zeroes([proc.FRAME_BYTES / 8]u64);
    frame[0] = mc.ss.rdi;
    frame[1] = mc.ss.rsi;
    frame[2] = mc.ss.rdx;
    frame[3] = mc.ss.r10;
    frame[4] = mc.ss.r8;
    frame[5] = mc.ss.r9;
    frame[8] = mc.ss.rax; // the syscall number
    frame[33] = mc.ss.rip + 2; // resume just past the ud2
    // Capture the full guest register image for the clone/fork child resume
    // paths (proc.resumeFrame/resumeIsland). XR_RIP is the resume pc, past the
    // 2-byte ud2, so the child continues after the trapped syscall.
    frame[proc.XR_RAX] = mc.ss.rax;
    frame[proc.XR_RBX] = mc.ss.rbx;
    frame[proc.XR_RCX] = mc.ss.rcx;
    frame[proc.XR_RDX] = mc.ss.rdx;
    frame[proc.XR_RSI] = mc.ss.rsi;
    frame[proc.XR_RDI] = mc.ss.rdi;
    frame[proc.XR_RBP] = mc.ss.rbp;
    frame[proc.XR_RSP] = mc.ss.rsp;
    frame[proc.XR_R8] = mc.ss.r8;
    frame[proc.XR_R9] = mc.ss.r9;
    frame[proc.XR_R10] = mc.ss.r10;
    frame[proc.XR_R11] = mc.ss.r11;
    frame[proc.XR_R12] = mc.ss.r12;
    frame[proc.XR_R13] = mc.ss.r13;
    frame[proc.XR_R14] = mc.ss.r14;
    frame[proc.XR_R15] = mc.ss.r15;
    frame[proc.XR_RIP] = mc.ss.rip + 2;
    frame[proc.XR_RFLAGS] = mc.ss.rflags;
    // FP/SSE state from fcw on is laid out as FXSAVE's; an AVX context then
    // carries 64 reserved bytes and the ymm upper halves after it.
    const fs: [*]const u8 = @ptrCast(&mc.fs);
    @memcpy(@as([*]u8, @ptrCast(&frame[proc.XR_FX]))[0..512], fs[8..520]);
    if (avx) {
        const ymmh = @sizeOf(@TypeOf(mc.fs)) + 64;
        @memcpy(@as([*]u8, @ptrCast(&frame[proc.XR_YMMH]))[0..256], fs[ymmh .. ymmh + 256]);
        frame[proc.XR_AVX] = 1;
    }
    // The signal path delivers handlers and applies sigreturn straight onto this
    // mcontext (there is no arm64 brk-trap context switch); g_sig_delivered then
    // means the mcontext already holds the handler or restored context.
    sig.g_sigmc = mc;
    sig.enter();
    while (true) {
        const r = serveSyscall(&frame);
        if (sig.g_sig_delivered) {
            sig.g_sig_delivered = false;
            return; // a sigreturn restored the interrupted context onto mc
        }
        if (sig.afterSyscall(&frame, r)) |v| {
            if (sig.g_sig_delivered) {
                sig.g_sig_delivered = false;
                return; // a signal handler was delivered onto mc
            }
            mc.ss.rax = v; // the syscall result
            mc.ss.rip = frame[33]; // resume (a restart leaves frame[33] at the site)
            return;
        }
    }
}

// localTraced reports a syscall the stub just served in-guest to the supervisor
// so a traced thread's ptrace stops still fire. Untraced (the common case) it is
// a no-op returning the result unchanged. Otherwise it publishes the entry
// registers and the result and posts MSG_TRACE_LOCAL; the supervisor runs the
// syscall-entry and -exit stops and replies the (possibly tracer-edited) result.
// The call has already run, so a tracer can observe it and rewrite its result,
// but cannot edit the arguments or suppress it.
fn localTraced(frame: [*]u64, r: u64) u64 {
    if (!tstate.arm64) return r; // x86-64 ptrace deferred (not on the startup path)
    const ch = g_chan;
    if (ch.stdio & STDIO_TRACED == 0) return r;
    sig.publishFrame(frame, frame[33]);
    ch.kind = chan.MSG_TRACE_LOCAL;
    ch.nr = frame[8];
    ch.guest_rip = frame[33] -% SITE_DELTA;
    ch.args[0] = frame[0];
    ch.args[1] = frame[1];
    ch.args[2] = frame[2];
    ch.args[3] = frame[3];
    ch.args[4] = frame[4];
    ch.args[5] = frame[5];
    ch.ret = r;
    return serveReplies(ch, frame);
}

// x64gen maps an x86-64 syscall number to the asm-generic number the stub's
// local handlers are keyed by, for the calls the stub serves in-guest (memory,
// clocks, stdio, futex, thread and process control). It is the in-stub dual of
// the supervisor's toGeneric; a call the stub does not serve maps to NO_LOCAL
// and forwards to the supervisor under its raw x86-64 number, which the
// supervisor translates (so the open-flag and legacy->at argument rewrites
// happen there, not here). A number the stub serves but x64gen misses forwards
// and ENOSYSes loudly rather than being mis-served -- the intended failure.
fn x64gen(nr: u64) u64 {
    return switch (nr) {
        0 => 63, // read
        1 => 64, // write
        17 => 67, // pread64
        18 => 68, // pwrite64
        19 => 65, // readv
        20 => 66, // writev
        295 => 69, // preadv
        296 => 70, // pwritev
        9 => 222, // mmap
        10 => 226, // mprotect
        11 => 215, // munmap
        12 => 214, // brk
        25 => 216, // mremap
        26 => 227, // msync
        27 => 232, // mincore
        28 => 233, // madvise
        149 => 228, // mlock
        150 => 229, // munlock
        151 => 230, // mlockall
        152 => 231, // munlockall
        325 => 284, // mlock2
        30 => 196, // shmat
        67 => 197, // shmdt
        35 => 101, // nanosleep
        24 => 124, // sched_yield
        219 => 128, // restart_syscall
        228 => 113, // clock_gettime
        229 => 114, // clock_getres
        230 => 115, // clock_nanosleep
        96 => 169, // gettimeofday
        318 => 278, // getrandom
        98 => 165, // getrusage
        309 => 168, // getcpu
        324 => 283, // membarrier
        281 => 22, // epoll_pwait
        232 => 22, // epoll_wait: epoll_pwait's leading arguments, measured alike
        441 => 441, // epoll_pwait2
        327 => 286, // preadv2
        202 => 98, // futex
        60 => 93, // exit
        218 => 96, // set_tid_address
        186 => 178, // gettid
        // The signal syscalls the stub serves in-guest (sig.handle): the
        // per-thread mask/altstack/pending/suspend/timedwait/return state.
        // rt_sigaction (13) is deliberately absent — it forwards to the
        // supervisor, which records the disposition, on both arches.
        131 => 132, // sigaltstack
        130 => 133, // rt_sigsuspend
        14 => 135, // rt_sigprocmask
        127 => 136, // rt_sigpending
        128 => 137, // rt_sigtimedwait
        15 => 139, // rt_sigreturn
        else => NO_LOCAL,
    };
}

// cutsFile reports whether the x86-64 call in frame may have cut a file
// short: truncate, ftruncate, or an open with O_TRUNC.
fn cutsFile(frame: [*]const u64) bool {
    const O_TRUNC: u64 = 0o1000;
    return switch (frame[8]) {
        76, 77 => true,
        2 => frame[1] & O_TRUNC != 0,
        257 => frame[2] & O_TRUNC != 0,
        else => false,
    };
}

// The guest's x86-64 %fs (and %gs) base. glibc sets %fs through arch_prctl and
// then reads its TLS as %fs:disp; the physical %fs base cannot be set under
// Rosetta (wrfsbase faults), so these hold the value the %fs-site handling
// resolves against. Per thread, like the segment base they stand in for.
pub threadlocal var g_guest_fsbase: u64 = 0;
threadlocal var g_guest_gsbase: u64 = 0;

// archPrctl serves an x86-64 arch_prctl(code, addr): it stores or returns the
// guest's virtual %fs/%gs base. frame[0] is the code, frame[1] the address.
fn archPrctl(frame: [*]u64) u64 {
    const addr = frame[1];
    switch (frame[0]) {
        ARCH_SET_FS => {
            g_guest_fsbase = addr;
            return 0;
        },
        ARCH_SET_GS => {
            g_guest_gsbase = addr;
            return 0;
        },
        ARCH_GET_FS => {
            @as(*align(1) u64, @ptrFromInt(addr)).* = g_guest_fsbase;
            return 0;
        },
        ARCH_GET_GS => {
            @as(*align(1) u64, @ptrFromInt(addr)).* = g_guest_gsbase;
            return 0;
        },
        else => return @bitCast(@as(i64, -22)), // EINVAL
    }
}

// seccompCheck posts the call in frame for the verdict of its process's
// seccomp filters before it is served: the result when they decided it, null
// to serve it.
fn seccompCheck(frame: [*]u64) ?u64 {
    const ch = g_chan;
    ch.kind = chan.MSG_SECCOMP;
    ch.nr = frame[8];
    ch.guest_rip = frame[33];
    for (0..6) |i| ch.args[i] = frame[i];
    const r = serveReplies(ch, frame);
    return if (ch.args[0] != 0) r else null;
}

fn serveSyscall(frame: [*]u64) u64 {
    if (g_chan.stdio & STDIO_SECCOMP != 0) {
        if (seccompCheck(frame)) |r| return r;
    }
    // No tpidr_el0 juggling: the guest's thread pointer lives in a TSD slot (see
    // g_tp_key), reached by the rewritten mrs/msr sites, and libSystem's own TLS
    // rides tpidrro_el0, which the kernel keeps per-thread. The physical
    // tpidr_el0 belongs entirely to Darwin here.
    // gen is the asm-generic number the local handlers key on; on arm64 the
    // guest already issues it, on x86-64 x64gen translates. frame[8] stays the
    // raw guest number, which the forward path hands the supervisor.
    const gen = if (tstate.arm64) frame[8] else x64gen(frame[8]);
    if (!tstate.arm64 and frame[8] == X64_ARCH_PRCTL) return archPrctl(frame);
    // The signal syscalls that touch only this thread's/process's signal state
    // are served in-guest on both arches (sigaltstack..rt_sigreturn); x64gen
    // maps the x86-64 numbers into this asm-generic range. rt_sigaction forwards
    // to the supervisor (it records the disposition).
    if (gen -% sig.NR_SIGALTSTACK <= sig.NR_RT_SIGRETURN - sig.NR_SIGALTSTACK) {
        if (sig.handle(gen, frame)) |r| return localTraced(frame, r);
    }
    if (gen == NR_MUNMAP and exitSp() != 0 and proc.guestSp(frame) -% frame[0] < frame[1]) {
        g_unmap = .{ frame[0], frame[1] };
        return 0;
    }
    switch (gen) {
        NR_FUTEX => return localTraced(frame, futex.handle(frame[0..6].*)),
        NR_EXIT => if (g_is_thread or g_threads.load(.seq_cst) > 1) threadExit(frame[0]),
        else => {
            if (stdio.handle(g_chan, gen, frame)) |r| return localTraced(frame, r);
            if (gen != NR_GETCPU or g_chan.stdio & STDIO_AFFINITY == 0) {
                if (local.handle(gen, frame)) |r| return localTraced(frame, r);
            }
            g_frame = frame;
            if (mem.handle(gen, frame)) |r| return localTraced(frame, r);
        },
    }
    const ch = g_chan;
    // A traced thread publishes its register frame before posting, so the
    // supervisor's syscall-entry stop and GETREGS see the guest state.
    if (tstate.arm64) {
        if (ch.stdio & STDIO_TRACED != 0) sig.publishFrame(frame, frame[33]);
    }
    ch.kind = chan.MSG_SYSCALL;
    ch.nr = frame[8]; // the raw guest number; the supervisor translates it
    if (gen == NR_SET_TID_ADDRESS) {
        // Record the clear-on-exit word here; the supervisor only supplies the
        // tid, which is what set_tid_address returns. Forward as gettid in the
        // guest's own ABI so the supervisor's translation lands on gettid.
        g_ctid = frame[0];
        ch.nr = if (tstate.arm64) NR_GETTID else X64_GETTID;
    }
    ch.guest_rip = frame[33] -% SITE_DELTA; // the syscall site is one instruction back
    ch.args[0] = frame[0];
    ch.args[1] = frame[1];
    ch.args[2] = frame[2];
    ch.args[3] = frame[3];
    ch.args[4] = frame[4];
    ch.args[5] = frame[5];
    ch.ret = mem.outPrefix(gen, frame);
    const r = serveReplies(ch, frame);
    if (!tstate.arm64 and @as(i64, @bitCast(r)) >= 0 and cutsFile(frame)) mem.refence();
    // A tracer may have edited the registers during a stop; apply them before
    // the guest resumes, overriding the syscall result in x0.
    if (tstate.arm64) {
        if (ch.stdio & STDIO_TRACED != 0 and sig.traceState().dirty != 0) return sig.traceRestore(frame);
    }
    return r;
}

// g_frame is the trap frame of the syscall this thread is serving, for
// hostCall's reply loop.
threadlocal var g_frame: [*]u64 = undefined;

// hostCall posts a supervisor service (an LC_* number) from inside the stub's
// own handling of a guest syscall, and returns its result.
pub fn hostCall(nr: u64, args: [6]u64) u64 {
    const ch = g_chan;
    ch.kind = chan.MSG_SYSCALL;
    ch.nr = nr;
    ch.guest_rip = g_frame[33] -% 4;
    ch.args = args;
    return serveReplies(ch, g_frame);
}

// serveReplies exchanges the posted request and services the supervisor's
// requests until it replies the final result.
fn serveReplies(ch: *chan.Chan, frame: [*]u64) u64 {
    while (true) {
        chan.exchange(ch);
        if (serveRequest(ch)) continue;
        switch (ch.kind) {
            chan.REP_FORK => return lcFork(ch, frame),
            chan.REP_CLONE => return lcClone(ch, frame),
            chan.REP_EXEC => return lcExec(ch), // enters the new program; returns only on E2BIG
            chan.REP_THREAD_END => threadExit(0),
            else => return ch.ret, // REP_RESULT
        }
    }
}

// serveRequest serves one supervisor request made while it holds a call --
// host calls and memory copies, such as a tracer's while the call is stopped
// -- leaving the answer in ch; it is false when ch holds anything else.
pub fn serveRequest(ch: *chan.Chan) bool {
    switch (ch.kind) {
        chan.REP_HOST => {
            // A supervisor-written code page (a shared library's text)
            // turning executable must not run stale instructions.
            if (ch.nr == DW_MPROTECT and ch.args[2] & PROT_EXEC != 0) syncCode(ch.args[0], ch.args[1]);
            ch.ret = svc6(ch.nr, ch.args[0], ch.args[1], ch.args[2], ch.args[3], ch.args[4], ch.args[5]);
            mem.wroteMaps();
            ch.kind = chan.MSG_HOSTRET;
        },
        chan.REP_PEEK => {
            // Copy args[1] bytes at guest args[0] into the slot window so
            // the supervisor can read guest memory; ret 1: the range faults.
            ch.ret = @intFromBool(!sig.copyGuest(@intFromPtr(window(ch)), ch.args[0], ch.args[1]));
            ch.kind = chan.MSG_HOSTRET;
        },
        chan.REP_POKE => {
            ch.ret = @intFromBool(!sig.copyGuest(ch.args[0], @intFromPtr(window(ch)), ch.args[1]));
            ch.kind = chan.MSG_HOSTRET;
        },
        chan.REP_REWRITE => lcRewrite(ch), // rewrite a runtime-loaded lib's sites
        chan.REP_FDSYNC => {
            ch.ret = fdlink.sync(@ptrCast(@alignCast(scratch(ch))), ch.args[0], ch.args[1], ch.args[2]);
            ch.kind = chan.MSG_HOSTRET;
        },
        chan.REP_MAPS => {
            const cap = (chan.SLOT_SIZE - chan.SCRATCH_OFF) / @sizeOf(mem.MapEnt);
            ch.ret = mem.maps(@ptrCast(@alignCast(scratch(ch))), cap, ch.args[0], &ch.args[1]);
            ch.kind = chan.MSG_HOSTRET;
        },
        chan.REP_SMAPS => {
            const cap = (chan.SLOT_SIZE - chan.SCRATCH_OFF) / @sizeOf(smaps.SmapEnt);
            ch.ret = serviceSmaps(@ptrCast(@alignCast(scratch(ch))), cap, ch.args[0], &ch.args[1]);
            ch.kind = chan.MSG_HOSTRET;
        },
        else => return false,
    }
    return true;
}

// lcFork is the parent's side of a fork. The child is not a fork() of this
// stub, in which Darwin would not keep x18, but a fresh stub the supervisor
// adopted for it, waiting on the slot it allocated (byte offset in args[0]);
// this stub sends it the guest's memory, files and state (sfork.zig) and
// returns the supervisor-assigned child pid (ch.ret) as the guest's fork()
// result. The child resumes the guest at the fork's return with 0 (forkChild).
//
// args[1..5] are the clone flags, the child stack, (unused), the TLS and the
// child-tid word. A child given its own stack resumes on it with the parent's
// registers, as Linux does; without one it returns as the trampoline would.
fn lcFork(ch: *chan.Chan, frame: [*]u64) u64 {
    const child_off = ch.args[0];
    const flags = ch.args[1];
    const cc: *chan.Chan = @ptrCast(@alignCast(g_base + child_off));
    // The guest thread pointer to carry to the child: arm64 keeps it in the
    // host TSD, x86-64 in the virtualized %fs base (g_guest_fsbase).
    const tp = if (tstate.arm64) @intFromPtr(pthread_getspecific(g_tp_key)) else g_guest_fsbase;
    const pid = sfork.parent(@intFromPtr(frame), flags, ch.args[2], ch.args[4], ch.args[5], tp);
    if (pid <= 0) {
        // No child: retire the slot the supervisor set up for it.
        cc.kind = chan.MSG_SYSCALL;
        cc.nr = NR_EXIT;
        chan.postReq(cc);
        reportForked(ch, 0);
        vforkWait(ch, flags);
        return neg(EAGAIN);
    }
    // The child's pid goes in its slot's rip (unused on Darwin) first, for a
    // supervisor that finds this process dead before the report.
    @atomicStore(u64, &cc.rip, @intCast(pid), .release);
    reportForked(ch, @intCast(pid));
    vforkWait(ch, flags);
    // The supervisor's last answer carries the child's pid, as a tracer that
    // stopped the call may have left it.
    return ch.ret;
}

// forkChild runs a pooled stub adopted as a fork child (REP_FORKCHILD): it
// takes over the guest its parent stub sends (sfork.child) on the child's
// slot, announces itself and resumes the guest at the fork's return, with 0.
fn forkChild(base: [*]u8, child_off: u64, parent_pid: u64, gpid: u64) noreturn {
    const cc: *chan.Chan = @ptrCast(@alignCast(base + child_off));
    g_chan = cc;
    const t = sfork.child(parent_pid) orelse _exit(1);
    // The parent's memory comes after the supervisor has set up the child's
    // signal records (it replies to the fork only then): bind to them now.
    sig.startThread(slotIndex(cc));
    procinfo.publish(cc);
    mem.account(slotIndex(cc));
    g_threads.store(1, .seq_cst);
    g_is_thread = false;
    g_ctid = if (t.flags & CLONE_CHILD_CLEARTID != 0) t.ctid else 0;
    // Restore the guest thread pointer where this arch keeps it: the host TSD
    // on arm64, the virtualized %fs base on x86-64 (as cloneBootstrap does).
    const gtls = if (t.flags & CLONE_SETTLS != 0) t.tls else t.tp;
    if (tstate.arm64) {
        _ = pthread_setspecific(g_tp_key, @ptrFromInt(gtls));
    } else {
        g_guest_fsbase = gtls;
    }
    cc.kind = chan.MSG_FORKED;
    cc.args[0] = rawGetpid();
    chan.exchange(cc); // supervisor records the pid and replies
    if (t.flags & CLONE_CHILD_SETTID != 0) @as(*u32, @ptrFromInt(t.ctid)).* = @truncate(gpid);
    if (tstate.arm64) sig.leaveTo(@ptrFromInt(t.frame), 0, if (t.stack != 0) t.stack else proc.guestSp(@ptrFromInt(t.frame)));
    ownStack();
    sig.enterGuest();
    if (t.stack != 0) proc.resumeFrame(@ptrFromInt(t.frame), t.stack);
    proc.resumeIsland(@ptrFromInt(t.frame));
}

// reportForked tells the supervisor the forked child's host pid, so it sees
// the child end even if that comes before the child checks in.
fn reportForked(ch: *chan.Chan, pid: u64) void {
    ch.kind = chan.MSG_SYSCALL;
    ch.nr = NR_FORKED;
    ch.args[0] = pid;
    _ = awaitReply(ch);
}

// awaitReply posts ch's request and serves the supervisor's memory requests
// (a tracer's, while the call is stopped) until its answer.
fn awaitReply(ch: *chan.Chan) u64 {
    var none = [_]u64{0} ** 34; // no fork or clone is answered here
    return serveReplies(ch, &none);
}

// vforkWait holds a CLONE_VFORK parent until the supervisor reports that the
// child has exec'd or exited (a pseudo-syscall the supervisor answers then).
fn vforkWait(ch: *chan.Chan, flags: u64) void {
    if (flags & CLONE_VFORK == 0) return;
    ch.kind = chan.MSG_SYSCALL;
    ch.nr = NR_VFORK_WAIT;
    _ = awaitReply(ch);
}

// CloneHandoff is the per-thread bootstrap block lcClone hands its new OS
// thread: where its channel slot is, the guest TLS and stack the clone call
// provided, and where the guest resumes (the instruction after the svc). It is
// heap-allocated and intentionally leaked — the thread runs the guest from it
// and never returns to free it.
const CloneHandoff = extern struct {
    slot: u64, // g_base + child slot offset
    tls: u64, // guest tpidr_el0
    ctid: u64, // CLONE_CHILD_CLEARTID word, 0 if none
    child_stack: u64, // guest sp for the new thread
    frame: [proc.FRAME_BYTES / 8]u64, // the parent's registers at the clone
};

extern "c" fn malloc(n: usize) ?*anyopaque;

// lcClone creates a guest thread. The supervisor allocated the tid (ret) and a
// channel slot, and passes the clone arguments decoded from clone or clone3:
// args = slot offset, flags, child stack, parent-tid ptr, TLS, child-tid ptr.
// A real OS thread (pthread) shares this address space; it adopts the slot as
// its thread-local g_chan, installs the guest TLS, and resumes the guest at the
// clone return on the new stack with the parent's registers and x0=0, exactly
// as Linux starts a clone child (glibc's keeps its start routine in x10/x12,
// musl's on the new stack). The parent returns the tid. The same thread also
// carries a CLONE_VM child process (vfork, posix_spawn): one given no stack
// runs on the parent's, from the guest sp at the call.
fn lcClone(ch: *chan.Chan, frame: [*]u64) u64 {
    const tid = ch.ret;
    const flags = ch.args[1];
    const h: *CloneHandoff = @ptrCast(@alignCast(malloc(@sizeOf(CloneHandoff)) orelse return cloneFailed(ch.args[0], flags, ch)));
    h.slot = @intFromPtr(g_base) + ch.args[0];
    h.tls = if (flags & CLONE_SETTLS != 0) ch.args[4] else if (tstate.arm64) @intFromPtr(pthread_getspecific(g_tp_key)) else g_guest_fsbase;
    h.child_stack = if (ch.args[2] != 0) ch.args[2] else if (tstate.arm64) proc.guestSp(frame) else frame[proc.XR_RSP];
    h.ctid = if (flags & CLONE_CHILD_CLEARTID != 0) ch.args[5] else 0;
    @memcpy(h.frame[0..], frame[0 .. proc.FRAME_BYTES / 8]);
    if (flags & CLONE_PARENT_SETTID != 0) @as(*u32, @ptrFromInt(ch.args[3])).* = @truncate(tid);
    if (flags & CLONE_CHILD_SETTID != 0) @as(*u32, @ptrFromInt(ch.args[5])).* = @truncate(tid);
    if (flags & (CLONE_VFORK | CLONE_THREAD) == CLONE_VFORK) return vforkSpawn(ch, h, tid, frame);
    const ok = spawnThread(h);
    if (ch.stdio & STDIO_TRACED == 0) return if (ok) tid else neg(EAGAIN);
    // A traced caller stops before it goes on (the clone event and syscall
    // exit), and the answer carries the result a tracer may have left.
    reportForked(ch, if (ok) tid else 0);
    return if (ok) ch.ret else neg(EAGAIN);
}



// spawnThread starts the OS thread for h. On failure it retires the slot the
// supervisor set up, as the thread's exit would.
fn spawnThread(h: *CloneHandoff) bool {
    var t: usize = 0;
    _ = g_threads.fetchAdd(1, .seq_cst);
    if (pthread_create(&t, null, cloneBootstrap, h) == 0) return true;
    _ = g_threads.fetchSub(1, .seq_cst);
    retireSlot(@ptrFromInt(h.slot));
    return false;
}

fn retireSlot(cc: *chan.Chan) void {
    cc.kind = chan.MSG_SYSCALL;
    cc.nr = NR_EXIT;
    chan.postReq(cc);
}

fn cloneFailed(child_off: u64, flags: u64, ch: *chan.Chan) u64 {
    retireSlot(@ptrCast(@alignCast(g_base + child_off)));
    if (flags & (CLONE_VFORK | CLONE_THREAD) == CLONE_VFORK) {
        vforkWait(ch, flags);
    } else if (ch.stdio & STDIO_TRACED != 0) {
        reportForked(ch, 0);
    }
    return neg(EAGAIN);
}

// A vfork child given no stack shares the parent's: it returns from the clone
// call on it and runs below the parent's sp until it execs or exits. The
// parent's trampoline frame lives below that sp too, so the parent copies
// that region aside,
// starts the child and waits on a stack of its own, and puts the region back
// once the child is done (to the guest it is dead stack, as on Linux).
const VforkPark = struct { ch: *chan.Chan, h: *CloneHandoff, lo: u64, len: u64, save: [*]u8, ok: bool };
const PARK_STACK: usize = 256 << 10;

extern "c" fn free(p: ?*anyopaque) void;

fn vforkSpawn(ch: *chan.Chan, h: *CloneHandoff, tid: u64, frame: [*]u64) u64 {
    // x86-64 serves the call on the Darwin alternate stack, so the child
    // running on the shared guest stack clobbers nothing the parent needs.
    if (!tstate.arm64) {
        const ok = spawnThread(h);
        vforkWait(ch, CLONE_VFORK);
        return if (ok) tid else neg(EAGAIN);
    }
    const top = proc.guestSp(frame);
    const stk = malloc(PARK_STACK) orelse return cloneFailed(h.slot - @intFromPtr(g_base), CLONE_VFORK, ch);
    var v = VforkPark{ .ch = ch, .h = h, .lo = 0, .len = 0, .save = undefined, .ok = false };
    v.lo = frame[98];
    v.len = top - v.lo;
    v.save = @ptrCast(malloc(v.len) orelse {
        free(stk);
        return cloneFailed(h.slot - @intFromPtr(g_base), CLONE_VFORK, ch);
    });
    @memcpy(v.save[0..v.len], @as([*]const u8, @ptrFromInt(v.lo))[0..v.len]);
    lc_call_on_stack(&v, &vforkParked, (@intFromPtr(stk) + PARK_STACK) & ~@as(usize, 15));
    free(v.save);
    free(stk);
    return if (v.ok) tid else neg(EAGAIN);
}

// lc_call_on_stack calls f(arg) on the stack whose top is sp, keeping the
// return state on that stack rather than the caller's.
extern fn lc_call_on_stack(arg: *VforkPark, f: *const fn (*VforkPark) callconv(.C) void, sp: u64) void;
comptime {
    if (tstate.arm64) asm (
        \\ .text
        \\ .p2align 2
        \\ .globl _lc_call_on_stack
        \\_lc_call_on_stack:
        \\ mov x9, sp
        \\ stp x9, x30, [x2, #-16]!
        \\ mov sp, x2
        \\ blr x1
        \\ ldp x9, x30, [sp], #16
        \\ mov sp, x9
        \\ ret
    );
}

// vforkParked runs on the parking stack: everything it needs is copied off
// the guest stack first, since the child may overwrite it.
fn vforkParked(vp: *VforkPark) callconv(.C) void {
    const v = vp.*;
    const ok = spawnThread(v.h);
    vforkWait(v.ch, CLONE_VFORK);
    @memcpy(@as([*]u8, @ptrFromInt(v.lo))[0..v.len], v.save[0..v.len]);
    vp.ok = ok;
}

// lcRewrite rewrites the svc/tpidr/ctr sites of a runtime-loaded shared
// library's executable segment, which the stub's own loader (mapElf) never saw
// -- ld-musl maps libraries with mmap, and without this their raw mrs tpidr_el0
// reads the kernel's clobbered CPU-info instead of the guest thread pointer and
// corrupts the guest (e.g. libstdc++'s thread-locals). The supervisor packs the
// site guest-addresses as u64s in the slot scratch (args[0] = count) and passes
// an island placement hint in args[1]; the segment is still writable (mem.zig
// mprotects R+X only after). Islands go in a fresh arena mmapped near the lib so
// the site's `b` reaches it. Dispatch mirrors mapElf's rewrite loop.
fn lcRewrite(ch: *chan.Chan) void {
    const count: usize = @intCast(ch.args[0]);
    ch.kind = chan.MSG_HOSTRET;
    if (count == 0) return;
    const sites: [*]const u64 = @ptrCast(@alignCast(scratch(ch)));
    var isl = Islands{ .size = rdUp(count * ISLAND_SIZE) };
    const room = mem.cur_room;
    if (room) |rm| {
        for (0..2) |a| isl.add(rm.area(a), rm.size, rm.used[a]);
    }
    var i: usize = 0;
    while (i < count) : (i += 1) rewriteSite(&isl, sites[i]);
    if (room) |rm| {
        for (0..2) |a| rm.used[a] = isl.arenas[a].used;
    }
    isl.seal();
}

// rewriteSite turns the svc, tpidr_el0 or ctr_el0 access at pc into a b to its
// island. A word that is none of them (a stray site, or data) is left as it is.
fn rewriteSite(isl: *Islands, pc: u64) void {
    if (!tstate.arm64) {
        // x86-64: the supervisor sends the guest's syscall (0f 05) site
        // addresses; overwrite each 2-byte syscall in place with ud2 (0f 0b),
        // which onFault traps and serves (serveTrap). No islands, no sysreg
        // rewrites (x86-64 TLS is arch_prctl, a serviced syscall). The rewrite
        // precedes guest execution, so no icache flush is needed.
        const u: *align(1) u16 = @ptrFromInt(pc);
        if (u.* == 0x050f) u.* = 0x0b0f;
        return;
    }
    const w: *u32 = @ptrFromInt(pc);
    const insn = w.*;
    const n = insn & 0x1f;
    const kind = insn & 0xffffffe0;
    if (insn != SVC0 and kind != MSR_TPIDR and !((kind == MRS_TPIDR or kind == MRS_CTR) and n != 31)) return;
    const at = isl.next(pc) orelse {
        // No island in reach: an svc becomes a trap, served as one (wx.zig).
        if (insn == SVC0 and @import("wx.zig").trapFile(pc)) {
            w.* = 0;
            syncCode(pc, 4);
        }
        return;
    };
    if (insn == SVC0) {
        if (loadsExit(pc)) buildExitIsland(at, pc + 4) else buildIsland(at, pc + 4);
    } else if (kind == MRS_TPIDR) {
        buildTpRead(at, pc + 4, n);
    } else if (kind == MSR_TPIDR) {
        buildTpWrite(at, pc + 4, n);
    } else {
        buildCtrRead(at, pc + 4, n);
    }
    w.* = encB(pc, at);
    syncCode(pc, 4);
}

// Islands places sites' islands in arenas within b range of each site: a site
// no arena reaches gets a new one mapped as near it as the address space has
// room, so a library wider than a b reaches is served from both its ends.
const Islands = struct {
    arenas: [16]Arena = undefined,
    n: usize = 0,
    size: u64, // of each arena it maps

    const Arena = struct { base: u64, len: u64, used: u64, mapped: bool };

    // add takes an arena the caller placed and seals (mapElf's, after the
    // image, or a mapping's room), of which used bytes are taken.
    fn add(self: *Islands, base: u64, len: u64, used: u64) void {
        self.arenas[self.n] = .{ .base = base, .len = len, .used = used, .mapped = false };
        self.n += 1;
    }

    fn next(self: *Islands, pc: u64) ?u64 {
        for (self.arenas[0..self.n]) |*a| {
            const p = a.base + a.used;
            if (a.used + ISLAND_SIZE <= a.len and inB(pc, p) and inB(p + ISLAND_SIZE, pc + 4)) {
                a.used += ISLAND_SIZE;
                return p;
            }
        }
        if (self.n == self.arenas.len) return null;
        const c = mem.freeNear(pc, self.size, B_REACH - ISLAND_SIZE) orelse return null;
        const m = mmap(@ptrFromInt(c), self.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (m == MAP_FAILED or m == null) return null;
        const b = @intFromPtr(m);
        if (!inB(pc, b) or !inB(b + ISLAND_SIZE, pc + 4)) {
            _ = munmap(m.?, self.size);
            return null;
        }
        self.arenas[self.n] = .{ .base = b, .len = self.size, .used = ISLAND_SIZE, .mapped = true };
        self.n += 1;
        return b;
    }

    // seal makes the arenas it mapped executable; the caller's are its own.
    fn seal(self: *Islands) void {
        for (self.arenas[0..self.n]) |a| {
            syncCode(a.base, a.used);
            if (a.mapped) _ = mprotect(@ptrFromInt(a.base), a.len, PROT_READ | PROT_EXEC);
        }
    }
};

const B_REACH: u64 = 1 << 27; // b's ±128 MiB

fn inB(from: u64, to: u64) bool {
    const d: i64 = @bitCast(to -% from);
    return d >= -@as(i64, B_REACH) and d < @as(i64, B_REACH);
}

// threadExit ends the calling guest thread (exit, not exit_group, from a clone
// child). The guest's joiner frees this thread's guest stack as soon as the
// clear-tid word clears, so the teardown first switches sp back to the thread's
// own libc stack (saved in cloneBootstrap) and finishes there: clear the word,
// wake its futex waiters, tell the supervisor (which retires the slot; the
// exit syscall is still posted in it), and pthread_exit. The slot is not
// touched after the post, since the supervisor may hand it to a new thread.
pub fn threadExit(code: u64) noreturn {
    // The main thread runs on the stack the stub built for the program, which
    // no joiner frees; it finishes where it is.
    const sp = exitSp();
    if (sp == 0) threadExitFinish(g_ctid, code);
    if (!tstate.arm64) {
        // Switch to this thread's own libc stack (16-align it, then call pushes
        // the return slot) and run the teardown there. ctid/code are pinned to
        // the C-ABI arg registers of threadExitFinish.
        asm volatile (
            \\ movq %%rax, %%rsp
            \\ andq $-16, %%rsp
            \\ callq *%%rdx
            :
            : [sp] "{rax}" (sp),
              [ctid] "{rdi}" (g_ctid),
              [code] "{rsi}" (code),
              [f] "{rdx}" (&threadExitFinish),
            : "memory", "cc"
        );
        unreachable;
    }
    asm volatile (
        \\ mov sp, %[sp]
        \\ mov x0, %[ctid]
        \\ mov x1, %[code]
        \\ bl %[f]
        :
        : [sp] "r" (sp),
          [ctid] "r" (g_ctid),
          [code] "r" (code),
          [f] "X" (&threadExitFinish),
        : "x0", "x1", "x30", "memory", "cc"
    );
    unreachable;
}

// deadThread ends the calling thread when its slot went dead (chan.ST_DEAD):
// its process is ending and the supervisor may already have handed the slot
// to another thread, so neither the slot nor its signal record is touched.
// A guest thread finishes on its own libc stack, as threadExit does.
pub fn deadThread() noreturn {
    const sp = exitSp();
    if (sp == 0) deadThreadFinish();
    if (!tstate.arm64) {
        asm volatile (
            \\ movq %%rax, %%rsp
            \\ andq $-16, %%rsp
            \\ callq *%%rdx
            :
            : [sp] "{rax}" (sp),
              [f] "{rdx}" (&deadThreadFinish),
            : "memory", "cc"
        );
        unreachable;
    }
    asm volatile (
        \\ mov sp, %[sp]
        \\ bl %[f]
        :
        : [sp] "r" (sp),
          [f] "X" (&deadThreadFinish),
        : "x30", "memory", "cc"
    );
    unreachable;
}

fn deadThreadFinish() callconv(.C) noreturn {
    if (g_threads.fetchSub(1, .seq_cst) == 1) _exit(0); // the last: life.zig's thread would keep the process
    pthread_exit(null);
}

fn threadExitFinish(ctid: u64, code: u64) callconv(.C) noreturn {
    if (g_unmap[1] != 0) {
        var f = std.mem.zeroes([proc.FRAME_BYTES / 8]u64);
        f[0] = g_unmap[0];
        f[1] = g_unmap[1];
        f[8] = NR_MUNMAP;
        g_frame = &f;
        _ = mem.handle(NR_MUNMAP, &f);
        g_unmap = .{ 0, 0 };
    }
    const last = g_threads.fetchSub(1, .seq_cst) == 1;
    if (ctid != 0) {
        @atomicStore(u32, @as(*u32, @ptrFromInt(ctid)), 0, .seq_cst);
        _ = futex.wake(ctid, 1); // as Linux's exit does
    }
    sig.endThread();
    const ch = g_chan;
    ch.kind = chan.MSG_SYSCALL;
    ch.nr = NR_THREAD_GONE;
    ch.args[0] = code;
    chan.postReq(ch);
    // The last guest thread (its leader exited first) ends the process, as
    // on Linux: life.zig's thread would keep it.
    if (last) _exit(@intCast(code & 0xff));
    pthread_exit(null);
}

fn cloneBootstrap(arg: ?*anyopaque) callconv(.C) ?*anyopaque {
    const h: *CloneHandoff = @ptrCast(@alignCast(arg.?));
    g_chan = @ptrFromInt(h.slot); // thread-local; also inits this thread's TLV
    procinfo.publish(g_chan);
    g_is_thread = true;
    g_ctid = h.ctid;
    jit.initThread();
    sig.startThread((h.slot - @intFromPtr(g_base)) / chan.SLOT_SIZE);
    // A clone is served inside onFault (the x86-64 syscall trap is a SIGILL),
    // so this pthread was created with the handler's mask: SIGILL blocked (plus
    // the handler sa_mask, USR1/USR2). A guest thread must have the stub's trap
    // and control signals unblocked at the host level -- the guest's own signal
    // blocking is virtual (tl.mask), separate from this -- or its ud2 syscall
    // traps (SIGILL) are never delivered. Reset to a clean host mask. arm64
    // serves the clone outside any handler, so it is unaffected.
    if (!tstate.arm64) {
        var unb: u32 = stubSignals;
        _ = pthread_sigmask(SIG_UNBLOCK, &unb, null);
    }
    // Install the guest thread pointer. On arm64 it goes in this thread's TSD
    // slot (not the physical tpidr_el0, which Darwin overwrites on every
    // reschedule); the rewritten mrs tpidr_el0 reads it back. On x86-64 it is
    // the %fs base this thread's %fs accesses resolve against (clone's
    // CLONE_SETTLS arg carried it). On Linux the kernel does this from clone.
    if (tstate.arm64) {
        _ = pthread_setspecific(g_tp_key, @ptrFromInt(h.tls));
    } else {
        g_guest_fsbase = h.tls;
    }
    // Save this pthread's own stack pointer before switching to the guest's, so
    // thread exit can return to it (see lcThreadExit). The libc stack is left
    // untouched for the thread's whole life and stays valid for pthread_exit.
    const own_sp = asm volatile (if (tstate.arm64) "mov %[o], sp" else "movq %%rsp, %[o]"
        : [o] "=r" (-> u64),
    );
    _ = pthread_setspecific(g_exit_key, @ptrFromInt(own_sp));
    if (g_chan.stdio & STDIO_TRACED != 0) {
        // A traced new thread starts stopped, as Linux's auto-attached one.
        g_chan.kind = chan.MSG_SYSCALL;
        g_chan.nr = NR_CHILD_STOP;
        _ = awaitReply(g_chan);
    }
    if (tstate.arm64) sig.leaveTo(&h.frame, 0, h.child_stack);
    ownStack();
    sig.enterGuest();
    proc.resumeFrame(&h.frame, h.child_stack);
}

// lcExec replaces this process image with a new guest program. The supervisor
// cannot write our address space (no mach_vm view), so unlike the Linux stub
// it hands us the work to do ourselves. The slot scratch holds four
// NUL-terminated host paths (main ELF, interpreter or "", main sites file,
// interpreter sites file or "") and then args[0] argv prefix strings (a #!
// script's interpreter, its argument and the script path). The rest of argv
// is the guest's own array at args[1] from index args[2], and the environment
// is the guest's envp at args[3]. The strings are copied out before the old
// image's memory is released (its brk heap, where a program often builds the
// environment it passes), as Linux copies them out of the old address space
// before tearing it down. args[4] / args[5] pack the
// uid|euid<<32 / gid|egid<<32 for the auxv. The new images map at fresh
// kernel-picked bases; the old mappings leak until the process exits, as the
// Linux path leaves them for exit to reclaim. It returns only on E2BIG, before
// anything is loaded.
fn lcExec(ch: *chan.Chan) u64 {
    const buf = scratch(ch);
    const nprefix: usize = @intCast(ch.args[0]);
    var off: usize = 0;
    const next = struct {
        fn f(b: [*]u8, o: *usize) [*:0]const u8 {
            const start = o.*;
            while (b[o.*] != 0) o.* += 1;
            o.* += 1; // skip NUL
            return @ptrCast(b + start);
        }
    }.f;
    const mainPath = next(buf, &off);
    const interpRaw = next(buf, &off);
    const mainSites = next(buf, &off);
    const interpSites = next(buf, &off);

    const gargv: ?[*]const ?[*:0]const u8 = @ptrFromInt(ch.args[1]);
    const skip: usize = @intCast(ch.args[2]);
    const genvp: ?[*]const ?[*:0]const u8 = @ptrFromInt(ch.args[3]);
    var nargv: usize = 0;
    if (gargv) |v| {
        while (v[nargv] != null) nargv += 1;
    }
    var nenv: usize = 0;
    if (genvp) |v| {
        while (v[nenv] != null) nenv += 1;
    }
    const rest = if (nargv > skip) nargv - skip else 0;
    const argc = nprefix + rest;
    const alloc = std.heap.page_allocator;
    const argv = alloc.alloc([*:0]const u8, @max(argc, 1)) catch return neg(E2BIG);
    const envp = alloc.alloc([*:0]const u8, @max(nenv, 1)) catch return neg(E2BIG);
    var total: usize = 0;
    var bytes: usize = 0;
    var i: usize = 0;
    while (i < nprefix) : (i += 1) argv[i] = next(buf, &off);
    i = 0;
    while (i < rest) : (i += 1) argv[nprefix + i] = gargv.?[skip + i].?;
    i = 0;
    while (i < nenv) : (i += 1) envp[i] = genvp.?[i].?;
    for (argv[0..argc]) |s| {
        const l = std.mem.len(s) + 1;
        if (l > MAX_ARG_STRLEN) return neg(E2BIG);
        total += l + 8;
        bytes += l;
    }
    for (envp[0..nenv]) |s| {
        const l = std.mem.len(s) + 1;
        if (l > MAX_ARG_STRLEN) return neg(E2BIG);
        total += l + 8;
        bytes += l;
    }
    if (total > ARG_MAX) return neg(E2BIG);
    const copy = alloc.alloc(u8, @max(bytes, 1)) catch return neg(E2BIG);
    var at: usize = 0;
    for ([2][][*:0]const u8{ argv[0..argc], envp[0..nenv] }) |list| {
        for (list) |*s| {
            const l = std.mem.len(s.*) + 1;
            @memcpy(copy[at..][0..l], s.*[0..l]);
            s.* = @ptrCast(copy[at..].ptr);
            at += l;
        }
    }
    var nv = argc;
    if (argc == 0) {
        // Linux runs an argv-less exec with argv = { "" }.
        argv[0] = "";
        nv = 1;
    }

    g_is_thread = false; // the exec'ing thread becomes the new image's only thread
    g_ctid = 0;
    g_threads.store(1, .seq_cst);
    proc.resetOnExec();
    mem.reset();
    g_auxids = .{ ch.args[4] & 0xffffffff, ch.args[4] >> 32, ch.args[5] & 0xffffffff, ch.args[5] >> 32 };
    const interp: ?[*:0]const u8 = if (interpRaw[0] == 0) null else interpRaw;
    if (tstate.arm64) loadAndEnter(mainPath, interp, mainSites, interpSites, argv[0..nv], envp[0..nenv]);
    // An x86-64 syscall is served inside the SIGILL handler of its trap, which
    // the new image never returns to: it goes on from the thread's own stack
    // (dead below where the guest took over), out of the handler's state.
    g_exec = .{ .path = mainPath, .interp = interp, .main_sites = mainSites, .interp_sites = interpSites, .argv = argv[0..nv], .envp = envp[0..nenv] };
    offHandler(@intFromPtr(pthread_getspecific(g_stk_key)));
}

var g_exec: struct { path: [*:0]const u8, interp: ?[*:0]const u8, main_sites: [*:0]const u8, interp_sites: [*:0]const u8, argv: []const [*:0]const u8, envp: []const [*:0]const u8 } = undefined;

fn offHandler(sp: u64) noreturn {
    if (!tstate.arm64) asm volatile (
        \\ movq %[sp], %%rsp
        \\ xorl %%ebp, %%ebp
        \\ callq *%[f]
        :
        : [sp] "r" (sp),
          [f] "r" (&execOffHandler),
        : "memory"
    );
    unreachable;
}

// execOffHandler loads g_exec once the handler's state is undone as its
// sigreturn would: the alternate signal stack is free again and the stub's
// signals are unblocked (as for a clone, cloneBootstrap), or the new image's
// first trap could never be delivered.
fn execOffHandler() callconv(.C) noreturn {
    _ = fdlink.sys(SYS_sigreturn, 0, UC_RESET_ALT_STACK, 0, 0, 0, 0);
    var unb: u32 = stubSignals;
    _ = pthread_sigmask(SIG_UNBLOCK, &unb, null);
    const e = g_exec;
    loadAndEnter(e.path, e.interp, e.main_sites, e.interp_sites, e.argv, e.envp);
}

const SYS_sigreturn: u64 = 184;
const UC_RESET_ALT_STACK: u64 = 0x80000000;

const E2BIG: i64 = 7;
const MAX_ARG_STRLEN: usize = 32 * 4096; // Linux's per-string limit
const ARG_MAX: usize = 2 << 20; // RLIMIT_STACK/4 for the 8 MiB default stack
const GUEST_STACK: u64 = 8 << 20; // the main thread's stack, as RLIMIT_STACK says

// g_auxids is the uid, euid, gid, egid the next image's auxv reports.
var g_auxids: [4]u64 = .{ 0, 0, 0, 0 };

// tramp_common is the shared thunk. Entry: sp = guest_sp-160 (the island's
// sp), [sp]=&epilogue, [sp+16]=guest x16, [sp+24]=guest x17, x17=resume, x16
// clobbered. It moves to the thread's own stack (g_stk_key), saves the full
// guest frame there, calls tramp_handler, restores every register except x0
// (the syscall result) and x16, and goes back to the island's sp and its
// epilogue, which restores x16 and x17. So nothing but the island's 160 bytes
// is written below the guest's sp, which has no more room than Linux promises
// there. tramp_common_here is an entry that keeps the frame below the island's
// sp: an exit's island is on the thread's own stack already. The arm64 Linux
// ABI preserves every register but x0 across `svc` AND restores the full user
// context, so x8 (the syscall number, which musl reuses), the condition flags
// (NZCV), FPCR/FPSR and all of q0-q31 must survive too -- libSystem's C code in
// the handler freely clobbers the flags and FP/SIMD registers, so they are
// saved and restored here. x18 (Apple-reserved) is preserved. tpidr_el0 is NOT
// touched: the guest's thread pointer lives in a TSD slot reached by rewritten
// mrs/msr sites (see g_tp_key).
//
// Frame (800 bytes): x0..x30 at 0..240; NZCV at 248; packed FPCR|FPSR<<32 at
// 256; resume at 264; q0..q31 at 272..784; the island's sp at 784.
pub extern fn tramp_common_here() callconv(.Naked) void;

pub export fn tramp_common() callconv(.Naked) void {
    // x86-64 has no island/tramp_common path: a rewritten syscall is a ud2
    // serviced from the SIGILL mcontext (serveTrap), so this symbol is unused
    // there and kept as a trap. The arm64 body saves the full guest frame.
    if (!tstate.arm64) asm volatile ("ud2") else asm volatile (
        \\ str x0, [sp, #8]          // free x0 (the island's spare slot)
        \\ adrp x0, _lc_stk_tsd@PAGE
        \\ ldr x0, [x0, _lc_stk_tsd@PAGEOFF]
        \\ mrs x16, tpidrro_el0
        \\ ldr x0, [x16, x0]         // this thread's own stack
        \\ mov x16, sp               // the island's sp
        \\ cbz x0, 2f
        \\ mov sp, x0
        \\ b 2f
        \\ .globl _tramp_common_here  // an entry already on the stack to use
        \\_tramp_common_here:
        \\ str x0, [sp, #8]
        \\ mov x16, sp
        \\2:
        \\ sub sp, sp, #800
        \\ str x16, [sp, #784]
        \\ ldr x0, [x16, #8]
        \\ stp x0,  x1,  [sp, #0]
        \\ stp x2,  x3,  [sp, #16]
        \\ stp x4,  x5,  [sp, #32]
        \\ stp x6,  x7,  [sp, #48]
        \\ stp x8,  x9,  [sp, #64]
        \\ stp x10, x11, [sp, #80]
        \\ stp x12, x13, [sp, #96]
        \\ stp x14, x15, [sp, #112]
        \\ ldr x0, [x16, #16]       // guest x16 (the island's second push)
        \\ str x0, [sp, #128]
        \\ ldr x0, [x16, #24]       // guest x17
        \\ str x0, [sp, #136]
        \\ str x17, [sp, #264]      // guest resume pc (for tramp_handler's guest_rip)
        \\ stp x18, x19, [sp, #144] // x18 preserved
        \\ stp x20, x21, [sp, #160]
        \\ stp x22, x23, [sp, #176]
        \\ stp x24, x25, [sp, #192]
        \\ stp x26, x27, [sp, #208]
        \\ stp x28, x29, [sp, #224]
        \\ str x30,      [sp, #240]
        \\ mrs x9, nzcv              // save condition flags (handler's C clobbers them)
        \\ str x9, [sp, #248]
        \\ mrs x9, fpcr             // save FPCR|FPSR packed into one 64-bit slot
        \\ mrs x10, fpsr
        \\ orr x9, x9, x10, lsl #32
        \\ str x9, [sp, #256]
        \\ stp q0,  q1,  [sp, #272] // save all of q0..q31 (libSystem uses SIMD)
        \\ stp q2,  q3,  [sp, #304]
        \\ stp q4,  q5,  [sp, #336]
        \\ stp q6,  q7,  [sp, #368]
        \\ stp q8,  q9,  [sp, #400]
        \\ stp q10, q11, [sp, #432]
        \\ stp q12, q13, [sp, #464]
        \\ stp q14, q15, [sp, #496]
        \\ stp q16, q17, [sp, #528]
        \\ stp q18, q19, [sp, #560]
        \\ stp q20, q21, [sp, #592]
        \\ stp q22, q23, [sp, #624]
        \\ stp q24, q25, [sp, #656]
        \\ stp q26, q27, [sp, #688]
        \\ stp q28, q29, [sp, #720]
        \\ stp q30, q31, [sp, #752]
        \\ adrp x9, _lc_busy_tsd@PAGE  // busy from here: a kick before this
        \\ ldr x9, [x9, _lc_busy_tsd@PAGEOFF] // leaves its signal to the syscall
        \\ mrs x10, tpidrro_el0
        \\ ldr x10, [x10, x9]
        \\ cbz x10, 1f
        \\ mov w9, #1
        \\ strb w9, [x10]
        \\1:
        \\ .globl _lc_tc_busy
        \\_lc_tc_busy:
        \\ mov x0, sp
        \\ bl _tramp_handler
        \\ str x0, [sp, #0]
        \\ ldp q0,  q1,  [sp, #272]
        \\ ldp q2,  q3,  [sp, #304]
        \\ ldp q4,  q5,  [sp, #336]
        \\ ldp q6,  q7,  [sp, #368]
        \\ ldp q8,  q9,  [sp, #400]
        \\ ldp q10, q11, [sp, #432]
        \\ ldp q12, q13, [sp, #464]
        \\ ldp q14, q15, [sp, #496]
        \\ ldp q16, q17, [sp, #528]
        \\ ldp q18, q19, [sp, #560]
        \\ ldp q20, q21, [sp, #592]
        \\ ldp q22, q23, [sp, #624]
        \\ ldp q24, q25, [sp, #656]
        \\ ldp q26, q27, [sp, #688]
        \\ ldp q28, q29, [sp, #720]
        \\ ldp q30, q31, [sp, #752]
        \\ ldr x9, [sp, #256]       // restore FPCR/FPSR
        \\ msr fpcr, x9
        \\ lsr x10, x9, #32
        \\ msr fpsr, x10
        \\ ldr x9, [sp, #248]       // restore condition flags last (loads below keep them)
        \\ msr nzcv, x9
        \\ ldr x30,      [sp, #240]
        \\ ldp x28, x29, [sp, #224]
        \\ ldp x26, x27, [sp, #208]
        \\ ldp x24, x25, [sp, #192]
        \\ ldp x22, x23, [sp, #176]
        \\ ldp x20, x21, [sp, #160]
        \\ ldp x18, x19, [sp, #144]
        \\ ldp x14, x15, [sp, #112]
        \\ ldp x12, x13, [sp, #96]
        \\ ldp x10, x11, [sp, #80]
        \\ ldp x8,  x9,  [sp, #64]  // x8 (syscall nr) preserved: Linux svc keeps it
        \\ ldp x6,  x7,  [sp, #48]
        \\ ldp x4,  x5,  [sp, #32]
        \\ ldp x2,  x3,  [sp, #16]
        \\ ldr x16, [sp, #784]      // the island's sp
        \\ ldr x17, [sp, #264]
        \\ str x17, [x16, #8]       // the resume pc, for a trap's return (lc_trap_ret)
        \\ ldp x0,  x1,  [sp, #0]   // x0 = syscall result
        \\ mov sp, x16
        \\ ldr x16, [sp]            // &per-site epilogue (the island's first push)
        \\ br  x16                  // -> epilogue; it restores guest x16/x17, pops, b resume
    );
}

pub const ISLAND_SIZE: u64 = 64; // svc islands need an entry, a per-site epilogue and 3 literals
const ISLAND_CAP: u64 = 0x80000; // room for islands after the image

// System-register encodings the stub rewrites, low 5 bits = register. See
// mapElf's dispatch.
const MRS_TPIDR: u32 = 0xd53bd040;
const MSR_TPIDR: u32 = 0xd51bd040;
const MRS_CTR: u32 = 0xd53b0020; // mrs xN, ctr_el0

// Synthetic CTR_EL0 for the guest: Apple Silicon traps the real read at EL0.
// IDC=DIC=0 forces musl's __clear_cache to do both dc cvau and ic ivau;
// DminLine=IminLine=4 => 64-byte stride, which is <= the real Apple cache line,
// so stepping by it cleans/invalidates every real line (correct, never stale).
pub const CTR_EL0_VALUE: u64 = 0x8444c004;

// encB returns `b to` encoded for an instruction placed at `from`.
// syncCode makes freshly written instructions visible to instruction fetch.
// The stub writes guest code into anonymous pages whose physical memory may
// have held another process's code a moment ago; making them executable does
// not clean the data cache or drop stale instruction-cache lines on Apple
// Silicon, so it is done explicitly before the code runs.
extern "c" fn sys_dcache_flush(start: *anyopaque, len: usize) void;
extern "c" fn sys_icache_invalidate(start: *anyopaque, len: usize) void;
fn syncCode(addr: u64, len: u64) void {
    if (len == 0) return;
    sys_dcache_flush(@ptrFromInt(addr), len);
    sys_icache_invalidate(@ptrFromInt(addr), len);
}

const DW_MPROTECT: u64 = 74;

fn encB(from: u64, to: u64) u32 {
    const off: i64 = @as(i64, @bitCast(to)) - @as(i64, @bitCast(from));
    const imm26: u32 = @intCast((@as(u64, @bitCast(off)) >> 2) & 0x03FFFFFF);
    return 0x14000000 | imm26;
}

// encLdrLit returns `ldr xRt, literal` (PC-relative) for an instruction at `from`.
fn encLdrLit(from: u64, lit: u64, rt: u32) u32 {
    const off: i64 = @as(i64, @bitCast(lit)) - @as(i64, @bitCast(from));
    const imm19: u32 = @intCast((@as(u64, @bitCast(off)) >> 2) & 0x7FFFF);
    return 0x58000000 | (imm19 << 5) | rt;
}

// buildIsland emits a svc #0 island (64 bytes): an entry that saves the guest's
// x16/x17 and hands control to tramp_common, and a per-site epilogue that
// tramp_common returns to on the island's sp. The epilogue restores
// the guest's own x16/x17 and branches back with a DIRECT `b`, so unlike a
// register-indirect return it sacrifices no guest register -- the Linux ABI
// keeps every register but x0 across svc, including x16/x17 (IP0/IP1), which an
// inlined syscall's caller may keep live. tramp_common gets the guest resume pc
// (for the handler's guest_rip) and the epilogue address through the frame.
// The 128 bytes below the guest's sp are skipped, not touched: Linux leaves
// them alone across svc (proc.ISLAND_PUSH).
//
//   0:  stp x16, x17, [sp, #-144]!     skip the gap, save guest x16/x17
//   4:  ldr x16, Lepi                  x16 = &epilogue
//   8:  str x16, [sp, #-16]!           push &epilogue (tramp_common reads it)
//   12: ldr x17, Lresume               x17 = guest resume pc
//   16: ldr x16, Lcommon               x16 = &tramp_common
//   20: br  x16
//   24: ldp x16, x17, [sp, #16]        epilogue: guest x16/x17
//   28: add sp, sp, #160               pop both pushes and the gap
//   32: nop
//   36: b   resume                     direct branch into the guest
//   40: .quad &epilogue; .quad resume; .quad &tramp_common
fn buildIsland(at: u64, resume_pc: u64) void {
    const w: [*]u32 = @ptrFromInt(at);
    w[0] = 0xa9b747f0; // stp x16, x17, [sp, #-144]!
    w[1] = encLdrLit(at + 4, at + 40, 16); // ldr x16, Lepi
    w[2] = 0xf81f0ff0; // str x16, [sp, #-16]!
    w[3] = encLdrLit(at + 12, at + 48, 17); // ldr x17, Lresume
    w[4] = encLdrLit(at + 16, at + 56, 16); // ldr x16, Lcommon
    w[5] = 0xd61f0200; // br x16
    w[6] = 0xa94147f0; // ldp x16, x17, [sp, #16]  (epilogue start = at+24)
    w[7] = 0x910283ff; // add sp, sp, #160
    w[8] = 0xd503201f; // nop
    w[9] = encB(at + 36, resume_pc); // b resume
    const q: [*]u64 = @ptrFromInt(at + 40);
    q[0] = at + 24; // Lepi = &epilogue
    q[1] = resume_pc; // Lresume (for tramp_handler's guest_rip)
    q[2] = @intFromPtr(&tramp_common); // Lcommon
}

// loadsExit reports whether the svc at pc follows `mov x8|w8, #93` (exit).
fn loadsExit(pc: u64) bool {
    if (pc & (PAGE - 1) == 0) {
        const p = mem.protAt(pc - 4) orelse return false;
        if (p & 1 == 0) return false;
    }
    const w = @as(*const u32, @ptrFromInt(pc - 4)).*;
    return w == 0xd2800ba8 or w == 0x52800ba8;
}

// buildExitIsland emits a thread exit's island: a svc island that first moves
// to the thread's own stack (g_stk_key), so not even the island touches the
// guest's stack, which may be free already (Go's exitThread says so before
// the syscall), and enters tramp_common where it is. Its x16 is lost, as an
// exit does not return. 64 bytes, as buildIsland's:
//
//   0:  mrs x16, tpidrro_el0
//   4:  ldr x16, [x16, #key*8]          this thread's own stack
//   8:  cbz x16, 16
//   12: mov sp, x16
//   16: stp x16, x17, [sp, #-144]!
//   20: adr x16, epilogue
//   24: str x16, [sp, #-16]!
//   28: adrp x17, resume
//   32: add x17, x17, :lo12:resume
//   36: ldr x16, Lcommon
//   40: br  x16
//   44: ldp x16, x17, [sp, #16]         epilogue
//   48: add sp, sp, #160
//   52: b   resume
//   56: .quad &tramp_common_here
fn buildExitIsland(at: u64, resume_pc: u64) void {
    const key: u32 = @intCast(g_stk_key);
    const w: [*]u32 = @ptrFromInt(at);
    w[0] = 0xd53bd070; // mrs x16, tpidrro_el0
    w[1] = 0xf9400210 | (key << 10); // ldr x16, [x16, #key*8]
    w[2] = 0xb4000050; // cbz x16, +8
    w[3] = 0x9100021f; // mov sp, x16
    w[4] = 0xa9b747f0; // stp x16, x17, [sp, #-144]!
    w[5] = encADR(at + 20, at + 44, 16);
    w[6] = 0xf81f0ff0; // str x16, [sp, #-16]!
    w[7] = encADRP(at + 28, resume_pc, 17);
    w[8] = 0x91000231 | @as(u32, @intCast(resume_pc & 0xfff)) << 10; // add x17, x17, #lo12
    w[9] = encLdrLit(at + 36, at + 56, 16);
    w[10] = 0xd61f0200; // br x16
    w[11] = 0xa94147f0; // ldp x16, x17, [sp, #16]
    w[12] = 0x910283ff; // add sp, sp, #160
    w[13] = encB(at + 52, resume_pc);
    @as(*u64, @ptrFromInt(at + 56)).* = @intFromPtr(&tramp_common_here);
}

fn encADR(from: u64, to: u64, rd: u32) u32 {
    const off: u32 = @truncate(to -% from);
    return 0x10000000 | (off & 3) << 29 | (off >> 2 & 0x7ffff) << 5 | rd;
}

fn encADRP(from: u64, to: u64, rd: u32) u32 {
    const off: u32 = @truncate((to >> 12) -% (from >> 12));
    return 0x90000000 | (off & 3) << 29 | (off >> 2 & 0x7ffff) << 5 | rd;
}

// buildTpRead emits an island for `mrs xN, tpidr_el0`: load the guest thread
// pointer from this thread's TSD slot (tpidrro_el0 + g_tp_key*8) into xN, then
// branch back. Clobbers only xN (which the mrs overwrites) and no flags.
fn buildTpRead(at: u64, resume_pc: u64, n: u32) void {
    const key: u32 = @intCast(g_tp_key);
    const w: [*]u32 = @ptrFromInt(at);
    w[0] = 0xd53bd060 | n; // mrs xN, tpidrro_el0  (TSD base)
    w[1] = 0xf9400000 | (key << 10) | (n << 5) | n; // ldr xN, [xN, #key*8]
    w[2] = encB(at + 8, resume_pc); // b resume
}

// buildCtrRead emits an island for `mrs xN, ctr_el0`: load the synthetic
// CTR_EL0 value into xN, then branch back. Clobbers only xN (which the mrs
// overwrites) and no flags.
fn buildCtrRead(at: u64, resume_pc: u64, n: u32) void {
    const w: [*]u32 = @ptrFromInt(at);
    w[0] = encLdrLit(at, at + 8, n); // ldr xN, Lctr
    w[1] = encB(at + 4, resume_pc); // b resume
    const q: [*]u64 = @ptrFromInt(at + 8);
    q[0] = CTR_EL0_VALUE;
}

// buildTpWrite emits an island for `msr tpidr_el0, xN`: store xN into this
// thread's TSD slot, then branch back. Uses one scratch register (!= xN) saved
// and restored on the stack past the 128 bytes below sp Linux leaves alone, so
// it preserves every guest register, flags and that memory.
fn buildTpWrite(at: u64, resume_pc: u64, n: u32) void {
    const key: u32 = @intCast(g_tp_key);
    const s: u32 = if (n == 16) 17 else 16; // scratch, distinct from xN
    const w: [*]u32 = @ptrFromInt(at);
    w[0] = 0xf8170fe0 | s; // str xS, [sp, #-144]!
    w[1] = 0xd53bd060 | s; // mrs xS, tpidrro_el0  (TSD base)
    w[2] = 0xf9000000 | (key << 10) | (s << 5) | n; // str xN, [xS, #key*8]
    w[3] = 0xf84907e0 | s; // ldr xS, [sp], #144
    w[4] = encB(at + 16, resume_pc); // b resume
}

// buildRestorer emits the sigreturn trampoline a handler registered without
// SA_RESTORER returns to (Linux's vDSO __kernel_rt_sigreturn): mov x8, #139
// and a rewritten svc.
// slotIndex is the channel slot number of ch.
fn slotIndex(ch: *chan.Chan) usize {
    return (@intFromPtr(ch) - @intFromPtr(g_base)) / chan.SLOT_SIZE;
}

fn buildRestorer() u64 {
    const p = mmap(@ptrFromInt(mem.GUEST_BASE), PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) orelse _exit(5);
    if (p == MAP_FAILED) _exit(5);
    const at: u64 = @intFromPtr(p);
    const w: [*]u32 = @ptrFromInt(at);
    w[0] = 0xd2801168; // movz x8, #139
    w[1] = encB(at + 4, at + 64);
    buildIsland(at + 64, at + 8);
    syncCode(at, PAGE);
    if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0) _exit(5);
    return at;
}

// ---- ELF load -----------------------------------------------------------------

fn rdDown(x: u64) u64 {
    return x & ~(PAGE - 1);
}
fn rdUp(x: u64) u64 {
    return (x + PAGE - 1) & ~(PAGE - 1);
}
// Linux auxv entry types the guest's libc/start reads.
const AT_NULL = 0;
const AT_PHDR = 3;
const AT_PHENT = 4;
const AT_PHNUM = 5;
const AT_PAGESZ = 6;
const AT_BASE = 7;
const AT_FLAGS = 8;
const AT_ENTRY = 9;
const AT_UID = 11;
const AT_EUID = 12;
const AT_GID = 13;
const AT_EGID = 14;
const AT_PLATFORM = 15;
const AT_HWCAP = 16;
const AT_CLKTCK = 17;
const AT_IGNORE = 1;
const AT_SECURE = 23;
const AT_SYSINFO_EHDR = 33;
const AT_RANDOM = 25;
const AT_HWCAP2 = 26;
const AT_EXECFN = 31;

// buildInitStack lays out the Linux arm64 process-entry stack at the top of the
// guest stack region and returns sp (pointing at argc). Layout, growing down:
// the string/aux-data area (argv/env strings, 16 random bytes) sits at the very
// top; below it, 16-aligned, the vector argc / argv.. NULL / envp.. NULL / auxv
// pairs / AT_NULL. A real libc/Zig _start reads exactly this. argv and env are
// the guest-visible vectors passed by the supervisor (argv over the stub's own
// argv tail, env over the stub's environment). atBase is AT_BASE: 0 for a
// static executable, the dynamic linker's load base when one is present, so the
// interpreter can find itself. phdrAddr/phent/phnum are the MAIN program's
// headers and entry is its entry point (where the interpreter hands off).
fn buildInitStack(stkBase: u64, stkSize: u64, argv: []const [*:0]const u8, envp: []const [*:0]const u8, phdrAddr: u64, phent: u64, phnum: u64, entry: u64, atBase: u64, vdso: u64) u64 {
    var top = stkBase + stkSize;

    // String area at the top, laid out as Linux does: argv strings ascending
    // from argv[0], then the env strings, then an 8-byte zero end marker.
    // Programs depend on argv being one contiguous ascending block (libuv
    // sizes process.title's buffer as argv[argc-1] + len - argv[0]).
    const nargv = argv.len;
    const nenv = envp.len;
    const argvAddr = std.heap.page_allocator.alloc(u64, nargv + 1) catch _exit(7);
    const envAddr = std.heap.page_allocator.alloc(u64, nenv + 1) catch _exit(7);
    defer std.heap.page_allocator.free(argvAddr);
    defer std.heap.page_allocator.free(envAddr);
    var total: u64 = 0;
    for (argv) |s| total += std.mem.len(s) + 1;
    for (envp) |s| total += std.mem.len(s) + 1;
    top -= 8;
    @as(*u64, @ptrFromInt(top)).* = 0;
    top -= total;
    var p = top;
    for (argv, 0..) |s, si| {
        const l = std.mem.len(s) + 1;
        @memcpy(@as([*]u8, @ptrFromInt(p))[0..l], s[0..l]);
        argvAddr[si] = p;
        p += l;
    }
    for (envp, 0..) |s, si| {
        const l = std.mem.len(s) + 1;
        @memcpy(@as([*]u8, @ptrFromInt(p))[0..l], s[0..l]);
        envAddr[si] = p;
        p += l;
    }
    top &= ~@as(u64, 15);

    top -= 16;
    const randAddr = top;
    arc4random_buf(@ptrFromInt(randAddr), 16);
    const execfn = if (nargv > 0) argvAddr[0] else randAddr;

    const aux = [_][2]u64{
        .{ if (vdso != 0) AT_SYSINFO_EHDR else AT_IGNORE, vdso },
        .{ AT_PHDR, phdrAddr },
        .{ AT_PHENT, phent },
        .{ AT_PHNUM, phnum },
        .{ AT_PAGESZ, PAGE }, // Darwin 16 KiB pages: tell the guest the truth so
        //                       its mmap/mprotect align to what the kernel enforces
        .{ AT_BASE, atBase },
        .{ AT_FLAGS, 0 },
        .{ AT_ENTRY, entry },
        .{ AT_UID, g_auxids[0] },
        .{ AT_EUID, g_auxids[1] },
        .{ AT_GID, g_auxids[2] },
        .{ AT_EGID, g_auxids[3] },
        .{ AT_HWCAP, hwcap.hwcap[0] },
        .{ AT_HWCAP2, hwcap.hwcap[1] },
        .{ AT_CLKTCK, 100 },
        .{ AT_SECURE, @intFromBool(g_auxids[0] != g_auxids[1] or g_auxids[2] != g_auxids[3]) },
        .{ AT_RANDOM, randAddr },
        .{ AT_EXECFN, execfn },
        .{ AT_NULL, 0 },
    };
    // argc + argv[]+NULL + env[]+NULL + auxv pairs.
    const words = 1 + (nargv + 1) + (nenv + 1) + aux.len * 2;
    const sp = (top - words * 8) & ~@as(u64, 15); // argc must be 16-aligned

    const v: [*]u64 = @ptrFromInt(sp);
    var i: usize = 0;
    v[i] = nargv;
    i += 1;
    for (0..nargv) |j| {
        v[i] = argvAddr[j];
        i += 1;
    }
    v[i] = 0; // argv NULL
    i += 1;
    for (0..nenv) |j| {
        v[i] = envAddr[j];
        i += 1;
    }
    v[i] = 0; // envp NULL
    i += 1;
    for (aux) |pair| {
        v[i] = pair[0];
        i += 1;
        v[i] = pair[1];
        i += 1;
    }
    return sp;
}

fn rd16(d: []const u8, o: usize) u16 {
    return std.mem.readInt(u16, d[o..][0..2], .little);
}
fn rd32(d: []const u8, o: usize) u32 {
    return std.mem.readInt(u32, d[o..][0..4], .little);
}
fn rd64(d: []const u8, o: usize) u64 {
    return std.mem.readInt(u64, d[o..][0..8], .little);
}

// Image is one mapped ELF: its load bias (base), runtime entry, and the
// runtime address + shape of its program headers (for AT_PHDR of the main
// program; unused for the interpreter).
const Image = struct {
    base: u64, // load bias: mapped_base - minbase (AT_BASE for an interpreter)
    entry: u64,
    phdr: u64,
    phent: u64,
    phnum: u64,
    lo: u64 = 0, // the mapped image (without its island area)
    hi: u64 = 0,
    exec: bool = false, // ET_EXEC: at its link address
};

// ElfSrc is where mapElf reads an image from: a file, or memory (the vDSO).
const ElfSrc = union(enum) {
    file: std.fs.File,
    mem: []const u8,

    fn read(s: ElfSrc, buf: []u8, off: u64) usize {
        switch (s) {
            .file => |f| return f.preadAll(buf, off) catch _exit(3),
            .mem => |m| {
                if (off >= m.len) return 0;
                const n = @min(buf.len, m.len - off);
                @memcpy(buf[0..n], m[@intCast(off)..][0..n]);
                return n;
            },
        }
    }
};

// mapElf maps one ELF (static exe, PIE, or dynamic linker) into its own region
// (image + island area), maps PT_LOAD segments from the file copy-on-write (a
// segment whose file offset is not congruent with its address is read in
// instead), rewrites the supervisor's
// `svc #0` sites into branches to freshly built islands, applies per-segment
// W^X, and returns its Image. ET_DYN binaries have minbase 0, so the load bias
// equals the kernel-picked base. Each site is an offset (vaddr - minbase) found
// by the Go recursive-descent rewriter, so a 0xd4000001 data word is never
// patched; only words that really are svc #0 are rewritten (guarded below).
fn mapElf(src: ElfSrc, sites: []const u32, hint: u64) Image {
    var isl: Islands = undefined;
    return loadElf(src, sites, hint, false, &isl) orelse _exit(5);
}

// loadElf maps the image src at hint, or exactly there when fixed, its sites
// rewritten; isl is left holding its islands' arenas. Its islands go after
// the image, or, when fixed, in arenas mapped near it.
fn loadElf(src: ElfSrc, sites: []const u32, hint: u64, fixed: bool, isl: *Islands) ?Image {
    // Read the headers only; segments are read straight into place below.
    var eh: [64]u8 = undefined;
    if (src.read(&eh, 0) != eh.len) _exit(3);
    const hdrLen: usize = @intCast(rd64(&eh, 32) + @as(u64, rd16(&eh, 54)) * rd16(&eh, 56));
    const d = std.heap.page_allocator.alloc(u8, @max(hdrLen, eh.len)) catch _exit(3);
    defer std.heap.page_allocator.free(d);
    if (src.read(d, 0) != d.len) _exit(3);
    const e_entry = rd64(d, 24);
    const e_phoff = rd64(d, 32);
    const e_phentsize = rd16(d, 54);
    const e_phnum = rd16(d, 56);

    var minbase: u64 = std.math.maxInt(u64);
    var maxend: u64 = 0;
    var i: u16 = 0;
    while (i < e_phnum) : (i += 1) {
        const ph = e_phoff + @as(u64, i) * e_phentsize;
        if (rd32(d, @intCast(ph)) != 1) continue; // PT_LOAD
        const p_vaddr = rd64(d, @intCast(ph + 16));
        const p_memsz = rd64(d, @intCast(ph + 40));
        if (rdDown(p_vaddr) < minbase) minbase = rdDown(p_vaddr);
        if (rdUp(p_vaddr + p_memsz) > maxend) maxend = rdUp(p_vaddr + p_memsz);
    }
    if (minbase == std.math.maxInt(u64)) _exit(4);
    const imageLen = maxend - minbase;

    // An ET_EXEC goes where it is linked: replacing the low reserve the
    // x86-64 stub keeps for it (sandbox patchStub), elsewhere only if free.
    const exec = rd16(d, 16) == ET_EXEC;
    const low = exec and maxend <= LOW_TOP;
    const near = fixed or low;
    const tail: u64 = if (near) 0 else ISLAND_CAP;
    const at = if (exec) minbase else if (hint == 0 and !fixed) mem.pickFree(imageLen + tail) else hint;
    const rp = mmap(@ptrFromInt(at), imageLen + tail, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | (if (near) MAP_FIXED else 0), -1, 0);
    if (rp == null or rp == MAP_FAILED) return null;
    const rb: u64 = @intFromPtr(rp);
    if (exec and rb != minbase) {
        _ = munmap(rp.?, imageLen + tail);
        return null;
    }
    mem.noteImage(rb, rb + imageLen + tail);
    const region: [*]u8 = @ptrCast(rp);
    const bias = rb - minbase;

    // Copy segments (region is R+W here).
    i = 0;
    while (i < e_phnum) : (i += 1) {
        const ph = e_phoff + @as(u64, i) * e_phentsize;
        if (rd32(d, @intCast(ph)) != 1) continue;
        const p_off = rd64(d, @intCast(ph + 8));
        const p_vaddr = rd64(d, @intCast(ph + 16));
        const p_filesz = rd64(d, @intCast(ph + 32));
        const dst = bias + p_vaddr;
        if (p_filesz == 0) continue;
        if (src == .file and p_vaddr % PAGE == p_off % PAGE) {
            const lo = rdDown(dst);
            const end = dst + p_filesz;
            const m = mmap(@ptrFromInt(lo), rdUp(end) - lo, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, src.file.handle, @intCast(rdDown(p_off)));
            if (m == MAP_FAILED or m == null) _exit(3);
            const p_memsz = rd64(d, @intCast(ph + 40));
            if (p_memsz > p_filesz and end % PAGE != 0) @memset(region[end - rb ..][0..@intCast(rdUp(end) - end)], 0);
            continue;
        }
        // A non-congruent segment is read in rather than mapped. An earlier
        // congruent segment's mmap, whose length rounds up to Darwin's 16 KiB
        // page, can leave this segment's first page file-backed by the same fd
        // (the ELF's 4 KiB segments straddle the coarser page). preadAll copies
        // straight into place, and a copyout that faults such a page deadlocks:
        // the read holds the file's vnode lock while servicing the fault needs
        // it. Read into a heap buffer, then copy in, where the COW fault is
        // serviced normally (the read lock is already released).
        const seg = region[dst - rb ..][0..@intCast(p_filesz)];
        const tmp = std.heap.page_allocator.alloc(u8, seg.len) catch _exit(3);
        if (src.read(tmp, p_off) != tmp.len) _exit(3);
        @memcpy(seg, tmp);
        std.heap.page_allocator.free(tmp);
        if (rd32(d, @intCast(ph + 4)) & 1 != 0) syncCode(dst, p_filesz);
    }
    const entry = bias + e_entry;

    // Rewrite each supervisor-supplied site into a `B island`. A site is an
    // offset from minbase, so the instruction is at rb + site. The supervisor
    // sends svc #0 sites and tpidr_el0 access sites in one list; dispatch on the
    // actual instruction word so a stray offset (or data) is never patched.
    // The islands go after the image, and for an image wider than a b reaches,
    // in arenas near its far sites too (Islands).
    isl.* = Islands{ .size = ISLAND_CAP };
    if (!near) isl.add(rb + imageLen, ISLAND_CAP, 0);
    for (sites) |s| rewriteSite(isl, rb + s);
    isl.seal();

    // Per-page W^X. Each 16 KiB Darwin page gets the union of the flags of every
    // PT_LOAD overlapping it, so a page two segments share -- e.g. the end of
    // .text and the start of .rodata, only 4 KiB apart in a static-PIE glibc
    // guest -- keeps every permission either needs, exec included. Darwin's
    // 16 KiB pages are coarser than the ELF's 4 KiB segment alignment, so this
    // straddle is normal; protecting segments independently let a later r--
    // segment drop exec from the shared page (then a never-yet-run instruction
    // there, like _fini at exit, faulted -- only once the process had threads,
    // as Rosetta tolerates running a non-exec page single-threaded). The island
    // area after the image is R+X.
    const npages: usize = @intCast(imageLen / PAGE);
    const protmap = std.heap.page_allocator.alloc(u8, npages) catch _exit(6);
    defer std.heap.page_allocator.free(protmap);
    @memset(protmap, 0);
    i = 0;
    while (i < e_phnum) : (i += 1) {
        const ph = e_phoff + @as(u64, i) * e_phentsize;
        if (rd32(d, @intCast(ph)) != 1) continue;
        const p_flags = rd32(d, @intCast(ph + 4));
        const p_vaddr = rd64(d, @intCast(ph + 16));
        const p_memsz = rd64(d, @intCast(ph + 40));
        var prot: u8 = @intCast(PROT_READ);
        if (p_flags & 1 != 0) prot |= @intCast(PROT_EXEC);
        if (p_flags & 2 != 0) prot |= @intCast(PROT_WRITE);
        var pg: usize = @intCast((rdDown(p_vaddr) - minbase) / PAGE);
        const pgEnd: usize = @intCast((rdUp(p_vaddr + p_memsz) - minbase) / PAGE);
        while (pg < pgEnd) : (pg += 1) protmap[pg] |= prot;
    }
    var pg: usize = 0;
    while (pg < npages) {
        if (protmap[pg] == 0) {
            pg += 1;
            continue; // a gap between segments: left R+W, as the initial mmap
        }
        var run = pg + 1;
        while (run < npages and protmap[run] == protmap[pg]) run += 1;
        if (mprotect(@ptrFromInt(rb + pg * PAGE), (run - pg) * PAGE, @intCast(protmap[pg])) != 0) _exit(6);
        pg = run;
    }
    if (!near and mprotect(@ptrFromInt(rb + imageLen), ISLAND_CAP, PROT_READ | PROT_EXEC) != 0) _exit(6);

    // AT_PHDR: prefer an explicit PT_PHDR, else the first PT_LOAD spanning e_phoff.
    var phdrAddr: u64 = 0;
    i = 0;
    while (i < e_phnum) : (i += 1) {
        const ph = e_phoff + @as(u64, i) * e_phentsize;
        if (rd32(d, @intCast(ph)) == 6) { // PT_PHDR
            phdrAddr = bias + rd64(d, @intCast(ph + 16));
            break;
        }
    }
    if (phdrAddr == 0) {
        i = 0;
        while (i < e_phnum) : (i += 1) {
            const ph = e_phoff + @as(u64, i) * e_phentsize;
            if (rd32(d, @intCast(ph)) != 1) continue;
            const p_off = rd64(d, @intCast(ph + 8));
            const p_filesz = rd64(d, @intCast(ph + 32));
            if (e_phoff >= p_off and e_phoff < p_off + p_filesz) {
                phdrAddr = bias + rd64(d, @intCast(ph + 16)) + (e_phoff - p_off);
                break;
            }
        }
    }

    return .{ .base = bias, .entry = entry, .phdr = phdrAddr, .phent = e_phentsize, .phnum = e_phnum, .lo = rb, .hi = rb + imageLen, .exec = exec };
}

// loadAndEnter maps the main guest ELF and, when interpPath is given (the ELF
// has a PT_INTERP), the dynamic linker as a second image; it builds the init
// stack and jumps to the interpreter's entry (static: the program's entry).
// For the dynamic case AT_BASE is the interpreter's load base, AT_PHDR/ENTRY
// stay the main program's: the interpreter relocates everything and hands off.
fn readSites(path: [*:0]const u8) []const u32 {
    const bytes = std.fs.cwd().readFileAlloc(std.heap.page_allocator, std.mem.span(path), 1 << 24) catch _exit(9);
    const n = bytes.len / 4;
    const p: [*]const u32 = @ptrCast(@alignCast(bytes.ptr));
    return p[0..n];
}

fn loadAndEnter(path: [*:0]const u8, interpPath: ?[*:0]const u8, mainSites: [*:0]const u8, interpSites: [*:0]const u8, argv: []const [*:0]const u8, envp: []const [*:0]const u8) noreturn {
    procinfo.publish(g_chan);
    mem.drawLayout(g_chan.flags);
    const mf = std.fs.cwd().openFileZ(path, .{}) catch _exit(3);
    // A program with an interpreter goes at ELF_ET_DYN_BASE, one without in
    // the mmap area, as Linux loads them.
    const main_img = mapElf(.{ .file = mf }, readSites(mainSites), if (interpPath != null) mem.hint_exe else 0);
    mf.close();
    mem.placeBreak(if (main_img.exec) main_img.hi else if (interpPath != null) main_img.hi + ISLAND_CAP else mem.ET_DYN_BASE);

    var enter = main_img.entry;
    var atBase: u64 = 0;
    procinfo.info = .{ .sp = 0, .main_lo = main_img.lo, .main_hi = main_img.hi, .interp_lo = 0, .interp_hi = 0, .stack_lo = 0, .stack_hi = 0 };
    if (interpPath) |ip| {
        const fi = std.fs.cwd().openFileZ(ip, .{}) catch _exit(8);
        const interp = mapElf(.{ .file = fi }, readSites(interpSites), 0);
        fi.close();
        enter = interp.entry;
        atBase = interp.base;
        procinfo.info.interp_lo = interp.lo;
        procinfo.info.interp_hi = interp.hi;
    }

    var vdso: u64 = 0;
    if (vdsoImage()) |v| {
        const img = loadElf(.{ .mem = v.img }, v.sites, 0, false, &vdso_isl) orelse _exit(5);
        mem.noteVdso(img.lo, img.hi);
        vdso = img.lo;
    }

    const stk_at = mem.mapStack(GUEST_STACK);
    if (stk_at >= std.math.maxInt(u64) - 4095) _exit(7);
    const stk: *anyopaque = @ptrFromInt(stk_at);
    const sp = buildInitStack(@intFromPtr(stk), GUEST_STACK, argv, envp, main_img.phdr, main_img.phent, main_img.phnum, main_img.entry, atBase, vdso);
    procinfo.info.sp = sp;
    procinfo.info.stack_lo = @intFromPtr(stk);
    procinfo.info.stack_hi = @intFromPtr(stk) + GUEST_STACK;
    mem.account(slotIndex(g_chan));
    if (g_chan.stdio & STDIO_TRACED != 0) {
        // A traced exec stops at the new image before its first instruction
        // (the ptrace exec-event stop); a tracer may read memory meanwhile.
        const ch = g_chan;
        ch.kind = chan.MSG_SYSCALL;
        ch.nr = LC_EXEC_STOP;
        ch.args = .{ enter, sp, 0, 0, 0, 0 };
        _ = awaitReply(ch);
    }
    enterGuest(enter, sp);
}

const LC_EXEC_STOP: u64 = 0x4c430018; // sandbox/lx_signal.go lxExecStop

// vdsoImage is this guest architecture's vDSO and the syscall sites the
// rewriter found in it, which the supervisor publishes in the run's shared
// region (sandbox/vdso_darwin.go): a record of the image's length, the site
// count, up to VDSO_SITES sites, then the image.
const VDSO_REC: usize = 0xf00;
const VDSO_SITES: usize = 16;

// vdso_isl holds the arenas of the vDSO's islands.
var vdso_isl: Islands = .{ .size = ISLAND_CAP };

// remapVdso maps the vDSO afresh at [dst, dst+n), over what is there, for an
// mremap that moves it: its sites branch to islands near where it was, which
// go with the old copy.
pub fn remapVdso(dst: u64, n: u64) bool {
    const v = vdsoImage() orelse return false;
    var isl: Islands = undefined;
    const img = loadElf(.{ .mem = v.img }, v.sites, dst, true, &isl) orelse return false;
    if (img.lo != dst or img.hi != dst + n) {
        _ = munmap(@ptrFromInt(img.lo), img.hi - img.lo);
        return false;
    }
    for (vdso_isl.arenas[0..vdso_isl.n]) |a| _ = munmap(@ptrFromInt(a.base), a.len);
    vdso_isl = isl;
    return true;
}

fn vdsoImage() ?struct { img: []const u8, sites: []const u32 } {
    const r: [*]const u8 = sig.runRegion() + 0x100 + (if (tstate.arm64) 0 else VDSO_REC);
    const n = std.mem.readInt(u32, r[0..4], .little);
    const ns = std.mem.readInt(u32, r[4..8], .little);
    const at = 8 + 4 * VDSO_SITES;
    if (n == 0 or ns > VDSO_SITES or at + n > VDSO_REC) return null;
    const sites: [*]const u32 = @ptrCast(@alignCast(r + 8));
    return .{ .img = r[at..][0..n], .sites = sites[0..ns] };
}

// enterGuest jumps to the guest entry on the guest stack, leaving no stub frame.
// It enters exactly as the kernel does at exec: x0, fp and lr are zero. x0 is the
// dynamic linker's fini pointer, which glibc's _start registers as an exit
// callback when it is nonzero; a leftover host value there made glibc call it at
// process exit and fault (musl ignores the parameter, so only glibc was hit).
// sp and entry are pinned to x1/x2 so clearing x0 cannot clobber the branch
// target, matching the Linux stub's enter (stub/zig/aarch64.zig).
fn enterGuest(entry: u64, sp: u64) noreturn {
    ownStack();
    sig.enterGuest();
    if (tstate.arm64) {
        asm volatile (
            \\ mov sp, x1
            \\ mov x0, xzr
            \\ mov x29, xzr
            \\ mov x30, xzr
            \\ br x2
            :
            : [sp] "{x1}" (sp),
              [entry] "{x2}" (entry),
            : "memory"
        );
    } else {
        // x86-64 exec ABI: %rdx is the dynamic linker's rtld_fini, which glibc's
        // _start registers as an exit callback when nonzero -- a stale host value
        // there faults at exit (as x0 did on arm64; see [[macos-port]]). sp and
        // entry ride r8/r9 so zeroing rdx/rbp cannot clobber the branch target.
        asm volatile (
            \\ movq %%r8, %%rsp
            \\ xorl %%edx, %%edx
            \\ xorl %%ebp, %%ebp
            \\ jmpq *%%r9
            :
            : [sp] "{r8}" (sp),
              [entry] "{r9}" (entry),
            : "memory"
        );
    }
    unreachable;
}

// main argv: [1] channel shm path, [2] guest ELF host path, [3] interpreter
// host path ("" = static), [4] main svc-sites file, [5] interpreter svc-sites
// file ("" = static), [6..] the guest-visible argv. The guest env is the stub's
// own environment (set by the supervisor). The channel + Seatbelt are brought
// up before the guest is loaded.
extern "c" var environ: [*c][*c]u8;

// parseMarker decodes the argv[0] the supervisor gives a stub it starts for
// an execve in a forked process: "lc-stub@<slot offset>@<uid|euid<<32>@
// <gid|egid<<32>@<argc>", hex. That stub's guest argv is argv[6..6+argc] and
// its guest environment the rest of argv: its own environment stays empty, so
// guest variables (DYLD_*, Malloc*) never configure the host process. A plain
// "lc-stub" is the run's first process (slot 0, root ids, env from environ).
fn parseMarker(a0: [*:0]const u8) ?[4]u64 {
    var it = std.mem.splitScalar(u8, std.mem.span(a0), '@');
    if (!std.mem.eql(u8, it.next() orelse return null, "lc-stub")) return null;
    var out: [4]u64 = undefined;
    for (&out) |*v| v.* = std.fmt.parseInt(u64, it.next() orelse return null, 16) catch return null;
    return out;
}

// A pooled stub ("lc-stub@pool@<slot offset>") is started ahead of need and
// parks on its own slot, fully set up and sandboxed, until the supervisor
// hands it a program: the path of a job file in the slot scratch holding
// NUL-separated fields -- target slot offset, uid|euid<<32, gid|egid<<32 and
// argc (hex), the four host paths main takes in argv[2..5], argv, then envp.
// It acks on the pool slot (which it never touches again), adopts the target
// slot and loads the program.
fn poolOffset(a0: [*:0]const u8) ?u64 {
    var it = std.mem.splitScalar(u8, std.mem.span(a0), '@');
    if (!std.mem.eql(u8, it.next() orelse return null, "lc-stub")) return null;
    if (!std.mem.eql(u8, it.next() orelse return null, "pool")) return null;
    return std.fmt.parseInt(u64, it.next() orelse return null, 16) catch null;
}

fn poolRun(base: [*]u8) noreturn {
    const ch = g_chan;
    ch.kind = chan.MSG_READY;
    chan.exchange(ch);
    if (ch.kind == chan.REP_FORKCHILD) {
        const job: [*]align(1) const u64 = @ptrCast(scratch(ch));
        const child_off, const parent_pid, const gpid = .{ job[0], job[1], job[2] };
        ch.kind = chan.MSG_HOSTRET;
        chan.postReq(ch); // the pool slot is the supervisor's again
        forkChild(base, child_off, parent_pid, gpid);
    }
    if (ch.kind != chan.REP_EXEC) _exit(2);
    const path: [*:0]const u8 = @ptrCast(scratch(ch));
    const data = std.fs.cwd().readFileAllocOptions(std.heap.page_allocator, std.mem.span(path), 1 << 24, null, 1, 0) catch _exit(9);
    ch.kind = chan.MSG_HOSTRET;
    chan.postReq(ch); // the pool slot is the supervisor's again

    var fields = std.ArrayList([*:0]const u8).init(std.heap.page_allocator);
    var start: usize = 0;
    for (data, 0..) |c, i| {
        if (c != 0) continue;
        fields.append(@ptrCast(data.ptr + start)) catch _exit(9);
        start = i + 1;
    }
    const f = fields.items;
    if (f.len < 8) _exit(9);
    var num: [4]u64 = undefined;
    for (&num, 0..) |*v, i| v.* = std.fmt.parseInt(u64, std.mem.span(f[i]), 16) catch _exit(9);
    g_chan = @ptrCast(@alignCast(base + num[0]));
    sig.startThread(slotIndex(g_chan));
    g_auxids = .{ num[1] & 0xffffffff, num[1] >> 32, num[2] & 0xffffffff, num[2] >> 32 };
    const argc: usize = @intCast(@min(num[3], f.len - 8));
    const interp: ?[*:0]const u8 = if (f[5][0] == 0) null else f[5];
    loadAndEnter(f[4], interp, f[6], f[7], f[8 .. 8 + argc], f[8 + argc ..]);
}

pub fn main() void {
    mem.noteHost();
    const argv = std.os.argv;
    if (argv.len < 6) _exit(2);
    const pool = poolOffset(argv[0]);
    const marker = if (pool == null) parseMarker(argv[0]) else null;
    if (pthread_key_create(&g_tp_key, null) != 0) _exit(126); // guest thread-pointer slot
    if (pthread_key_create(&g_exit_key, null) != 0) _exit(126);
    if (pthread_key_create(&g_stk_key, null) != 0) _exit(126);
    lc_stk_tsd = g_stk_key * 8;
    const base = mapChannel(argv[1]);
    g_base = base;
    g_chan = if (marker) |m| @ptrCast(@alignCast(base + m[0])) else slotAt(base, 0);
    if (pool) |off| g_chan = @ptrCast(@alignCast(base + off));
    if (marker) |m| g_auxids = .{ m[1] & 0xffffffff, m[1] >> 32, m[2] & 0xffffffff, m[2] >> 32 };

    // Auto-reap forked children so they never linger as zombies; this also lets
    // the supervisor detect a child that died by signal via kill(pid, 0). Set
    // before Seatbelt (sigaction is not in the allowlist) — the kernel reaps on
    // its own afterward, with no further syscall from the stub.
    _ = signal(SIGCHLD, SIG_IGN);
    life.start();

    if (!chan.init()) _exit(125); // resolve os_sync (dlsym) before Seatbelt locks down
    if (!futex.init()) _exit(124);
    sig.install(base);
    if (pool == null) sig.startThread(slotIndex(g_chan));
    sig.g_restorer = buildRestorer();
    jit.initThread();
    hwcap.init();
    fdlink.init();
    mem.init();
    stdio.init();
    noCore();
    sfork.register();
    service.start(serviceMaps, serviceSmaps, &@import("wx.zig").code);
    dropBootstrap();
    if (!sbcache.apply(seatbelt_profile, argv[1])) _exit(126);
    if (pool != null) poolRun(base);

    const interp: ?[*:0]const u8 = blk: {
        const p = argv[3];
        break :blk if (p[0] == 0) null else p;
    };

    const rest: []const [*:0]const u8 = @ptrCast(argv[6..]);
    var gargv: []const [*:0]const u8 = rest;
    var genv: []const [*:0]const u8 = &.{};
    if (marker) |mk| {
        const argc: usize = @intCast(@min(mk[3], rest.len));
        gargv = rest[0..argc];
        genv = rest[argc..];
    } else {
        // Guest env: the stub's environment, as the supervisor set it.
        var m: usize = 0;
        if (@intFromPtr(environ) != 0) {
            while (environ[m] != null) m += 1;
        }
        if (m > 0) genv = @as([*]const [*:0]const u8, @ptrCast(environ))[0..m];
    }
    // Guest argv: argv[6..]. Fall back to the host path if none was passed.
    if (gargv.len == 0) gargv = @as([*]const [*:0]const u8, @ptrCast(&argv[2]))[0..1];

    loadAndEnter(argv[2], interp, argv[4], argv[5], gargv, genv);
}
