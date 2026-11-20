// proc.zig — process-level pieces the stub owns because they need this
// process's CPU state: resuming a clone/fork child on its own stack with the
// parent's full register frame, getcpu, and membarrier (a barrier on every
// other thread of this task).

const std = @import("std");
const tstate = @import("tstate.zig");

const NR_GETRUSAGE: u64 = 165;
const NR_GETCPU: u64 = 168;
const NR_MEMBARRIER: u64 = 283;

const EINVAL: i64 = 22;
const EPERM: i64 = 1;
const EFAULT: i64 = 14;

fn neg(e: i64) u64 {
    return @bitCast(-e);
}

// resumeFrame enters the guest with the register state saved in a trampoline
// frame (tramp_common's layout: x0..x30 at 0..240, NZCV at 248, FPCR|FPSR<<32
// at 256, the resume pc at 264, q0..q31 at 272..784), but on stack sp and with
// x0 = 0: what a clone child sees on Linux. x16 carries the branch and is not
// restored, as on the trampoline's own return path.
pub fn resumeFrame(frame: [*]const u64, sp: u64) callconv(.C) noreturn {
    if (!tstate.arm64) {
        // clone/fork child resume: pending the x86-64 full-context port (not on
        // the single-process startup milestone).
        asm volatile ("ud2");
        unreachable;
    }
    asm volatile (
        \\ mov x16, x0
        \\ ldp q0,  q1,  [x16, #272]
        \\ ldp q2,  q3,  [x16, #304]
        \\ ldp q4,  q5,  [x16, #336]
        \\ ldp q6,  q7,  [x16, #368]
        \\ ldp q8,  q9,  [x16, #400]
        \\ ldp q10, q11, [x16, #432]
        \\ ldp q12, q13, [x16, #464]
        \\ ldp q14, q15, [x16, #496]
        \\ ldp q16, q17, [x16, #528]
        \\ ldp q18, q19, [x16, #560]
        \\ ldp q20, q21, [x16, #592]
        \\ ldp q22, q23, [x16, #624]
        \\ ldp q24, q25, [x16, #656]
        \\ ldp q26, q27, [x16, #688]
        \\ ldp q28, q29, [x16, #720]
        \\ ldp q30, q31, [x16, #752]
        \\ ldr x9, [x16, #256]
        \\ msr fpcr, x9
        \\ lsr x10, x9, #32
        \\ msr fpsr, x10
        \\ ldr x9, [x16, #248]
        \\ msr nzcv, x9
        \\ mov sp, x1
        \\ ldp x2,  x3,  [x16, #16]
        \\ ldp x4,  x5,  [x16, #32]
        \\ ldp x6,  x7,  [x16, #48]
        \\ ldp x8,  x9,  [x16, #64]
        \\ ldp x10, x11, [x16, #80]
        \\ ldp x12, x13, [x16, #96]
        \\ ldp x14, x15, [x16, #112]
        \\ ldr x17,      [x16, #136]
        \\ ldp x18, x19, [x16, #144]
        \\ ldp x20, x21, [x16, #160]
        \\ ldp x22, x23, [x16, #176]
        \\ ldp x24, x25, [x16, #192]
        \\ ldp x26, x27, [x16, #208]
        \\ ldp x28, x29, [x16, #224]
        \\ ldr x30,      [x16, #240]
        \\ ldr x1,       [x16, #8]
        \\ mov x0, #0
        \\ ldr x16,      [x16, #264]
        \\ br x16
        :
        : [frame] "{x0}" (frame),
          [sp] "{x1}" (sp),
    );
    unreachable;
}

pub const FRAME_BYTES: usize = 784;

// resumeIsland returns to the guest from a trampoline frame as tramp_common
// does, with x0 = 0: every register restored from the frame (x16 and x17 by
// the site's own epilogue, whose address the island pushed at frame+784, and
// which pops the frame and branches back to the site). A fork child that is a
// fresh stub resumes this way at the fork's return.
pub fn resumeIsland(frame: [*]u64) callconv(.C) noreturn {
    frame[0] = 0;
    if (!tstate.arm64) {
        asm volatile ("ud2"); // fork resume: pending the x86-64 full-context port
        unreachable;
    }
    asm volatile (
        \\ mov sp, x0
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
        \\ ldr x9, [sp, #256]
        \\ msr fpcr, x9
        \\ lsr x10, x9, #32
        \\ msr fpsr, x10
        \\ ldr x9, [sp, #248]
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
        \\ ldp x8,  x9,  [sp, #64]
        \\ ldp x6,  x7,  [sp, #48]
        \\ ldp x4,  x5,  [sp, #32]
        \\ ldp x2,  x3,  [sp, #16]
        \\ ldp x0,  x1,  [sp, #0]
        \\ ldr x16, [sp, #784]
        \\ br  x16
        :
        : [frame] "{x0}" (frame),
    );
    unreachable;
}

// ---- getcpu / membarrier ------------------------------------------------------------

extern "c" fn pthread_cpu_number_np(cpu: *usize) c_int;

const mach_port_t = c_uint;
extern "c" fn mach_task_self() mach_port_t;
extern "c" fn mach_thread_self() mach_port_t;
extern "c" fn task_threads(task: mach_port_t, list: *[*]mach_port_t, count: *c_uint) c_int;
extern "c" fn thread_get_register_pointer_values(t: mach_port_t, sp: *usize, len: *usize, regs: [*]usize) c_int;
extern "c" fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) c_int;
extern "c" fn vm_deallocate(task: mach_port_t, addr: usize, size: usize) c_int;

const MB_QUERY: u64 = 0;
const MB_GLOBAL: u64 = 1;
const MB_PRIVATE_EXPEDITED: u64 = 8;
const MB_REGISTER_PRIVATE_EXPEDITED: u64 = 16;
const MB_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 32;
const MB_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 64;
const MB_SUPPORTED = MB_GLOBAL | MB_PRIVATE_EXPEDITED | MB_REGISTER_PRIVATE_EXPEDITED |
    MB_PRIVATE_EXPEDITED_SYNC_CORE | MB_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;

// Registrations are per address space: shared by this task's threads, reset
// by exec.
var mb_registered: u64 = 0;

pub fn resetOnExec() void {
    @atomicStore(u64, &mb_registered, 0, .seq_cst);
}

// barrierAllThreads makes every other thread of this task pass a full memory
// barrier and a context synchronization before it returns: reading a thread's
// registers forces it off its core (the kernel interrupts a running thread to
// save its state), the same trick .NET's FlushProcessWriteBuffers uses on
// Apple Silicon, where a TLB shootdown sends no IPI.
fn barrierAllThreads() bool {
    asm volatile (if (tstate.arm64) "dmb ish" else "mfence" ::: "memory");
    const task = mach_task_self();
    var list: [*]mach_port_t = undefined;
    var count: c_uint = 0;
    if (task_threads(task, &list, &count) != 0) return false;
    const self = mach_thread_self();
    var regs: [128]usize = undefined;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (list[i] != self) {
            var sp: usize = 0;
            var n: usize = regs.len;
            _ = thread_get_register_pointer_values(list[i], &sp, &n, &regs);
        }
        _ = mach_port_deallocate(task, list[i]);
    }
    _ = mach_port_deallocate(task, self);
    _ = vm_deallocate(task, @intFromPtr(list), count * @sizeOf(mach_port_t));
    asm volatile (if (tstate.arm64) "dmb ish" else "mfence" ::: "memory");
    return true;
}

fn membarrier(cmd: u64, flags: u64) u64 {
    if (flags != 0) return neg(EINVAL);
    switch (cmd) {
        MB_QUERY => return MB_SUPPORTED,
        MB_GLOBAL => {
            if (!barrierAllThreads()) return neg(EINVAL);
            return 0;
        },
        MB_REGISTER_PRIVATE_EXPEDITED, MB_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            _ = @atomicRmw(u64, &mb_registered, .Or, cmd, .seq_cst);
            return 0;
        },
        MB_PRIVATE_EXPEDITED, MB_PRIVATE_EXPEDITED_SYNC_CORE => {
            if (@atomicLoad(u64, &mb_registered, .seq_cst) & (cmd << 1) == 0) return neg(EPERM);
            if (!barrierAllThreads()) return neg(EINVAL);
            return 0;
        },
        else => return neg(EINVAL),
    }
}

// ---- getrusage(RUSAGE_THREAD) ------------------------------------------------------

// Only the calling thread can be asked for its own CPU times, so RUSAGE_THREAD
// is answered here from thread_info; the process-wide forms go to the
// supervisor.
const THREAD_BASIC_INFO: c_int = 3;
const TimeValue = extern struct { sec: i32, usec: i32 };
const ThreadBasicInfo = extern struct {
    user_time: TimeValue,
    system_time: TimeValue,
    cpu_usage: i32,
    policy: i32,
    run_state: i32,
    flags: i32,
    suspend_count: i32,
    sleep_time: i32,
};
extern "c" fn thread_info(t: mach_port_t, flavor: c_int, info: *ThreadBasicInfo, count: *c_uint) c_int;

fn threadRusage(addr: u64) u64 {
    var info: ThreadBasicInfo = undefined;
    var count: c_uint = @sizeOf(ThreadBasicInfo) / 4;
    const self = mach_thread_self();
    const kr = thread_info(self, THREAD_BASIC_INFO, &info, &count);
    _ = mach_port_deallocate(mach_task_self(), self);
    if (kr != 0) return neg(EINVAL);
    const ru: *[18]i64 = @ptrFromInt(addr); // struct rusage: 2 timevals, 14 longs
    ru.* = std.mem.zeroes([18]i64);
    ru[0] = info.user_time.sec;
    ru[1] = info.user_time.usec;
    ru[2] = info.system_time.sec;
    ru[3] = info.system_time.usec;
    return 0;
}

// handle returns the result if nr is one this module serves, else null.
pub fn handle(nr: u64, a: [*]const u64) ?u64 {
    return switch (nr) {
        NR_GETCPU => blk: {
            var cpu: usize = 0;
            _ = pthread_cpu_number_np(&cpu);
            if (a[0] != 0) @as(*u32, @ptrFromInt(a[0])).* = @truncate(cpu);
            if (a[1] != 0) @as(*u32, @ptrFromInt(a[1])).* = 0;
            break :blk 0;
        },
        NR_MEMBARRIER => membarrier(a[0], a[1]),
        NR_GETRUSAGE => if (a[0] == 1) threadRusage(a[1]) else null, // RUSAGE_THREAD
        else => null,
    };
}
