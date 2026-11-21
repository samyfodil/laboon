// arm64 half of sig.zig: the guest register file, its moves to and from the
// Windows CONTEXT, and the Linux arm64 rt_sigframe (siginfo, then a ucontext
// whose __reserved area holds the fpsimd record and, for a fault, the esr
// record).

const std = @import("std");
const win = std.os.windows;
const sig = @import("sig.zig");
const arch = @import("aarch64.zig");

extern "ntdll" fn NtContinue(ctx: *win.CONTEXT, alert: u8) callconv(win.WINAPI) i32;

pub const NR = struct {
    pub const rt_sigaction: u64 = 134;
    pub const rt_sigprocmask: u64 = 135;
    pub const rt_sigreturn: u64 = 139;
    pub const rt_sigpending: u64 = 136;
    pub const rt_sigtimedwait: u64 = 137;
    pub const rt_sigsuspend: u64 = 133;
    pub const sigaltstack: u64 = 132;
    pub const write: u64 = 64;
    pub const writev: u64 = 66;
    pub const sendto: u64 = 206;
    pub const sendmsg: u64 = 211;
};

// arm64 has no red zone.
pub const RED_ZONE: u64 = 0;

// The restorer for a handler without SA_RESTORER (Go's): `mov x8, #139;
// udf #0`, the udf trapping rt_sigreturn.
pub const restorer_code = [_]u8{ 0x68, 0x11, 0x80, 0xd2, 0, 0, 0, 0 };
pub const restorer_trap = 4;

// Ctx is a guest thread's user state: the sigcontext registers, the FP/SIMD
// state, and the fault's address and syndrome.
pub const Ctx = extern struct {
    x: [31]u64 = [_]u64{0} ** 31,
    sp: u64 = 0,
    pc: u64 = 0,
    pstate: u64 = 0,
    fault: u64 = 0,
    esr: u64 = 0,
    fpsr: u32 = 0,
    fpcr: u32 = 0,
    v: [32]u128 align(16) = [_]u128{0} ** 32,
};

// Frame is what lc_syscall_entry saves on the thread's stub stack.
pub const Frame = extern struct {
    x: [31]u64,
    nzcv: u64,
    resume_at: u64,
    gsp: u64,
    q: [32]u128,
    fpcr: u64,
    fpsr: u64,
};

// The arm64 NT_PRSTATUS register image a tracer reads, published at offset 256
// of this thread's record (sig.tracePtr), the same layout the supervisor's
// arm64 traceFrame reads: a kind and dirty word, then x0..x30, sp, pc, pstate.
pub const TraceRegs = extern struct { x: [31]u64, sp: u64, pc: u64, pstate: u64 };
pub const TraceState = extern struct { kind: u64, dirty: u64, regs: TraceRegs };

pub fn traceState() *TraceState {
    return @ptrFromInt(sig.tracePtr());
}

// publishFrameCtx publishes the guest registers at a signal or fault stop (not
// a syscall) so a tracer's GETREGS sees the real register file.
pub fn publishFrameCtx(c: *const Ctx) void {
    const s = traceState();
    s.kind = 2;
    s.dirty = 0;
    for (0..31) |i| s.regs.x[i] = c.x[i];
    s.regs.sp = c.sp;
    s.regs.pc = c.pc;
    s.regs.pstate = c.pstate;
}

// traceRestoreCtx applies a tracer's edits back onto a signal/fault context.
pub fn traceRestoreCtx(c: *Ctx) void {
    const s = traceState();
    s.dirty = 0;
    for (0..31) |i| c.x[i] = s.regs.x[i];
    c.sp = s.regs.sp;
    c.pc = s.regs.pc;
    c.pstate = (c.pstate & ~NZCV) | (s.regs.pstate & NZCV);
}

// traceRestore applies a tracer's register edits before the guest resumes:
// x1..x30 into the frame, pc and sp into the trap (ctxFromTrap reads them),
// NZCV into the frame. It returns the edited x0, which the caller stores.
pub fn traceRestore(f: *Frame, t: *sig.Trap) u64 {
    const s = traceState();
    s.dirty = 0;
    for (1..31) |i| f.x[i] = s.regs.x[i];
    t.resume_at = s.regs.pc;
    t.gsp = s.regs.sp;
    f.nzcv = (f.nzcv & ~NZCV) | (s.regs.pstate & NZCV);
    return s.regs.x[0];
}

pub fn publishFrame(f: *const Frame) void {
    const s: *TraceState = @ptrFromInt(sig.tracePtr());
    s.kind = 1;
    s.dirty = 0;
    for (0..31) |i| s.regs.x[i] = f.x[i];
    s.regs.sp = f.gsp;
    s.regs.pc = f.resume_at;
    s.regs.pstate = f.nzcv;
}

comptime {
    std.debug.assert(@offsetOf(Frame, "nzcv") == 248);
    std.debug.assert(@offsetOf(Frame, "resume_at") == 256);
    std.debug.assert(@offsetOf(Frame, "gsp") == 264);
    std.debug.assert(@offsetOf(Frame, "q") == 272);
    std.debug.assert(@offsetOf(Frame, "fpcr") == 784);
    std.debug.assert(@offsetOf(Frame, "fpsr") == 792);
    std.debug.assert(@sizeOf(Frame) == 800);
}

pub const Trap = struct {
    frame: *const Frame, // the registers at the svc; x0 is still the first argument
    gsp: u64,
    resume_at: u64,
    site: u64, // the svc (or its branch to an island), for restart
    nr: u64,
};

pub fn args(f: *const Frame) [6]u64 {
    return f.x[0..6].*;
}

const NZCV: u64 = 0xf0000000;

pub fn ctxFromTrap(t: *const Trap) Ctx {
    const f = t.frame;
    return .{ .x = f.x, .sp = t.gsp, .pc = t.resume_at, .pstate = f.nzcv & NZCV, .fpsr = @truncate(f.fpsr), .fpcr = @truncate(f.fpcr), .v = f.q };
}

// trapFromCtx describes c, a syscall's state copied out of its trap, as the
// trap of syscall nr, with f as the frame's storage.
pub fn trapFromCtx(c: *const Ctx, nr: u64, f: *Frame) Trap {
    f.* = .{ .x = c.x, .nzcv = c.pstate, .resume_at = c.pc, .gsp = c.sp, .q = c.v, .fpcr = c.fpcr, .fpsr = c.fpsr };
    f.x[8] = nr;
    return .{ .frame = f, .gsp = c.sp, .resume_at = c.pc, .site = c.pc -% 4, .nr = nr };
}

// ctxFromWin reads a CONTEXT whose X18 holds the guest's x18: the dispatcher
// hook and lc_sig_redirect store it there.
pub fn ctxFromWin(w: *const win.CONTEXT) Ctx {
    var c = Ctx{ .x = w.DUMMYUNIONNAME.X, .sp = w.Sp, .pc = w.Pc, .pstate = w.Cpsr & NZCV, .fpsr = w.Fpsr, .fpcr = w.Fpcr };
    for (&c.v, w.V) |*d, s| d.* = @bitCast(s);
    return c;
}

// faultCtx is the guest state at a fault at addr, with an ESR_EL1 like the
// one Linux reports (Windows does not hand over the real one).
pub fn faultCtx(w: *const win.CONTEXT, rec: *const win.EXCEPTION_RECORD, addr: u64) Ctx {
    var c = ctxFromWin(w);
    c.fault = addr;
    c.esr = esrOf(rec, w.Pc);
    return c;
}

fn esrOf(rec: *const win.EXCEPTION_RECORD, pc: u64) u64 {
    const IL: u64 = 1 << 25;
    return switch (rec.ExceptionCode) {
        0xC0000005, 0xC00000FD => blk: {
            const kind = if (rec.NumberParameters >= 1) rec.ExceptionInformation[0] else 0;
            if (kind == 8) break :blk 0x20 << 26 | IL | 0x07; // instruction abort, translation fault
            break :blk 0x24 << 26 | IL | (if (kind == 1) @as(u64, 1) << 6 else 0) | 0x07; // data abort
        },
        0x80000002 => 0x24 << 26 | IL | 0x21, // alignment fault
        0x80000003 => blk: {
            const ins = @as(*const u32, @ptrFromInt(pc)).*;
            break :blk 0x3c << 26 | IL | ((ins >> 5) & 0xffff); // brk #imm
        },
        else => IL,
    };
}

pub fn winPc(w: *const win.CONTEXT) u64 {
    return w.Pc;
}

pub fn sp(c: *const Ctx) u64 {
    return c.sp;
}

pub fn setPc(c: *Ctx, pc: u64) void {
    c.pc = pc;
}

pub fn ctxPc(c: *const Ctx) u64 {
    return c.pc;
}

pub fn setResult(c: *Ctx, r: u64) void {
    c.x[0] = r;
}

// setRestart points c back at t's syscall, to issue nr; x0 still holds the
// first argument (the trap's copy predates the result).
pub fn setRestart(c: *Ctx, t: *const Trap, nr: u64) void {
    c.x[8] = nr;
    c.pc = t.site;
}

const MSG_NOSIGNAL: u64 = 0x4000;

// epipeRaises tells whether an EPIPE from the call raises SIGPIPE: always for
// write and writev, unless MSG_NOSIGNAL for sendto (flags in x3) and sendmsg
// (flags in x2).
pub fn epipeRaises(t: *const Trap) bool {
    return switch (t.nr) {
        NR.write, NR.writev => true,
        NR.sendto => t.frame.x[3] & MSG_NOSIGNAL == 0,
        NR.sendmsg => t.frame.x[2] & MSG_NOSIGNAL == 0,
        else => false,
    };
}

// continueWith resumes the guest in state c and never returns. NtContinue
// resumes with x18 = TEB. The common gate eventually restores the guest's
// x18 through the per-thread resume slot.
pub fn continueWith(c: *const Ctx) noreturn {
    var w = std.mem.zeroes(win.CONTEXT);
    w.ContextFlags = 0x400007; // CONTEXT_ARM64 | CONTROL | INTEGER | FLOATING_POINT
    w.Cpsr = @truncate(c.pstate & NZCV);
    w.DUMMYUNIONNAME.X = c.x;
    w.Sp = c.sp;
    w.Pc = c.pc;
    w.Fpcr = c.fpcr;
    w.Fpsr = c.fpsr;
    for (&w.V, c.v) |*d, s| d.* = @bitCast(s);
    arch.prepareGuestReturn(&w);
    _ = NtContinue(&w, 0);
    unreachable;
}

// ---- the rt_sigframe -------------------------------------------------------
//
// struct rt_sigframe { siginfo_t info; struct ucontext uc; }, 16-aligned,
// below a frame record {fp, lr} that x29 points at:
//   uc + 0    uc_flags, uc_link
//   uc + 16   uc_stack {ss_sp, ss_flags, ss_size}
//   uc + 40   uc_sigmask (then the rest of a 1024-bit sigset)
//   uc + 176  uc_mcontext: fault_address, regs[31], sp, pc, pstate, then
//             __reserved[4096] at +288

const UC_OFF: u64 = 128;
const MC_OFF: u64 = UC_OFF + 176;
const RES_OFF: u64 = MC_OFF + 288;
const FRAME_BYTES: u64 = RES_OFF + 4096;
const FPSIMD_MAGIC: u32 = 0x46508001;
const FPSIMD_SIZE: u32 = 528;
const ESR_MAGIC: u32 = 0x45535201;

comptime {
    std.debug.assert(FRAME_BYTES == 4688);
}

fn wr(comptime T: type, addr: u64, v: T) void {
    @as(*align(1) T, @ptrFromInt(addr)).* = v;
}

fn rd(comptime T: type, addr: u64) T {
    return @as(*align(1) const T, @ptrFromInt(addr)).*;
}

// buildFrame writes the rt_sigframe below top (the interrupted sp, or the
// alternate stack's top) and points c at handler, as the kernel's
// setup_rt_frame does.
pub fn buildFrame(c: *Ctx, top: u64, signo: u32, info: *const [128]u8, ss: sig.StackT, uc_mask: u64, is_fault: bool, handler: u64, restorer: u64) void {
    const rec = (top - 16) & ~@as(u64, 15);
    const frame = rec - FRAME_BYTES;
    @memset(@as([*]u8, @ptrFromInt(frame))[0..RES_OFF], 0);
    @memcpy(@as([*]u8, @ptrFromInt(frame))[0..128], info);
    const uc = frame + UC_OFF;
    wr(u64, uc + 16, ss.sp);
    wr(u32, uc + 24, ss.flags);
    wr(u64, uc + 32, ss.size);
    wr(u64, uc + 40, uc_mask);
    const mc = frame + MC_OFF;
    wr(u64, mc, if (is_fault) c.fault else 0);
    for (c.x, 0..) |v, i| wr(u64, mc + 8 + 8 * i, v);
    wr(u64, mc + 256, c.sp);
    wr(u64, mc + 264, c.pc);
    wr(u64, mc + 272, c.pstate & NZCV);
    var r = frame + RES_OFF;
    wr(u32, r, FPSIMD_MAGIC);
    wr(u32, r + 4, FPSIMD_SIZE);
    wr(u32, r + 8, c.fpsr);
    wr(u32, r + 12, c.fpcr);
    @memcpy(@as([*]u8, @ptrFromInt(r + 16))[0..512], std.mem.asBytes(&c.v));
    r += FPSIMD_SIZE;
    if (is_fault) {
        wr(u32, r, ESR_MAGIC);
        wr(u32, r + 4, 16);
        wr(u64, r + 8, c.esr);
        r += 16;
    }
    wr(u64, r, 0); // the terminator
    wr(u64, rec, c.x[29]);
    wr(u64, rec + 8, c.x[30]);

    c.x[0] = signo;
    c.x[1] = frame;
    c.x[2] = uc;
    c.x[29] = rec;
    c.x[30] = restorer;
    c.sp = frame;
    c.pc = handler;
}

// readFrame reads back the frame rt_sigreturn finds at gsp (the handler
// left sp where the frame starts): the state, the mask and the alternate
// stack to restore. False when gsp holds no frame.
pub fn readFrame(gsp: u64, c: *Ctx, mask: *u64, ss: *sig.StackT) bool {
    if (gsp == 0 or gsp & 15 != 0) return false;
    const uc = gsp + UC_OFF;
    const mc = gsp + MC_OFF;
    for (&c.x, 0..) |*v, i| v.* = rd(u64, mc + 8 + 8 * i);
    c.sp = rd(u64, mc + 256);
    c.pc = rd(u64, mc + 264);
    c.pstate = rd(u64, mc + 272) & NZCV;
    var off: u64 = 0;
    while (off + 8 <= 4096) {
        const r = gsp + RES_OFF + off;
        const magic = rd(u32, r);
        const size = rd(u32, r + 4);
        if (magic == 0 or size < 8 or off + size > 4096) break;
        if (magic == FPSIMD_MAGIC and size >= FPSIMD_SIZE) {
            c.fpsr = rd(u32, r + 8);
            c.fpcr = rd(u32, r + 12);
            @memcpy(std.mem.asBytes(&c.v), @as([*]const u8, @ptrFromInt(r + 16))[0..512]);
        }
        off += size;
    }
    mask.* = rd(u64, uc + 40);
    ss.* = rd(sig.StackT, uc + 16);
    return true;
}
