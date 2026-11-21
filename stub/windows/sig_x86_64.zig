// x86-64 half of sig.zig: the guest register file, its moves to and from the
// Windows CONTEXT, and the Linux x86-64 rt_sigframe.

const std = @import("std");
const win = std.os.windows;
const sig = @import("sig.zig");

extern "ntdll" fn NtContinue(ctx: *win.CONTEXT, alert: u8) callconv(win.WINAPI) i32;
extern "ntdll" fn RtlCaptureContext(ctx: *win.CONTEXT) callconv(win.WINAPI) void;

pub const NR = struct {
    pub const rt_sigaction: u64 = 13;
    pub const rt_sigprocmask: u64 = 14;
    pub const rt_sigreturn: u64 = 15;
    pub const rt_sigpending: u64 = 127;
    pub const rt_sigtimedwait: u64 = 128;
    pub const rt_sigsuspend: u64 = 130;
    pub const sigaltstack: u64 = 131;
    pub const write: u64 = 1;
    pub const writev: u64 = 20;
    pub const sendto: u64 = 44;
    pub const sendmsg: u64 = 46;
};

// The red zone a signal frame skips below the interrupted rsp.
pub const RED_ZONE: u64 = 128;

// The restorer for a handler without SA_RESTORER: `mov $15,%eax; ud2`, the ud2
// trapping rt_sigreturn.
pub const restorer_code = [_]u8{ 0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x0b };
pub const restorer_trap = 5;

// Ctx is a guest thread's user state in sigcontext order, the currency between
// the trap frame, the Windows CONTEXT and the Linux sigcontext.
pub const Ctx = extern struct {
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    rdi: u64 = 0,
    rsi: u64 = 0,
    rbp: u64 = 0,
    rbx: u64 = 0,
    rdx: u64 = 0,
    rax: u64 = 0,
    rcx: u64 = 0,
    rsp: u64 = 0,
    rip: u64 = 0,
    eflags: u64 = 0,
    cr2: u64 = 0,
    fx: [512]u8 align(16) = [_]u8{0} ** 512,
};

// Trap is the thin descriptor the syscall paths hand afterSyscall so a Ctx is
// built only when a signal actually needs delivery.
pub const Trap = struct {
    frame: *const Frame, // the 15 GPRs the trampoline saved
    gsp: u64, // guest rsp at the syscall
    resume_at: u64, // where the guest resumes after the syscall
    rflags: u64,
    fx: [*]const u8, // 512-byte fxsave image
    site: u64, // the syscall instruction address (resume - 2), for restart
    nr: u64, // the syscall number, reloaded into rax on restart
};

// Frame is the 15 integer registers lc_syscall_entry pushes.
pub const Frame = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rax: u64,
};

pub fn args(f: *const Frame) [6]u64 {
    return .{ f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9 };
}

// The x86-64 NT_PRSTATUS register image a tracer reads, and its publication at
// a trapped syscall. The layout matches the Linux stub's arch.Registers and the
// supervisor's amd64 traceFrame: a kind and dirty word, then user_regs_struct.
// As Linux leaves it at syscall entry, rcx holds the resume pc and r11 the
// flags, orig_rax the syscall number.
pub const TraceRegs = extern struct {
    r15: u64, r14: u64, r13: u64, r12: u64, rbp: u64, rbx: u64,
    r11: u64, r10: u64, r9: u64, r8: u64, rax: u64, rcx: u64,
    rdx: u64, rsi: u64, rdi: u64, orig_rax: u64, rip: u64,
    cs: u64, eflags: u64, rsp: u64, ss: u64,
    fs_base: u64, gs_base: u64, ds: u64, es: u64, fs: u64, gs: u64,
};
pub const TraceState = extern struct { kind: u64, dirty: u64, regs: TraceRegs };

pub fn traceState() *TraceState {
    return @ptrFromInt(sig.tracePtr());
}

// publishFrameCtx publishes the guest registers at a signal or fault stop (not
// a syscall), so a tracer's GETREGS sees the real register file -- rip is the
// faulting pc, rcx/r11 are the guest's, not the syscall convention.
pub fn publishFrameCtx(c: *const Ctx) void {
    const s = traceState();
    s.kind = 2;
    s.dirty = 0;
    const g = &s.regs;
    g.r15 = c.r15;
    g.r14 = c.r14;
    g.r13 = c.r13;
    g.r12 = c.r12;
    g.rbp = c.rbp;
    g.rbx = c.rbx;
    g.r11 = c.r11;
    g.r10 = c.r10;
    g.r9 = c.r9;
    g.r8 = c.r8;
    g.rax = c.rax;
    g.rcx = c.rcx;
    g.rdx = c.rdx;
    g.rsi = c.rsi;
    g.rdi = c.rdi;
    g.orig_rax = c.rax;
    g.rip = c.rip;
    g.cs = 0x33;
    g.eflags = c.eflags;
    g.rsp = c.rsp;
    g.ss = 0x2b;
    g.fs_base = 0;
    g.gs_base = 0;
    g.ds = 0;
    g.es = 0;
    g.fs = 0;
    g.gs = 0;
}

// traceRestoreCtx applies a tracer's edits back onto a signal/fault context
// before the guest resumes.
pub fn traceRestoreCtx(c: *Ctx) void {
    const s = traceState();
    s.dirty = 0;
    const g = &s.regs;
    c.r15 = g.r15;
    c.r14 = g.r14;
    c.r13 = g.r13;
    c.r12 = g.r12;
    c.rbp = g.rbp;
    c.rbx = g.rbx;
    c.r11 = g.r11;
    c.r10 = g.r10;
    c.r9 = g.r9;
    c.r8 = g.r8;
    c.rax = g.rax;
    c.rcx = g.rcx;
    c.rdx = g.rdx;
    c.rsi = g.rsi;
    c.rdi = g.rdi;
    c.rip = g.rip;
    c.rsp = g.rsp;
    c.eflags = g.eflags;
}

comptime {
    std.debug.assert(256 + @sizeOf(TraceState) <= 0x1000);
}

// traceRestore applies a tracer's register edits (SETREGS/POKEUSER) before the
// guest resumes: the GPRs go back into the trap frame, and rip/rsp/eflags into
// the trap so ctxFromTrap carries them. It returns the edited rax, which the
// caller stores in the frame. dirty is cleared.
pub fn traceRestore(f: *Frame, t: *sig.Trap) u64 {
    const s: *TraceState = @ptrFromInt(sig.tracePtr());
    s.dirty = 0;
    const g = &s.regs;
    f.r15 = g.r15;
    f.r14 = g.r14;
    f.r13 = g.r13;
    f.r12 = g.r12;
    f.rbp = g.rbp;
    f.rbx = g.rbx;
    f.r11 = g.r11;
    f.r10 = g.r10;
    f.r9 = g.r9;
    f.r8 = g.r8;
    f.rcx = g.rcx;
    f.rdx = g.rdx;
    f.rsi = g.rsi;
    f.rdi = g.rdi;
    t.resume_at = g.rip;
    t.gsp = g.rsp;
    t.rflags = g.eflags;
    return g.rax;
}

pub fn publishFrame(f: *const Frame, pc: u64, gsp: u64, rflags: u64) void {
    const s: *TraceState = @ptrFromInt(sig.tracePtr());
    s.kind = 1;
    s.dirty = 0;
    s.regs = .{
        .r15 = f.r15, .r14 = f.r14, .r13 = f.r13, .r12 = f.r12, .rbp = f.rbp, .rbx = f.rbx,
        .r11 = rflags, .r10 = f.r10, .r9 = f.r9, .r8 = f.r8, .rax = f.rax, .rcx = pc,
        .rdx = f.rdx, .rsi = f.rsi, .rdi = f.rdi, .orig_rax = f.rax, .rip = pc,
        .cs = 0x33, .eflags = rflags, .rsp = gsp, .ss = 0x2b,
        .fs_base = 0, .gs_base = 0, .ds = 0, .es = 0, .fs = 0, .gs = 0,
    };
}

pub fn ctxFromTrap(t: *const Trap) Ctx {
    const f = t.frame;
    var c = Ctx{
        .r8 = f.r8,  .r9 = f.r9,   .r10 = f.r10, .r11 = f.r11,
        .r12 = f.r12, .r13 = f.r13, .r14 = f.r14, .r15 = f.r15,
        .rdi = f.rdi, .rsi = f.rsi, .rbp = f.rbp, .rbx = f.rbx,
        .rdx = f.rdx, .rax = f.rax, .rcx = f.rcx, .rsp = t.gsp,
        .rip = t.resume_at, .eflags = t.rflags,
    };
    @memcpy(c.fx[0..], t.fx[0..512]);
    return c;
}

// trapFromCtx describes c, a syscall's state copied out of its trap, as the
// trap of syscall nr, with f as the frame's storage.
pub fn trapFromCtx(c: *const Ctx, nr: u64, f: *Frame) Trap {
    f.* = .{
        .r15 = c.r15, .r14 = c.r14, .r13 = c.r13, .r12 = c.r12,
        .rbp = c.rbp, .rbx = c.rbx, .r11 = c.r11, .r10 = c.r10,
        .r9 = c.r9,   .r8 = c.r8,   .rcx = c.rcx, .rdx = c.rdx,
        .rsi = c.rsi, .rdi = c.rdi, .rax = nr,
    };
    return .{ .frame = f, .gsp = c.rsp, .resume_at = c.rip, .rflags = c.eflags, .fx = &c.fx, .site = c.rip -% 2, .nr = nr };
}

pub fn ctxFromWin(w: *const win.CONTEXT) Ctx {
    var c = Ctx{
        .r8 = w.R8,  .r9 = w.R9,   .r10 = w.R10, .r11 = w.R11,
        .r12 = w.R12, .r13 = w.R13, .r14 = w.R14, .r15 = w.R15,
        .rdi = w.Rdi, .rsi = w.Rsi, .rbp = w.Rbp, .rbx = w.Rbx,
        .rdx = w.Rdx, .rax = w.Rax, .rcx = w.Rcx, .rsp = w.Rsp,
        .rip = w.Rip, .eflags = w.EFlags,
    };
    const fx: *const [512]u8 = @ptrCast(&w.DUMMYUNIONNAME.FltSave);
    @memcpy(c.fx[0..], fx);
    return c;
}

// faultCtx is the guest state at a fault at addr.
pub fn faultCtx(w: *const win.CONTEXT, _: *const win.EXCEPTION_RECORD, addr: u64) Ctx {
    var c = ctxFromWin(w);
    c.cr2 = addr;
    return c;
}

pub fn winPc(w: *const win.CONTEXT) u64 {
    return w.Rip;
}

pub fn sp(c: *const Ctx) u64 {
    return c.rsp;
}

pub fn setPc(c: *Ctx, pc: u64) void {
    c.rip = pc;
}

pub fn ctxPc(c: *const Ctx) u64 {
    return c.rip;
}

pub fn setResult(c: *Ctx, r: u64) void {
    c.rax = r;
}

// setRestart points c back at t's syscall instruction, to issue nr.
pub fn setRestart(c: *Ctx, t: *const Trap, nr: u64) void {
    c.rax = nr;
    c.rip = t.site;
}

const MSG_NOSIGNAL: u64 = 0x4000;

// epipeRaises tells whether an EPIPE from the call raises SIGPIPE: always for
// write and writev, unless MSG_NOSIGNAL for sendto (flags in r10) and sendmsg
// (flags in rdx).
pub fn epipeRaises(t: *const Trap) bool {
    return switch (t.nr) {
        NR.write, NR.writev => true,
        NR.sendto => t.frame.r10 & MSG_NOSIGNAL == 0,
        NR.sendmsg => t.frame.rdx & MSG_NOSIGNAL == 0,
        else => false,
    };
}

// continueWith resumes the guest in state c and never returns. It captures a
// fresh CONTEXT (for valid segment selectors and MxCsr) and overwrites the
// guest-visible registers and the FP/SIMD image.
pub fn continueWith(c: *const Ctx) noreturn {
    var w: win.CONTEXT = undefined;
    RtlCaptureContext(&w);
    w.Rax = c.rax; w.Rbx = c.rbx; w.Rcx = c.rcx; w.Rdx = c.rdx;
    w.Rsi = c.rsi; w.Rdi = c.rdi; w.Rbp = c.rbp; w.Rsp = c.rsp;
    w.R8 = c.r8; w.R9 = c.r9; w.R10 = c.r10; w.R11 = c.r11;
    w.R12 = c.r12; w.R13 = c.r13; w.R14 = c.r14; w.R15 = c.r15;
    w.Rip = c.rip;
    w.EFlags = @truncate(c.eflags);
    const fx: *[512]u8 = @ptrCast(&w.DUMMYUNIONNAME.FltSave);
    @memcpy(fx, c.fx[0..]);
    @import("x86_64.zig").prepareGuestReturn(&w);
    _ = NtContinue(&w, 0);
    unreachable;
}

// ---- extended state ---------------------------------------------------------
//
// Linux's signal frame holds the XSAVE image of the user state components (AVX
// and later), not only the 512-byte fxsave one, and rt_sigreturn restores it,
// so a handler that uses AVX (Go's memmove does) leaves the interrupted code's
// upper YMM halves as they were. The stub runs only legacy SSE (-mcpu=baseline),
// which leaves those components alone, so the live state is still the guest's
// when a frame is built; its x87 and SSE part comes from the saved fxsave image,
// which the stub's own code may have changed since.

const FP_XSTATE_MAGIC1: u32 = 0x46505853;
const FP_XSTATE_MAGIC2: u32 = 0x46505845;
const UC_FP_XSTATE: u64 = 1;

var xfeat: u64 = 0; // the components a frame carries: XCR0's, less the AMX tiles
var xsize: u64 = 0; // the size of their XSAVE image
var x_init: [576]u8 align(64) = [_]u8{0} ** 576; // an image whose header asks for every component's initial state

const Cpuid = struct { eax: u32, ebx: u32, ecx: u32, edx: u32 };

fn cpuid(leaf: u32, sub: u32) Cpuid {
    var a: u32 = undefined;
    var b: u32 = undefined;
    var c: u32 = undefined;
    var d: u32 = undefined;
    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [l] "{eax}" (leaf),
          [s] "{ecx}" (sub),
    );
    return .{ .eax = a, .ebx = b, .ecx = c, .edx = d };
}

// initXstate learns the components the OS enabled; with no OSXSAVE a frame
// keeps only the fxsave image, as Linux's does then. AMX's are left out, as
// Linux leaves them out of a process that did not ask for them.
pub fn initXstate() void {
    if (cpuid(1, 0).ecx & (1 << 27) == 0) return;
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("xgetbv"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        : [n] "{ecx}" (@as(u32, 0)),
    );
    const f = (@as(u64, hi) << 32 | lo) & ~@as(u64, 0x60000);
    var size: u64 = 576;
    var i: u32 = 2;
    while (i < 64) : (i += 1) {
        if (f & (@as(u64, 1) << @intCast(i)) == 0) continue;
        const l = cpuid(0xd, i);
        size = @max(size, @as(u64, l.ebx) + l.eax);
    }
    xfeat = f;
    xsize = size;
}

fn xsave(p: u64, mask: u64) void {
    asm volatile ("xsave64 (%[p])"
        :
        : [p] "r" (p),
          [lo] "{eax}" (@as(u32, @truncate(mask))),
          [hi] "{edx}" (@as(u32, @truncate(mask >> 32))),
        : "memory"
    );
}

fn xrstor(p: u64, mask: u64) void {
    asm volatile ("xrstor64 (%[p])"
        :
        : [p] "r" (p),
          [lo] "{eax}" (@as(u32, @truncate(mask))),
          [hi] "{edx}" (@as(u32, @truncate(mask >> 32))),
        : "memory"
    );
}

// saveX writes the guest's XSAVE image at fp (64-byte aligned, xsize + 4 bytes)
// as Linux lays it out: the components, the software bytes that describe them
// and the trailing magic.
fn saveX(fp: u64, c: *const Ctx) void {
    @memset(@as([*]u8, @ptrFromInt(fp + 512))[0..64], 0);
    xsave(fp, xfeat);
    @memcpy(@as([*]u8, @ptrFromInt(fp))[0..464], c.fx[0..464]);
    wr(u64, fp + 512, rd(u64, fp + 512) | 3); // x87 and SSE: the saved image's
    wr(u32, fp + 464, FP_XSTATE_MAGIC1);
    wr(u32, fp + 468, @truncate(xsize + 4));
    wr(u64, fp + 472, xfeat);
    wr(u32, fp + 480, @truncate(xsize));
    @memset(@as([*]u8, @ptrFromInt(fp + 484))[0..28], 0);
    wr(u32, fp + xsize, FP_XSTATE_MAGIC2);
}

// restoreX loads the extended components rt_sigreturn finds in the frame's
// fpstate at fpp; the x87 and SSE part goes back with the rest of the context.
// Without a valid XSAVE image there they start clean, as on Linux.
fn restoreX(fpp: u64) void {
    const ext = xfeat & ~@as(u64, 3);
    if (ext == 0) return;
    if (fpp != 0 and fpp & 63 == 0 and rd(u32, fpp + 464) == FP_XSTATE_MAGIC1) {
        const size: u64 = rd(u32, fpp + 480);
        const feat = rd(u64, fpp + 472);
        const bv = rd(u64, fpp + 512);
        var clean = true;
        var o: u64 = 520;
        while (o < 576) : (o += 8) clean = clean and rd(u64, fpp + o) == 0;
        if (size >= 576 and size <= xsize and rd(u32, fpp + size) == FP_XSTATE_MAGIC2 and
            feat & ~xfeat == 0 and bv & ~feat == 0 and clean and rd(u32, fpp + 24) >> 16 == 0)
        {
            xrstor(fpp, ext);
            return;
        }
    }
    xrstor(@intFromPtr(&x_init), ext);
}

// ---- the rt_sigframe -------------------------------------------------------

const FRAME_BYTES: u64 = 448;
const MC_OFF: u64 = 48; // uc_mcontext, relative to frame
const INFO_OFF: u64 = 320;
const UC_OFF: u64 = 8;

fn wr(comptime T: type, addr: u64, v: T) void {
    @as(*align(1) T, @ptrFromInt(addr)).* = v;
}

fn rd(comptime T: type, addr: u64) T {
    return @as(*align(1) const T, @ptrFromInt(addr)).*;
}

// buildFrame writes the rt_sigframe below sp (the red zone already skipped,
// or the alternate stack's top) and points c at handler.
pub fn buildFrame(c: *Ctx, top: u64, signo: u32, info: *const [128]u8, ss: sig.StackT, uc_mask: u64, is_fault: bool, handler: u64, restorer: u64) void {
    const fp = (top - if (xfeat != 0) xsize + 4 else 512) & ~@as(u64, 63);
    const frame = ((fp - FRAME_BYTES) & ~@as(u64, 15)) - 8;

    wr(u64, frame, restorer);
    const uc = frame + UC_OFF;
    wr(u64, uc, if (xfeat != 0) UC_FP_XSTATE else 0); // uc_flags
    wr(u64, uc + 8, 0); // uc_link
    wr(u64, uc + 16, ss.sp);
    wr(u32, uc + 24, ss.flags);
    wr(u32, uc + 28, 0);
    wr(u64, uc + 32, ss.size);
    const mc = frame + MC_OFF;
    wr(u64, mc + 0, c.r8);
    wr(u64, mc + 8, c.r9);
    wr(u64, mc + 16, c.r10);
    wr(u64, mc + 24, c.r11);
    wr(u64, mc + 32, c.r12);
    wr(u64, mc + 40, c.r13);
    wr(u64, mc + 48, c.r14);
    wr(u64, mc + 56, c.r15);
    wr(u64, mc + 64, c.rdi);
    wr(u64, mc + 72, c.rsi);
    wr(u64, mc + 80, c.rbp);
    wr(u64, mc + 88, c.rbx);
    wr(u64, mc + 96, c.rdx);
    wr(u64, mc + 104, c.rax);
    wr(u64, mc + 112, c.rcx);
    wr(u64, mc + 120, c.rsp);
    wr(u64, mc + 128, c.rip);
    wr(u64, mc + 136, c.eflags);
    wr(u64, mc + 144, 0); // csgsfsss
    wr(u64, mc + 152, 0); // err
    wr(u64, mc + 160, 0); // trapno
    wr(u64, mc + 168, 0); // oldmask
    wr(u64, mc + 176, if (is_fault) c.cr2 else 0);
    wr(u64, mc + 184, fp); // fpstate pointer
    var i: u64 = 192;
    while (i < 256) : (i += 8) wr(u64, mc + i, 0);
    wr(u64, frame + 304, uc_mask); // uc_sigmask

    if (xfeat != 0) saveX(fp, c) else @as(*[512]u8, @ptrFromInt(fp)).* = c.fx;
    @memcpy(@as([*]u8, @ptrFromInt(frame + INFO_OFF))[0..128], info);

    c.rdi = signo;
    c.rsi = frame + INFO_OFF;
    c.rdx = uc;
    c.rsp = frame;
    c.rip = handler;
}

// readFrame reads back the frame rt_sigreturn finds at gsp (the handler's
// ret popped the restorer address): the state, the mask and the alternate
// stack to restore. False when there is no frame there.
pub fn readFrame(gsp: u64, c: *Ctx, mask: *u64, ss: *sig.StackT) bool {
    const frame = gsp -% 8;
    if (frame == 0) return false;
    const uc = frame + UC_OFF;
    const mc = frame + MC_OFF;
    c.r8 = rd(u64, mc + 0);
    c.r9 = rd(u64, mc + 8);
    c.r10 = rd(u64, mc + 16);
    c.r11 = rd(u64, mc + 24);
    c.r12 = rd(u64, mc + 32);
    c.r13 = rd(u64, mc + 40);
    c.r14 = rd(u64, mc + 48);
    c.r15 = rd(u64, mc + 56);
    c.rdi = rd(u64, mc + 64);
    c.rsi = rd(u64, mc + 72);
    c.rbp = rd(u64, mc + 80);
    c.rbx = rd(u64, mc + 88);
    c.rdx = rd(u64, mc + 96);
    c.rax = rd(u64, mc + 104);
    c.rcx = rd(u64, mc + 112);
    c.rsp = rd(u64, mc + 120);
    c.rip = rd(u64, mc + 128);
    c.eflags = rd(u64, mc + 136) & 0x3c7fd7 | 2;
    const fpp = rd(u64, mc + 184);
    if (fpp != 0) c.fx = rd([512]u8, fpp);
    restoreX(fpp);
    mask.* = rd(u64, frame + 304);
    ss.* = rd(sig.StackT, uc + 16);
    return true;
}
