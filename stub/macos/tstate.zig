// Per-architecture access to the parts of a signal's mcontext that the trap
// machinery reads and writes the same way on both Darwin targets: the
// instruction pointer, the stack pointer, the faulting address and the flags
// register. The general-purpose register file (31 arm64 registers vs 16 on
// x86-64) and the SIMD/float state (NEON q[] vs SSE) differ in shape and are
// handled per-arch at the save/restore sites (sig.zig's Ctx/fromMc/toMc), not
// here. This is the arch seam the x86-64 port builds on; see AMD64.md.
const std = @import("std");
const builtin = @import("builtin");

pub const arm64 = builtin.target.cpu.arch == .aarch64;

pub inline fn pc(mc: *std.c.mcontext_t) u64 {
    return if (arm64) mc.ss.pc else mc.ss.rip;
}

pub inline fn setPc(mc: *std.c.mcontext_t, v: u64) void {
    if (arm64) {
        mc.ss.pc = v;
    } else {
        mc.ss.rip = v;
    }
}

pub inline fn sp(mc: *std.c.mcontext_t) u64 {
    return if (arm64) mc.ss.sp else mc.ss.rsp;
}

pub inline fn setSp(mc: *std.c.mcontext_t, v: u64) void {
    if (arm64) {
        mc.ss.sp = v;
    } else {
        mc.ss.rsp = v;
    }
}

// faultAddr is the address a memory fault touched (SIGSEGV/SIGBUS): arm64 carries
// it in the exception state's FAR, x86-64 in faultvaddr.
pub inline fn faultAddr(mc: *std.c.mcontext_t) u64 {
    return if (arm64) mc.es.far else mc.es.faultvaddr;
}

// flags is the processor status word: arm64 CPSR (the single-step bit lives in
// SPSR.SS), x86-64 RFLAGS (the single-step bit is TF, bit 8).
pub inline fn flags(mc: *std.c.mcontext_t) u64 {
    return if (arm64) @as(u64, mc.ss.cpsr) else mc.ss.rflags;
}

pub inline fn setFlags(mc: *std.c.mcontext_t, v: u64) void {
    if (arm64) {
        mc.ss.cpsr = @intCast(v);
    } else {
        mc.ss.rflags = v;
    }
}
