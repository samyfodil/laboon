// fsmem.zig — emulate an x86-64 %fs-relative memory instruction that faulted.
//
// glibc keeps its thread pointer in %fs and reads its TLS as %fs:disp. The
// physical %fs base cannot be set under Rosetta (wrfsbase raises SIGILL), so the
// guest's %fs base is virtualized: arch_prctl(ARCH_SET_FS) stores it
// (stub.g_guest_fsbase) and the %fs-relative instructions are left in place.
// Each one faults (the real %fs base is 0, so it touches a low address); onFault
// calls emulate, which recomputes the address against the stored base, performs
// the access, sets the flags the opcode defines, and steps past it. This is the
// fault-handler fallback rewrite/fs.go's PatchFS leaves sites for; an island
// rewrite is the later fast path.

const std = @import("std");
const tstate = @import("tstate.zig");

// gpr returns a pointer to GPR n (0=rax..15=r15) in the thread state.
fn gpr(mc: *std.c.mcontext_t, n: u8) *u64 {
    return switch (n & 15) {
        0 => &mc.ss.rax,
        1 => &mc.ss.rcx,
        2 => &mc.ss.rdx,
        3 => &mc.ss.rbx,
        4 => &mc.ss.rsp,
        5 => &mc.ss.rbp,
        6 => &mc.ss.rsi,
        7 => &mc.ss.rdi,
        8 => &mc.ss.r8,
        9 => &mc.ss.r9,
        10 => &mc.ss.r10,
        11 => &mc.ss.r11,
        12 => &mc.ss.r12,
        13 => &mc.ss.r13,
        14 => &mc.ss.r14,
        else => &mc.ss.r15,
    };
}

fn mask(size: u8) u64 {
    return switch (size) {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffffffff,
        else => ~@as(u64, 0),
    };
}

fn rd32(p: [*]const u8) u32 {
    return @as(u32, p[0]) | @as(u32, p[1]) << 8 | @as(u32, p[2]) << 16 | @as(u32, p[3]) << 24;
}

fn loadN(ea: u64, size: u8) u64 {
    return switch (size) {
        1 => @as(*align(1) const u8, @ptrFromInt(ea)).*,
        2 => @as(*align(1) const u16, @ptrFromInt(ea)).*,
        4 => @as(*align(1) const u32, @ptrFromInt(ea)).*,
        else => @as(*align(1) const u64, @ptrFromInt(ea)).*,
    };
}

fn storeN(ea: u64, size: u8, v: u64) void {
    switch (size) {
        1 => @as(*align(1) u8, @ptrFromInt(ea)).* = @truncate(v),
        2 => @as(*align(1) u16, @ptrFromInt(ea)).* = @truncate(v),
        4 => @as(*align(1) u32, @ptrFromInt(ea)).* = @truncate(v),
        else => @as(*align(1) u64, @ptrFromInt(ea)).* = v,
    }
}

// setReg writes v into register r with x86 width semantics: a 32-bit result
// zero-extends to 64, 16- and 8-bit results leave the upper bits intact.
fn setReg(r: *u64, size: u8, v: u64) void {
    switch (size) {
        8 => r.* = v,
        4 => r.* = v & 0xffffffff,
        2 => r.* = (r.* & ~@as(u64, 0xffff)) | (v & 0xffff),
        else => r.* = (r.* & ~@as(u64, 0xff)) | (v & 0xff),
    }
}

const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;

fn parity(v: u64) bool {
    return @popCount(v & 0xff) & 1 == 0;
}

fn signBit(size: u8) u64 {
    return (mask(size) >> 1) + 1;
}

// szZSP sets the result-only flags (ZF, SF, PF) from res, clearing them first.
fn szZSP(f: u64, size: u8, res: u64) u64 {
    var out = f & ~(ZF | SF | PF);
    const r = res & mask(size);
    if (r == 0) out |= ZF;
    if ((r & signBit(size)) != 0) out |= SF;
    if (parity(r)) out |= PF;
    return out;
}

// logicFlags is the flag result of AND/OR/XOR/TEST: CF=OF=0, AF undefined (0).
fn logicFlags(f: u64, size: u8, res: u64) u64 {
    return szZSP(f & ~(CF | OF | AF), size, res);
}

// subFlags is the flag result of SUB/CMP (a - b at this width).
fn subFlags(f: u64, size: u8, a: u64, b: u64) u64 {
    const m = mask(size);
    const res = (a -% b) & m;
    var out = szZSP(f & ~(CF | OF | AF), size, res);
    if ((a & m) < (b & m)) out |= CF;
    const sign = signBit(size);
    if ((((a ^ b) & (a ^ res)) & sign) != 0) out |= OF;
    if (((a ^ b ^ res) & 0x10) != 0) out |= AF;
    return out;
}

// addFlags is the flag result of ADD (a + b at this width).
fn addFlags(f: u64, size: u8, a: u64, b: u64) u64 {
    const m = mask(size);
    const res = (a +% b) & m;
    var out = szZSP(f & ~(CF | OF | AF), size, res);
    if (res < (a & m)) out |= CF;
    const sign = signBit(size);
    if (((~(a ^ b) & (a ^ res)) & sign) != 0) out |= OF;
    if (((a ^ b ^ res) & 0x10) != 0) out |= AF;
    return out;
}

// emulate services a faulted %fs-relative instruction. Returns false if the
// fault is not an emulable %fs memory instruction (the caller delivers it).
pub fn emulate(mc: *std.c.mcontext_t) bool {
    const code: [*]const u8 = if (@import("fsisl.zig").original(tstate.pc(mc))) |o| o.ptr else @ptrFromInt(tstate.pc(mc));
    var i: usize = 0;
    var has_fs = false;
    var op66 = false;
    var rex: u8 = 0;
    // Legacy prefixes.
    while (true) : (i += 1) {
        switch (code[i]) {
            0x64 => has_fs = true,
            0x66 => op66 = true,
            0xf0, 0xf2, 0xf3 => {}, // lock/rep: ignore for these forms
            0x2e, 0x36, 0x3e, 0x26, 0x65, 0x67 => return false, // other seg / addr-size
            else => break,
        }
    }
    if (!has_fs) return false;
    if ((code[i] & 0xf0) == 0x40) {
        rex = code[i];
        i += 1;
    }
    const rexW = rex & 8 != 0;
    const rexR: u8 = if (rex & 4 != 0) 8 else 0;
    const rexX: u8 = if (rex & 2 != 0) 8 else 0;
    const rexB: u8 = if (rex & 1 != 0) 8 else 0;

    var op = code[i];
    i += 1;
    var two = false;
    if (op == 0x0f) {
        two = true;
        op = code[i];
        i += 1;
    }

    // ModRM.
    const modrm = code[i];
    i += 1;
    const mod = modrm >> 6;
    const reg = ((modrm >> 3) & 7) | rexR;
    const rm = modrm & 7;
    if (mod == 3) return false; // register operand: not a memory fault

    var base: i16 = -1;
    var index: i16 = -1;
    var scale: u6 = 0;
    var disp: i64 = 0;
    var disp_len: usize = 0;
    switch (mod) {
        1 => disp_len = 1,
        2 => disp_len = 4,
        else => {},
    }
    if (rm == 4) {
        const sib = code[i];
        i += 1;
        scale = @intCast(sib >> 6);
        const idx = ((sib >> 3) & 7) | rexX;
        if (idx != 4) index = idx;
        const b = sib & 7;
        if (mod == 0 and b == 5) {
            disp_len = 4;
        } else {
            base = b | rexB;
        }
    } else if (mod == 0 and rm == 5) {
        return false; // rip-relative
    } else {
        base = rm | rexB;
    }
    switch (disp_len) {
        1 => disp = @as(i8, @bitCast(code[i])),
        4 => disp = @as(i32, @bitCast(rd32(code + i))),
        else => {},
    }
    i += disp_len;

    // Effective address: the stored guest %fs base plus the ordinary memory
    // operand (base + index*scale + disp).
    var ea = @import("root").g_guest_fsbase +% @as(u64, @bitCast(disp));
    if (base >= 0) ea +%= gpr(mc, @intCast(base)).*;
    if (index >= 0) ea +%= gpr(mc, @intCast(index)).* << scale;

    if (two) {
        // MOVZX/MOVSX r, r/m8|r/m16.
        const dsize: u8 = if (rexW) @as(u8, 8) else if (op66) @as(u8, 2) else 4;
        const ssize: u8 = if (op == 0xb6 or op == 0xbe) @as(u8, 1) else 2;
        if (op == 0xb6 or op == 0xb7) {
            setReg(gpr(mc, reg), dsize, loadN(ea, ssize));
        } else if (op == 0xbe or op == 0xbf) {
            const v = loadN(ea, ssize);
            const ext = if ((v & signBit(ssize)) != 0) v | ~mask(ssize) else v;
            setReg(gpr(mc, reg), dsize, ext);
        } else return fault(mc);
        tstate.setPc(mc, tstate.pc(mc) + i);
        return true;
    }

    // size and direction for the ALU/MOV grid: low bit selects 8-bit, the next
    // bit selects reg<-mem (load) vs mem<-reg (store).
    const byte_sz = (op & 1) == 0;
    const load = (op & 2) != 0;
    const size: u8 = if (byte_sz) 1 else if (rexW) @as(u8, 8) else if (op66) @as(u8, 2) else 4;
    // A high-byte register (AH..BH: reg 4..7, 8-bit, no REX) is not modelled.
    // Only the forms with a register operand carry one; the /digit groups below
    // (0x80/0x81/0x83, 0xc6/0xc7) use ModRM.reg as an opcode extension.
    const hiByte = byte_sz and rex == 0 and reg >= 4;

    switch (op) {
        0x88, 0x89, 0x8a, 0x8b => { // MOV
            if (hiByte) return fault(mc);
            if (load) {
                setReg(gpr(mc, reg), size, loadN(ea, size));
            } else {
                storeN(ea, size, gpr(mc, reg).*);
            }
        },
        0x80, 0x81, 0x83 => { // ALU r/m, imm (operation in ModRM.reg)
            const gsize: u8 = if (op == 0x80) 1 else if (rexW) @as(u8, 8) else if (op66) @as(u8, 2) else 4;
            const ilen: u8 = if (op == 0x81 and !op66) @as(u8, 4) else if (op == 0x81) @as(u8, 2) else 1;
            const raw = loadN(@intFromPtr(code + i), ilen);
            const imm = (if ((raw & signBit(ilen)) != 0) raw | ~mask(ilen) else raw) & mask(gsize);
            i += ilen;
            const a = loadN(ea, gsize);
            var res: u64 = 0;
            var f = mc.ss.rflags;
            var writes = true;
            switch ((modrm >> 3) & 7) {
                0 => {
                    res = a +% imm;
                    f = addFlags(f, gsize, a, imm);
                },
                1 => {
                    res = a | imm;
                    f = logicFlags(f, gsize, res);
                },
                4 => {
                    res = a & imm;
                    f = logicFlags(f, gsize, res);
                },
                5 => {
                    res = a -% imm;
                    f = subFlags(f, gsize, a, imm);
                },
                6 => {
                    res = a ^ imm;
                    f = logicFlags(f, gsize, res);
                },
                7 => { // CMP
                    f = subFlags(f, gsize, a, imm);
                    writes = false;
                },
                else => return fault(mc),
            }
            mc.ss.rflags = f;
            if (writes) storeN(ea, gsize, res);
        },
        0xc6, 0xc7 => { // MOV r/m, imm
            const imlen: u8 = if (op == 0xc6) 1 else 4;
            const raw = loadN(@intFromPtr(code + i), imlen);
            const imm = if (size == 8 and (raw & signBit(imlen)) != 0) raw | ~mask(imlen) else raw;
            storeN(ea, size, imm);
            i += imlen;
        },
        0x84, 0x85 => { // TEST r/m, r
            const res = loadN(ea, size) & gpr(mc, reg).*;
            mc.ss.rflags = logicFlags(mc.ss.rflags, size, res);
        },
        0xf6, 0xf7 => { // TEST r/m, imm; NOT; NEG
            const a = loadN(ea, size);
            switch ((modrm >> 3) & 7) {
                0, 1 => {
                    const ilen: u8 = if (op == 0xf6) 1 else if (op66) @as(u8, 2) else 4;
                    const raw = loadN(@intFromPtr(code + i), ilen);
                    const imm = if ((raw & signBit(ilen)) != 0) raw | ~mask(ilen) else raw;
                    i += ilen;
                    mc.ss.rflags = logicFlags(mc.ss.rflags, size, a & imm);
                },
                2 => storeN(ea, size, ~a),
                3 => {
                    var f = subFlags(mc.ss.rflags, size, 0, a) & ~CF;
                    if ((a & mask(size)) != 0) f |= CF;
                    mc.ss.rflags = f;
                    storeN(ea, size, 0 -% a);
                },
                else => return fault(mc),
            }
        },
        0xfe, 0xff => { // INC/DEC r/m (CF preserved)
            const a = loadN(ea, size);
            const cf = mc.ss.rflags & CF;
            switch ((modrm >> 3) & 7) {
                0 => {
                    mc.ss.rflags = (addFlags(mc.ss.rflags, size, a, 1) & ~CF) | cf;
                    storeN(ea, size, a +% 1);
                },
                1 => {
                    mc.ss.rflags = (subFlags(mc.ss.rflags, size, a, 1) & ~CF) | cf;
                    storeN(ea, size, a -% 1);
                },
                else => return fault(mc),
            }
        },
        0x86, 0x87 => { // XCHG r/m, r
            if (hiByte) return fault(mc);
            const r = gpr(mc, reg);
            const m = loadN(ea, size);
            storeN(ea, size, r.*);
            setReg(r, size, m);
        },
        else => {
            // ALU grid 0x00..0x3b: ADD/OR/AND/SUB/XOR/CMP (ADC/SBB excluded).
            if ((op & 0xc4) != 0 or (op & 7) >= 4 or hiByte) return fault(mc);
            const alu = (op >> 3) & 7;
            const m = loadN(ea, size);
            const rv = gpr(mc, reg).* & mask(size);
            const a = if (load) rv else m;
            const b = if (load) m else rv;
            var res: u64 = 0;
            var f = mc.ss.rflags;
            var writes = true;
            switch (alu) {
                0 => {
                    res = a +% b;
                    f = addFlags(f, size, a, b);
                },
                1 => {
                    res = a | b;
                    f = logicFlags(f, size, res);
                },
                4 => {
                    res = a & b;
                    f = logicFlags(f, size, res);
                },
                5 => {
                    res = a -% b;
                    f = subFlags(f, size, a, b);
                },
                6 => {
                    res = a ^ b;
                    f = logicFlags(f, size, res);
                },
                7 => { // CMP: flags only, no writeback
                    f = subFlags(f, size, a, b);
                    writes = false;
                },
                else => return fault(mc),
            }
            mc.ss.rflags = f;
            if (writes) {
                if (load) setReg(gpr(mc, reg), size, res) else storeN(ea, size, res);
            }
        },
    }
    tstate.setPc(mc, tstate.pc(mc) + i);
    return true;
}

extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;

// fault takes an %fs instruction form emulate does not handle: it runs in an
// island (fsisl.zig) where it can have one; else it is reported, so the corpus
// can be grown from what a real guest issues, and the fault is delivered
// (return false) -- a loud miss, never a silent wrong answer.
fn fault(mc: *std.c.mcontext_t) bool {
    if (@import("fsisl.zig").patch(tstate.pc(mc), @import("root").g_tp_key, true)) return true;
    const p: [*]const u8 = @ptrFromInt(tstate.pc(mc));
    var b: [128]u8 = undefined;
    const s = std.fmt.bufPrint(&b, "FSEMU-MISS pc={x} b={x} {x} {x} {x} {x} {x} {x} {x}\n", .{
        tstate.pc(mc), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
    }) catch return false;
    _ = write(2, s.ptr, s.len);
    return false;
}
