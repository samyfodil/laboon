// hwcap.zig — AT_HWCAP / AT_HWCAP2 for the guest, from the host's
// hw.optional sysctls. Libraries pick their fast paths from these bits
// (OpenSSL's AES/SHA/PMULL code, LSE atomics), so reporting none leaves the
// guest on generic code.
//
// Left out even when the CPU has them: CPUID (Darwin does not emulate EL0 reads
// of the ID registers, Linux does), SVE/SME (the trampolines do not save that
// state), BTI and MTE (they need Linux mmap/prctl support), PAC (Linux manages
// the keys; Darwin's arm64 ABI differs), and EVTSTRM/ECV/WFxT (timer behaviour
// Linux promises and Darwin does not).

const std = @import("std");

extern "c" fn sysctlbyname(name: [*:0]const u8, old: ?*anyopaque, oldlen: ?*usize, new: ?*anyopaque, newlen: usize) c_int;

const Feat = struct { name: [*:0]const u8, word: u1, bit: u6 };

const feats = [_]Feat{
    .{ .name = "hw.optional.floatingpoint", .word = 0, .bit = 0 }, // FP
    .{ .name = "hw.optional.arm.AdvSIMD", .word = 0, .bit = 1 }, // ASIMD
    .{ .name = "hw.optional.arm.FEAT_AES", .word = 0, .bit = 3 },
    .{ .name = "hw.optional.arm.FEAT_PMULL", .word = 0, .bit = 4 },
    .{ .name = "hw.optional.arm.FEAT_SHA1", .word = 0, .bit = 5 },
    .{ .name = "hw.optional.arm.FEAT_SHA256", .word = 0, .bit = 6 }, // SHA2
    .{ .name = "hw.optional.arm.FEAT_CRC32", .word = 0, .bit = 7 },
    .{ .name = "hw.optional.arm.FEAT_LSE", .word = 0, .bit = 8 }, // ATOMICS
    .{ .name = "hw.optional.arm.FEAT_FP16", .word = 0, .bit = 9 }, // FPHP
    .{ .name = "hw.optional.arm.FEAT_FP16", .word = 0, .bit = 10 }, // ASIMDHP
    .{ .name = "hw.optional.arm.FEAT_RDM", .word = 0, .bit = 12 },
    .{ .name = "hw.optional.arm.FEAT_JSCVT", .word = 0, .bit = 13 },
    .{ .name = "hw.optional.arm.FEAT_FCMA", .word = 0, .bit = 14 },
    .{ .name = "hw.optional.arm.FEAT_LRCPC", .word = 0, .bit = 15 },
    .{ .name = "hw.optional.arm.FEAT_DPB", .word = 0, .bit = 16 }, // DCPOP
    .{ .name = "hw.optional.arm.FEAT_SHA3", .word = 0, .bit = 17 },
    .{ .name = "hw.optional.arm.FEAT_DotProd", .word = 0, .bit = 20 },
    .{ .name = "hw.optional.arm.FEAT_SHA512", .word = 0, .bit = 21 },
    .{ .name = "hw.optional.arm.FEAT_FHM", .word = 0, .bit = 23 },
    .{ .name = "hw.optional.arm.FEAT_DIT", .word = 0, .bit = 24 },
    .{ .name = "hw.optional.arm.FEAT_LSE2", .word = 0, .bit = 25 }, // USCAT
    .{ .name = "hw.optional.arm.FEAT_LRCPC2", .word = 0, .bit = 26 }, // ILRCPC
    .{ .name = "hw.optional.arm.FEAT_FlagM", .word = 0, .bit = 27 },
    .{ .name = "hw.optional.arm.FEAT_SSBS", .word = 0, .bit = 28 },
    .{ .name = "hw.optional.arm.FEAT_SB", .word = 0, .bit = 29 },
    .{ .name = "hw.optional.arm.FEAT_DPB2", .word = 1, .bit = 0 }, // DCPODP
    .{ .name = "hw.optional.arm.FEAT_FlagM2", .word = 1, .bit = 7 },
    .{ .name = "hw.optional.arm.FEAT_FRINTTS", .word = 1, .bit = 8 }, // FRINT
    .{ .name = "hw.optional.arm.FEAT_I8MM", .word = 1, .bit = 13 },
    .{ .name = "hw.optional.arm.FEAT_BF16", .word = 1, .bit = 14 },
    .{ .name = "hw.optional.arm.FEAT_AFP", .word = 1, .bit = 20 },
    .{ .name = "hw.optional.arm.FEAT_RPRES", .word = 1, .bit = 21 },
    .{ .name = "hw.optional.arm.FEAT_CSSC", .word = 1, .bit = 34 },
};

pub var hwcap: [2]u64 = .{ 0, 0 };

// midr is the MIDR_EL1 the guest reads: Apple's implementer, the P-core part
// of this chip generation, variant and revision 0, as /proc/cpuinfo names it
// (appleChips in sandbox/hostinfo_darwin.go; keep them in step).
pub var midr: u64 = midrOf(0x023);

fn midrOf(part: u64) u64 {
    return 0x61 << 24 | 0xf << 16 | part << 4;
}

const chips = [_]struct { prefix: []const u8, part: u64 }{
    .{ .prefix = "Apple M1", .part = 0x023 },
    .{ .prefix = "Apple M2", .part = 0x033 },
    .{ .prefix = "Apple M3", .part = 0x049 },
    .{ .prefix = "Apple M4", .part = 0x059 },
};

// init reads the sysctls; it must run before Seatbelt, which denies sysctl.
pub fn init() void {
    for (feats) |f| {
        var v: u32 = 0;
        var len: usize = @sizeOf(u32);
        if (sysctlbyname(f.name, &v, &len, null, 0) == 0 and v != 0) hwcap[f.word] |= @as(u64, 1) << f.bit;
    }
    var brand: [128]u8 = undefined;
    var blen: usize = brand.len;
    if (sysctlbyname("machdep.cpu.brand_string", &brand, &blen, null, 0) == 0) {
        for (chips) |c| {
            if (blen >= c.prefix.len and std.mem.eql(u8, brand[0..c.prefix.len], c.prefix)) midr = midrOf(c.part);
        }
    }
}

// isar builds ID_AA64ISAR0/1/2_EL1 from the host features above, for the mrs
// reads the stub serves (sig.zig); every field is a feature level, so one left
// 0 reads as absent and never claims what the host lacks. This mirrors the
// supervisor's isarFromHwcap (sandbox/idregs.go); keep them in step. The
// registers that also hold layout values are not built (they keep trapping).
pub fn isar() [3]u64 {
    var r = [3]u64{ 0, 0, 0 };
    const h0 = hwcap[0];
    const h1 = hwcap[1];
    const has = struct {
        fn f(h: u64, b: u6) bool {
            return h & (@as(u64, 1) << b) != 0;
        }
    }.f;
    // ISAR0.
    if (has(h0, 4)) r[0] |= @as(u64, 2) << 4 else if (has(h0, 3)) r[0] |= @as(u64, 1) << 4; // AES / PMULL
    if (has(h0, 5)) r[0] |= @as(u64, 1) << 8; // SHA1
    if (has(h0, 21)) r[0] |= @as(u64, 2) << 12 else if (has(h0, 6)) r[0] |= @as(u64, 1) << 12; // SHA2 / SHA512
    if (has(h0, 7)) r[0] |= @as(u64, 1) << 16; // CRC32
    if (has(h0, 8)) r[0] |= @as(u64, 2) << 20; // LSE
    if (has(h0, 12)) r[0] |= @as(u64, 1) << 28; // RDM
    if (has(h0, 17)) r[0] |= @as(u64, 1) << 32; // SHA3
    if (has(h0, 20)) r[0] |= @as(u64, 1) << 44; // DP
    if (has(h0, 23)) r[0] |= @as(u64, 1) << 48; // FHM
    if (has(h1, 7)) r[0] |= @as(u64, 2) << 52 else if (has(h0, 27)) r[0] |= @as(u64, 1) << 52; // FlagM / FlagM2
    // ISAR1.
    if (has(h1, 0)) r[1] |= @as(u64, 2) << 0 else if (has(h0, 16)) r[1] |= @as(u64, 1) << 0; // DPB / DPB2
    if (has(h0, 13)) r[1] |= @as(u64, 1) << 12; // JSCVT
    if (has(h0, 14)) r[1] |= @as(u64, 1) << 16; // FCMA
    if (has(h0, 26)) r[1] |= @as(u64, 2) << 20 else if (has(h0, 15)) r[1] |= @as(u64, 1) << 20; // LRCPC / LRCPC2
    if (has(h1, 8)) r[1] |= @as(u64, 1) << 32; // FRINTTS
    if (has(h0, 29)) r[1] |= @as(u64, 1) << 36; // SB
    if (has(h1, 14)) r[1] |= @as(u64, 1) << 44; // BF16
    if (has(h1, 13)) r[1] |= @as(u64, 1) << 52; // I8MM
    // ISAR2.
    if (has(h1, 21)) r[2] |= @as(u64, 1) << 4; // RPRES
    if (has(h1, 34)) r[2] |= @as(u64, 1) << 52; // CSSC
    return r;
}
