// vmm.zig — the HVF backend's VM monitor: run an unmodified Linux guest inside a
// Hypervisor.framework VM and surface each `svc` as a syscall for laboon's
// existing supervisor to service (see BACKEND.md). This is the Zig form of the
// proven C spikes (../hvf/hvspike5.c). run() surfaces each `svc`; serveSyscall()
// posts it over the existing channel and handles REP_PEEK/REP_POKE against the
// VM's RAM. Phase 2b: REP_HOST/fork/clone in the VM model, the stub-local fast
// paths, and the HVF stub main that drives this with chan.exchange.
//
// Register/sysreg values are from <Hypervisor/hv_vcpu_types.h>.

const std = @import("std");
const smaps = @import("smaps.zig");
const chan = @import("chan.zig"); // the shared-memory channel ABI, reused as-is

const hv_return_t = c_int;
const HV_SUCCESS: hv_return_t = 0;

// hv_vcpu_exit_t: a 4-byte reason, 4 pad, then the exception triple.
const VcpuExit = extern struct {
    reason: u32,
    exception: extern struct {
        syndrome: u64, // ESR of the trapping exception
        virtual_address: u64,
        physical_address: u64, // the faulting IPA (stage-2 faults)
    },
};
const EXIT_EXCEPTION: u32 = 1;

// General registers (enum order: X0=0..X30=30, then PC, FPCR, FPSR, CPSR).
const REG_X0: u32 = 0;
const REG_PC: u32 = 31;
const REG_FPCR: u32 = 32;
const REG_FPSR: u32 = 33;
const REG_CPSR: u32 = 34;
const SIMD_Q0: u32 = 0; // hv_simd_fp_reg_t enum: Q0..Q31 = 0..31
const Simd16 = @Vector(16, u8); // hv_simd_fp_uchar16_t

// System registers (explicit values from the header).
const SR_SCTLR_EL1: u32 = 0xc080;
const SR_CPACR_EL1: u32 = 0xc082;
const SR_TTBR0_EL1: u32 = 0xc100;
const SR_TCR_EL1: u32 = 0xc102;
const SR_SPSR_EL1: u32 = 0xc200;
const SR_ELR_EL1: u32 = 0xc201;
const SR_ESR_EL1: u32 = 0xc290;
const SR_FAR_EL1: u32 = 0xc300;
const SR_MAIR_EL1: u32 = 0xc510;
const SR_VBAR_EL1: u32 = 0xc600;
const SR_SP_EL1: u32 = 0xe208;

const MEM_READ: u64 = 1;
const MEM_WRITE: u64 = 2;
const MEM_EXEC: u64 = 4;

extern "c" fn hv_vm_create(config: ?*anyopaque) hv_return_t;
extern "c" fn hv_vm_destroy() hv_return_t;
extern "c" fn hv_vm_map(addr: *anyopaque, ipa: u64, size: usize, flags: u64) hv_return_t;
extern "c" fn hv_vcpu_create(vcpu: *u64, exit: **VcpuExit, config: ?*anyopaque) hv_return_t;
extern "c" fn hv_vcpu_destroy(vcpu: u64) hv_return_t;
extern "c" fn hv_vcpu_run(vcpu: u64) hv_return_t;
extern "c" fn hv_vcpus_exit(vcpus: [*]const u64, count: u32) hv_return_t;
extern "c" fn hv_vcpu_set_reg(vcpu: u64, reg: u32, value: u64) hv_return_t;
extern "c" fn hv_vcpu_get_reg(vcpu: u64, reg: u32, value: *u64) hv_return_t;
extern "c" fn hv_vcpu_set_sys_reg(vcpu: u64, reg: u32, value: u64) hv_return_t;
extern "c" fn hv_vcpu_set_trap_debug_exceptions(vcpu: u64, value: bool) hv_return_t;
extern "c" fn hv_vcpu_get_sys_reg(vcpu: u64, reg: u32, value: *u64) hv_return_t;
extern "c" fn hv_vcpu_get_simd_fp_reg(vcpu: u64, reg: u32, value: *Simd16) hv_return_t;
extern "c" fn hv_vcpu_set_simd_fp_reg(vcpu: u64, reg: u32, value: Simd16) hv_return_t;

// Control region near the top of the FIRST GiB (identity-mapped), out of the way
// of the guest binary (low), its brk heap (grows up) and its mmap/stack (grow
// down). 4 KiB granule: L0 -> L1 -> L2 -> 512 L3 tables (2 MiB, L3_BASE) that map
// the first GiB as pages, so mprotect can enforce per-page permissions there;
// L1[1..32] then block-map [1 GiB, 32 GiB) for the extended mmap window (init).
const L3_BASE: u64 = 0x3FC0_0000; // 512 L3 tables, 4 KiB each = 2 MiB (0..1 GiB)
const L2_IPA: u64 = 0x3FE0_0000;
const L1_IPA: u64 = 0x3FE0_1000;
const L0_IPA: u64 = 0x3FE0_2000;
const VBAR: u64 = 0x3FE1_0000;
const TLBI_TRAMP: u64 = VBAR + 0x800; // tlbi; dsb; isb; hvc -- run to flush the guest TLB
// rt_sigreturn restorer trampoline (`mov x8, #139; svc #0`). A signal handler
// with no SA_RESTORER returns (ret to x30) to the kernel's VDSO sigreturn
// trampoline; we have no VDSO, so deliverSignal points x30 here instead. Go and
// arm64 musl rely on this (they do not set sa_restorer).
const SIG_RESTORER: u64 = VBAR + 0x900;

// Page-descriptor flags: valid page, AttrIndx0 (Normal WB), AP=RW-EL1, inner-
// shareable, access flag. Protection variants toggle AP (RO) and PXN/UXN (XN).
const PAGE_RWX: u64 = 0x3 | (3 << 8) | (1 << 10);
const PTE_RO: u64 = 2 << 6; // AP=10: read-only at EL1
const PTE_XN: u64 = (1 << 53) | (1 << 54); // PXN|UXN: execute-never

// MMAP_TOP: small anonymous mmaps bump down from here through the first GiB; the
// stack lives above it (its top is below L3_BASE in hvf_stub.zig).
pub const MMAP_TOP: u64 = 0x3FB0_0000;

// MMAP_MIN is Linux's mmap_min_addr: nothing is mapped below it, so a null
// pointer's access faults (Go's nil checks rely on it, and its arm64
// executables are linked right above it).
const MMAP_MIN: u64 = 0x10000;

// Extended mmap window [1 GiB, 32 GiB): large mappings that no longer fit the
// first-GiB arena live here, bumping down from EXT_TOP. It is mapped by 1 GiB
// block descriptors in L1[1..32] (init), so it needs no per-page tables.
const EXT_BASE: u64 = 0x4000_0000; // 1 GiB -- end of the first-GiB arena
pub const EXT_TOP: u64 = 0x8_0000_0000; // 32 GiB == RAM_LEN (hvf_stub.zig)
// A dynamically-linked guest's interpreter (ld.so) loads at or above here, in
// the extended window -- above the first-GiB arena (main ELF, brk, small mmaps,
// stack and page tables all live below 1 GiB). Guest mmaps bump down from the
// window's top and are floored above the loaded interpreter (see g_ext_floor).
pub const INTERP_BASE: u64 = EXT_BASE;
// 1 GiB block descriptor: valid block (bits[1:0]=01) vs the 0x3 of a table/page,
// same Normal-WB / AP=RW-EL1 / inner-shareable / access-flag attributes as PAGE_RWX.
const BLOCK_RWX: u64 = 0x1 | (3 << 8) | (1 << 10);

// Linux/arm64 memory syscalls the VM services locally (the guest's address space
// is the VM RAM, already mapped RWX), plus the MAP_ANONYMOUS flag.
const NR_PREAD64: u64 = 67;
const NR_BRK: u64 = 214;
const NR_MUNMAP: u64 = 215;
const NR_MMAP: u64 = 222;
const NR_MPROTECT: u64 = 226;
const NR_MADVISE: u64 = 233;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_REMOVE: u64 = 9;
const MADV_DONTNEED_LOCKED: u64 = 24;
const MAP_ANON: u64 = 0x20;
const MAP_FIXED: u64 = 0x10;
const MAP_SHARED: u64 = 0x1;
const MAP_TYPE: u64 = 0xf;
const PROT_WRITE: u64 = 2;
const NR_PWRITE64: u64 = 68;
const NR_MREMAP: u64 = 216;
const NR_MSYNC: u64 = 227;
const NR_MINCORE: u64 = 232;
const NR_MEMBARRIER: u64 = 283;
const NR_RT_SIGPENDING: u64 = 136;
const MS_ASYNC: u64 = 1;
const MS_INVALIDATE: u64 = 2;
const MS_SYNC: u64 = 4;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;
const EPERM: u64 = 1;
const ENOMEM: u64 = 12;
const EINVAL: u64 = 22;
const EFAULT: u64 = 14;

// Linux/arm64 clock, sleep and randomness syscalls the VM serves locally against
// the Darwin host (they touch only this process). The native stub does the same
// in local.zig, but via @ptrFromInt on the guest VA, which is wrong here -- the
// guest timespec/buffer lives at v.ram + VA. Without these the HVF stub forwarded
// them to the supervisor, which has no handler and returns ENOSYS; a Go runtime
// then spun forever calling clock_gettime+nanosleep (e.g. the `go` tool).
const NR_NANOSLEEP: u64 = 101;
const NR_CLOCK_GETTIME: u64 = 113;
const NR_CLOCK_GETRES: u64 = 114;
const NR_CLOCK_NANOSLEEP: u64 = 115;
const NR_SCHED_YIELD: u64 = 124;
const NR_GETTIMEOFDAY: u64 = 169;
const NR_GETRANDOM: u64 = 278;
const NR_RESTART_SYSCALL: u64 = 128;

// The rest of a relative sleep a signal cut short (monotonic ns), which
// restart_syscall resumes on this vcpu thread (Linux's restart block); 0 for
// none.
threadlocal var restart_deadline: i64 = 0;
threadlocal var restart_rem: u64 = 0;

// Darwin clock ids (for clock_gettime).
const DW_CLOCK_REALTIME: c_int = 0;
const DW_CLOCK_MONOTONIC_RAW: c_int = 4;
const DW_CLOCK_MONOTONIC: c_int = 6;

const Timespec = extern struct { sec: i64, nsec: i64 };
extern "c" fn clock_gettime(clk: c_int, ts: *Timespec) c_int;
extern "c" fn nanosleep(req: *const Timespec, rem: ?*Timespec) c_int;
extern "c" fn getentropy(buf: [*]u8, len: usize) c_int;
extern "c" fn sched_yield() c_int;

// darwinClock maps a Linux clockid; CPU-time clocks (2,3) approximate with the
// monotonic clock (Darwin's per-thread CPU time goes through a Mach call the
// Seatbelt profile would deny, as local.zig notes).
fn darwinClock(id: u64) ?c_int {
    return switch (id) {
        0, 5, 8 => DW_CLOCK_REALTIME, // REALTIME, _COARSE, _ALARM
        1, 6, 7, 9 => DW_CLOCK_MONOTONIC, // MONOTONIC, _COARSE, BOOTTIME, _ALARM
        4 => DW_CLOCK_MONOTONIC_RAW,
        2, 3 => DW_CLOCK_MONOTONIC, // PROCESS/THREAD CPUTIME approximated
        else => null,
    };
}

fn monoNs() i64 {
    var ts: Timespec = undefined;
    _ = clock_gettime(DW_CLOCK_MONOTONIC, &ts);
    return ts.sec * 1_000_000_000 + ts.nsec;
}

fn readTs(ram: [*]u8, addr: u64) Timespec {
    return @as(*align(1) const Timespec, @ptrFromInt(@intFromPtr(ram) + addr)).*;
}
fn writeTs(ram: [*]u8, addr: u64, ts: Timespec) void {
    @as(*align(1) Timespec, @ptrFromInt(@intFromPtr(ram) + addr)).* = ts;
}

pub const Error = error{ VmCreate, Map, VcpuCreate, Run };

// Syscall is what run() surfaces on each guest `svc`: the Linux syscall number
// and its six argument registers. The caller services it (phase 2: over the
// channel to the supervisor) and calls resume() with the result.
pub const Syscall = struct {
    nr: u64,
    args: [6]u64,
    elr: u64, // PC to resume at (after the svc)
    spsr: u64,
};

pub const Exit = union(enum) {
    syscall: Syscall,
    fault: Fault, // a real guest exception
    done: void, // guest ran off / brk
    signal: void, // a signal waits for the thread, which ran guest code
};

pub const Vmm = struct {
    ram: [*]u8,
    ram_len: usize,
    vcpu: u64 = 0,
    exit: *VcpuExit = undefined,

    // init creates the VM and maps `ram` (caller-owned, page-aligned, zeroed)
    // at IPA 0, then writes the flat identity stage-1 tables and the hvc-stub
    // exception vector into it. A MAP_SHARED ram lets the supervisor peek/poke
    // guest memory directly (phase 2).
    pub fn init(ram: [*]u8, ram_len: usize) Error!Vmm {
        ram_base = @intFromPtr(ram);
        if (hv_vm_create(null) != HV_SUCCESS) return error.VmCreate;
        var v = Vmm{ .ram = ram, .ram_len = ram_len };
        // L0[0] -> L1 -> L2 -> 512 L3 tables; each L3 maps 512 identity 4 KiB
        // pages (RWX), so mprotect can change per-page permissions later.
        v.put64(L0_IPA, L1_IPA | 0x3);
        v.put64(L1_IPA, L2_IPA | 0x3);
        for (0..512) |k| v.put64(L2_IPA + k * 8, (L3_BASE + k * 0x1000) | 0x3);
        for (0..512) |k| {
            const tbl = L3_BASE + k * 0x1000;
            for (0..512) |j| v.put64(tbl + j * 8, (k * 0x200000 + j * 0x1000) | PAGE_RWX);
        }
        for (0..MMAP_MIN / 0x1000) |j| v.put64(L3_BASE + j * 8, 0);
        // Extend the stage-1 map to [1 GiB, 32 GiB) with 1 GiB block descriptors
        // in L1[1..32] -- one per gigabyte, no extra tables. The extended mmap
        // window lives here; it is RWX (mprotect is enforced only in the first
        // GiB, where the guest's code and the page tables sit).
        for (1..32) |g| v.put64(L1_IPA + g * 8, (@as(u64, g) * EXT_BASE) | BLOCK_RWX);
        // Sync-from-current-EL/SPx vector (VBAR+0x200): `hvc #1; b .`. Not
        // hvc #0: the hypervisor serves an hvc #0 whose x0 reads as an SMCCC
        // function itself (answering -1, NOT_SUPPORTED) and never exits, and
        // x0 here is the guest's syscall argument.
        v.put32(VBAR + 0x200, 0xD4000022);
        v.put32(VBAR + 0x204, 0x14000000);
        // TLB-flush trampoline: tlbi vmalle1; dsb ish; isb; hvc #1.
        v.put32(TLBI_TRAMP + 0, 0xD508871F);
        v.put32(TLBI_TRAMP + 4, 0xD5033B9F);
        v.put32(TLBI_TRAMP + 8, 0xD5033FDF);
        v.put32(TLBI_TRAMP + 12, 0xD4000022);
        // rt_sigreturn restorer: mov x8, #139 (0x8b); svc #0.
        v.put32(SIG_RESTORER + 0, 0xD2801168);
        v.put32(SIG_RESTORER + 4, 0xD4000001);
        if (hv_vm_map(@ptrCast(ram), 0, ram_len, MEM_READ | MEM_WRITE | MEM_EXEC) != HV_SUCCESS)
            return error.Map;
        if (hv_vcpu_create(&v.vcpu, &v.exit, null) != HV_SUCCESS) return error.VcpuCreate;
        return v;
    }

    pub fn deinit(v: *Vmm) void {
        _ = hv_vcpu_destroy(v.vcpu);
        _ = hv_vm_destroy();
    }

    fn put64(v: *Vmm, ipa: u64, val: u64) void {
        @as(*u64, @ptrCast(@alignCast(v.ram + ipa))).* = val;
    }
    fn put32(v: *Vmm, ipa: u64, val: u32) void {
        @as(*u32, @ptrCast(@alignCast(v.ram + ipa))).* = val;
    }

    // loadSegment copies a guest PT_LOAD into RAM at its vaddr (identity IPA).
    pub fn loadSegment(v: *Vmm, vaddr: u64, bytes: []const u8) void {
        @memcpy((v.ram + vaddr)[0..bytes.len], bytes);
    }

    // start sets the MMU up and places the vcpu at the guest entry with the
    // prepared stack pointer (the initial argv/envp/auxv stack is built by the
    // caller in RAM; sp points at argc). EL1h, FP/SIMD enabled, caches off.
    pub fn start(v: *Vmm, entry: u64, sp: u64) void {
        const tcr: u64 = 16 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (@as(u64, 2) << 32);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_MAIR_EL1, 0xFF);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_TCR_EL1, tcr);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_TTBR0_EL1, L0_IPA);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_VBAR_EL1, VBAR);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_SP_EL1, sp);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_CPACR_EL1, 0x300000); // FPEN=0b11
        var sctlr: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SCTLR_EL1, &sctlr);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_SCTLR_EL1, sctlr | 0x1005); // MMU + D-cache + I-cache (atomics/exclusives need cacheable memory; Apple Silicon keeps the vcpu coherent with the host)
        _ = hv_vcpu_set_reg(v.vcpu, REG_PC, entry);
        _ = hv_vcpu_set_reg(v.vcpu, REG_CPSR, 0x3c5); // EL1h, DAIF masked
        // Enter as the kernel does at exec: x0 is the dynamic linker's fini
        // pointer, which glibc's _start registers as an exit callback when it is
        // nonzero; a stale value there makes glibc call garbage at process exit
        // (musl ignores it). A fresh vcpu starts zeroed, but make the invariant
        // explicit, as the non-HVF stub does (stub.zig enterGuest).
        _ = hv_vcpu_set_reg(v.vcpu, REG_X0, 0);
    }

    // enableStep arms arm64 software single-step: MDSCR_EL1.SS, PSTATE.SS for the
    // next instruction, and trap debug exceptions to the host. The guest executes
    // one instruction, then takes a Software Step exception that run() surfaces.
    pub fn enableStep(v: *Vmm) void {
        const SR_MDSCR_EL1 = 0x8012;
        var mdscr: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_MDSCR_EL1, &mdscr);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_MDSCR_EL1, mdscr | 1);
        var cpsr: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_CPSR, &cpsr);
        _ = hv_vcpu_set_reg(v.vcpu, REG_CPSR, cpsr | (1 << 21)); // PSTATE.SS
        _ = hv_vcpu_set_trap_debug_exceptions(v.vcpu, true);
    }

    pub fn disableStep(v: *Vmm) void {
        const SR_MDSCR_EL1 = 0x8012;
        var mdscr: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_MDSCR_EL1, &mdscr);
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_MDSCR_EL1, mdscr & ~@as(u64, 1));
        _ = hv_vcpu_set_trap_debug_exceptions(v.vcpu, false);
    }

    // stepStop reports the SIGTRAP stop after a single-stepped instruction: it
    // disarms stepping, publishes the guest registers at the new pc, and posts
    // LC_STEP_STOP for the supervisor's ptrace step stop.
    pub fn stepStop(v: *Vmm, ch: *chan.Chan, pc: u64, exchange: ExchangeFn) void {
        v.disableStep();
        var x0: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_X0, &x0);
        var cpsr: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_CPSR, &cpsr);
        v.publishTraceCtx(ch, x0, pc, cpsr);
        ch.kind = chan.MSG_SYSCALL;
        ch.nr = LC_STEP_STOP;
        ch.args = .{ pc, 0, 0, 0, 0, 0 };
        v.served(ch, exchange);
    }

    // run executes the guest until the next event: a syscall (from the hvc
    // stub), a real fault, or the guest ending.
    // A signal for the thread stops it: the run publishes its vcpu before it
    // looks for one, so a kick that comes after the look finds the vcpu to
    // stop (kickRunning).
    pub fn run(v: *Vmm, ch: *chan.Chan) Error!Exit {
        const run_at = &g_running[slotIndex(ch)];
        while (true) {
            @atomicStore(u64, run_at, v.vcpu + 1, .seq_cst);
            if (deliverable(sigThreadRec(ch)) != 0 and !v.inVector()) {
                @atomicStore(u64, run_at, 0, .seq_cst);
                return .signal;
            }
            const r = hv_vcpu_run(v.vcpu);
            @atomicStore(u64, run_at, 0, .seq_cst);
            if (r != HV_SUCCESS) return error.Run;
            if (v.exit.reason == EXIT_EXCEPTION) break;
        }
        if (ec(v.exit.exception.syndrome) != 0x16) {
            var pc: u64 = 0;
            var far: u64 = 0;
            _ = hv_vcpu_get_reg(v.vcpu, REG_PC, &pc);
            _ = hv_vcpu_get_sys_reg(v.vcpu, SR_FAR_EL1, &far);
            return Exit{ .fault = .{ .ec = ec(v.exit.exception.syndrome), .iss = iss(v.exit.exception.syndrome), .far = far, .pc = pc } };
        }
        return v.vectored();
    }

    // inVector reports whether the vcpu is in the VM's own vector page, on
    // its way to the hvc that ends an exception: a signal waits for the
    // syscall's end there, which looks for it.
    fn inVector(v: *Vmm) bool {
        var pc: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_PC, &pc);
        return pc >= VBAR and pc < SIG_RESTORER;
    }

    // deliverAsync takes the signals waiting for a thread stopped in guest
    // code, onto the context it was stopped in.
    pub fn deliverAsync(v: *Vmm, ch: *chan.Chan, exchange: ExchangeFn) void {
        var x0: u64 = 0;
        var pc: u64 = 0;
        var pstate: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_X0, &x0);
        _ = hv_vcpu_get_reg(v.vcpu, REG_PC, &pc);
        _ = hv_vcpu_get_reg(v.vcpu, REG_CPSR, &pstate);
        _ = v.deliverPending(ch, (ch.stdio & STDIO_TRACED) != 0, null, &x0, &pc, pstate, exchange);
    }

    // vectored is the exception the guest took to its vector, whose hvc
    // stopped the run: a syscall, or a fault of the guest's own.
    fn vectored(v: *Vmm) Exit {
        var esr: u64 = 0;
        var elr: u64 = 0;
        var spsr: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_ESR_EL1, &esr);
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_ELR_EL1, &elr);
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SPSR_EL1, &spsr);
        if (ec(esr) != 0x15) { // not an SVC: a real exception took the guest's own vector
            var far: u64 = 0;
            _ = hv_vcpu_get_sys_reg(v.vcpu, SR_FAR_EL1, &far);
            return Exit{ .fault = .{ .ec = ec(esr), .iss = iss(esr), .far = far, .pc = elr } }; // pc = ELR_EL1: the faulting instruction
        }
        var sc = Syscall{ .nr = 0, .args = undefined, .elr = elr, .spsr = spsr };
        var x8: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_X0 + 8, &x8);
        sc.nr = x8;
        for (0..6) |i| {
            var a: u64 = 0;
            _ = hv_vcpu_get_reg(v.vcpu, REG_X0 + @as(u32, @intCast(i)), &a);
            sc.args[i] = a;
        }
        return Exit{ .syscall = sc };
    }

    // resume continues the guest after a serviced syscall (resume is a Zig keyword): x0 = ret, PC/CPSR
    // restored from the exception's saved ELR/SPSR.
    pub fn resumeGuest(v: *Vmm, sc: Syscall, ret: u64) void {
        _ = hv_vcpu_set_reg(v.vcpu, REG_X0, ret);
        _ = hv_vcpu_set_reg(v.vcpu, REG_PC, sc.elr);
        _ = hv_vcpu_set_reg(v.vcpu, REG_CPSR, sc.spsr);
    }

    // dispatchSyscall runs one guest syscall (shared by the main and thread run
    // loops). Untraced (the common case) it is just handleLocal-or-serveSyscall
    // then resumeGuest. Traced, it publishes the guest registers for the stop,
    // reports a locally-served syscall to the supervisor so its stops still fire,
    // and applies a tracer's register edits before resuming.
    pub fn dispatchSyscall(v: *Vmm, ch: *chan.Chan, sc: Syscall, exchange: ExchangeFn) void {
        const traced = (ch.stdio & STDIO_TRACED) != 0;
        if (traced) v.publishTrace(ch, sc);
        const ret = if (v.handleLocal(ch, sc, exchange)) |r|
            (if (traced) v.traceLocalStop(ch, sc, r, exchange) else r)
        else
            v.serveSyscall(ch, sc, exchange);
        // One resume context: the syscall result and the resume pc/pstate, then
        // any tracer SETREGS edits (x1..x30/sp go straight to the vcpu), then any
        // pending signals (a delivered handler vectors the vcpu itself).
        var x0 = ret;
        var pc = sc.elr;
        var pstate = sc.spsr;
        if (traced) v.applyTraceEdits(ch, &x0, &pc, &pstate);
        if (v.deliverPending(ch, traced, sc, &x0, &pc, pstate, exchange)) return;
        _ = hv_vcpu_set_reg(v.vcpu, REG_X0, x0);
        _ = hv_vcpu_set_reg(v.vcpu, REG_PC, pc);
        _ = hv_vcpu_set_reg(v.vcpu, REG_CPSR, pstate);
    }

    // traceFrame is the thread's published register image in its signal area.
    fn traceFrame(v: *Vmm, ch: *chan.Chan) usize {
        _ = v;
        const slot = (@intFromPtr(ch) - @intFromPtr(g_chan_base)) / chan.SLOT_SIZE;
        return @intFromPtr(g_chan_base) + TRACE_AREA_OFF + slot * TRACE_SIG_STRIDE + TRACE_REGS_OFF;
    }

    // publishTrace writes the guest registers at a syscall stop: x0..x30, the
    // guest sp, the resume pc and NZCV, for the supervisor's stop and GETREGS.
    fn publishTrace(v: *Vmm, ch: *chan.Chan, sc: Syscall) void {
        const f = v.traceFrame(ch);
        putU64(f, 0, 1); // kind: syscall frame
        putU64(f, 8, 0); // dirty: no tracer edits yet
        for (0..31) |i| {
            var x: u64 = 0;
            _ = hv_vcpu_get_reg(v.vcpu, REG_X0 + @as(u32, @intCast(i)), &x);
            putU64(f, 16 + i * 8, x);
        }
        var sp: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SP_EL1, &sp);
        putU64(f, 16 + 31 * 8, sp);
        putU64(f, 16 + 32 * 8, sc.elr);
        putU64(f, 16 + 33 * 8, sc.spsr & 0xf0000000);
    }

    // traceLocalStop reports a syscall already served in the VM, so the tracer
    // observes it; the supervisor runs the entry+exit stops and may edit the
    // result (returned) or the registers (applied by applyTraceEdits).
    fn traceLocalStop(v: *Vmm, ch: *chan.Chan, sc: Syscall, r: u64, exchange: ExchangeFn) u64 {
        ch.kind = chan.MSG_TRACE_LOCAL;
        ch.nr = sc.nr;
        ch.guest_rip = sc.elr -% 4; // the svc site is one instruction before the resume pc
        for (0..6) |i| ch.args[i] = sc.args[i];
        ch.ret = r;
        v.served(ch, exchange);
        return ch.ret;
    }

    // applyTraceEdits applies a tracer's SETREGS edits from the trace frame: x1..x30
    // and sp go straight to the vcpu; the caller-visible x0/pc/pstate come back
    // through the out-params. No-op when the frame is not dirty.
    fn applyTraceEdits(v: *Vmm, ch: *chan.Chan, x0: *u64, pc: *u64, pstate: *u64) void {
        const f = v.traceFrame(ch);
        if (getU64(f, 8) == 0) return;
        for (1..31) |i| _ = hv_vcpu_set_reg(v.vcpu, REG_X0 + @as(u32, @intCast(i)), getU64(f, 16 + i * 8));
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_SP_EL1, getU64(f, 16 + 31 * 8));
        x0.* = getU64(f, 16);
        pc.* = getU64(f, 16 + 32 * 8);
        pstate.* = (pstate.* & ~@as(u64, 0xf0000000)) | (getU64(f, 16 + 33 * 8) & 0xf0000000);
    }

    // publishTraceCtx publishes the resumable context (x0/pc/pstate explicit,
    // x1..x30/sp from the vcpu) before a signal stop, so a tracer's GETREGS there
    // reads the post-syscall state rather than the syscall-entry registers.
    fn publishTraceCtx(v: *Vmm, ch: *chan.Chan, x0: u64, pc: u64, pstate: u64) void {
        const f = v.traceFrame(ch);
        putU64(f, 0, 1);
        putU64(f, 8, 0);
        putU64(f, 16, x0);
        for (1..31) |i| {
            var r: u64 = 0;
            _ = hv_vcpu_get_reg(v.vcpu, REG_X0 + @as(u32, @intCast(i)), &r);
            putU64(f, 16 + i * 8, r);
        }
        var sp: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SP_EL1, &sp);
        putU64(f, 16 + 31 * 8, sp);
        putU64(f, 16 + 32 * 8, pc);
        putU64(f, 16 + 33 * 8, pstate & 0xf0000000);
    }

    // execStop runs the ptrace exec-event stop for a traced respawn: the fresh
    // stub, which has just loaded the new image, hands the supervisor the new
    // entry and sp so it can publish the exec frame and stop the tracee before
    // the new program's first instruction.
    pub fn execStop(v: *Vmm, ch: *chan.Chan, entry: u64, sp: u64, exchange: ExchangeFn) void {
        ch.kind = chan.MSG_SYSCALL;
        ch.nr = LC_EXEC_STOP;
        ch.args = .{ entry, sp, 0, 0, 0, 0 };
        v.served(ch, exchange);
    }

    // setBrk records the guest's initial break (the page-aligned end of its
    // loaded segments). The heap is process-wide (shared by every vcpu thread),
    // so it lives in guarded globals, not the per-thread Vmm.
    pub fn setBrk(v: *Vmm, data_end: u64) void {
        _ = v;
        g_brk_start = data_end;
        g_brk_cur = data_end;
    }

    // vmProtect enforces mprotect: it rewrites the guest's L3 page descriptors
    // for [addr, addr+len) and flushes this vcpu's TLB. PROT_NONE clears the
    // entry (any access faults); otherwise AP/XN follow read/write/exec. Pages at
    // or above the table region are left alone. (A multithreaded guest's sibling
    // vcpus flush their own TLBs on their next exit; mprotect is rarely racing.)
    fn vmProtect(v: *Vmm, addr: u64, len: u64, prot: u64) u64 {
        var va = @max(addr & ~@as(u64, 0xfff), MMAP_MIN);
        const end = addr +% len;
        while (va < end and va < L3_BASE) : (va += 0x1000) {
            const l3e = L3_BASE + (va >> 21) * 0x1000 + ((va >> 12) & 0x1ff) * 8;
            var desc: u64 = 0;
            if (prot != 0) {
                desc = va | PAGE_RWX;
                if (prot & 2 == 0) desc |= PTE_RO; // no PROT_WRITE -> read-only
                if (prot & 4 == 0) desc |= PTE_XN; // no PROT_EXEC -> execute-never
            }
            v.put64(l3e, desc);
        }
        v.flushTlb();
        return 0;
    }

    // flushTlb makes the guest invalidate its own TLB after the stub rewrites a
    // page table (arm64 HVF has no host-side flush -- hv_vcpu_invalidate_tlb is
    // the x86 entry). It points the vcpu at a one-shot trampoline (tlbi vmalle1;
    // dsb; isb; hvc) and runs it, then the caller resumes the guest normally.
    fn flushTlb(v: *Vmm) void {
        var pc: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_PC, &pc);
        _ = hv_vcpu_set_reg(v.vcpu, REG_PC, TLBI_TRAMP);
        // Runs tlbi; dsb; isb; hvc and exits back here. A kick may cancel the
        // run before the trampoline ends: it goes on from where it stood.
        while (hv_vcpu_run(v.vcpu) == HV_SUCCESS and v.exit.reason != EXIT_EXCEPTION) {
            var at: u64 = 0;
            _ = hv_vcpu_get_reg(v.vcpu, REG_PC, &at);
            if (at == TLBI_TRAMP + 16) break;
        }
        _ = hv_vcpu_set_reg(v.vcpu, REG_PC, pc);
    }

    // handleLocal services the syscalls the VM owns itself: memory (the guest's
    // address space IS the RAM, already mapped RWX, so these only partition it --
    // anonymous mmap bumps the region down, brk moves the break up, mprotect is a
    // no-op and munmap is not reclaimed; a file-backed mmap forwards) and futex
    // (guest threads share this process's RAM, so a futex word is an ordinary
    // address Darwin's os_sync waits/wakes on). Returns the result, or null to
    // forward the syscall to the supervisor.
    pub fn handleLocal(v: *Vmm, ch: *chan.Chan, sc: Syscall, exchange: ExchangeFn) ?u64 {
        if (overCap(growth(sc))) {
            if (sc.nr == NR_BRK) {
                heapLock();
                defer heapUnlock();
                return g_brk_cur;
            }
            return neg(ENOMEM);
        }
        const r = v.handleMem(ch, sc, exchange);
        switch (sc.nr) {
            NR_MMAP, NR_MUNMAP, NR_MREMAP, NR_BRK => publishMem(),
            else => {},
        }
        return r;
    }

    fn handleMem(v: *Vmm, ch: *chan.Chan, sc: Syscall, exchange: ExchangeFn) ?u64 {
        switch (sc.nr) {
            NR_MMAP => {
                const len = (sc.args[1] + 0xfff) & ~@as(u64, 0xfff);
                if (len == 0) return neg(ENOMEM);
                if (sc.args[3] & MAP_FIXED != 0) {
                    // The guest demands a specific address -- a Go/Rust runtime
                    // committing a range it reserved earlier (that reservation came
                    // from our bump allocator, so it already lies in the window).
                    // The whole [0, 32 GiB) is mapped and zeroed, so committing is
                    // just handing the address back; mmap(MAP_FIXED) requires
                    // p == addr, which a bump allocation would violate.
                    const addr = sc.args[0] & ~@as(u64, 0xfff);
                    if (addr < MMAP_MIN) return neg(EPERM);
                    if (addr + len > EXT_TOP) return neg(ENOMEM);
                    if (sc.args[3] & MAP_ANON == 0) {
                        // Recorded before the fill: the supervisor's writes reach
                        // only mapped guest memory (guestMapped).
                        addMap(addr, addr + len, sc.args[2], M_FILE, mapShared(sc.args[3]), sc.args[5], mapName(v, ch, sc, sc.args[4], exchange));
                        const pr = Syscall{ .nr = NR_PREAD64, .args = .{ sc.args[4], addr, sc.args[1], sc.args[5], 0, 0 }, .elr = sc.elr, .spsr = sc.spsr };
                        _ = v.serveSyscall(ch, pr, exchange);
                        vmaRecord(addr, sc.args[1], sc.args[4], sc.args[5], fileWb(sc.args[2], sc.args[3]));
                    } else addMap(addr, addr + len, sc.args[2], M_ANON, mapShared(sc.args[3]), 0, 0);
                    return addr;
                }
                heapLock();
                // Small mappings bump down through the first-GiB arena, between
                // the brk heap (below) and the stack (above), exactly as before.
                // Anything that no longer fits there goes to the extended window
                // [1 GiB, 32 GiB), which bumps down from EXT_TOP -- that is how a
                // Go/Rust arena or a multi-GiB mmap is served now (it used to
                // underflow the single arena and hand back a bogus high VA).
                var region: u64 = undefined;
                if (len <= g_mmap_cur - g_brk_cur) {
                    g_mmap_cur -= len; // RAM was zeroed and regions are never reused
                    region = g_mmap_cur;
                } else if (len <= g_ext_cur - g_ext_floor) {
                    g_ext_cur -= len;
                    region = g_ext_cur;
                } else {
                    heapUnlock();
                    return neg(ENOMEM);
                }
                heapUnlock();
                if (sc.args[3] & MAP_ANON == 0) {
                    // File-backed: fill the region from the file with a pread64 to
                    // the supervisor (the tail past EOF stays zero). offset is
                    // page-aligned per the guest; a short read zero-fills the rest.
                    addMap(region, region + len, sc.args[2], M_FILE, mapShared(sc.args[3]), sc.args[5], mapName(v, ch, sc, sc.args[4], exchange));
                    const pr = Syscall{ .nr = NR_PREAD64, .args = .{ sc.args[4], region, sc.args[1], sc.args[5], 0, 0 }, .elr = sc.elr, .spsr = sc.spsr };
                    _ = v.serveSyscall(ch, pr, exchange);
                    vmaRecord(region, sc.args[1], sc.args[4], sc.args[5], fileWb(sc.args[2], sc.args[3]));
                } else addMap(region, region + len, sc.args[2], M_ANON, mapShared(sc.args[3]), 0, 0);
                return region;
            },
            NR_MUNMAP => {
                // The RAM is never reclaimed (bump allocator), but a writable
                // MAP_SHARED file mapping must be written back to the file first,
                // or the guest's writes (e.g. the linker's output) are lost.
                const lo = sc.args[0] & ~@as(u64, 0xfff);
                const hi = (sc.args[0] +% sc.args[1] +% 0xfff) & ~@as(u64, 0xfff);
                if (hi > lo) vmaWriteBack(v, ch, lo, hi, true, sc, exchange);
                dropMaps(lo, hi);
                return 0;
            },
            NR_MSYNC => {
                const addr = sc.args[0];
                const flags = sc.args[2];
                if (addr & 0xfff != 0) return neg(EINVAL);
                if (flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0) return neg(EINVAL);
                if (flags & MS_ASYNC != 0 and flags & MS_SYNC != 0) return neg(EINVAL);
                if (sc.args[1] == 0) return 0;
                const hi = (addr +% sc.args[1] +% 0xfff) & ~@as(u64, 0xfff);
                vmaWriteBack(v, ch, addr, hi, false, sc, exchange); // keep the mapping; MS_INVALIDATE is a no-op
                return 0;
            },
            NR_MPROTECT => {
                protectMaps(sc.args[0] & ~@as(u64, 0xfff), (sc.args[0] +% sc.args[1] +% 0xfff) & ~@as(u64, 0xfff), sc.args[2]);
                return v.vmProtect(sc.args[0], sc.args[1], sc.args[2]);
            },
            // madvise: on Linux, MADV_DONTNEED/FREE/REMOVE on private anonymous
            // memory makes the range read back as zero. Go's scavenger relies on
            // this -- it advises freed heap spans away and later reuses the same
            // addresses expecting zeros (default madvdontneed), so if the advice is
            // a no-op the reused span keeps stale pointers and the GC trips on a bad
            // pointer, while nothing is ever released and the guest runs out of
            // memory. The guest heap is the bump-allocated identity RAM (private
            // anonymous), so give those advices their Linux meaning by zeroing the
            // range; any other advice is a hint and succeeds as a no-op. The native
            // stub does the same in mem.zig (discard).
            NR_MADVISE => switch (sc.args[2]) {
                MADV_DONTNEED, MADV_FREE, MADV_REMOVE, MADV_DONTNEED_LOCKED => {
                    const addr = sc.args[0];
                    if (addr & 0xfff != 0) return neg(EINVAL);
                    if (addr >= v.ram_len or sc.args[1] == 0) return 0;
                    const end = @min((addr +% sc.args[1] +% 0xfff) & ~@as(u64, 0xfff), v.ram_len);
                    discard(v, ch, addr, end, sc, exchange);
                    return 0;
                },
                else => return 0,
            },
            NR_MREMAP => return mremap(v, ch, sc, exchange),
            NR_MINCORE => {
                const addr = sc.args[0];
                if (addr & 0xfff != 0) return neg(EINVAL);
                const n = (sc.args[1] +% 0xfff) & ~@as(u64, 0xfff);
                if (n == 0) return 0;
                if (addr +% n > v.ram_len) return neg(ENOMEM);
                const pages: usize = @intCast(n >> 12);
                if (sc.args[2] +% pages > v.ram_len) return neg(EFAULT);
                const vec: [*]u8 = @ptrFromInt(@intFromPtr(v.ram) + sc.args[2]);
                for (0..pages) |i| vec[i] = 1; // identity VM RAM: every page resident
                return 0;
            },
            NR_MEMBARRIER => return membarrier(sc.args[0], sc.args[1]),
            NR_RT_SIGPENDING => {
                if (sc.args[1] > 8) return neg(EINVAL);
                const thr = sigThreadRec(ch);
                const prc = sigProcRec(thr.proc);
                const pend = (@atomicLoad(u64, &thr.pending, .monotonic) | @atomicLoad(u64, &prc.pending, .monotonic)) & @atomicLoad(u64, &thr.mask, .monotonic);
                const n: usize = @intCast(sc.args[1]);
                const b = std.mem.toBytes(pend);
                @memcpy(@as([*]u8, @ptrFromInt(@intFromPtr(v.ram) + sc.args[0]))[0..n], b[0..n]);
                return 0;
            },
            // rt_sigaction records the handler so a fault can be delivered to it
            // (see deliverFault). sigaltstack records the signal stack so a handler
            // with SA_ONSTACK runs on it (deliverSignal); Go requires its gsignal
            // stack for every handler. rt_sigreturn is handled in the run loop (it
            // restores, it does not return a value).
            NR_SIGALTSTACK => return sysSigaltstack(v, ch, sc.args[0], sc.args[1]),
            NR_RT_SIGPROCMASK => {
                // Track the blocked mask in the shared signal-area thread record
                // (how: 0=SIG_BLOCK, 1=SIG_UNBLOCK, else SIG_SETMASK), so the
                // pending check and the supervisor see the same mask.
                const thr = sigThreadRec(ch);
                const base = @intFromPtr(v.ram);
                const old = @atomicLoad(u64, &thr.mask, .monotonic);
                if (sc.args[2] != 0) putU64(base, sc.args[2], old);
                if (sc.args[1] != 0) {
                    const set = getU64(base, sc.args[1]);
                    const nm = switch (sc.args[0]) {
                        0 => old | set,
                        1 => old & ~set,
                        else => set,
                    } & ~(sigBit(SIGKILL) | sigBit(SIGSTOP));
                    @atomicStore(u64, &thr.mask, nm, .release);
                }
                return 0;
            },
            NR_BRK => {
                heapLock();
                defer heapUnlock();
                const want = sc.args[0];
                if (want >= g_brk_start and want < g_mmap_cur) g_brk_cur = want;
                return g_brk_cur;
            },
            NR_FUTEX, NR_FUTEX_TIME64 => return futexOp(v, sc),
            NR_CLOCK_GETTIME => {
                const clk = darwinClock(sc.args[0]) orelse return neg(EINVAL);
                var ts: Timespec = undefined;
                if (clock_gettime(clk, &ts) != 0) return neg(EFAULT);
                writeTs(v.ram, sc.args[1], ts);
                return 0;
            },
            NR_CLOCK_GETRES => {
                _ = darwinClock(sc.args[0]) orelse return neg(EINVAL);
                if (sc.args[1] != 0) writeTs(v.ram, sc.args[1], .{ .sec = 0, .nsec = 1 });
                return 0;
            },
            NR_GETTIMEOFDAY => {
                if (sc.args[0] != 0) {
                    var ts: Timespec = undefined;
                    _ = clock_gettime(DW_CLOCK_REALTIME, &ts);
                    const tv: *align(1) [2]i64 = @ptrFromInt(@intFromPtr(v.ram) + sc.args[0]);
                    tv.* = .{ ts.sec, @divTrunc(ts.nsec, 1000) }; // {tv_sec, tv_usec}
                }
                if (sc.args[1] != 0) (@as(*align(1) [2]i32, @ptrFromInt(@intFromPtr(v.ram) + sc.args[1]))).* = .{ 0, 0 };
                return 0;
            },
            NR_NANOSLEEP => return v.doSleep(DW_CLOCK_MONOTONIC, false, sc.args[0], sc.args[1]),
            NR_CLOCK_NANOSLEEP => {
                const clk = darwinClock(sc.args[0]) orelse return neg(EINVAL);
                return v.doSleep(clk, sc.args[1] & 1 != 0, sc.args[2], sc.args[3]); // bit0 = TIMER_ABSTIME
            },
            NR_SCHED_YIELD => {
                _ = sched_yield();
                return 0;
            },
            NR_RESTART_SYSCALL => {
                const d = restart_deadline;
                if (d == 0) return null; // not a sleep's: the supervisor's
                restart_deadline = 0;
                return v.sleepTo(d, restart_rem, false);
            },
            NR_GETRANDOM => {
                const buf: [*]u8 = @ptrFromInt(@intFromPtr(v.ram) + sc.args[0]);
                var off: usize = 0;
                const len: usize = @intCast(sc.args[1]);
                while (off < len) {
                    const n = @min(len - off, 256); // getentropy serves at most 256 bytes
                    if (getentropy(buf + off, n) != 0) return neg(EFAULT);
                    off += n;
                }
                return sc.args[1];
            },
            else => return null,
        }
    }

    // doSleep serves nanosleep / clock_nanosleep: it blocks the vcpu thread for
    // the guest timespec at `req` (relative, or until an absolute time on `clk`).
    fn doSleep(v: *Vmm, clk: c_int, absolute: bool, req: u64, rem: u64) u64 {
        var want = readTs(v.ram, req);
        if (want.sec < 0 or want.nsec < 0 or want.nsec >= 1_000_000_000) return neg(EINVAL);
        if (absolute) {
            var now: Timespec = undefined;
            _ = clock_gettime(clk, &now);
            var dsec = want.sec - now.sec;
            var dnsec = want.nsec - now.nsec;
            if (dnsec < 0) {
                dnsec += 1_000_000_000;
                dsec -= 1;
            }
            if (dsec < 0 or (dsec == 0 and dnsec <= 0)) return 0;
            want = .{ .sec = dsec, .nsec = dnsec };
        } else if (want.sec == 0 and want.nsec == 0) return 0;
        return v.sleepTo(monoNs() +| (want.sec *| 1_000_000_000 +| want.nsec), rem, absolute);
    }

    // sleepTo blocks the vcpu thread until deadline (monotonic ns). A Darwin
    // nanosleep does the waiting and a kick cuts it short: then a relative sleep
    // reports the time left in rem and returns ERESTART_RESTARTBLOCK, keeping
    // the rest for restart_syscall, and an absolute one ERESTARTNOHAND.
    // deliverPending restarts it unless a handler runs (EINTR), as Linux's
    // hrtimer_nanosleep, so a signal ignored or stopping the process lets the
    // sleep go on.
    fn sleepTo(v: *Vmm, deadline: i64, rem: u64, absolute: bool) u64 {
        const left = deadline - monoNs();
        if (left <= 0) return 0;
        const want = Timespec{ .sec = @divTrunc(left, 1_000_000_000), .nsec = @rem(left, 1_000_000_000) };
        if (nanosleep(&want, null) == 0) return 0;
        if (absolute) return @bitCast(ERESTARTNOHAND);
        if (rem != 0) {
            const l = @max(deadline - monoNs(), 0);
            writeTs(v.ram, rem, .{ .sec = @divTrunc(l, 1_000_000_000), .nsec = @rem(l, 1_000_000_000) });
        }
        restart_deadline = deadline;
        restart_rem = rem;
        return @bitCast(ERESTART_RESTARTBLOCK);
    }

    // mem returns the guest's RAM, so the caller (and the supervisor, once RAM
    // is MAP_SHARED) can read/write syscall buffers at their guest vaddr.
    pub fn mem(v: *Vmm) []u8 {
        return v.ram[0..v.ram_len];
    }

    // serveSyscall posts the guest syscall over the channel to the supervisor
    // and runs the reply loop to REP_RESULT, mirroring the native stub's
    // serveReplies -- but REP_PEEK/REP_POKE read and write guest memory in the
    // VM's RAM (identity-mapped at its vaddr) rather than the stub's own address
    // space. `exchange` is chan.exchange, passed in so this module need not pull
    // the stub's thread-end machinery. Phase 2b: REP_HOST guest-memory ops map
    // via hv_vm_map/protect; REP_FORK/CLONE/EXEC get VM-model implementations.
    pub fn serveSyscall(v: *Vmm, ch: *chan.Chan, sc: Syscall, exchange: *const fn (*chan.Chan) void) u64 {
        ch.kind = chan.MSG_SYSCALL;
        ch.nr = sc.nr;
        ch.guest_rip = sc.elr;
        ch.ret = 0; // untagged: the supervisor may write all of an output buffer (see outPrefix in mem.zig)
        for (0..6) |i| ch.args[i] = sc.args[i];
        while (true) {
            exchange(ch);
            if (v.serveRequest(ch)) continue;
            switch (ch.kind) {
                chan.REP_CLONE => return spawnThread(v, ch, sc, exchange),
                chan.REP_FORK => return forkSpawn(v, ch, sc, exchange),
                chan.REP_THREAD_END => {
                    // A CLONE_VM (vfork) child is exec'ing: the supervisor is
                    // ending this thread so it can respawn a fresh stub for the
                    // new program on this slot. Post THREAD_GONE as the slot's
                    // last message, free this thread's vcpu, and end the OS
                    // thread -- without it the vfork parent (held in vforkHold
                    // awaiting THREAD_GONE) never resumes, so a Go os/exec hung.
                    ch.kind = chan.MSG_SYSCALL;
                    ch.nr = NR_THREAD_GONE;
                    ch.args[0] = 0;
                    chan.postReq(ch);
                    _ = hv_vcpu_destroy(v.vcpu);
                    pthread_exit(null);
                },
                else => return ch.ret, // REP_RESULT (REP_EXEC: phase 2b)
            }
        }
    }

    // serveRequest serves one supervisor request made while it holds a call --
    // a memory copy (a tracer's, while the call is stopped), a host call, the
    // mappings -- leaving the answer in ch; false for anything else.
    fn serveRequest(v: *Vmm, ch: *chan.Chan) bool {
        switch (ch.kind) {
            // A range not all mapped faults: ret 1, nothing copied.
            chan.REP_PEEK => {
                ch.ret = @intFromBool(!guestMapped(ch.args[0], ch.args[1], v.ram_len));
                if (ch.ret == 0) {
                    const n: usize = @intCast(ch.args[1]);
                    @memcpy(window(ch)[0..n], (v.ram + @as(usize, @intCast(ch.args[0])))[0..n]);
                }
            },
            chan.REP_POKE => {
                ch.ret = @intFromBool(!guestMapped(ch.args[0], ch.args[1], v.ram_len));
                if (ch.ret == 0) {
                    const n: usize = @intCast(ch.args[1]);
                    @memcpy((v.ram + @as(usize, @intCast(ch.args[0])))[0..n], window(ch)[0..n]);
                }
            },
            // Perform a Darwin syscall the supervisor delegated. Pointer args
            // are guest VAs living at v.ram + VA in the stub, so they are
            // translated (the native stub shares the guest's address space and
            // skips this). dwExit ends the process here.
            chan.REP_HOST => ch.ret = v.hostCall(ch.nr, ch.args),
            chan.REP_MAPS => {
                const sc_base: [*]MapEnt = @ptrFromInt(@intFromPtr(ch) + chan.SCRATCH_OFF);
                ch.ret = listMaps(sc_base, (chan.SLOT_SIZE - chan.SCRATCH_OFF) / @sizeOf(MapEnt), ch.args[0], &ch.args[1]);
            },
            chan.REP_SMAPS => {
                const sc_base: [*]smaps.SmapEnt = @ptrFromInt(@intFromPtr(ch) + chan.SCRATCH_OFF);
                ch.ret = smaps.with(sc_base, (chan.SLOT_SIZE - chan.SCRATCH_OFF) / @sizeOf(smaps.SmapEnt), ch.args[0], &ch.args[1], listMapsAs, ram_base, 0x1000, true);
            },
            else => return false,
        }
        ch.kind = chan.MSG_HOSTRET;
        return true;
    }

    // served exchanges the message posted in ch and serves the supervisor's
    // requests until its answer: a call it holds in a ptrace stop has the
    // tracer read and write this VM's memory through it.
    pub fn served(v: *Vmm, ch: *chan.Chan, exchange: ExchangeFn) void {
        while (true) {
            exchange(ch);
            if (!v.serveRequest(ch)) return;
        }
    }

    // hostCall performs a Darwin syscall the supervisor delegated (REP_HOST),
    // translating guest-VA pointer args to their stub address (v.ram + VA). Only
    // the stdio ops that carry buffers need translation; dwExit and register-only
    // calls pass straight through. writev/readv translate the iovec array and
    // each entry's base into a stub-stack copy (capped; stdio uses few vectors).
    fn hostCall(v: *Vmm, nr: u64, args: [6]u64) u64 {
        const base = @intFromPtr(v.ram);
        const a = args;
        switch (nr) {
            DW_WRITE, DW_READ => return svc6(nr, a[0], a[1] +% base, a[2], a[3], a[4], a[5]),
            DW_WRITEV, DW_READV => {
                var tmp: [16]Iovec = undefined;
                const n = @min(@as(usize, @intCast(a[2])), tmp.len);
                const src: [*]const Iovec = @ptrCast(@alignCast(v.ram + @as(usize, @intCast(a[1]))));
                for (0..n) |i| tmp[i] = .{ .base = src[i].base +% base, .len = src[i].len };
                return svc6(nr, a[0], @intFromPtr(&tmp), n, a[3], a[4], a[5]);
            },
            else => return svc6(nr, a[0], a[1], a[2], a[3], a[4], a[5]),
        }
    }

    // threadRunLoop is a guest thread's syscall loop (its own vcpu, slot and
    // ctid). Memory/futex stay local; SYS_exit ends the thread (clears the ctid
    // and wakes its joiner); exit_group and a fault end it too.
    pub fn threadRunLoop(v: *Vmm, ch: *chan.Chan, exchange: ExchangeFn, ctid: u64) void {
        while (true) {
            if (ch.stdio & STDIO_SINGLESTEP != 0) v.enableStep(); // ptrace single-step
            const ev = v.run(ch) catch return;
            switch (ev) {
                .signal => v.deliverAsync(ch, exchange),
                .syscall => |sc| {
                    if (sc.nr == NR_EXIT) return v.threadExit(ch, ctid, sc.args[0]);
                    var s = sc;
                    if (s.nr == NR_SET_TID_ADDRESS) s.nr = NR_GETTID;
                    if (s.nr == NR_RT_SIGRETURN) {
                        v.sigreturn(ch);
                        continue;
                    }
                    v.dispatchSyscall(ch, s, exchange);
                },
                .fault => |fl| {
                    if (fl.ec == 0x32 or fl.ec == 0x33) { // a software-step exception
                        v.stepStop(ch, fl.pc, exchange);
                    } else if (!v.deliverFault(ch, fl, exchange)) return;
                },
                .done => return,
            }
        }
    }

    // threadExit does the kernel's CLONE_CHILD_CLEARTID duty (clear the tid word
    // and wake a joiner futex-waiting on it), then posts THREAD_GONE so the
    // supervisor frees the slot. The OS thread returns to threadEntry after.
    pub fn threadExit(v: *Vmm, ch: *chan.Chan, ctid: u64, code: u64) void {
        if (ctid != 0) {
            const w: *u32 = @ptrFromInt(@intFromPtr(v.ram) + ctid);
            @atomicStore(u32, w, 0, .seq_cst);
            futexWake(v.ram, ctid);
        }
        ch.kind = chan.MSG_SYSCALL;
        ch.nr = NR_THREAD_GONE;
        ch.args[0] = code;
        chan.postReq(ch);
    }

    // deliverFault raises the signal Linux sends for a synchronous guest
    // exception (arm64's fault tables): an abort is SIGSEGV (SEGV_ACCERR for a
    // permission fault, SEGV_MAPERR otherwise) or, misaligned, SIGBUS; an
    // undefined instruction SIGILL, a brk SIGTRAP, a misaligned pc or sp SIGBUS.
    // As force_sig_fault does, the supervisor (LC_SIGFAULT) runs any ptrace
    // signal-delivery stop and resets the action to the default when the signal
    // is blocked or ignored. A handler gets it and the caller resumes there;
    // without one the process ends of it (LC_SIGDIE). False for an exception
    // with no signal.
    pub fn deliverFault(v: *Vmm, ch: *chan.Chan, fl: Fault, exchange: ExchangeFn) bool {
        var sp: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SP_EL1, &sp);
        const fsc = fl.iss & 0x3f;
        const s: struct { sig: u32, code: i32, addr: u64 } = switch (fl.ec) {
            0x20, 0x21, 0x24, 0x25 => if (fsc == 0x21)
                .{ .sig = SIGBUS, .code = BUS_ADRALN, .addr = fl.far }
            else if (fsc & 0x3c == 0x0c)
                .{ .sig = SIGSEGV, .code = SEGV_ACCERR, .addr = fl.far }
            else
                .{ .sig = SIGSEGV, .code = SEGV_MAPERR, .addr = fl.far },
            0x00, 0x0e => .{ .sig = SIGILL, .code = ILL_ILLOPC, .addr = fl.pc },
            0x3c => .{ .sig = SIGTRAP, .code = TRAP_BRKPT, .addr = fl.pc },
            0x22 => .{ .sig = SIGBUS, .code = BUS_ADRALN, .addr = fl.pc },
            0x26 => .{ .sig = SIGBUS, .code = BUS_ADRALN, .addr = sp },
            else => return false,
        };
        var pstate: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SPSR_EL1, &pstate); // the faulting pstate, not the handler's
        var x0: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_X0, &x0);
        const thr = sigThreadRec(ch);
        const mask = @atomicLoad(u64, &thr.mask, .monotonic);
        if (ch.stdio & STDIO_TRACED != 0) v.publishTraceCtx(ch, x0, fl.pc, pstate);
        ch.kind = chan.MSG_SYSCALL;
        ch.nr = LC_SIGFAULT;
        ch.args = .{ s.sig, @intFromBool(mask & sigBit(s.sig) != 0), s.addr, @as(u32, @bitCast(s.code)), fl.pc, 0 };
        v.served(ch, exchange);
        const sig: u32 = @truncate(ch.ret);
        if (sig == 0) {
            // A tracer discarded it: the instruction runs again, from the
            // vector's hvc back to where the guest took the fault.
            var pc: u64 = 0;
            _ = hv_vcpu_get_reg(v.vcpu, REG_PC, &pc);
            if (pc == VBAR + 0x204) {
                _ = hv_vcpu_set_reg(v.vcpu, REG_PC, fl.pc);
                _ = hv_vcpu_set_reg(v.vcpu, REG_CPSR, pstate);
            }
            return true;
        }
        const act = sigReply(ch).act;
        if (classify(sig, act) != .handler) {
            ch.kind = chan.MSG_SYSCALL;
            ch.nr = LC_SIGDIE;
            ch.args = .{ sig, 0, 0, 0, 0, 0 };
            v.served(ch, exchange);
            _exit(@intCast(128 + sig));
        }
        const info = Info{ .signo = @intCast(sig), .err = 0, .code = s.code, .pad = 0, .a = s.addr, .b = 0 };
        v.deliverSignal(ch, sig, &info, x0, fl.pc, pstate, act, mask);
        return true;
    }

    // deliverSignal builds the Linux arm64 rt_sigframe for `signo` onto the given
    // resume context (ctx_x0 in x0, ctx_pc/ctx_pstate the interrupted pc/pstate;
    // x1..x30 and sp are the vcpu's own) and points the vcpu at the handler, as
    // the kernel's setup_rt_frame does. prev_mask goes in uc_sigmask (sigreturn
    // restores it), the handler runs with prev_mask | act.mask | signo blocked
    // (unless SA_NODEFER), and siginfo is copied from info.
    fn deliverSignal(v: *Vmm, ch: *chan.Chan, signo: u32, info: *const Info, ctx_x0: u64, ctx_pc: u64, ctx_pstate: u64, act: Act, prev_mask: u64) void {
        var x: [31]u64 = undefined;
        for (0..31) |i| {
            var r: u64 = 0;
            _ = hv_vcpu_get_reg(v.vcpu, REG_X0 + @as(u32, @intCast(i)), &r);
            x[i] = r;
        }
        x[0] = ctx_x0;
        var orig_sp: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SP_EL1, &orig_sp);
        const base = @intFromPtr(v.ram);
        // A handler with SA_ONSTACK runs on the registered altstack unless we are
        // already on it. Go installs every handler this way (its per-M gsignal
        // stack), and derails if a signal lands on a goroutine stack instead.
        const ast = sigThreadRec(ch);
        var fsp = orig_sp;
        if (act.flags & SA_ONSTACK != 0 and ast.ss_size != 0 and !onAltStack(ast, orig_sp)) {
            fsp = ast.ss_sp + ast.ss_size; // the altstack top (the stack grows down)
            if (ast.ss_flags & SS_AUTODISARM != 0) {
                ast.ss_sp = 0;
                ast.ss_size = 0;
                ast.ss_flags = 0;
            }
        }
        const frame = (fsp - FRAME_SIZE) & ~@as(u64, 15);
        @memset(@as([*]u8, @ptrFromInt(base + frame))[0..@intCast(FRAME_SIZE)], 0);
        putU32(base, frame, signo); // si_signo
        putU32(base, frame + 8, @bitCast(info.code)); // si_code
        putU64(base, frame + 16, info.a); // si_addr / si_pid+uid
        putU64(base, frame + 24, info.b);
        const uc = frame + 128;
        putU64(base, uc + 40, prev_mask); // uc_sigmask: what sigreturn restores
        const mc = uc + UC_MCONTEXT;
        putU64(base, mc, info.a); // fault_address
        for (0..31) |i| putU64(base, mc + 8 + i * 8, x[i]);
        putU64(base, mc + 256, orig_sp); // sigreturn restores the interrupted SP, not the altstack
        putU64(base, mc + 264, ctx_pc);
        putU64(base, mc + 272, ctx_pstate);
        const rsv = mc + SC_RESERVED;
        putU32(base, rsv, FPSIMD_MAGIC);
        putU32(base, rsv + 4, FPSIMD_SIZE);
        var fpsr: u64 = 0;
        var fpcr: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_FPSR, &fpsr);
        _ = hv_vcpu_get_reg(v.vcpu, REG_FPCR, &fpcr);
        putU32(base, rsv + 8, @truncate(fpsr));
        putU32(base, rsv + 12, @truncate(fpcr));
        for (0..32) |i| {
            var q: Simd16 = undefined;
            _ = hv_vcpu_get_simd_fp_reg(v.vcpu, SIMD_Q0 + @as(u32, @intCast(i)), &q);
            @as(*Simd16, @ptrFromInt(base + rsv + 16 + i * 16)).* = q;
        }
        // Block the signal (and act.mask) while the handler runs; sigreturn
        // restores prev_mask. SIGKILL/SIGSTOP can never be blocked.
        const thr = sigThreadRec(ch);
        var nm = prev_mask | act.mask;
        if (act.flags & SA_NODEFER == 0) nm |= sigBit(signo);
        nm &= ~(sigBit(SIGKILL) | sigBit(SIGSTOP));
        @atomicStore(u64, &thr.mask, nm, .release);
        _ = hv_vcpu_set_reg(v.vcpu, REG_X0, signo);
        _ = hv_vcpu_set_reg(v.vcpu, REG_X0 + 1, frame); // x1 = &siginfo
        _ = hv_vcpu_set_reg(v.vcpu, REG_X0 + 2, uc); // x2 = &ucontext
        _ = hv_vcpu_set_reg(v.vcpu, REG_X0 + 30, if (act.flags & SA_RESTORER != 0) act.restorer else SIG_RESTORER);
        _ = hv_vcpu_set_reg(v.vcpu, REG_PC, act.handler);
        _ = hv_vcpu_set_reg(v.vcpu, REG_CPSR, 0x3c5); // EL1h, DAIF masked (the guest's normal pstate)
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_SP_EL1, frame);
    }

    // sigreturn restores the vcpu from the rt_sigframe at the guest sp (the
    // rt_sigreturn syscall), including the mask the handler ran under.
    pub fn sigreturn(v: *Vmm, ch: *chan.Chan) void {
        var sp: u64 = 0;
        _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SP_EL1, &sp);
        const base = @intFromPtr(v.ram);
        const uc = sp + 128;
        const mc = uc + UC_MCONTEXT;
        for (0..31) |i| _ = hv_vcpu_set_reg(v.vcpu, REG_X0 + @as(u32, @intCast(i)), getU64(base, mc + 8 + i * 8));
        _ = hv_vcpu_set_sys_reg(v.vcpu, SR_SP_EL1, getU64(base, mc + 256));
        _ = hv_vcpu_set_reg(v.vcpu, REG_PC, getU64(base, mc + 264));
        _ = hv_vcpu_set_reg(v.vcpu, REG_CPSR, getU64(base, mc + 272));
        const rsv = mc + SC_RESERVED; // restore FPSIMD (fpsr, fpcr, q0..q31)
        _ = hv_vcpu_set_reg(v.vcpu, REG_FPSR, getU32(base, rsv + 8));
        _ = hv_vcpu_set_reg(v.vcpu, REG_FPCR, getU32(base, rsv + 12));
        for (0..32) |i| {
            const q = @as(*const Simd16, @ptrFromInt(base + rsv + 16 + i * 16)).*;
            _ = hv_vcpu_set_simd_fp_reg(v.vcpu, SIMD_Q0 + @as(u32, @intCast(i)), q);
        }
        @atomicStore(u64, &sigThreadRec(ch).mask, getU64(base, uc + 40), .release);
    }

    // restart re-executes the svc with the original args; ERESTART_RESTARTBLOCK
    // as restart_syscall, which goes on from the call's restart block.
    fn restart(v: *Vmm, sc: Syscall, x0: *u64, pc: *u64) void {
        if (@as(i64, @bitCast(x0.*)) == ERESTART_RESTARTBLOCK) _ = hv_vcpu_set_reg(v.vcpu, REG_X0 + 8, NR_RESTART_SYSCALL);
        x0.* = sc.args[0];
        pc.* = sc.elr - 4;
    }

    // deliverPending takes any signals that became deliverable during the syscall
    // just served: for each, LC_SIGTAKE dequeues it (the supervisor runs a ptrace
    // signal-stop and returns the siginfo + action), then it is ignored, stopped
    // (LC_SIGSTOP), terminated (LC_SIGDIE), or delivered to a handler onto the
    // post-syscall context (x0 = ret). Returns true if it vectored the vcpu into a
    // handler, so the caller must not resume the syscall normally.
    pub fn deliverPending(v: *Vmm, ch: *chan.Chan, traced: bool, sc_in: ?Syscall, x0: *u64, pc: *u64, pstate: u64, exchange: ExchangeFn) bool {
        // A blocking syscall interrupted by a signal comes back as -ERESTART*; it
        // is never exposed. With a handler, SA_RESTART (or ERESTARTNOINTR) restarts
        // by re-executing the svc (pc-4, original args), otherwise the syscall sees
        // -EINTR; with no handler it just restarts. Without a syscall (sc_in null:
        // the thread was stopped in guest code) x0 is the guest's own.
        const restartable = sc_in != null and isRestart(@bitCast(x0.*));
        const sc = sc_in orelse Syscall{ .nr = 0, .args = .{ 0, 0, 0, 0, 0, 0 }, .elr = pc.*, .spsr = pstate };
        const thr = sigThreadRec(ch);
        while (true) {
            const proc = sigProcRec(thr.proc);
            const mask = @atomicLoad(u64, &thr.mask, .monotonic);
            if ((@atomicLoad(u64, &thr.pending, .monotonic) | @atomicLoad(u64, &proc.pending, .monotonic)) & ~mask == 0) {
                if (restartable) v.restart(sc, x0, pc);
                return false;
            }
            // A traced thread publishes the resumable context so the ptrace
            // signal-stop inside LC_SIGTAKE and its GETREGS see the post-syscall state.
            if (traced) v.publishTraceCtx(ch, x0.*, pc.*, pstate);
            ch.kind = chan.MSG_SYSCALL;
            ch.nr = LC_SIGTAKE;
            ch.args = .{ ~mask, 0, 0, 0, 0, 0 };
            v.served(ch, exchange);
            const sig: u32 = @truncate(ch.ret);
            if (sig == 0) { // nothing deliverable (or the tracer suppressed it)
                if (restartable) v.restart(sc, x0, pc);
                return false;
            }
            const reply = sigReply(ch).*;
            switch (classify(sig, reply.act)) {
                .ignore => {},
                .stop => {
                    ch.kind = chan.MSG_SYSCALL;
                    ch.nr = LC_SIGSTOP;
                    ch.args = .{ sig, 0, 0, 0, 0, 0 };
                    v.served(ch, exchange);
                },
                .term => {
                    ch.kind = chan.MSG_SYSCALL;
                    ch.nr = LC_SIGDIE;
                    ch.args = .{ sig, 0, 0, 0, 0, 0 };
                    v.served(ch, exchange);
                    _exit(@intCast(128 + sig));
                },
                .handler => {
                    var hx0 = x0.*;
                    var hpc = pc.*;
                    if (restartable) {
                        const rv = @as(i64, @bitCast(x0.*));
                        if (rv == ERESTARTNOINTR or (rv == ERESTARTSYS and reply.act.flags & SA_RESTART != 0)) {
                            hx0 = sc.args[0]; // restart: re-execute the svc with the original args
                            hpc = sc.elr - 4;
                        } else {
                            if (rv == ERESTART_RESTARTBLOCK) restart_deadline = 0;
                            hx0 = @bitCast(-@as(i64, @intCast(EINTR))); // a handler ran: -EINTR
                            hpc = sc.elr;
                        }
                    }
                    v.deliverSignal(ch, sig, &reply.info, hx0, hpc, pstate, reply.act, mask);
                    return true;
                },
            }
        }
    }
};

// Darwin BSD syscall numbers the supervisor delegates to the stub (REP_HOST).
const DW_EXIT: u64 = 1;
const DW_READ: u64 = 3;
const DW_WRITE: u64 = 4;
const DW_READV: u64 = 120;
const DW_WRITEV: u64 = 121;

const Iovec = extern struct { base: u64, len: u64 };

// svc6 issues a Darwin syscall (svc #0x80); on the carry flag Darwin set, it
// negates the positive errno so the guest sees Linux's negative-errno convention.
fn svc6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) u64 {
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
}

fn ec(syndrome: u64) u32 {
    return @intCast((syndrome >> 26) & 0x3f);
}

fn iss(syndrome: u64) u32 {
    return @intCast(syndrome & 0x1ffffff);
}

// Fault is a synchronous guest exception: its class and syndrome, the faulting
// address (FAR) and instruction.
pub const Fault = struct { ec: u32, iss: u32, far: u64, pc: u64 };

// neg returns a Linux negative-errno result from a positive errno.
fn neg(e: u64) u64 {
    return @bitCast(-@as(i64, @intCast(e)));
}

// The peek/poke window is a dedicated per-slot region past all the slots and the
// signal area, WIN_SIZE bytes each -- NOT the tiny per-slot scratch. The layout
// must match the supervisor (sandbox/chanwin.go) and the native stub (stub.zig).
const SIG_STRIDE: usize = 0x4000;
const WIN_OFF: usize = chan.SLOT_SIZE * chan.MAX_SLOTS + SIG_STRIDE * chan.MAX_SLOTS;
const WIN_SIZE: usize = 256 * 1024;
pub const CHAN_LEN: usize = WIN_OFF + WIN_SIZE * chan.MAX_SLOTS;

// window returns the supervisor's read/write window for a slot (REP_PEEK/POKE).
fn window(ch: *chan.Chan) [*]u8 {
    const idx = (@intFromPtr(ch) - @intFromPtr(g_chan_base)) / chan.SLOT_SIZE;
    return g_chan_base + WIN_OFF + idx * WIN_SIZE;
}

// ---- threads, futex and the guest heap ----------------------------------------

pub const ExchangeFn = *const fn (*chan.Chan) void;

const SR_TPIDR_EL0: u32 = 0xde82;
const NR_EXIT: u64 = 93;
const NR_SET_TID_ADDRESS: u64 = 96;
const NR_GETTID: u64 = 178;
const NR_FUTEX: u64 = 98;
const NR_FUTEX_TIME64: u64 = 422;
const NR_SIGALTSTACK: u64 = 132;
const NR_RT_SIGPROCMASK: u64 = 135;
const NR_RT_SIGRETURN: u64 = 139;
const NR_THREAD_GONE: u64 = 0x1_0000_0002;
const NR_VFORK_WAIT: u64 = 0x1_0000_0001; // stub->supervisor only, not a Linux number
const NR_FORKED: u64 = 0x1_0000_0003; // the child's host pid, right after a fork
const NR_CHILD_STOP: u64 = 0x1_0000_0004; // a traced new thread, before its first instruction
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_PRIVATE: u64 = 128;
const FUTEX_CLOCK_REALTIME: u64 = 256;
const CLONE_VFORK: u64 = 0x4000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;

// ptrace: the supervisor sets STDIO_TRACED on a traced thread's channel slot. At
// each syscall a traced thread publishes its guest registers into the shared
// trace frame (so the supervisor's syscall-entry/exit stops and GETREGS see
// them) and, on resume, applies any registers the tracer edited (SETREGS). The
// frame lives in the thread's signal area at a fixed offset, matching the
// supervisor's traceFrame(): base + slotsLen + slot*sigStride + 256, laid out
// as [kind u64][dirty u64][34 regs: x0..x30, sp, pc, pstate].
pub const STDIO_TRACED: u64 = 1 << 63;
pub const STDIO_SINGLESTEP: u64 = 1 << 62; // the supervisor asked for one-instruction step
const TRACE_AREA_OFF: usize = chan.SLOT_SIZE * chan.MAX_SLOTS; // = supervisor slotsLen
const TRACE_SIG_STRIDE: usize = 0x4000; // = supervisor sigStride
const TRACE_REGS_OFF: usize = 256;
const EAGAIN: u64 = 11;
const ENOSYS: u64 = 38;

// Signal state and the Linux arm64 rt_sigframe layout (matches sig.zig). Handlers
// are recorded per signal; a fault delivers SIGSEGV onto the guest stack.
const Act = extern struct { handler: u64, flags: u64, restorer: u64, mask: u64 };
const SIGSEGV: u32 = 11;
const SIGILL: u32 = 4;
const SIGTRAP: u32 = 5;
const SIGBUS: u32 = 7;
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;
const BUS_ADRALN: i32 = 1;
const ILL_ILLOPC: i32 = 1;
const TRAP_BRKPT: i32 = 1;
const SA_RESTORER: u64 = 0x04000000;
const SA_ONSTACK: u64 = 0x08000000;
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
const SS_AUTODISARM: u32 = 1 << 31;
const MINSIGSTKSZ: u64 = 5120;
const FRAME_SIZE: u64 = 128 + 4560;
const UC_MCONTEXT: u64 = 176;
const SC_RESERVED: u64 = 288;
const FPSIMD_MAGIC: u32 = 0x46508001;
const FPSIMD_SIZE: u32 = 528;

// ---- async signals --------------------------------------------------------
// Queued Linux signals (tkill/kill/raise, the ptrace signal-stop) are delivered
// at syscall boundaries, mirroring the native stub (sig.zig): the shared signal
// area holds this thread's pending bits and mask; after a syscall the stub takes
// a deliverable signal with LC_SIGTAKE (the supervisor does any ptrace
// signal-stop and returns the siginfo + action in the slot scratch), then acts:
// ignore, stop (LC_SIGSTOP), terminate (LC_SIGDIE), or run a handler (build the
// rt_sigframe + vector the vcpu). The signal area and scratch layout, and the
// LC_SIG* numbers, match sig.zig / sandbox/lx_signal.go exactly.
const LC_SIGDIE: u64 = 0x4c43_0010;
const LC_SIGSTOP: u64 = 0x4c43_0011;
const LC_SIGTAKE: u64 = 0x4c43_0012;
const LC_SIGFAULT: u64 = 0x4c43_0014;
const LC_EXEC_STOP: u64 = 0x4c43_0018; // a traced respawn: run the ptrace exec-event stop
const LC_MAPNAME: u64 = 0x4c43_0031; // (guest fd) -> the id a mapping of its file is listed by
const LC_STEP_STOP: u64 = 0x4c43_0019; // one instruction stepped: run the SIGTRAP step stop
const SIG_PROC_OFF: usize = 0x1000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
const EINTR: u64 = 4;
// A blocking syscall interrupted by a signal returns one of these (never exposed
// to the guest): the syscall restarts (re-execute the svc) or sees -EINTR.
const ERESTARTSYS: i64 = -512;
const ERESTARTNOINTR: i64 = -513;
const ERESTARTNOHAND: i64 = -514;
const ERESTART_RESTARTBLOCK: i64 = -516;
fn isRestart(rv: i64) bool {
    return rv == ERESTARTSYS or rv == ERESTARTNOINTR or rv == ERESTARTNOHAND or rv == ERESTART_RESTARTBLOCK;
}

fn sigBit(s: u32) u64 {
    return @as(u64, 1) << @intCast(s - 1);
}

const Info = extern struct { signo: i32, err: i32, code: i32, pad: i32, a: u64, b: u64 };
const SigThread = extern struct {
    _res: u32,
    proc: u32,
    mask: u64,
    pending: u64,
    waitset: u64,
    ss_sp: u64,
    ss_size: u64,
    ss_flags: u32,
    tid: u32,
    tgid: u32,
    saved: u32,
    saved_mask: u64,
};
const SigProc = extern struct { _res: u64, pending: u64, mem: u64 };
const SigReply = extern struct { info: Info, act: Act };

comptime {
    std.debug.assert(@offsetOf(SigThread, "mask") == 8);
    std.debug.assert(@offsetOf(SigThread, "pending") == 16);
    std.debug.assert(@offsetOf(SigProc, "pending") == 8);
    std.debug.assert(@sizeOf(Info) == 32);
}

// g_running holds, per channel slot, the vcpu its thread runs guest code on,
// plus one (0: none).
var g_running = [_]u64{0} ** chan.MAX_SLOTS;

fn deliverable(thr: *SigThread) u64 {
    const proc = sigProcRec(thr.proc);
    return (@atomicLoad(u64, &thr.pending, .seq_cst) | @atomicLoad(u64, &proc.pending, .seq_cst)) & ~@atomicLoad(u64, &thr.mask, .seq_cst);
}

// kickRunning stops the vcpus running guest code for threads a signal waits
// for, for their run loops to deliver it (the supervisor's kick).
pub fn kickRunning() void {
    for (&g_running, 0..) |*r, i| {
        const vc = @atomicLoad(u64, r, .seq_cst);
        if (vc == 0) continue;
        const thr: *SigThread = @ptrFromInt(@intFromPtr(g_chan_base) + TRACE_AREA_OFF + i * TRACE_SIG_STRIDE);
        if (deliverable(thr) == 0) continue;
        const one = [1]u64{vc - 1};
        _ = hv_vcpus_exit(&one, 1);
    }
}

fn slotIndex(ch: *chan.Chan) usize {
    return (@intFromPtr(ch) - @intFromPtr(g_chan_base)) / chan.SLOT_SIZE;
}
fn sigThreadRec(ch: *chan.Chan) *SigThread {
    return @ptrFromInt(@intFromPtr(g_chan_base) + TRACE_AREA_OFF + slotIndex(ch) * TRACE_SIG_STRIDE);
}

// onAltStack reports whether sp lies within the thread's registered signal stack.
fn onAltStack(thr: *SigThread, sp: u64) bool {
    return thr.ss_size != 0 and sp > thr.ss_sp and sp - thr.ss_sp <= thr.ss_size;
}

// sysSigaltstack records (ss) and/or reports (oss) the thread's signal stack,
// mirroring the native stub's sysSigaltstack (sig.zig). The Linux arm64 stack_t
// is {ss_sp u64 @0, ss_flags i32 @8, ss_size u64 @16}. deliverSignal consults
// the record for SA_ONSTACK handlers.
fn sysSigaltstack(v: *Vmm, ch: *chan.Chan, ss: u64, oss: u64) u64 {
    const thr = sigThreadRec(ch);
    const base = @intFromPtr(v.ram);
    var sp: u64 = 0;
    _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SP_EL1, &sp);
    const on = onAltStack(thr, sp);
    const old_sp = thr.ss_sp;
    const old_size = thr.ss_size;
    const old_flags: u32 = (if (old_size == 0) SS_DISABLE else if (on) SS_ONSTACK else 0) | thr.ss_flags;
    if (ss != 0) {
        if (on) return neg(EPERM); // cannot change the altstack while running on it
        const nsp = getU64(base, ss);
        const nflags: u32 = getU32(base, ss + 8);
        const nsize = getU64(base, ss + 16);
        const mode = nflags & ~SS_AUTODISARM;
        if (mode != 0 and mode != SS_ONSTACK and mode != SS_DISABLE) return neg(EINVAL);
        if (mode == SS_DISABLE) {
            thr.ss_sp = 0;
            thr.ss_size = 0;
            thr.ss_flags = 0;
        } else {
            if (nsize < MINSIGSTKSZ) return neg(ENOMEM);
            thr.ss_sp = nsp;
            thr.ss_size = nsize;
            thr.ss_flags = nflags & SS_AUTODISARM;
        }
    }
    if (oss != 0) {
        putU64(base, oss, old_sp);
        putU32(base, oss + 8, old_flags);
        putU32(base, oss + 12, 0);
        putU64(base, oss + 16, old_size);
    }
    return 0;
}
fn sigProcRec(proc_slot: u32) *SigProc {
    return @ptrFromInt(@intFromPtr(g_chan_base) + TRACE_AREA_OFF + @as(usize, proc_slot) * TRACE_SIG_STRIDE + SIG_PROC_OFF);
}
fn sigReply(ch: *chan.Chan) *align(1) const SigReply {
    return @ptrFromInt(@intFromPtr(ch) + chan.SCRATCH_OFF);
}

const SigKind = enum { ignore, stop, term, handler };
fn classify(sig: u32, act: Act) SigKind {
    if (act.handler == 1) return .ignore; // SIG_IGN
    if (act.handler != 0) return .handler; // not SIG_DFL
    return switch (sig) {
        17, 23, 28, 18 => .ignore, // SIGCHLD, SIGURG, SIGWINCH, SIGCONT
        19, 20, 21, 22 => .stop, // SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU
        else => .term,
    };
}

fn putU64(base: usize, ga: u64, val: u64) void {
    @as(*u64, @ptrFromInt(base + ga)).* = val;
}
fn putU32(base: usize, ga: u64, val: u32) void {
    @as(*u32, @ptrFromInt(base + ga)).* = val;
}
fn getU64(base: usize, ga: u64) u64 {
    return @as(*const u64, @ptrFromInt(base + ga)).*;
}
fn getU32(base: usize, ga: u64) u32 {
    return @as(*const u32, @ptrFromInt(base + ga)).*;
}

// The guest heap is process-wide (shared by every vcpu thread), under g_heap_lock.
var g_brk_start: u64 = 0;
var g_brk_cur: u64 = 0;
var g_mmap_cur: u64 = MMAP_TOP;
var g_ext_cur: u64 = EXT_TOP; // extended mmap window bump pointer [1 GiB, 32 GiB)
var g_ext_floor: u64 = EXT_BASE; // extended window floor: raised above a loaded interpreter so guest mmaps cannot overrun ld.so

// reserveInterp raises the extended-window floor to just past a loaded
// interpreter, which ends at end, so a large guest mmap bumping down cannot land
// on ld.so. Called once at startup after the interpreter is loaded.
pub fn reserveInterp(end: u64) void {
    g_ext_floor = (end + 0xffff) & ~@as(u64, 0xffff);
}

// setMmapTops places the tops the two mmap regions bump down from: small
// mmaps in the first GiB, large ones in the extended window.
pub fn setMmapTops(first: u64, ext: u64) void {
    g_mmap_cur = first;
    g_ext_cur = ext;
}
var g_heap_lock: u32 = 0;
var g_chan_base: [*]u8 = undefined; // channel region base, for sibling thread slots

fn heapLock() void {
    while (@cmpxchgWeak(u32, &g_heap_lock, 0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}
fn heapUnlock() void {
    @atomicStore(u32, &g_heap_lock, 0, .release);
}

// ---- file-backed VMA tracking + the memory/parity syscalls the native stub
// serves locally (mem.zig / proc.zig). The stub keeps only VM-memory metadata and
// forwards every file byte to the supervisor's vfs (NR_PREAD64 / NR_PWRITE64); it
// never holds a host fd or touches the filesystem. ------------------------------
const gpa = std.heap.c_allocator;

const FileVma = struct {
    lo: u64, // page-aligned start (guest VA == RAM offset)
    hi: u64, // page-aligned end (lookup/containment)
    flen: u64, // exact mapped byte length: write back at most this from lo
    fd: u64, // the guest fd the mapping came from (the supervisor resolves it)
    off: u64, // file offset at lo
    wb: bool, // writable MAP_SHARED: the only write-back candidate
};
const WbJob = struct { va: u64, len: u64, fd: u64, off: u64 };
var g_vmas: std.ArrayListUnmanaged(FileVma) = .{};
var g_vma_lock: u32 = 0;

fn vmaLock() void {
    while (@cmpxchgWeak(u32, &g_vma_lock, 0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}
fn vmaUnlock() void {
    @atomicStore(u32, &g_vma_lock, 0, .release);
}

fn fileWb(prot: u64, flags: u64) bool {
    const t = flags & MAP_TYPE;
    return (t == MAP_SHARED or t == 3) and (prot & PROT_WRITE) != 0; // writable MAP_SHARED(_VALIDATE)
}

// ---- the guest's mappings, as /proc/<pid>/maps lists them. Each has its range,
// protection (bits 0-2, Linux's PROT_*), MAP_SHARED (bit 3) and kind (bits 8
// up), and a file's supervisor id and offset at lo: the native stub's
// mem.MapEnt, which the supervisor renders. The RAM behind them is
// identity-mapped and never moves; this is the guest's account of it, kept by
// mmap, munmap, mprotect and mremap. The brk heap is listed from its bounds. --
pub const MapEnt = extern struct { lo: u64, hi: u64, off: u64, aux: u64, attr: u64 };
pub const M_ANON: u64 = 1;
pub const M_FILE: u64 = 2;
pub const M_HEAP: u64 = 4;
pub const M_MAIN: u64 = 5;
pub const M_INTERP: u64 = 6;
pub const M_STACK: u64 = 7;
var g_maps: std.ArrayListUnmanaged(MapEnt) = .{};
var g_maps_lock: std.Thread.Mutex = .{};

fn fileOff(e: MapEnt, at: u64) u64 {
    return if (e.attr >> 8 == M_FILE) e.off + (at - e.lo) else 0;
}

// guestMapped reports whether every byte of [addr, addr+n) is guest memory:
// in RAM and in a mapping or the heap, whatever its protection (a tracer's
// peek and poke reach any of it, as ptrace's do).
fn guestMapped(addr: u64, n: u64, ram_len: usize) bool {
    const end, const o = @addWithOverflow(addr, n);
    if (o != 0 or end > ram_len) return false;
    heapLock();
    const hlo = g_brk_start;
    const hhi = g_brk_cur;
    heapUnlock();
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    var cur = addr;
    outer: while (cur < end) {
        if (cur >= hlo and cur < hhi) {
            cur = hhi;
            continue;
        }
        for (g_maps.items) |e| {
            if (cur >= e.lo and cur < e.hi) {
                cur = e.hi;
                continue :outer;
            }
        }
        return false;
    }
    return true;
}

// cutMaps takes [lo, hi) out of the table, keeping the parts of the mappings
// it cuts through. g_maps_lock is held.
fn cutMaps(lo: u64, hi: u64) void {
    var i: usize = 0;
    while (i < g_maps.items.len) {
        const e = g_maps.items[i];
        if (e.hi <= lo or e.lo >= hi) {
            i += 1;
            continue;
        }
        _ = g_maps.swapRemove(i);
        if (e.lo < lo) g_maps.append(gpa, .{ .lo = e.lo, .hi = lo, .off = e.off, .aux = e.aux, .attr = e.attr }) catch {};
        if (e.hi > hi) g_maps.append(gpa, .{ .lo = hi, .hi = e.hi, .off = fileOff(e, hi), .aux = e.aux, .attr = e.attr }) catch {};
    }
}

// addMap records a mapping of [lo, hi), in place of any it overlaps.
pub fn addMap(lo: u64, hi: u64, prot: u64, kind: u64, shared: bool, off: u64, aux: u64) void {
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    cutMaps(lo, hi);
    g_maps.append(gpa, .{ .lo = lo, .hi = hi, .off = off, .aux = aux, .attr = kind << 8 | @as(u64, @intFromBool(shared)) << 3 | (prot & 7) }) catch {};
}

fn dropMaps(lo: u64, hi: u64) void {
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    cutMaps(lo, hi);
}

// protectMaps gives the mapped parts of [lo, hi) protection prot.
fn protectMaps(lo: u64, hi: u64, prot: u64) void {
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    var parts: std.ArrayListUnmanaged(MapEnt) = .{};
    defer parts.deinit(gpa);
    for (g_maps.items) |e| {
        if (e.hi <= lo or e.lo >= hi) continue;
        const a = @max(e.lo, lo);
        parts.append(gpa, .{ .lo = a, .hi = @min(e.hi, hi), .off = fileOff(e, a), .aux = e.aux, .attr = (e.attr & ~@as(u64, 7)) | (prot & 7) }) catch return;
    }
    cutMaps(lo, hi);
    g_maps.appendSlice(gpa, parts.items) catch {};
}

// moveMaps records mremap's move of the mapping at old, [old, old+on), to
// [new, new+nn). keep: the old range stays mapped (MREMAP_DONTUNMAP).
fn moveMaps(old: u64, on: u64, new: u64, nn: u64, keep: bool) void {
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    var src: ?MapEnt = null;
    for (g_maps.items) |e| {
        if (e.lo <= old and old < e.hi) {
            src = e;
            break;
        }
    }
    if (!keep) cutMaps(old, old + on);
    const e = src orelse return;
    cutMaps(new, new + nn);
    g_maps.append(gpa, .{ .lo = new, .hi = new + nn, .off = fileOff(e, old), .aux = e.aux, .attr = e.attr }) catch {};
}

fn mapLess(_: void, a: MapEnt, b: MapEnt) bool {
    return a.lo < b.lo;
}

// listMaps writes the mappings at or above from into out in address order, the
// heap among them, at most cap; next is where the next call starts, 0 once all
// are written. It returns how many it wrote.
pub fn listMaps(out: [*]MapEnt, cap: usize, from: u64, next: *u64) u64 {
    next.* = 0;
    heapLock();
    const hlo = (g_brk_start + 0xfff) & ~@as(u64, 0xfff);
    const hhi = (g_brk_cur + 0xfff) & ~@as(u64, 0xfff);
    heapUnlock();
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    const all = gpa.alloc(MapEnt, g_maps.items.len + 1) catch return 0;
    defer gpa.free(all);
    @memcpy(all[0..g_maps.items.len], g_maps.items);
    var n = g_maps.items.len;
    if (hhi > hlo) {
        all[n] = .{ .lo = hlo, .hi = hhi, .off = 0, .aux = 0, .attr = M_HEAP << 8 | 3 };
        n += 1;
    }
    std.mem.sort(MapEnt, all[0..n], {}, mapLess);
    var w: usize = 0;
    for (all[0..n]) |e| {
        if (e.lo < from) continue;
        if (w == cap) {
            next.* = e.lo;
            break;
        }
        out[w] = e;
        w += 1;
    }
    return w;
}

fn listMapsAs(out: [*]smaps.MapEnt, cap: usize, from: u64, next: *u64) u64 {
    return listMaps(@ptrCast(out), cap, from, next);
}

// ram_base is where the guest's RAM lies in the stub: a guest address a is at
// ram_base + a.
var ram_base: u64 = 0;

pub fn ramBase() u64 {
    return ram_base;
}

// mapsSnapshot copies the table, for a fork child (adoptMaps).
pub fn mapsSnapshot() []MapEnt {
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    return gpa.dupe(MapEnt, g_maps.items) catch &.{};
}

pub fn adoptMaps(es: []const MapEnt) void {
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    g_maps.appendSlice(gpa, es) catch {};
}

// mapName has the supervisor name the file behind guest fd for the maps, and
// returns the id the mapping is listed by (0 if it has none).
fn mapName(v: *Vmm, ch: *chan.Chan, sc: Syscall, fd: u64, exchange: ExchangeFn) u64 {
    const r = v.serveSyscall(ch, .{ .nr = LC_MAPNAME, .args = .{ fd, 0, 0, 0, 0, 0 }, .elr = sc.elr, .spsr = sc.spsr }, exchange);
    return if (@as(i64, @bitCast(r)) > 0) r else 0;
}

fn mapShared(flags: u64) bool {
    const t = flags & MAP_TYPE;
    return t == MAP_SHARED or t == 3;
}

fn vmaAtLocked(a: u64) ?FileVma {
    for (g_vmas.items) |e| {
        if (a >= e.lo and a < e.hi) return e;
    }
    return null;
}
fn vmaNextLocked(a: u64, hi: u64) u64 {
    var n = hi;
    for (g_vmas.items) |e| {
        if (e.lo > a and e.lo < n) n = e.lo;
    }
    return n;
}

// vmaTrimLocked removes file-VMA coverage in [lo,hi), splitting/trimming overlaps
// (mirrors mem.zig vmaPunch). Caller holds g_vma_lock.
fn vmaTrimLocked(lo: u64, hi: u64) void {
    var i: usize = 0;
    while (i < g_vmas.items.len) {
        const e = g_vmas.items[i];
        if (e.hi <= lo or e.lo >= hi) {
            i += 1;
            continue;
        }
        if (e.lo < lo) {
            var l = e;
            l.hi = lo;
            l.flen = @min(e.flen, lo - e.lo);
            g_vmas.append(gpa, l) catch {};
        }
        if (e.hi > hi) {
            var r = e;
            r.lo = hi;
            r.off = e.off + (hi - e.lo);
            r.flen = if (e.lo + e.flen > hi) e.lo + e.flen - hi else 0;
            g_vmas.append(gpa, r) catch {};
        }
        _ = g_vmas.swapRemove(i);
    }
}

// vmaRecord notes a file-backed mapping after its pread-fill; prior coverage is
// forgotten (MAP_FIXED replace). No host fd is held -- only metadata.
fn vmaRecord(lo: u64, flen: u64, fd: u64, off: u64, wb: bool) void {
    const hi = (lo +% flen +% 0xfff) & ~@as(u64, 0xfff);
    vmaLock();
    defer vmaUnlock();
    vmaTrimLocked(lo, hi);
    g_vmas.append(gpa, .{ .lo = lo, .hi = hi, .flen = flen, .fd = fd, .off = off, .wb = wb }) catch {};
}

// vmaRelocate moves VMAs fully inside [lo,hi) by (dst-lo); partial overlaps are
// left (rare). Used by mremap.
fn vmaRelocate(lo: u64, hi: u64, dst: u64) void {
    vmaLock();
    defer vmaUnlock();
    const delta = dst -% lo;
    for (g_vmas.items) |*e| {
        if (e.lo >= lo and e.hi <= hi) {
            e.lo +%= delta;
            e.hi +%= delta;
        }
    }
}

// vmaWriteBack forwards the dirty writable-MAP_SHARED portions of [lo,hi) to their
// files, one batched NR_PWRITE64 each (the supervisor owns the fd and does the
// pwrite through the vfs; the stub touches no host fd). remove=true (munmap) trims
// the coverage; false (msync) keeps it. The spinlock is released before any
// serveSyscall so a long forward never stalls sibling vcpu threads.
fn vmaWriteBack(v: *Vmm, ch: *chan.Chan, lo: u64, hi: u64, remove: bool, sc: Syscall, exchange: ExchangeFn) void {
    var jobs: [64]WbJob = undefined;
    var nj: usize = 0;
    vmaLock();
    var i: usize = 0;
    while (i < g_vmas.items.len) {
        const e = g_vmas.items[i];
        if (e.hi <= lo or e.lo >= hi) {
            i += 1;
            continue;
        }
        if (e.wb and nj < jobs.len) {
            const wlo = @max(lo, e.lo);
            const wend = @min(@min(hi, e.hi), e.lo + e.flen);
            if (wend > wlo) {
                jobs[nj] = .{ .va = wlo, .len = wend - wlo, .fd = e.fd, .off = e.off + (wlo - e.lo) };
                nj += 1;
            }
        }
        if (!remove) {
            i += 1;
            continue;
        }
        if (e.lo < lo) {
            var l = e;
            l.hi = lo;
            l.flen = @min(e.flen, lo - e.lo);
            g_vmas.append(gpa, l) catch {};
        }
        if (e.hi > hi) {
            var r = e;
            r.lo = hi;
            r.off = e.off + (hi - e.lo);
            r.flen = if (e.lo + e.flen > hi) e.lo + e.flen - hi else 0;
            g_vmas.append(gpa, r) catch {};
        }
        _ = g_vmas.swapRemove(i);
    }
    vmaUnlock();
    var k: usize = 0;
    while (k < nj) : (k += 1) {
        const pr = Syscall{ .nr = NR_PWRITE64, .args = .{ jobs[k].fd, jobs[k].va, jobs[k].len, jobs[k].off, 0, 0 }, .elr = sc.elr, .spsr = sc.spsr };
        _ = v.serveSyscall(ch, pr, exchange);
    }
}

// discard gives MADV_DONTNEED/FREE/REMOVE their Linux meaning without corrupting
// file mappings: anonymous -> zero (Go's scavenger needs this); private/read-only
// file -> restore from the file (forwarded pread); writable MAP_SHARED -> leave
// intact (live in RAM, written back only at msync/munmap). Mirrors mem.zig discard.
fn discard(v: *Vmm, ch: *chan.Chan, lo: u64, hi: u64, sc: Syscall, exchange: ExchangeFn) void {
    var a = lo;
    while (a < hi) {
        vmaLock();
        const hit = vmaAtLocked(a);
        const seg_hi = if (hit) |e| @min(hi, e.hi) else vmaNextLocked(a, hi);
        vmaUnlock();
        if (hit) |e| {
            if (!e.wb) { // private or read-only shared file: restore the file bytes
                @memset(v.ram[@intCast(a)..@intCast(seg_hi)], 0);
                const flen_here = if (e.lo + e.flen > a) @min(seg_hi - a, e.lo + e.flen - a) else 0;
                if (flen_here > 0) {
                    const pr = Syscall{ .nr = NR_PREAD64, .args = .{ e.fd, a, flen_here, e.off + (a - e.lo), 0, 0 }, .elr = sc.elr, .spsr = sc.spsr };
                    _ = v.serveSyscall(ch, pr, exchange);
                }
            } // writable MAP_SHARED: leave as-is
        } else {
            @memset(v.ram[@intCast(a)..@intCast(seg_hi)], 0); // anonymous
        }
        a = seg_hi;
    }
}

// mremap moves/grows a mapping within VM RAM: copy the bytes, move the file-VMA
// coverage. Shrink/same is in place; growing needs MAYMOVE (the bump model can't
// guarantee the bytes above a mapping are free). Flag checks mirror mem.zig remap.
fn mremap(v: *Vmm, ch: *chan.Chan, sc: Syscall, exchange: ExchangeFn) u64 {
    const old = sc.args[0];
    const old_len = sc.args[1];
    const new_len = sc.args[2];
    const flags = sc.args[3];
    const new_addr = sc.args[4];
    if (old & 0xfff != 0) return neg(EINVAL);
    if (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0) return neg(EINVAL);
    if (flags & MREMAP_FIXED != 0 and flags & MREMAP_MAYMOVE == 0) return neg(EINVAL);
    if (flags & MREMAP_DONTUNMAP != 0 and (flags & MREMAP_MAYMOVE == 0 or old_len != new_len)) return neg(EINVAL);
    const on = (old_len +% 0xfff) & ~@as(u64, 0xfff);
    const nn = (new_len +% 0xfff) & ~@as(u64, 0xfff);
    if (nn == 0 or on == 0) return neg(EINVAL);
    if (nn <= on and flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) == 0) {
        if (nn < on) {
            vmaWriteBack(v, ch, old + nn, old + on, true, sc, exchange); // flush+trim the tail
            dropMaps(old + nn, old + on);
        }
        return old;
    }
    var dst: u64 = undefined;
    if (flags & MREMAP_FIXED != 0) {
        if (new_addr & 0xfff != 0) return neg(EINVAL);
        if (new_addr +% nn > EXT_TOP) return neg(ENOMEM);
        if (new_addr < old + on and old < new_addr + nn) return neg(EINVAL); // overlap
        vmaWriteBack(v, ch, new_addr, new_addr + nn, true, sc, exchange); // clobber target: flush+forget
        dst = new_addr;
    } else {
        if (flags & MREMAP_MAYMOVE == 0) return neg(ENOMEM);
        heapLock();
        if (nn <= g_mmap_cur - g_brk_cur) {
            g_mmap_cur -= nn;
            dst = g_mmap_cur;
        } else if (nn <= g_ext_cur - g_ext_floor) {
            g_ext_cur -= nn;
            dst = g_ext_cur;
        } else {
            heapUnlock();
            return neg(ENOMEM);
        }
        heapUnlock();
    }
    const n = @min(on, nn);
    @memcpy(v.ram[@intCast(dst)..@intCast(dst + n)], v.ram[@intCast(old)..@intCast(old + n)]);
    if (nn > n) @memset(v.ram[@intCast(dst + n)..@intCast(dst + nn)], 0);
    vmaRelocate(old, old + on, dst);
    moveMaps(old, on, dst, nn, flags & MREMAP_DONTUNMAP != 0);
    return dst;
}

// ---- memory cap: each stub process publishes what its guest has mapped into
// its leader slot's Proc record, and a call that would take the run's total past
// the cap fails, as the native stub does (mem.zig).
var g_acct: usize = 0;

// account makes ch's slot the one this process publishes its total in: its
// image's, or its fork child's.
pub fn account(ch: *chan.Chan) void {
    g_acct = slotIndex(ch);
    publishMem();
}

fn runMemCap() u64 {
    return @atomicLoad(u64, @as(*const u64, @ptrFromInt(@intFromPtr(g_chan_base) + TRACE_AREA_OFF + 0x2000 + 8)), .acquire);
}

fn publishMem() void {
    if (runMemCap() == 0) return;
    @atomicStore(u64, &sigProcRec(@intCast(g_acct)).mem, mappedIn(0, std.math.maxInt(u64)), .release);
}

fn othersMem() u64 {
    var n: u64 = 0;
    for (0..chan.MAX_SLOTS) |s| {
        if (s != g_acct) n +|= @atomicLoad(u64, &sigProcRec(@intCast(s)).mem, .acquire);
    }
    return n;
}

fn pageUp(n: u64) u64 {
    return (n +| 0xfff) & ~@as(u64, 0xfff);
}

// growth is how much more a call asks to map, at most.
fn growth(sc: Syscall) u64 {
    if (runMemCap() == 0) return 0;
    switch (sc.nr) {
        NR_MMAP => {
            const n = pageUp(sc.args[1]);
            if (sc.args[3] & MAP_FIXED == 0) return n;
            const lo = sc.args[0] & ~@as(u64, 0xfff);
            return n -| mappedIn(lo, lo +| n);
        },
        NR_MREMAP => return if (sc.args[3] & MREMAP_DONTUNMAP != 0) pageUp(sc.args[2]) else pageUp(sc.args[2]) -| pageUp(sc.args[1]),
        NR_BRK => {
            heapLock();
            defer heapUnlock();
            return if (sc.args[0] > g_brk_cur) pageUp(sc.args[0]) -| pageUp(g_brk_cur) else 0;
        },
        else => return 0,
    }
}

fn overCap(more: u64) bool {
    if (more == 0) return false;
    const cap = runMemCap();
    if (cap == 0) return false;
    return mappedIn(0, std.math.maxInt(u64)) +| more +| othersMem() > cap;
}

// mappedIn is how much of [lo, hi) the guest has mapped: the union of its
// mappings and its heap there, each byte counted once.
fn mappedIn(lo: u64, hi: u64) u64 {
    heapLock();
    const hlo = g_brk_start & ~@as(u64, 0xfff);
    const hhi = pageUp(g_brk_cur);
    heapUnlock();
    g_maps_lock.lock();
    defer g_maps_lock.unlock();
    const all = gpa.alloc(MapEnt, g_maps.items.len + 1) catch return 0;
    defer gpa.free(all);
    @memcpy(all[0..g_maps.items.len], g_maps.items);
    var n = g_maps.items.len;
    if (hhi > hlo) {
        all[n] = .{ .lo = hlo, .hi = hhi, .off = 0, .aux = 0, .attr = 0 };
        n += 1;
    }
    std.mem.sort(MapEnt, all[0..n], {}, mapLess);
    var total: u64 = 0;
    var cur = lo;
    for (all[0..n]) |e| {
        const a = @max(e.lo, cur);
        const b = @min(e.hi, hi);
        if (b > a) {
            total += b - a;
            cur = b;
        }
    }
    return total;
}

// ---- membarrier (ported from proc.zig): reading each other vcpu thread's
// registers forces it off its core -- a full memory barrier + context sync, the
// Apple-Silicon trick (the guest threads are real OS threads here). ---------------
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
const MB_SUPPORTED: u64 = MB_GLOBAL | MB_PRIVATE_EXPEDITED | MB_REGISTER_PRIVATE_EXPEDITED |
    MB_PRIVATE_EXPEDITED_SYNC_CORE | MB_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;
var mb_registered: u64 = 0;

fn barrierAllThreads() bool {
    asm volatile ("dmb ish" ::: "memory");
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
    asm volatile ("dmb ish" ::: "memory");
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

extern "c" fn pthread_create(t: *usize, attr: ?*anyopaque, f: *const fn (?*anyopaque) callconv(.C) ?*anyopaque, arg: ?*anyopaque) c_int;
extern "c" fn pthread_detach(t: usize) c_int;
extern "c" fn pthread_exit(value: ?*anyopaque) noreturn;
extern "c" fn malloc(n: usize) ?*anyopaque;
extern "c" fn free(p: ?*anyopaque) void;

// Guest futexes (and the CLONE_CHILD_CLEARTID join wake) are served by a
// stub-side bucket lock -- a hashed array of pthread mutex+cond -- not by
// os_sync_wait_on_address. os_sync compares the futex word itself, but that word
// is written by the guest vcpu and value-checked by a host thread, and the
// compare-and-enqueue is not serialized with the wake across that boundary, so a
// wake landing between a waiter's read of the word and its enqueue is lost (an
// intermittent hang in multi-threaded guests). The bucket lock closes the
// window: a waiter reads the word and blocks under the lock (pthread_cond_wait
// releases it atomically), and a waker bumps the bucket generation and
// broadcasts under the same lock. A thread's vcpu and its syscall handler are
// the same OS thread, so a waker takes the lock after the guest's word write; a
// waiter that locks afterwards reads the new word and does not block, and one
// already blocked is reached by the broadcast. Spurious wakes are fine -- the
// guest re-checks the word and re-waits. Every guest thread shares one VM (one
// process), so all futexes are intra-process; buckets key on the host address,
// identical across threads for a given guest word.
const PthreadMutex = extern struct { b: [64]u8 align(8) }; // _opaque_pthread_mutex_t
const PthreadCond = extern struct { b: [48]u8 align(8) }; // _opaque_pthread_cond_t
extern "c" fn pthread_mutex_init(m: *PthreadMutex, a: ?*anyopaque) c_int;
extern "c" fn pthread_mutex_lock(m: *PthreadMutex) c_int;
extern "c" fn pthread_mutex_unlock(m: *PthreadMutex) c_int;
extern "c" fn pthread_cond_init(c: *PthreadCond, a: ?*anyopaque) c_int;
extern "c" fn pthread_cond_wait(c: *PthreadCond, m: *PthreadMutex) c_int;
extern "c" fn pthread_cond_broadcast(c: *PthreadCond) c_int;

const FUTEX_BUCKETS = 64;
const FutexBucket = struct { mu: PthreadMutex, cv: PthreadCond, gen: u64 };
var g_futex: [FUTEX_BUCKETS]FutexBucket = undefined;

fn futexBucket(host_addr: usize) *FutexBucket {
    const h = (host_addr >> 2) *% 0x9E3779B97F4A7C15;
    return &g_futex[(h >> 58) & (FUTEX_BUCKETS - 1)];
}

// futexWait blocks while the guest word at ram+addr still equals val.
fn futexWait(ram: [*]u8, addr: u64, val: u32) void {
    const ua: *const u32 = @ptrFromInt(@intFromPtr(ram) + addr);
    const bk = futexBucket(@intFromPtr(ua));
    _ = pthread_mutex_lock(&bk.mu);
    if (@atomicLoad(u32, ua, .acquire) == val) {
        const g = bk.gen;
        while (bk.gen == g) _ = pthread_cond_wait(&bk.cv, &bk.mu);
    }
    _ = pthread_mutex_unlock(&bk.mu);
}

// futexWake wakes everything in the word's bucket; woken guests re-check.
fn futexWake(ram: [*]u8, addr: u64) void {
    const bk = futexBucket(@intFromPtr(ram) + addr);
    _ = pthread_mutex_lock(&bk.mu);
    bk.gen +%= 1;
    _ = pthread_cond_broadcast(&bk.cv);
    _ = pthread_mutex_unlock(&bk.mu);
}

// initThreads records the channel base (sibling slots live at base + slotOff)
// and initialises the futex buckets; call once after chan.init.
pub fn initThreads(chan_base: [*]u8) bool {
    g_chan_base = chan_base;
    for (&g_futex) |*bk| {
        _ = pthread_mutex_init(&bk.mu, null);
        _ = pthread_cond_init(&bk.cv, null);
        bk.gen = 0;
    }
    return true;
}

// futexOp serves FUTEX_WAIT/WAKE on a guest futex word (at v.ram + addr) via the
// stub-side bucket lock (see futexWait/futexWake).
fn futexOp(v: *Vmm, sc: Syscall) u64 {
    const op = sc.args[1] & ~@as(u64, FUTEX_PRIVATE | FUTEX_CLOCK_REALTIME);
    switch (op) {
        FUTEX_WAIT => {
            futexWait(v.ram, sc.args[0], @truncate(sc.args[2]));
            return 0; // the caller re-checks (spurious wakes allowed)
        },
        FUTEX_WAKE => {
            futexWake(v.ram, sc.args[0]);
            return sc.args[2];
        },
        else => return neg(ENOSYS),
    }
}

// ThreadArg bootstraps a new guest thread's OS thread.
const ThreadArg = struct {
    ram: [*]u8,
    ram_len: usize,
    slot: *chan.Chan,
    exchange: ExchangeFn,
    ctid: u64,
    regs: ForkRegs, // the context the child starts in
};

// threadEntry runs on the new OS thread: it creates this thread's own vcpu in the
// shared VM, sets it up at the clone return, and runs the thread's syscall loop.
fn threadEntry(p: ?*anyopaque) callconv(.C) ?*anyopaque {
    const a: *ThreadArg = @ptrCast(@alignCast(p.?));
    var child = Vmm{ .ram = a.ram, .ram_len = a.ram_len };
    if (hv_vcpu_create(&child.vcpu, &child.exit, null) != HV_SUCCESS) {
        // Out of host vcpus (the limit is system-wide, not the per-VM
        // hv_vm_get_max_vcpu_count). clone() already handed the guest this
        // thread's tid, so run the kernel's thread-exit duties anyway -- clear
        // the CLONE_CHILD_CLEARTID word, wake a joiner, and post THREAD_GONE so
        // the supervisor frees the slot -- instead of looping on a null vcpu.
        // Otherwise the guest blocks forever joining a thread that never ran, is
        // then SIGKILLed, and the abrupt kill can leak this stub.
        child.threadExit(a.slot, a.ctid, 0);
        free(p);
        return null;
    }
    startForked(&child, &a.regs, false); // a thread of the parent's stub: it shares the live heap globals, so do not rewrite them
    // A traced new thread takes the stop an auto-attached tracee starts with
    // before its first instruction.
    if (a.slot.stdio & STDIO_TRACED != 0)
        _ = child.serveSyscall(a.slot, .{ .nr = NR_CHILD_STOP, .args = .{ 0, 0, 0, 0, 0, 0 }, .elr = 0, .spsr = 0 }, a.exchange);
    child.threadRunLoop(a.slot, a.exchange, a.ctid);
    _ = hv_vcpu_destroy(child.vcpu);
    free(p);
    return null;
}

// putTid stores tid at guest address addr, when that lies in the guest's memory.
fn putTid(v: *Vmm, addr: u64, tid: u64) void {
    if (addr == 0 or addr > v.ram_len - 4) return;
    @as(*align(1) u32, @ptrFromInt(@intFromPtr(v.ram) + addr)).* = @truncate(tid);
}

// spawnThread is the parent's REP_CLONE handler: it starts the OS thread the
// supervisor allocated a slot/tid for, and returns the tid as clone's result.
fn spawnThread(v: *Vmm, ch: *chan.Chan, sc: Syscall, exchange: ExchangeFn) u64 {
    const tid = ch.ret;
    const flags = ch.args[1];
    // As on Linux, the child starts with all of the parent's registers but x0
    // (0), on the stack clone was given (the parent's own when 0: a vfork child
    // runs on it while the parent is held) and, with CLONE_SETTLS, its tls.
    // glibc keeps the function it calls in the child in x10 across clone, and
    // returns from its vfork through x30.
    const a: *ThreadArg = @ptrCast(@alignCast(malloc(@sizeOf(ThreadArg)) orelse return neg(EAGAIN)));
    a.* = .{
        .ram = v.ram,
        .ram_len = v.ram_len,
        .slot = @ptrCast(@alignCast(g_chan_base + @as(usize, @intCast(ch.args[0])))),
        .exchange = exchange,
        .ctid = if (flags & CLONE_CHILD_CLEARTID != 0) ch.args[5] else 0,
        .regs = undefined,
    };
    saveForkRegs(v, sc, &a.regs);
    if (ch.args[2] != 0) a.regs.sp = ch.args[2];
    if (flags & CLONE_SETTLS != 0) a.regs.tpidr = ch.args[4];
    // The new tid goes where the clone asked before either side runs on, as
    // the kernel stores it (both in the one VM memory); musl learns a thread's
    // own tid only from CLONE_PARENT_SETTID. An address outside the guest's
    // memory is skipped, as the kernel ignores a failed store there.
    if (flags & CLONE_PARENT_SETTID != 0) putTid(v, ch.args[3], tid);
    if (flags & CLONE_CHILD_SETTID != 0) putTid(v, ch.args[5], tid);
    const traced = ch.stdio & STDIO_TRACED != 0; // as the supervisor saw it when it replied
    var t: usize = 0;
    if (pthread_create(&t, null, threadEntry, a) != 0) {
        free(a);
        if (flags & CLONE_VFORK != 0) {
            _ = vforkWait(v, ch, sc, exchange);
        } else if (traced) {
            _ = reportForked(v, ch, sc, 0, exchange);
        }
        return neg(EAGAIN);
    }
    _ = pthread_detach(t);
    // A vfork (CLONE_VFORK) parent must be suspended until the child execs or
    // exits: parent and child share one stack, so letting the parent run on
    // concurrently corrupts it.
    if (flags & CLONE_VFORK != 0) return vforkWait(v, ch, sc, exchange);
    // A traced caller reports the started thread, for its tracer's clone event
    // and the call's exit stop.
    if (traced) return reportForked(v, ch, sc, tid, exchange);
    return tid;
}

// ---- fork -----------------------------------------------------------------
// A forked child must run in its own VM -- Hypervisor.framework is not fork-safe
// (hv_vm_create in a fork() child returns HV_BUSY forever) -- so a fork cannot
// share this process. Instead the parent snapshots its used guest RAM into a
// fresh file and posix_spawns a new stub (a new task, where hv_vm_create works)
// that maps the snapshot and resumes at the fork return.
extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn ftruncate(fd: c_int, len: i64) c_int;
extern "c" fn pwrite(fd: c_int, buf: [*]const u8, n: usize, off: i64) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn getpid() c_int;
extern "c" fn _exit(code: c_int) noreturn;
extern "c" fn _NSGetExecutablePath(buf: [*]u8, size: *u32) c_int;
extern "c" fn pthread_sigmask(how: c_int, set: ?*const u32, old: ?*u32) c_int;
const SIG_BLOCK: c_int = 1;
const SIG_SETMASK: c_int = 3;
extern "c" fn posix_spawn(pid: *c_int, path: [*:0]const u8, fa: ?*anyopaque, attr: ?*anyopaque, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) c_int;
extern "c" var environ: [*:null]?[*:0]u8;

const O_RDWR_V: c_int = 2;
const O_CREAT_V: c_int = 0x0200;
const O_TRUNC_V: c_int = 0x0400;

// g_chan_path is the channel file path; a forked child is spawned with it so it
// maps the same channel. Set by the stub's main before the run loop.
pub var g_chan_path: [*:0]const u8 = undefined;

// ForkRegs is the parent's vcpu state handed to a forked child, which reloads it
// (with x0 = 0) to resume exactly at the fork return.
pub const ForkRegs = extern struct {
    x: [31]u64, // x0..x30
    sp: u64, // SP_EL1
    pc: u64, // resume PC (parent's ELR_EL1)
    pstate: u64, // SPSR_EL1
    tpidr: u64, // TPIDR_EL0
    fpcr: u64,
    fpsr: u64,
    brk_start: u64, // g_brk_start (brk floor)
    brk_cur: u64, // g_brk_cur (heap top)
    mmap_cur: u64, // g_mmap_cur (mmap bump pointer)
    ext_cur: u64, // g_ext_cur (extended mmap window bump pointer)
    ext_floor: u64, // g_ext_floor (extended window floor, past the interpreter)
    q: [32]Simd16, // q0..q31
};

// initForked attaches a VM to a forked child's RAM, which already holds the
// parent's page tables, exception vector and TLB trampoline (copied with the
// memory), so it only maps the RAM and creates the vcpu.
pub fn initForked(ram: [*]u8, ram_len: usize) Error!Vmm {
    if (hv_vm_create(null) != HV_SUCCESS) return error.VmCreate;
    var v = Vmm{ .ram = ram, .ram_len = ram_len };
    if (hv_vm_map(@ptrCast(ram), 0, ram_len, MEM_READ | MEM_WRITE | MEM_EXEC) != HV_SUCCESS)
        return error.Map;
    if (hv_vcpu_create(&v.vcpu, &v.exit, null) != HV_SUCCESS) return error.VcpuCreate;
    return v;
}

// saveForkRegs captures the parent's vcpu state at the fork syscall.
fn saveForkRegs(v: *Vmm, sc: Syscall, r: *ForkRegs) void {
    for (0..31) |i| {
        var x: u64 = 0;
        _ = hv_vcpu_get_reg(v.vcpu, REG_X0 + @as(u32, @intCast(i)), &x);
        r.x[i] = x;
    }
    var sp: u64 = 0;
    _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SP_EL1, &sp);
    r.sp = sp;
    r.pc = sc.elr; // resume after the svc
    r.pstate = sc.spsr; // the guest's pstate at the trap
    var tp: u64 = 0;
    _ = hv_vcpu_get_sys_reg(v.vcpu, SR_TPIDR_EL0, &tp);
    r.tpidr = tp;
    var fpcr: u64 = 0;
    _ = hv_vcpu_get_reg(v.vcpu, REG_FPCR, &fpcr);
    r.fpcr = fpcr;
    var fpsr: u64 = 0;
    _ = hv_vcpu_get_reg(v.vcpu, REG_FPSR, &fpsr);
    r.fpsr = fpsr;
    r.brk_start = g_brk_start;
    r.brk_cur = g_brk_cur;
    r.mmap_cur = g_mmap_cur;
    r.ext_cur = g_ext_cur;
    r.ext_floor = g_ext_floor;
    for (0..32) |i| {
        var q: Simd16 = undefined;
        _ = hv_vcpu_get_simd_fp_reg(v.vcpu, SIMD_Q0 + @as(u32, @intCast(i)), &q);
        r.q[i] = q;
    }
}

// startForked sets a forked child's vcpu to resume where the parent's fork
// returned, with the parent's registers and x0 = 0 (same MMU/EL1 state as
// start(); the page tables already live in the copied RAM).
pub fn startForked(v: *Vmm, r: *const ForkRegs, set_heap: bool) void {
    // A forked child is a fresh process whose heap globals start at their
    // defaults, so it adopts the parent's snapshot (set_heap). A vfork child
    // runs as a thread inside the parent's stub and shares these same live
    // globals, so it must not write the snapshot back: the snapshot was taken
    // before hv_vcpu_create, another of the parent's threads may have mmap'd or
    // moved brk since, and restoring the older values rolls the bump allocator
    // backward and hands one guest address out twice -- overlapping heap that
    // surfaces as a GC bad pointer in the parent.
    if (set_heap) {
        g_brk_start = r.brk_start;
        g_brk_cur = r.brk_cur;
        g_mmap_cur = r.mmap_cur;
        g_ext_cur = r.ext_cur;
        g_ext_floor = r.ext_floor;
    }
    const tcr: u64 = 16 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (@as(u64, 2) << 32);
    _ = hv_vcpu_set_sys_reg(v.vcpu, SR_MAIR_EL1, 0xFF);
    _ = hv_vcpu_set_sys_reg(v.vcpu, SR_TCR_EL1, tcr);
    _ = hv_vcpu_set_sys_reg(v.vcpu, SR_TTBR0_EL1, L0_IPA);
    _ = hv_vcpu_set_sys_reg(v.vcpu, SR_VBAR_EL1, VBAR);
    _ = hv_vcpu_set_sys_reg(v.vcpu, SR_SP_EL1, r.sp);
    _ = hv_vcpu_set_sys_reg(v.vcpu, SR_CPACR_EL1, 0x300000);
    _ = hv_vcpu_set_sys_reg(v.vcpu, SR_TPIDR_EL0, r.tpidr);
    var sctlr: u64 = 0;
    _ = hv_vcpu_get_sys_reg(v.vcpu, SR_SCTLR_EL1, &sctlr);
    _ = hv_vcpu_set_sys_reg(v.vcpu, SR_SCTLR_EL1, sctlr | 0x1005);
    _ = hv_vcpu_set_reg(v.vcpu, REG_X0, 0);
    for (1..31) |i| _ = hv_vcpu_set_reg(v.vcpu, REG_X0 + @as(u32, @intCast(i)), r.x[i]);
    _ = hv_vcpu_set_reg(v.vcpu, REG_PC, r.pc);
    _ = hv_vcpu_set_reg(v.vcpu, REG_CPSR, r.pstate);
    _ = hv_vcpu_set_reg(v.vcpu, REG_FPCR, r.fpcr);
    _ = hv_vcpu_set_reg(v.vcpu, REG_FPSR, r.fpsr);
    for (0..32) |i| _ = hv_vcpu_set_simd_fp_reg(v.vcpu, SIMD_Q0 + @as(u32, @intCast(i)), r.q[i]);
}

// copyRam writes guest RAM [lo, hi) into the snapshot file at the same offset.
fn copyRam(v: *Vmm, fd: c_int, lo: u64, hi: u64) bool {
    if (hi <= lo) return true;
    return pwriteAll(fd, v.ram + @as(usize, @intCast(lo)), @intCast(hi - lo), @intCast(lo));
}

fn pwriteAll(fd: c_int, buf: [*]const u8, n: usize, off: i64) bool {
    var done: usize = 0;
    while (done < n) {
        const w = pwrite(fd, buf + done, n - done, off + @as(i64, @intCast(done)));
        if (w <= 0) return false;
        done += @intCast(w);
    }
    return true;
}

// reportForked reports the child a fork (its host pid) or a traced clone (its
// tid; 0: none) made and returns the supervisor's answer, the call's result as
// a tracer may have left it; the reply loop serves the tracer's memory requests
// while the call is stopped.
fn reportForked(v: *Vmm, ch: *chan.Chan, sc: Syscall, pid: u64, exchange: ExchangeFn) u64 {
    return v.serveSyscall(ch, .{ .nr = NR_FORKED, .args = .{ pid, 0, 0, 0, 0, 0 }, .elr = sc.elr, .spsr = sc.spsr }, exchange);
}

// vforkWait holds a CLONE_VFORK parent until the supervisor reports the child
// has exec'd or exited, and returns its answer (the call's result).
fn vforkWait(v: *Vmm, ch: *chan.Chan, sc: Syscall, exchange: ExchangeFn) u64 {
    return v.serveSyscall(ch, .{ .nr = NR_VFORK_WAIT, .args = .{ 0, 0, 0, 0, 0, 0 }, .elr = sc.elr, .spsr = sc.spsr }, exchange);
}

// forkSpawn is the parent's REP_FORK handler. It snapshots the used guest RAM --
// every mapping, the heap, and the page tables and vectors above the stack, the
// rest being sparse zero -- into a fresh file by reading the parent's own mmap
// (coherent with the guest's vcpu writes, so the snapshot is current), saves the
// parent's registers, and
// posix_spawns a fresh stub for the child, which maps the snapshot and resumes
// at the fork return. The child adopts the supervisor-allocated slot and
// announces itself; the parent reports the child's pid and, for vfork, holds
// until the child execs or exits.
fn forkSpawn(v: *Vmm, ch: *chan.Chan, sc: Syscall, exchange: ExchangeFn) u64 {
    const child_off = ch.args[0];
    const flags = ch.args[1];
    const tls = ch.args[4];
    const ctid = ch.args[5];
    const gpid = ch.ret;
    const pid: c_int = getpid();

    var vram_buf: [64]u8 = undefined;
    var regs_buf: [64]u8 = undefined;
    const vram_path = std.fmt.bufPrintZ(&vram_buf, "/tmp/lc-fork-{d}-{d}-r", .{ pid, gpid }) catch return neg(EAGAIN);
    const regs_path = std.fmt.bufPrintZ(&regs_buf, "/tmp/lc-fork-{d}-{d}-s", .{ pid, gpid }) catch return neg(EAGAIN);

    // 1. Snapshot the used RAM (reading v.ram, coherent with guest writes).
    const maps = mapsSnapshot();
    defer gpa.free(maps);
    const cfd = open(vram_path.ptr, O_RDWR_V | O_CREAT_V | O_TRUNC_V, @as(c_int, 0o600));
    if (cfd < 0) return neg(EAGAIN);
    var copied = ftruncate(cfd, @intCast(v.ram_len)) == 0 and
        copyRam(v, cfd, g_brk_start, g_brk_cur) and
        copyRam(v, cfd, L3_BASE, EXT_BASE);
    for (maps) |e| copied = copied and copyRam(v, cfd, e.lo, e.hi);
    _ = close(cfd);
    if (!copied) return neg(EAGAIN);

    // 2. Save the parent's registers.
    var regs: ForkRegs = undefined;
    saveForkRegs(v, sc, &regs);
    const rfd = open(regs_path.ptr, O_RDWR_V | O_CREAT_V | O_TRUNC_V, @as(c_int, 0o600));
    if (rfd < 0) return neg(EAGAIN);
    _ = write(rfd, @ptrCast(&regs), @sizeOf(ForkRegs));
    // and the mappings, for the child's /proc/self/maps.
    const count: u64 = maps.len;
    const ok = pwriteAll(rfd, @ptrCast(&count), 8, @sizeOf(ForkRegs)) and
        pwriteAll(rfd, @ptrCast(maps.ptr), maps.len * @sizeOf(MapEnt), @sizeOf(ForkRegs) + 8);
    _ = close(rfd);
    if (!ok) return neg(EAGAIN);

    // 3. posix_spawn a fresh stub (new task -> HVF works) for the child.
    var self_buf: [1024]u8 = undefined;
    var self_size: u32 = self_buf.len;
    if (_NSGetExecutablePath(&self_buf, &self_size) != 0) return neg(EAGAIN);
    var mk_buf: [160]u8 = undefined;
    const marker = std.fmt.bufPrintZ(&mk_buf, "lc-fork@{x}@{x}@{x}@{x}@{x}", .{ child_off, flags, tls, ctid, gpid }) catch return neg(EAGAIN);
    const self_z: [*:0]const u8 = @ptrCast(&self_buf);
    var argv = [_]?[*:0]const u8{ marker.ptr, g_chan_path, vram_path.ptr, regs_path.ptr, null };
    // The child starts with kicks (SIGUSR1) blocked, as it inherits this
    // thread's mask: one sent before it installs its handler would end it.
    var kick: u32 = 1 << (30 - 1);
    var old_mask: u32 = 0;
    _ = pthread_sigmask(SIG_BLOCK, &kick, &old_mask);
    var cpid: c_int = 0;
    const spawned = posix_spawn(&cpid, self_z, null, null, @ptrCast(&argv), environ);
    _ = pthread_sigmask(SIG_SETMASK, &old_mask, null);
    if (spawned != 0) return neg(EAGAIN);

    // 4. Report the child's pid; hold for vfork.
    const cc: *chan.Chan = @ptrCast(@alignCast(g_chan_base + @as(usize, @intCast(child_off))));
    @atomicStore(u64, &cc.rip, @intCast(cpid), .release);
    const r = reportForked(v, ch, sc, @intCast(cpid), exchange);
    if (flags & CLONE_VFORK != 0) return vforkWait(v, ch, sc, exchange);
    return r;
}
