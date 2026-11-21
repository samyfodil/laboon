// hvf_stub.zig — the HVF backend's stub main. Like the native stub (macos/stub/
// stub.zig) it is exec'd by the supervisor with the channel path and the guest
// ELF path in argv, and talks the same shared-memory channel. Unlike it, it runs
// the guest unmodified inside a VM (vmm.zig) instead of mapping it into its own
// address space and rewriting its syscalls. See BACKEND.md.
//
// Status: the guest load, initial stack, run loop, and channel-slot handshake
// (acquireSlot: mmap the slot, slot 0) are ported from the proven spikes and the
// native stub, and compile for aarch64-macos. The guest ELF arrives in argv like
// the native stub (not via REP_START). Remaining (phase 2b): REP_HOST/fork/clone
// in the VM model, a build.sh (link Hypervisor.framework + sign), and the
// run_darwin.go spawn -- all need the M4 to build, sign, and run.

const std = @import("std");
const chan = @import("chan.zig");
const vmm = @import("vmm.zig");
const service = @import("service.zig");
const smaps = @import("smaps.zig");
const life = @import("life.zig");

// chan.zig calls root.deadThread() when the supervisor marks the slot ST_DEAD
// (this thread's guest process is ending). For the VMM that is the vcpu thread.
pub fn deadThread() noreturn {
    _exit(0);
}
extern "c" fn _exit(code: c_int) noreturn;

// 32 GiB of guest RAM, identity-mapped and sparse (the backing file is only
// touched where the guest writes). The first GiB holds the binary, brk heap,
// stack and VMM control region (4 KiB pages, so mprotect works there); the rest,
// [1 GiB, 32 GiB), is the extended mmap window (1 GiB block descriptors, vmm.zig).
// STACK_TOP sits just below the control region; small mmaps grow down below it
// (MMAP_TOP), large ones live in the extended window.
const RAM_LEN: usize = 0x8_0000_0000;
const STACK_TOP: u64 = 0x3FC0_0000; // just below the L3 page tables (vmm.zig L3_BASE)
const STACK_LEN: u64 = STACK_TOP - vmm.MMAP_TOP;

// Layout is where an exec places what Linux's ASLR moves (the program, an
// ET_EXEC, stays at its link address): the stack's top, with the small-mmap
// region below it; the break's distance past the program; the interpreter; and
// the top of the extended mmap window. drawLayout draws it anew at each exec; a
// fork child takes the parent's. The ranges are narrower than Linux's (64 MiB
// for the stack, 32 MiB for the break, 4 GiB for the interpreter and the mmap
// top) to fit the first-GiB arena and the extended window. Unrandomized
// (ADDR_NO_RANDOMIZE) it is the fixed layout.
const Layout = struct { stack_top: u64, brk_gap: u64, interp: u64, ext_top: u64 };

extern "c" fn arc4random_uniform(upper: u32) u32;
extern "c" fn arc4random_buf(buf: [*]u8, n: usize) void;

fn drawLayout(norand: bool) Layout {
    if (norand) return .{ .stack_top = STACK_TOP, .brk_gap = 0, .interp = vmm.INTERP_BASE, .ext_top = vmm.EXT_TOP };
    return .{
        .stack_top = STACK_TOP - @as(u64, arc4random_uniform(1 << 14)) * 0x1000,
        .brk_gap = @as(u64, arc4random_uniform(1 << 13)) * 0x1000,
        .interp = vmm.INTERP_BASE + @as(u64, arc4random_uniform(1 << 16)) * 0x10000,
        .ext_top = vmm.EXT_TOP - @as(u64, arc4random_uniform(1 << 16)) * 0x10000,
    };
}

const Ehdr = extern struct {
    ident: [16]u8,
    etype: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
};
const Phdr = extern struct {
    ptype: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    alignv: u64,
};
const PT_LOAD: u32 = 1;
// ET_DYN (the interpreter, and any PIE) is position-independent: load it at the
// requested base. A non-PIE ET_EXEC carries absolute p_vaddr and loads there.
const ET_DYN: u16 = 3;

const Loaded = struct { entry: u64, brk: u64, phdr: u64, phnum: u64, phent: u64 };

// loadGuestAt reads the ELF at path and copies each PT_LOAD into the guest RAM
// at base + its p_vaddr (base 0 = identity, used for the main ELF; a nonzero
// base loads the interpreter above the first-GiB arena). Returns the entry point
// (also biased by base), the page-aligned end of the
// loaded segments (the initial program break), and the in-memory address of the
// program headers (for AT_PHDR -- musl reads them to find PT_TLS and size the
// per-thread TLS block; without it a cloned thread's static TLS overlaps the
// pthread struct's tsd[] and thread-local destructors corrupt it). bss (memsz
// past filesz) is already zero: the RAM was zeroed and regions are never reused.
fn loadGuestAt(ram: []u8, path: [*:0]const u8, base: u64) !Loaded {
    const f = try std.fs.cwd().openFileZ(path, .{});
    defer f.close();
    const bytes = try f.readToEndAlloc(heap, 1 << 30);
    const eh: *const Ehdr = @ptrCast(@alignCast(bytes.ptr));
    // A non-PIE ET_EXEC carries absolute p_vaddr: load it there (identity), base
    // ignored. A PIE (ET_DYN) is position-independent: load it at base.
    const b: u64 = if (eh.etype == ET_DYN) base else 0;
    var brk: u64 = 0;
    var phdr: u64 = 0;
    var i: usize = 0;
    while (i < eh.phnum) : (i += 1) {
        const ph: *const Phdr = @ptrCast(@alignCast(bytes.ptr + eh.phoff + i * @sizeOf(Phdr)));
        if (ph.ptype != PT_LOAD) continue;
        const n: usize = @intCast(ph.filesz);
        @memcpy(ram[@intCast(b + ph.vaddr)..][0..n], bytes[@intCast(ph.offset)..][0..n]);
        const end = b + ph.vaddr + ph.memsz;
        // PF_X, PF_W, PF_R are PROT_EXEC, PROT_WRITE, PROT_READ backwards.
        const prot = (ph.flags & 1) << 2 | (ph.flags & 2) | (ph.flags & 4) >> 2;
        vmm.addMap((b + ph.vaddr) & ~@as(u64, 0xfff), (end + 0xfff) & ~@as(u64, 0xfff), prot, if (base == 0) vmm.M_MAIN else vmm.M_INTERP, false, ph.offset & ~@as(u64, 0xfff), 0);
        if (end > brk) brk = end;
        // The phdrs live at file offset eh.phoff; find the PT_LOAD that maps it
        // and translate to its guest VA (phdr table is contiguous within it).
        if (eh.phoff >= ph.offset and eh.phoff + @as(u64, eh.phnum) * eh.phentsize <= ph.offset + ph.filesz)
            phdr = b + ph.vaddr + (eh.phoff - ph.offset);
    }
    return .{ .entry = b + eh.entry, .brk = (brk + 0xfff) & ~@as(u64, 0xfff), .phdr = phdr, .phnum = eh.phnum, .phent = eh.phentsize };
}

var heap = std.heap.c_allocator;

fn serviceMaps(out: [*]service.MapEnt, cap: usize, from: u64, next: *u64) u64 {
    return vmm.listMaps(@ptrCast(out), cap, from, next);
}

fn vmmMaps(out: [*]smaps.MapEnt, cap: usize, from: u64, next: *u64) u64 {
    return vmm.listMaps(@ptrCast(out), cap, from, next);
}

// serviceSmaps counts the guest's 4 KiB pages by the RAM behind them, at
// vmm.ramBase + their address. A fork copies the RAM, so nothing is shared
// after one.
fn serviceSmaps(out: [*]smaps.SmapEnt, cap: usize, from: u64, next: *u64) u64 {
    return smaps.with(out, cap, from, next, vmmMaps, vmm.ramBase(), 0x1000, true);
}

fn readAll(fd: c_int, buf: []u8) void {
    var done: usize = 0;
    while (done < buf.len) {
        const n = read(fd, buf.ptr + done, buf.len - done);
        if (n <= 0) _exit(1);
        done += @intCast(n);
    }
}

// Linux auxv types the guest's libc start reads.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;

fn put64(ram: []u8, at: u64, v: u64) void {
    @as(*u64, @ptrCast(@alignCast(ram.ptr + at))).* = v;
}

// pushStr copies a NUL-terminated string onto the descending stack string area
// and returns its guest VA.
fn pushStr(ram: []u8, top: *u64, s: [*:0]u8) u64 {
    const n = std.mem.len(s) + 1;
    top.* -= n;
    @memcpy(ram[@intCast(top.*)..][0..n], s[0..n]);
    return top.*;
}

// buildStack lays out the Linux initial stack: the argv and env strings and 16
// random bytes grow down from stack_top, then the vector
// (argc, argv.., NULL, envp.., NULL, auxv) sits below them, 16-aligned, with the
// returned sp at argc -- exactly what a libc _start expects.
fn buildStack(ram: []u8, stack_top: u64, argv: [][*:0]u8, envp: [][*:0]u8, ld: Loaded, at_base: u64) u64 {
    var top: u64 = stack_top;
    top -= 16; // 16 random bytes for AT_RANDOM
    const rnd = top;
    arc4random_buf(ram[@intCast(rnd)..].ptr, 16);
    const argv_va = heap.alloc(u64, argv.len) catch _exit(1);
    const envp_va = heap.alloc(u64, envp.len) catch _exit(1);
    for (argv, 0..) |a, i| argv_va[i] = pushStr(ram, &top, a);
    for (envp, 0..) |e, i| envp_va[i] = pushStr(ram, &top, e);
    top &= ~@as(u64, 0xf);
    // argc + argv + NULL + envp + NULL + eight auxv pairs (PHDR/PHENT/PHNUM/
    // PAGESZ/BASE/ENTRY/RANDOM/NULL). PHDR/PHENT/PHNUM let musl locate PT_TLS and
    // size the per-thread TLS block; omitting them left cloned threads' static
    // TLS overlapping the pthread tsd[] (thread-local destructors then corrupt
    // it). BASE is the interpreter load base (0 when the guest is static), which
    // a dynamic ld.so reads to relocate itself.
    const nslots = 1 + argv.len + 1 + envp.len + 1 + 16;
    const sp = (top - @as(u64, nslots) * 8) & ~@as(u64, 0xf);
    var w = sp;
    put64(ram, w, argv.len);
    w += 8;
    for (argv_va) |va| {
        put64(ram, w, va);
        w += 8;
    }
    put64(ram, w, 0);
    w += 8; // argv NULL
    for (envp_va) |va| {
        put64(ram, w, va);
        w += 8;
    }
    put64(ram, w, 0);
    w += 8; // envp NULL
    const aux = [_][2]u64{
        .{ AT_PHDR, ld.phdr },
        .{ AT_PHENT, ld.phent },
        .{ AT_PHNUM, ld.phnum },
        .{ AT_PAGESZ, 4096 },
        .{ AT_BASE, at_base },
        .{ AT_ENTRY, ld.entry },
        .{ AT_RANDOM, rnd },
        .{ AT_NULL, 0 },
    };
    for (aux) |pair| {
        put64(ram, w, pair[0]);
        put64(ram, w + 8, pair[1]);
        w += 16;
    }
    heap.free(argv_va);
    heap.free(envp_va);
    return sp;
}

const O_RDWR: c_int = 2;
const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_SHARED: c_int = 1;
const MAP_FAILED: ?*anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
const CHAN_LEN: usize = vmm.CHAN_LEN; // slots + signal area + the peek/poke windows

extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn mmap(addr: ?*anyopaque, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) ?*anyopaque;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn ftruncate(fd: c_int, len: i64) c_int;
extern "c" fn unlink(path: [*:0]const u8) c_int;
extern "c" fn getpid() c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn signal(sig: c_int, h: *const fn (c_int) callconv(.C) void) usize;

const CLONE_CHILD_SETTID: u64 = 0x1000000;

// The supervisor pokes a process with SIGUSR1 (Darwin 30) to make it notice a
// freshly queued signal. A thread in a syscall takes it as the syscall ends
// (dispatchSyscall); one running guest code is stopped for its run loop to
// deliver it (vmm.kickRunning).
fn sigKick(_: c_int) callconv(.C) void {
    vmm.kickRunning();
}
fn installSigKick() void {
    _ = signal(30, sigKick);
}

// unblockKick lets kicks (SIGUSR1) in: a fork child starts with them blocked
// (forkSpawn), since one arriving before installSigKick would end it.
fn unblockKick() void {
    var set: u32 = 1 << (30 - 1);
    _ = pthread_sigmask(SIG_UNBLOCK, &set, null);
}
const SIG_UNBLOCK: c_int = 2;
extern "c" fn pthread_sigmask(how: c_int, set: ?*const u32, old: ?*u32) c_int;
extern "c" var environ: [*:null]?[*:0]u8;

const O_CREAT: c_int = 0x0200; // darwin
const O_TRUNC: c_int = 0x0400; // darwin

// The VM RAM is a file-backed MAP_SHARED mapping instead of an anonymous heap
// block, so the guest's pages are sparse -- only touched pages cost real memory,
// not a committed 1 GiB per process. (A fork snapshots the parent's used RAM by
// reading this mapping directly, which is coherent with the guest's writes; see
// forkSpawn in vmm.zig.) The path is unlinked right after open so nothing is
// left in /tmp; the mmap keeps the RAM alive.
fn mapRamFile() [*]u8 {
    var buf: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&buf, "/tmp/lc-vram-{d}", .{getpid()}) catch _exit(1);
    const fd = open(path.ptr, O_RDWR | O_CREAT | O_TRUNC, @as(c_int, 0o600));
    if (fd < 0) _exit(1);
    _ = unlink(path.ptr);
    if (ftruncate(fd, @intCast(RAM_LEN)) != 0) _exit(1);
    const p = mmap(null, RAM_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    _ = close(fd);
    if (p == null or p == MAP_FAILED) _exit(1);
    return @ptrCast(@alignCast(p.?));
}

// mapChannel maps the channel file MAP_SHARED (as the supervisor created it) and
// returns its base, like the native stub's mapChannel. A slot is base + offset;
// sibling threads' slots and this process's own (for a respawn) live there.
fn mapChannel(chan_path: [*:0]const u8) [*]u8 {
    const fd = open(chan_path, O_RDWR);
    if (fd < 0) _exit(123);
    const p = mmap(null, CHAN_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == null or p == MAP_FAILED) _exit(123);
    _ = close(fd);
    return @ptrCast(@alignCast(p.?));
}

// A respawn (an execve that crosses into this stub) is spawned with a marker
// "lc-stub@<slotOff>@<uids>@<gids>@<argc>" in argv[0], giving this process's own
// channel slot and the count of guest argv entries (the guest's env follows
// them inline). The initial spawn has a plain argv[0], slot 0, and its env in
// the process environment.
const Marker = struct { slot_off: usize, argc: usize };

fn parseMarker(a0: [*:0]const u8) ?Marker {
    var it = std.mem.splitScalar(u8, std.mem.span(a0), '@');
    _ = it.next(); // "lc-stub"
    const off_s = it.next() orelse return null;
    _ = it.next() orelse return null; // uids
    _ = it.next() orelse return null; // gids
    const argc_s = it.next() orelse return null;
    return .{
        .slot_off = std.fmt.parseInt(usize, off_s, 16) catch return null,
        .argc = std.fmt.parseInt(usize, argc_s, 16) catch return null,
    };
}

pub fn main() void {
    const argv = std.os.argv;
    if (argv.len >= 1 and std.mem.startsWith(u8, std.mem.span(argv[0]), "lc-fork@")) forkChildMain(argv);
    if (argv.len < 3) _exit(2);
    life.start(); // exit when the supervisor dies (lifeline fd 4); without this
    // an HVF stub survives a dead/SIGKILLed laboon and wedges the backend by
    // holding its Hypervisor.framework VM (new hv_vm_create then fails).
    const chan_path = argv[1];
    const guest_path = argv[2];
    service.start(serviceMaps, serviceSmaps, null);

    const ram = mapRamFile()[0..RAM_LEN];
    var vm = vmm.Vmm.init(ram.ptr, RAM_LEN) catch _exit(1);
    defer vm.deinit();

    const marker = parseMarker(argv[0]);
    const base = mapChannel(chan_path);
    const slot_off = if (marker) |m| m.slot_off else 0;
    const ch: *chan.Chan = @ptrCast(@alignCast(base + slot_off));
    const lay = drawLayout(ch.flags & chan.LAYOUT_NORAND != 0);

    const ld = loadGuestAt(ram, guest_path, 0) catch _exit(1);
    // A dynamically-linked guest names its interpreter (ld.so) in argv[3]: load
    // it at lay.interp and enter THERE with AT_BASE pointing ld.so at itself
    // (it relocates itself, maps the shared libraries via file-backed mmap,
    // relocates the main program and jumps to AT_ENTRY). A static guest has an
    // empty argv[3] and enters at its own entry, as before.
    var enter: u64 = ld.entry;
    var at_base: u64 = 0;
    if (argv.len > 3 and argv[3][0] != 0) {
        const ldi = loadGuestAt(ram, argv[3], lay.interp) catch _exit(1);
        vmm.reserveInterp(ldi.brk);
        enter = ldi.entry;
        at_base = lay.interp;
    }
    vm.setBrk(ld.brk + lay.brk_gap);
    vmm.setMmapTops(lay.stack_top - STACK_LEN, lay.ext_top);
    // The guest's own argv follows the stub's fixed args (chan, guest, interp,
    // two site files). On an initial spawn the env rides the process
    // environment; on a respawn it is inline after the argc'th argv entry.
    const gargv = if (marker) |m| argv[6 .. 6 + m.argc] else (if (argv.len > 6) argv[6..] else argv[2..3]);
    const genv = if (marker) |m| argv[6 + m.argc ..] else blk: {
        var nenv: usize = 0;
        while (environ[nenv] != null) nenv += 1;
        const e = heap.alloc([*:0]u8, nenv) catch _exit(1);
        for (0..nenv) |i| e[i] = environ[i].?;
        break :blk e;
    };
    const sp = buildStack(ram, lay.stack_top, gargv, genv, ld, at_base);
    vmm.addMap(lay.stack_top - STACK_LEN, lay.stack_top, 3, vmm.M_STACK, false, 0, 0);
    vm.start(enter, sp);

    vmm.g_chan_path = chan_path; // so a forked child maps the same channel
    if (!chan.init()) _exit(126);
    if (!vmm.initThreads(base)) _exit(124); // futex buckets + threads; base for sibling slots
    vmm.account(ch);
    installSigKick();
    // A respawn is an execve; if the process is traced, stop at the new image's
    // entry before running it (the ptrace exec-event stop).
    if (marker != null and (ch.stdio & vmm.STDIO_TRACED) != 0) vm.execStop(ch, enter, sp, chan.exchange);
    runLoop(&vm, ch);
}

// runLoop is the guest's main-thread syscall/fault loop, shared by a fresh spawn
// and a forked child (which sets its VM up differently but runs the same loop).
fn runLoop(vm: *vmm.Vmm, ch: *chan.Chan) noreturn {
    while (true) {
        if (ch.stdio & vmm.STDIO_SINGLESTEP != 0) vm.enableStep(); // ptrace single-step
        const ev = vm.run(ch) catch _exit(1);
        switch (ev) {
            .signal => vm.deliverAsync(ch, chan.exchange),
            .syscall => |sc| {
                if (vm.filtered(ch, sc, chan.exchange)) continue;
                // Memory and futex syscalls are serviced against the VM RAM
                // locally; the rest go to the supervisor over the channel.
                // set_tid_address has no supervisor handler -- rewrite it to
                // gettid as the native stub does (the main thread's clear-on-exit
                // word is unused here).
                var s = sc;
                if (s.nr == 96) s.nr = 178;
                if (s.nr == 139) { // rt_sigreturn restores the vcpu; do not resume over it
                    vm.sigreturn(ch);
                    continue;
                }
                vm.dispatchSyscall(ch, s, chan.exchange);
            },
            .fault => |fl| {
                if (fl.ec == 0x32 or fl.ec == 0x33) { // a software-step exception: report the step stop
                    vm.stepStop(ch, fl.pc, chan.exchange);
                    continue;
                }
                if (vm.deliverFault(ch, fl, chan.exchange)) continue;
                var b: [96]u8 = undefined;
                const s = std.fmt.bufPrint(&b, "[hvf] fault ec={x} far={x} pc={x}\n", .{ fl.ec, fl.far, fl.pc }) catch "";
                _ = write(2, s.ptr, s.len);
                _exit(139); // no handler: terminate (SIGSEGV default action)
            },
            .done => _exit(0),
        }
    }
}

// A fork child is posix_spawned by forkSpawn (vmm.zig) with argv[0]
// "lc-fork@<child_off>@<flags>@<tls>@<ctid>@<gpid>", argv = [marker, chan_path,
// vram_path, regs_path]. It maps the snapshot of the parent's RAM, reloads the
// parent's registers (resuming at the fork return with x0 = 0), adopts the
// supervisor-allocated slot and announces its pid, then runs the normal loop.
const ForkMarker = struct { child_off: usize, flags: u64, tls: u64, ctid: u64, gpid: u64 };

fn parseForkMarker(a0: [*:0]const u8) ?ForkMarker {
    var it = std.mem.splitScalar(u8, std.mem.span(a0), '@');
    if (!std.mem.eql(u8, it.next() orelse return null, "lc-fork")) return null;
    const co = it.next() orelse return null;
    const fl = it.next() orelse return null;
    const tl = it.next() orelse return null;
    const ct = it.next() orelse return null;
    const gp = it.next() orelse return null;
    return .{
        .child_off = std.fmt.parseInt(usize, co, 16) catch return null,
        .flags = std.fmt.parseInt(u64, fl, 16) catch return null,
        .tls = std.fmt.parseInt(u64, tl, 16) catch return null,
        .ctid = std.fmt.parseInt(u64, ct, 16) catch return null,
        .gpid = std.fmt.parseInt(u64, gp, 16) catch return null,
    };
}

fn forkChildMain(argv: [][*:0]u8) noreturn {
    if (argv.len < 4) _exit(2);
    life.start(); // a fork child inherits fd 4 but must watch it too, or it
    // lingers for hours holding an HVF VM after the supervisor is gone.
    const m = parseForkMarker(argv[0]) orelse _exit(2);
    const chan_path = argv[1];
    const vram_path = argv[2];
    const regs_path = argv[3];

    // Map the snapshot of the parent's RAM (it already holds the page tables).
    const fd = open(vram_path, O_RDWR);
    if (fd < 0) _exit(1);
    const p = mmap(null, RAM_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    _ = close(fd);
    if (p == null or p == MAP_FAILED) _exit(1);
    const ram: [*]u8 = @ptrCast(@alignCast(p.?));

    vmm.g_chan_path = chan_path;
    var vm = vmm.initForked(ram, RAM_LEN) catch _exit(1);

    // Reload the parent's registers; the vcpu resumes at the fork return, x0 = 0.
    var regs: vmm.ForkRegs = undefined;
    const rfd = open(regs_path, O_RDWR);
    if (rfd < 0) _exit(1);
    if (read(rfd, @ptrCast(&regs), @sizeOf(vmm.ForkRegs)) != @sizeOf(vmm.ForkRegs)) _exit(1);
    var count: u64 = 0;
    if (read(rfd, @ptrCast(&count), 8) != 8) _exit(1);
    const maps = heap.alloc(vmm.MapEnt, @intCast(count)) catch _exit(1);
    readAll(rfd, std.mem.sliceAsBytes(maps));
    vmm.adoptMaps(maps);
    heap.free(maps);
    service.start(serviceMaps, serviceSmaps, null);
    _ = close(rfd);
    _ = unlink(vram_path); // the mmap keeps the RAM; the snapshot files are done
    _ = unlink(regs_path);
    vmm.startForked(&vm, &regs, true); // a forked child is a fresh process: adopt the parent's heap bounds
    if (m.flags & CLONE_CHILD_SETTID != 0 and m.ctid != 0)
        @as(*u32, @ptrFromInt(@intFromPtr(ram) + m.ctid)).* = @truncate(m.gpid);

    const base = mapChannel(chan_path);
    const ch: *chan.Chan = @ptrCast(@alignCast(base + m.child_off));
    if (!chan.init()) _exit(126);
    if (!vmm.initThreads(base)) _exit(124);
    vmm.account(ch);
    installSigKick();
    unblockKick(); // a kick that came before the handler was held, not fatal
    // A traced child takes its first stop before this is answered, and its
    // tracer reads and writes the VM's memory through it meanwhile.
    ch.kind = chan.MSG_FORKED;
    ch.args[0] = @intCast(getpid());
    vm.served(ch, chan.exchange);
    runLoop(&vm, ch);
}
