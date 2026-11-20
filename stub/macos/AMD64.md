# darwin/amd64 — x86-64 macOS stub port

Status: **WORKING — glibc static-PIE guests run end-to-end on the M4 under
Rosetta.** `testdata/startup.c` prints `STARTUP-OK` and exits 0; `testdata/hello.c`
prints its uname/argv line and exits 7 (exercising printf/stdio, uname, malloc's
brk/mmap, argv, and the exit code). The x86-64 stub compiles, both darwin arches
build with per-arch embed, and the two remaining subsystems — the syscall-number
ABI and `%fs` TLS virtualization — are both done and mac-validated (below).

`%fs` TLS (DONE, mac-validated 2026-11-20): glibc keeps its thread pointer in
`%fs` and reads TLS as `%fs:disp`. The physical `%fs` base cannot be set under
Rosetta (`wrfsbase` SIGILLs), so it is virtualized: `arch_prctl(ARCH_SET_FS)`
stores the base in the stub (`g_guest_fsbase`), the `%fs` instructions are left
in place and fault (real `%fs` base 0 → low address), and `onFault` emulates
each against the stored base (`fsmem.zig`: an x86-64 decoder/executor for the
MOV / MOVZX/MOVSX / ALU-reg / ALU-imm `%fs` forms, with correct flags for the
stack-canary `xor %fs:0x28` check). An unhandled form prints `FSEMU-MISS <bytes>`
and is delivered as a signal — a loud miss to grow the corpus from, never a
silent wrong answer. This is the fault-handler fallback `rewrite/fs.go`'s
`PatchFS` already leaves sites for; rewriting the hot sites to `%gs:[tp]` islands
(the windows fast path, reusing `fsIsland`) is the later optimization.

NOTE: `/proc/self/exe` must resolve to an absolute path or glibc's
`_dl_get_origin` asserts `linkval[0] == '/'`. Run the guest by an absolute path;
a relative program path is a cross-platform gap (arm64 too), not x86-64-specific.

The syscall-number ABI (DONE, mac-validated 2026-11-20): an x86-64 guest posts
x86-64 numbers; the stub's `x64gen` translates for its local dispatch (memory,
clocks, stdio, futex, thread/proc control) while forwarding the raw number, and
the supervisor's `toGeneric`/`fromGeneric` (`gen_darwin_amd64.go`, reusing the
shared `x64Generic`/`x64Result`) translate the forwarded calls — the open-flag
and legacy→at argument rewrites happen in the supervisor, not the stub. This
removed the earlier xattr "hang" (brk(12) had mis-dispatched to the arm64-keyed
xattr handler). `arch_prctl(ARCH_SET_FS)` is served in the stub (stores the
guest `%fs` base; no `wrfsbase`).

## Arch-specific surface (per file, heaviest first)

- `stub.zig` — entry, syscall entry/exit, trampolines. amd64: syscall ABI
  (`rax`=nr, `rdi rsi rdx r10 r8 r9`=args, ret in `rax`), the entry zeroing (see
  invariant below).
- `vmm.zig` — the arm64 HVF micro-VM, used only for non-PIE `ET_EXEC` guests.
  **Recommend deferring**: require static-PIE guests at first (the arm64 port
  already requires static-PIE for the signal path) and skip the vmm/HVF port.
- `sig.zig` — the trap mechanism: thread_state access, single-step, the signal
  trampolines, the GPR/NEON save-restore. The core of the port.
- `proc.zig` — fork/exec/thread context setup.
- `wx.zig` — W^X / JIT (`MAP_JIT` + `pthread_jit_write_protect_np`). The Apple-
  Silicon `CTR_EL0`/`tpidr_el0` islands have no x86-64 analogue (no sysreg-read
  traps), so this gets simpler, not harder.

## The mcontext arch seam — `tstate.zig` (DONE, compile-verified both arches)

`tstate.zig` wraps the mcontext fields the trap machinery touches identically on
both targets: `pc/setPc` (arm64 `ss.pc` / x86-64 `ss.rip`), `sp/setSp`
(`ss.sp`/`ss.rsp`), `faultAddr` (`es.far`/`es.faultvaddr`), `flags/setFlags`
(`ss.cpsr`/`ss.rflags`). The **GPR file** (31 arm64 vs 16 x86-64) and the
**SIMD/float state** (`ns.q[32]` vs the x86-64 `fs` float_state) differ in shape
and stay per-arch at `sig.zig`'s `Ctx`/`fromMc`/`toMc`.

Compile-check either arch standalone:
`zig build-obj -target {x86_64,aarch64}-macos -lc tstate.zig` (reference it from a
probe with `export fn`, since the accessors are `inline`).

## x86-64 design decisions

- **Entry invariant (the glibc fix).** On arm64, `_start` reads `x0` as the
  dynamic linker's `rtld_fini` and registers it at exit; a stale value crashes a
  static-PIE glibc guest, so the stub zeros `x0` at guest entry (matching the
  kernel). On x86-64 System V the same pointer arrives in **`%rdx`**, so the amd64
  entry must zero `%rdx` (see [[macos-port]] and the linux/windows stubs, which
  already zero their arch's register).
- **Single-step.** arm64 uses the SS bit (SPSR.SS). x86-64 has no such bit; set
  **RFLAGS.TF (bit 8)** via `tstate.setFlags` and the CPU raises `#DB`/SIGTRAP
  after each instruction. Clear TF to stop.
- **Syscall trap.** The rewriter patches guest `syscall` (`0f 05`) sites. The
  handler reads the request from `tstate`/`ss` (`rax` = number, the six arg
  registers) and writes the result to `rax`, then resumes past the site.
- **GPR save/restore.** Add an x86-64 `Ctx` (16 named registers) and amd64
  `fromMc`/`toMc`. The generic callers should move to `tstate` where they only
  touch pc/sp/flags; the register copy stays arch-specific.
- **Trampolines.** `lc_sig_switch`, `lc_trap_ret`, `lc_cp_*` are inline arm64 asm;
  write x86-64 counterparts. Keep the names and the pc landmarks the fault handler
  compares against.

## Phased plan

1. `sig.zig` — the trap core. Sub-steps:
   a. Route the arch-neutral fault-handler spine through `tstate` (the
      `lc_sig_switch` / `lc_trap_ret` / `lc_copy` / `lc_load32` landmark checks
      and `cpCancel`). **DONE** — arm64 `__text` rebuilds byte-identical (only the
      content-hash `LC_UUID` and the symbol string table move).
   b. Arch-split `Ctx` and `TraceRegs` (both now `if (tstate.arm64) …Arm else …X64`).
      **DONE.** `CtxX64` = 16 named GPRs + `rip` + `rflags` + the FP/SSE state as
      the 512-byte FXSAVE image (`fx`, the common currency between Darwin's
      `x86_float_state64` and Linux's `_fpstate`) + the fault triple
      (`fault`/`trapno`/`err`). `TraceRegsX64` = the Linux `user_regs_struct`
      (r15…gs, 27×u64). Both compile-checked standalone for `x86_64-macos`; arm64
      `__text` byte-identical. `publishFrame`/`traceRestore` keep their arm64
      bodies behind a `!tstate.arm64 → @compileError` guard — their x86-64 images
      come from the trampoline frame (1e/1f), so they are filled then.
   c. Arch-split `fromMc` / `toMc`. **DONE** (x86-64 branch probe-verified against
      `std.c.mcontext_t` for `x86_64-macos`; arm64 `__text`/`stub.bin` unchanged —
      the comptime-dead branch adds no code). x86-64 copies the 16 GPRs by name
      (`ss.rax`…`ss.r15`), `rip`/`rflags` direct, the FP state as the 512-byte
      FXSAVE image from `&fs + 8` (Darwin's `float_state` is FXSAVE behind an
      8-byte reserved prefix), and `fault`/`trapno`/`err` from `es`. Two
      deferrals: the guest-`rip` out-of-line translation (arm64's `ool.guestPc`)
      waits on the x86-64 OOL layer (phase 3); the FXSAVE FIP/FDP form wants
      confirming on the mac.
   d. `onFault`'s arm64-only body. The self-contained leaf functions are
      **DONE** (probe-verified for `x86_64-macos`, arm64 `stub.bin` unchanged):
      `faultSignal` (x86-64 reads the trap vector + the #PF present bit instead
      of the ESR) and `pthreadKill` (the Darwin BSD-class `syscall`). The rest —
      the structural split of `onFault` itself, gating `wx.fault`, `idReg` (the
      sysreg islands, no x86-64 analogue) and `jit.Fault` behind `if
      (tstate.arm64)` and routing the x86-64 syscall trap to the trampolines —
      is coupled to the x86-64 `wx` layer (phase 3) and the trampoline frame
      (1f), so it lands with them, not before.
   e/f. **The x86-64 trap core is NOT arm64's island/`tramp_common` model — it is
      the Linux x86-64 stub's `ud2`+SIGILL trap** (see `stub/zig/x86_64.zig` and
      `stub/zig/stub.zig`). Why: arm64 `svc` is 4 bytes, so a rewritten site
      branches to an island that runs `tramp_common` (the 784-byte saved frame).
      x86-64 `syscall` is 2 bytes (`0f 05`) — too small for a 5-byte jmp — but
      `ud2` is also 2 bytes (`0f 0b`), so **`rewriteSite` replaces `syscall`→`ud2`
      in place**; the guest hits `ud2` → SIGILL → `onFault`, which services the
      syscall straight from the signal's mcontext (the kernel already saved the
      full register file there — no `tramp_common`, no islands, no
      `buildIsland`/`ISLAND_SIZE`, no `lc_cp_*`/`lc_copy`/`lc_load32` trampolines
      for the syscall path). Flow: `onFault` sees a `ud2` at a known guest site →
      read nr=`ss.rax`, args={rdi,rsi,rdx,r10,r8,r9} (Linux x86-64 `Frame`
      mapping) → run the dispatch → write the result to `ss.rax` → advance
      `ss.rip` by 2 → return. The arm64 `tramp_common`/island machinery stays
      arm64-only behind `if (tstate.arm64)` / per-arch build; it is not ported.
      The remaining x86-64 work is therefore: (1) `rewriteSite` writes `0f 0b`;
      (2) `onFault`'s x86-64 SIGILL path builds a frame from the mcontext and
      calls the dispatch; (3) the dispatch (`serveSyscall` & friends) gets a frame
      abstraction so it reads nr/args/resume/result per-arch (the macOS stub now
      uses a raw arm64-shaped `frame: [*]u64`; the clone/fork/exec full-context
      paths need the x86-64 register set, like the Linux stub's typed `Frame`);
      (4) `%gs`-based per-thread slot like the Linux stub (`setSlot`), virtualized
      for guest `%gs`. Single-step (RFLAGS.TF) is only needed where the x86-64
      `wx`/`ool` layer wants it (phase 3), not for the syscall path.
   g. Signal-frame build/parse. `deliverOnto` (the Linux `rt_sigframe` builder)
      is **DONE** — the x86-64 branch builds `[pretcode][ucontext][siginfo]` with
      the 512-byte FXSAVE `_fpstate` above, grounded in the kernel UAPI
      `sigcontext_64` (r8…r15, rdi…rsp at 0–127, rip@128, flags@136, cs/gs/fs/ss@144,
      err/trapno/oldmask/cr2@152–176, fpstate@184) and `ucontext` (uc_mcontext@40,
      uc_sigmask@296) offsets, handler entry rdi/rsi/rdx + rax=0, rsp≡8 (mod 16).
      Probe-compiled for `x86_64-macos`; arm64 `__text` byte-identical. VERIFY ON
      MAC: the exact offsets and entry alignment. Its reverse, `sysSigreturn`
      (and `sysSigaltstack`/`sysSigsuspend`), reads the same frame back and is
      **NEXT** (reuses these offsets).
2. `proc.zig`: x86-64 fork/exec/thread context; zero `%rdx` at entry.
3. `wx.zig`: x86-64 `MAP_JIT` W^X (drop the sysreg islands).
4. `stub.zig`: x86-64 entry + syscall dispatch.
5. `build.sh`: emit `stub-amd64.bin` too; `macstub.go`: embed per-arch (build tag
   or a per-arch embed), like the windows stub split (`stub-amd64.bin` /
   `stub-arm64.bin`).
6. Defer `vmm.zig` (HVF) — require static-PIE guests first.

## Running status (2026-11-20): end-to-end trap core WORKS on the mac

The x86-64 stub compiles, both darwin arches build+embed per-arch (build.sh →
stub-{arm64,amd64}.bin, macstub_{arm64,amd64}.go), and on the M4 under Rosetta the
darwin/amd64 supervisor loads an x86-64 static-PIE glibc guest, the stub rewrites
its syscalls to ud2, the guest runs and traps, and the supervisor serves syscalls
over the channel. Proven keystones (all mac-validated): the mcontext/FXSAVE
layout, the ud2+SIGILL trap/serve/resume, the Seatbelt Mach allowlist (Rosetta's
exception server needs it), the x86-64 site finder (computeSitesELFX64, 109 sites
in startup), rewriteSite→ud2.

**Remaining blocker — the syscall-number ABI.** The darwin `syscalls` map is
keyed by arm64 Linux numbers (gen_linux_arm64.go: "keyed by the arm64 numbers").
An x86-64 guest uses x86-64 Linux numbers, so e.g. brk(12)/mmap(9)/fstat(5)
dispatch to the xattr handler (syscalls[5..16]). The fix mirrors linux/amd64 and
windows/amd64: call `toGeneric(nr, a)` before the dispatch in run_darwin.go's
serveLoop (around the `handler(nr)` / `nr==lxClone`/`lxExecve` sites), and define
`toGeneric`/`fromGeneric` for darwin — identity for arm64 (gen_darwin_arm64.go,
like gen_linux_arm64.go), and the x86-64 translation for amd64 (gen_darwin_amd64.go).
`x64Generic`/`x64Result`/`swapOFlags` already compile for darwin/amd64
(lx_x64nr_amd64.go). The amd64 side also needs the x86-64-specific handlers
gen_linux_amd64.go registers (arch_prctl, poll, select, time, the x64Memory
calls) adapted to darwin host calls. The hard sub-piece is **arch_prctl(ARCH_SET_FS) / %fs TLS.** Measured on the mac:
**`wrfsbase` raises SIGILL under Rosetta** (CR4.FSGSBASE not honored), so the
guest's %fs base cannot be set directly — the windows stub's wrfsbase fast path
(stub/windows/x86_64.zig) is unavailable here. The guest's %fs TLS must be
**virtualized by rewriting the %fs-relative instructions**, like the windows port
does and like the arm64 stub virtualizes tpidr_el0:
- Supervisor: `rewrite.AnalyzeFS`/`AnalyzeEntriesFS` already find %fs sites
  (`FSSite`); pass them to the stub alongside the syscall sites (a second list,
  or merged — see run_windows_amd64.go which emits "%fs islands").
- Stub: rewrite each %fs site so the access computes from a stored guest thread
  pointer (a slot field, the SLOT_TP analog in stub/windows/x86_64.zig) instead
  of the real %fs base; serve arch_prctl(ARCH_SET_FS) locally by storing the tp
  in that slot (no wrfsbase). A %fs site with no room for a branch faults and is
  serviced by onFault (the real %fs base is 0, so it faults low) — the
  ud2/SIGILL machinery already exists.
This is the one substantial remaining subsystem; the windows x86-64 port is the
direct reference. glibc sets up %fs TLS before main, so startup.c blocks until
it works. (Darwin/libSystem TLS is %gs, so the guest's %fs is otherwise free.)

## Implementation status (serve path DONE)

The validated serve path is in (`0edbf42`): `onFault` SIGILL at a `0f 0b` site →
`stub.serveTrap(mc)` → projects the mcontext into the arm64-shaped dispatch frame
(args@0..5, nr@8, resume@33) → `serveSyscall` → result→`rax`, `rip`+=2. Because
the dispatch reads args by index, `mem`/`local`/`stdio`/`futex` handlers work
unchanged. `SITE_DELTA` (svc=4/ud2=2) and the ptrace-trace paths are gated.

Remaining grind to a **compiling** `x86_64-macos` stub (then run `startup.c`).
Drive it with `zig build-exe -target x86_64-macos -lc -O ReleaseSmall stub.zig`
and fix the lazy-analysis error tip; keep arm64 `__text` byte-identical each
batch. Known arm64-only reachables to gate behind `if (tstate.arm64)` or port
(deferred paths `startup.c` never runs, so gate/stub them):
- `onFault`'s W^X/OOL fault body (`wx.fault`/`ool.*`/`jit.flip`) and the
  `lc_copy`/`lc_load32` landmarks — gate; the generic fault→signal tail
  (`faultSignal`/`fromMc`/`deliverOnto`) already works but has a shared-`Ctx`
  `c.pc` that must become `if (tstate.arm64) c.pc else c.rip` (this pattern
  recurs at every shared `c.pc`/`c.sp`/… site).
- `fromFrame`, `sysSigreturn`, `sysSigsuspend`, `trapEnter`/`trapReturn`/
  `doSwitch`/`step` — arm64 trampoline-frame machinery; gate (x86-64 signal
  delivery from a syscall is the `serveTrap`/mcontext path, ported later).
- `ool.zig`, `wx.zig`, `lc_copy`/`lc_load32` asm — once the callers above are
  gated these stop being analyzed on x86-64; if any leak through, top-gate each
  pub fn with `if (!tstate.arm64) return <default>;`.
- Then `proc.zig` (thread/fork/exec context — `startup.c` is single-threaded, so
  clone/fork gate; exec+enter must work), `mem.zig` (mostly channel-forwarding),
  and the entry in `stub.zig` (`mapElf`/enter — zero `%rdx` at guest entry).
- Finally `build.sh` emits `stub-amd64.bin`; `macstub.go` embeds per-arch.

## Testing

The M4 mac runs x86-64 under Rosetta: `ssh mac` (192.168.29.43), build the stub
on Linux (zig cross-compiles `-target x86_64-macos`), run a static-PIE x86-64
guest (`testdata/hello.c`, `testdata/startup.c` — build with
`zig cc -target x86_64-macos` or on an x86-64 toolchain) under `arch -x86_64`.
Start with `startup` (libc init + clean exit — exercises the `%rdx` invariant),
then `hello`, then the mmap matrix.

Probes: cross-compile a Zig object or a C harness and run it on the mac. Note a
plain Zig `build-exe` with `pub fn main` SIGSEGVs in Zig's `start` under Rosetta,
so write mac probes in C and build them there: `arch -x86_64 clang -arch x86_64`.
A freshly written Mach-O needs `codesign -s - -f <bin>` (clang signs adhoc
itself); stdout over ssh is block-buffered, so `setvbuf(stdout,NULL,_IONBF,0)` or
`fflush` before `_exit`.

**Validated on the mac (2026-11-19, C harness, faulting program):** the Darwin
x86-64 mcontext layout (`offsetof es=0, ss=16, fs=184`), the GPR field reads
(`ss.r15` survives a fault), `es.trapno==14`/`faultvaddr` for a #PF, and the
FXSAVE-prefix claim that `fromMc`/`toMc`/`deliverOnto` rely on — `fcw` at `fs+8`,
`xmm0` at `fs+8+160`, hardware-populated. So those pieces are mac-verified, not
just probe-compiled.
