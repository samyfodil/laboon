# darwin/amd64 — x86-64 macOS stub port

Status: **in progress**. The macOS stub is arm64-only. `GOOS=darwin GOARCH=amd64`
builds on the Go side (`macstub.go` embeds the arm64 `stub.bin` regardless), but
at runtime the arm64 stub cannot run an amd64 guest's machine code, so it SIGILLs.
This is a full x86-64 stub port, not a flag. The rewriter already classifies
x86-64 syscall sites (`0f 05`), so the supervisor/rewrite side is ready; the work
is the Zig stub.

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
   c. Arch-split `fromMc` / `toMc`: pc/sp/flags/fault go through `tstate`; the GPR
      copy and SIMD save/restore stay per-arch (x86-64 reads `ss.rN` and the `fs`
      float state; arm64 reads `ss.regs` and `ns.q`).
   d. `onFault`'s arm64-only body — `es.esr` / `es.far` decode (`faultSignal`),
      `wx.fault(esr,far,pc)`, `idReg` (the sysreg-read islands — no x86-64
      analogue), `jit.Fault{esr,far}` — goes behind `if (tstate.arm64)`; the
      x86-64 fault path reads `es.trapno` / `es.err` / `es.faultvaddr`.
   e. Single-step: arm64 `step()` sets SPSR.SS; x86-64 sets RFLAGS.TF (bit 8) via
      `tstate.setFlags`. `step` / `doSwitch` / `trapEnter` / `trapReturn`
      arch-split (arm64 frame stride 816 and the x16/x17 pushes vs the x86-64
      frame).
   f. x86-64 trampolines: `lc_sig_switch`, `lc_trap_ret`, `lc_cp_*`, `lc_copy`,
      `lc_load32` rewritten in x86-64 asm — same names and the same pc landmarks
      the handler compares against.
2. `proc.zig`: x86-64 fork/exec/thread context; zero `%rdx` at entry.
3. `wx.zig`: x86-64 `MAP_JIT` W^X (drop the sysreg islands).
4. `stub.zig`: x86-64 entry + syscall dispatch.
5. `build.sh`: emit `stub-amd64.bin` too; `macstub.go`: embed per-arch (build tag
   or a per-arch embed), like the windows stub split (`stub-amd64.bin` /
   `stub-arm64.bin`).
6. Defer `vmm.zig` (HVF) — require static-PIE guests first.

## Testing

The M4 mac runs x86-64 under Rosetta: `ssh mac` (192.168.29.43), build the stub
on Linux (zig cross-compiles `-target x86_64-macos`), run a static-PIE x86-64
guest (`testdata/hello.c`, `testdata/startup.c` — build with
`zig cc -target x86_64-macos` or on an x86-64 toolchain) under `arch -x86_64`.
Start with `startup` (libc init + clean exit — exercises the `%rdx` invariant),
then `hello`, then the mmap matrix.
