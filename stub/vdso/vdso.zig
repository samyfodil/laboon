// vdso.zig — the guest's vDSO on hosts without a Linux kernel (macOS,
// Windows): an ELF shared object with the kernel's symbols and versions, each
// a system call the stub rewrites as it rewrites every image, so a program
// that looks its clocks up through AT_SYSINFO_EHDR finds them as on Linux.

const builtin = @import("builtin");

comptime {
    switch (builtin.cpu.arch) {
        .x86_64 => asm (fns(&.{
                .{ "__vdso_clock_gettime", 228 },
                .{ "__vdso_gettimeofday", 96 },
                .{ "__vdso_time", 201 },
                .{ "__vdso_getcpu", 309 },
                .{ "__vdso_clock_getres", 229 },
            }) ++
                \\.globl clock_gettime, gettimeofday, time, getcpu, clock_getres
                \\.set clock_gettime, __vdso_clock_gettime
                \\.set gettimeofday, __vdso_gettimeofday
                \\.set time, __vdso_time
                \\.set getcpu, __vdso_getcpu
                \\.set clock_getres, __vdso_clock_getres
                \\
        ),
        .aarch64 => asm (fns(&.{
                .{ "__kernel_clock_gettime", 113 },
                .{ "__kernel_gettimeofday", 169 },
                .{ "__kernel_clock_getres", 114 },
            }) ++
                \\.globl __kernel_rt_sigreturn
                \\.type __kernel_rt_sigreturn, %function
                \\__kernel_rt_sigreturn:
                \\  mov x8, #139
                \\  svc #0
                \\.size __kernel_rt_sigreturn, .-__kernel_rt_sigreturn
                \\
        ),
        else => @compileError("no vDSO for this arch"),
    }
}

fn fns(comptime list: []const struct { []const u8, u32 }) []const u8 {
    comptime var s: []const u8 = ".text\n";
    inline for (list) |f| {
        const n = f[0];
        const nr = std.fmt.comptimePrint("{d}", .{f[1]});
        s = s ++ ".globl " ++ n ++ "\n.type " ++ n ++ ", %function\n" ++ n ++ ":\n" ++
            (if (builtin.cpu.arch == .x86_64)
            "  mov $" ++ nr ++ ", %eax\n  syscall\n  ret\n"
        else
            "  mov x8, #" ++ nr ++ "\n  svc #0\n  ret\n") ++
            ".size " ++ n ++ ", .-" ++ n ++ "\n";
    }
    return s;
}

const std = @import("std");
