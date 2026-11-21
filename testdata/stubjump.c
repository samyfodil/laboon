// A guest thread that branches into the stub's own syscall instructions (a
// `syscall; ret` or `svc #0; ret` in its text) must not get system calls the
// supervisor would mediate: here an mmap the supervisor never sees. The
// stub's guest-thread filter admits none, so the kernel kills the process.
// With "signal pid", it sends the stub's kick signal to a process outside the
// sandbox instead, which the filter admits only to the stub's own process.
#include <elf.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define STUB_BASE 0x6f0000000000ul // stub/zig/layout.zig

typedef long (*gadget_fn)(long, long, long, long, long, long, long);

static long call_gadget(const uint8_t *g, long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    long r;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    __asm__ volatile("call *%[g]"
                     : "=a"(r)
                     : [g] "r"(g), "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("blr %[g]"
                     : "+r"(x0)
                     : [g] "r"(g), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "x30", "memory");
    r = x0;
#endif
    return r;
}

int main(int argc, char **argv) {
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)STUB_BASE;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
        printf("no stub image at %#lx\n", STUB_BASE);
        return 2;
    }
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(STUB_BASE + eh->e_phoff);
    const uint8_t *g = NULL;
    for (int i = 0; i < eh->e_phnum && !g; i++) {
        if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X)) continue;
        const uint8_t *p = (const uint8_t *)ph[i].p_vaddr, *end = p + ph[i].p_filesz;
#if defined(__x86_64__)
        static const uint8_t pat[] = {0x0f, 0x05, 0xc3};
        for (; p + sizeof pat <= end; p++)
#else
        static const uint8_t pat[] = {0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6};
        for (; p + sizeof pat <= end; p += 4)
#endif
            if (memcmp(p, pat, sizeof pat) == 0) {
                g = p;
                break;
            }
    }
    if (!g) {
        printf("no gadget\n");
        return 2;
    }
    printf("gadget at %p\n", (void *)g);
    fflush(stdout);
    if (argc > 2 && strcmp(argv[1], "signal") == 0) {
        long pid = atol(argv[2]);
        long r = call_gadget(g, SYS_tgkill, pid, pid, SIGURG, 0, 0, 0);
        printf("ESCAPED: tgkill of pid %ld through the stub returned %ld\n", pid, r);
        return 1;
    }
    long r = call_gadget(g, SYS_mmap, 0, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("ESCAPED: mmap through the stub returned %#lx\n", r);
    return 1;
}
