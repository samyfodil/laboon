// darwinopen: a guest's own Darwin system call (svc #0x80, which the rewriter
// leaves alone, as it does any code it never sees) meets only the stub's
// Seatbelt profile. A run with no host-directory root must not let it read a
// host file: each path given must fail to open.
#include <stdio.h>

static long darwin_open(const char *p) {
    register long x0 __asm__("x0") = (long)p;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x16 __asm__("x16") = 5; // SYS_open
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs" : "+r"(x0), "=r"(carry) : "r"(x1), "r"(x2), "r"(x16) : "memory", "cc");
    return carry ? -x0 : x0;
}

int main(int argc, char **argv) {
    int leaks = 0;
    for (int i = 1; i < argc; i++) {
        long fd = darwin_open(argv[i]);
        printf("%s: %ld\n", argv[i], fd);
        if (fd >= 0)
            leaks++;
    }
    puts(leaks ? "LEAKED" : "DARWIN-OPEN-DENIED");
    return leaks;
}
