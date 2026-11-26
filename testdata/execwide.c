// execwide: a guest makes a 64 GiB range executable after writing code into
// it, and calls it: a routine past the range's start, one far inside it, and
// one at its start that sets the syscall number and jumps to the syscall in a
// later stretch of the range, where nothing before it shows it is code.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void put32(char *p, uint32_t v) { memcpy(p, &v, 4); }

int main(void) {
    size_t size = (size_t)64 << 30, near = 4096, far = ((size_t)192 << 20) + 4160, to = ((size_t)64 << 20) + 8192;
    char *p = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
#if defined(__x86_64__)
    static const unsigned char fn[] = {0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xc3}; // mov eax, getpid; syscall; ret
    memcpy(p + near, fn, sizeof fn);
    memcpy(p + far, fn, sizeof fn);
    memcpy(p, fn, 5);                         // mov eax, getpid
    p[5] = (char)0xe9;                        // jmp to
    put32(p + 6, (uint32_t)(to - 10));
    memcpy(p + to, fn + 5, 3);                // syscall; ret
#else
    static const uint32_t fn[] = {0xd2801588, 0xd4000001, 0xd65f03c0}; // mov x8, getpid; svc #0; ret
    memcpy(p + near, fn, sizeof fn);
    memcpy(p + far, fn, sizeof fn);
    put32(p, fn[0]);                                     // mov x8, getpid
    put32(p + 4, 0x14000000 | (uint32_t)((to - 4) / 4)); // b to
    memcpy(p + to, fn + 1, 8);                           // svc #0; ret
#endif
    if (mprotect(p, size, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        return 1;
    }
    long pid = getpid();
    long a = ((long (*)(void))(p + near))(), b = ((long (*)(void))(p + far))(), c = ((long (*)(void))p)();
    if (a != pid || b != pid || c != pid) {
        printf("got %ld %ld %ld, want %ld\n", a, b, c, pid);
        return 1;
    }
    puts("EXECWIDE-OK");
    return 0;
}
