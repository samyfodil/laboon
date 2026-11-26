// execwide: a guest makes a 64 GiB range executable after writing two
// routines into it, one at its start and one far inside it, and calls both.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__x86_64__)
static const unsigned char fn[] = {0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xc3}; // mov eax, getpid; syscall; ret
#else
static const unsigned int fn[] = {0xd2801588, 0xd4000001, 0xd65f03c0}; // mov x8, getpid; svc #0; ret
#endif

int main(void) {
    size_t size = (size_t)64 << 30, far = ((size_t)192 << 20) + 4160;
    char *p = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memcpy(p, fn, sizeof fn);
    memcpy(p + far, fn, sizeof fn);
    if (mprotect(p, size, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        return 1;
    }
    long pid = getpid(), a = ((long (*)(void))p)(), b = ((long (*)(void))(p + far))();
    if (a != pid || b != pid) {
        printf("got %ld %ld, want %ld\n", a, b, pid);
        return 1;
    }
    puts("EXECWIDE-OK");
    return 0;
}
