// memcap maps anonymous memory a MiB at a time, touching each, until a
// mapping fails, and reports how many it got and why it stopped. Under a
// memory cap (WithMaxMemory) the failure is ENOMEM well before 256 MiB.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

int main(void) {
    int n = 0, err = 0;
    for (; n < 256; n++) {
        char *p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            err = errno;
            break;
        }
        memset(p, 1, 1 << 20);
    }
    printf("memcap %d %s\n", n, err == ENOMEM ? "ENOMEM" : err ? strerror(err) : "none");
    return 0;
}
