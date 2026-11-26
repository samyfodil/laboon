// guestlen: guest-chosen lengths that the supervisor must bound before it
// allocates, each answered with an error instead of taking the run down.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fails++;                                              \
            printf("FAIL %s:%d: %s: ", __func__, __LINE__, #cond); \
            printf(__VA_ARGS__);                                  \
            printf(" (errno %d)\n", errno);                       \
        }                                                         \
    } while (0)

#define ARGSTR (32 * 4096)

// Thousands of argv entries all pointing at one unterminated 128 KiB string
// ask the supervisor for gigabytes unless it charges each entry as it reads.
static void argv_bomb(void) {
    char *s = mmap(NULL, ARGSTR + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(s, 'A', ARGSTR + 4096);
    int n = 16384;
    char **argv = malloc((n + 1) * sizeof *argv);
    for (int i = 0; i < n; i++)
        argv[i] = s;
    argv[n] = NULL;
    errno = 0;
    CHECK(execve("/proc/self/exe", argv, NULL) == -1 && errno == E2BIG, "argv bomb");
    free(argv);
    munmap(s, ARGSTR + 4096);
}

// An executable private mapping of a non-host file reads only what the file
// holds: a huge length fails as the host mapping would, and the part past the
// file's end is zero and carries the mapping's protection.
static void exec_map(void) {
    int fd = open("/m/code", O_CREAT | O_RDWR | O_TRUNC, 0755);
    CHECK(fd >= 0, "open /m/code");
    char page[4096 + 100];
    memset(page, 0xc3, sizeof page);
    CHECK(write(fd, page, sizeof page) == sizeof page, "write");

    errno = 0;
    void *huge = mmap(NULL, 1UL << 62, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    CHECK(huge == MAP_FAILED && errno == ENOMEM, "huge exec map %p", huge);

    // One small enough to be copied, one mapped from a staged copy of the file.
    size_t lens[] = {3 * 4096, 1 << 20};
    for (int i = 0; i < 2; i++) {
        size_t len = lens[i];
        unsigned char *p = mmap(NULL, len, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        CHECK(p != MAP_FAILED, "exec map %zu", len);
        if (p == MAP_FAILED)
            continue;
        CHECK(p[0] == 0xc3 && p[4096 + 99] == 0xc3, "file bytes %zu", len);
        CHECK(p[4096 + 100] == 0 && p[len - 1] == 0, "zero tail %zu", len);

        unsigned long end = 0;
        char perms[5] = "";
        FILE *m = fopen("/proc/self/maps", "r");
        char line[512];
        while (m && fgets(line, sizeof line, m)) {
            unsigned long lo, hi;
            char pr[5];
            if (sscanf(line, "%lx-%lx %4s", &lo, &hi, pr) == 3 && lo <= (unsigned long)p + len - 1 && (unsigned long)p + len - 1 < hi) {
                end = hi;
                memcpy(perms, pr, 5);
            }
        }
        if (m)
            fclose(m);
        CHECK(end >= (unsigned long)p + len && strncmp(perms, "r-x", 3) == 0, "map %zu %s to %#lx", len, perms, end);
        munmap(p, len);
    }
    close(fd);
}

// Datagram sends in a guest network namespace take the virtual network's own
// path; a length past any datagram's fails there.
static void vnet_send(void) {
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare");
    static char buf[4096];
    int ports[] = {53, 9999};
    for (int i = 0; i < 2; i++) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(s >= 0, "socket");
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(ports[i])};
        inet_pton(AF_INET, "8.8.8.8", &to.sin_addr);
        CHECK(sendto(s, buf, 1UL << 40, 0, (struct sockaddr *)&to, sizeof to) == -1, "sendto %d", ports[i]);
        struct iovec iov = {.iov_base = buf, .iov_len = 1UL << 62};
        struct msghdr m = {.msg_name = &to, .msg_namelen = sizeof to, .msg_iov = &iov, .msg_iovlen = 1};
        CHECK(sendmsg(s, &m, 0) == -1, "sendmsg %d", ports[i]);
        close(s);
    }
}

int main(void) {
    argv_bomb();
    exec_map();
    vnet_send();
    printf(fails ? "FAILED %d\n" : "GUESTLEN-OK\n", fails);
    return fails != 0;
}
