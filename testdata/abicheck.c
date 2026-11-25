// abicheck: what the supervisor lays out per guest architecture, read back
// as this program's own ABI expects it: struct stat, uname's machine, struct
// epoll_event, struct semid64_ds, openat2's open flags and seccomp's
// AUDIT_ARCH. On macOS a native arm64 supervisor hosts the x86-64 build too.
// cross: x64
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ipc.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__x86_64__)
#define MACHINE "x86_64"
#define ARCH AUDIT_ARCH_X86_64
#else
#define MACHINE "aarch64"
#define ARCH AUDIT_ARCH_AARCH64
#endif

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

struct how { uint64_t flags, mode, resolve; };

int main(int argc, char **argv) {
    struct stat st;
    CHECK(stat(argv[0], &st) == 0, "stat");
    int fd = open(argv[0], O_RDONLY);
    off_t size = lseek(fd, 0, SEEK_END);
    close(fd);
    CHECK(S_ISREG(st.st_mode) && (st.st_mode & 0111) && st.st_nlink >= 1 && st.st_size == size,
          "stat mode %o nlink %lu size %ld want %ld", st.st_mode, (unsigned long)st.st_nlink, (long)st.st_size, (long)size);
    CHECK(access(argv[0], X_OK) == 0, "access X_OK");

    struct utsname u;
    CHECK(uname(&u) == 0 && strcmp(u.machine, MACHINE) == 0, "uname machine %s", u.machine);

    int ep = epoll_create1(0), ev = eventfd(1, 0);
    struct epoll_event in = {.events = EPOLLIN, .data.u64 = 0x1122334455667788ull}, out[2];
    memset(out, 0xab, sizeof out);
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, ev, &in) == 0, "epoll_ctl");
    int n = epoll_wait(ep, out, 2, 1000);
    CHECK(n == 1 && out[0].events == EPOLLIN && out[0].data.u64 == 0x1122334455667788ull,
          "epoll_wait n %d events %#x data %#llx", n, out[0].events, (unsigned long long)out[0].data.u64);

    int sem = semget(IPC_PRIVATE, 3, IPC_CREAT | 0600);
    struct semid_ds ds;
    CHECK(sem >= 0 && semctl(sem, 0, IPC_STAT, &ds) == 0 && ds.sem_nsems == 3, "sem_nsems %lu", (unsigned long)ds.sem_nsems);
    semctl(sem, 0, IPC_RMID);

    struct how dir = {.flags = O_RDONLY | O_DIRECTORY};
    int d = syscall(437, AT_FDCWD, "/", &dir, sizeof dir);
    CHECK(d >= 0, "openat2 O_DIRECTORY on /");
    errno = 0;
    CHECK(syscall(437, AT_FDCWD, argv[0], &dir, sizeof dir) == -1 && errno == ENOTDIR, "openat2 O_DIRECTORY on a file");

    // getppid fails unless the filter sees this architecture.
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 77),
    };
    struct sock_fprog prog = {.len = sizeof f / sizeof f[0], .filter = f};
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0, "seccomp");
    errno = 0;
    CHECK(syscall(SYS_getppid) >= 0, "seccomp saw another arch");

    if (fails)
        printf("FAILED %d\n", fails);
    else
        printf("ABI-OK %s\n", MACHINE);
    return fails != 0;
}
