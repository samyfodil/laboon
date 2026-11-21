// tmpfsany: a tmpfs is the same filesystem wherever it is mounted: TMPFS_MAGIC,
// a sticky world-writable root unless mode= says otherwise, and files a
// MAP_SHARED mapping keeps coherent with read and write. Prints the first failed
// check and "done fails=N".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

static void check(const char *at, const char *opts, unsigned want) {
    mkdir(at, 0755);
    CHECK(mount("tmpfs", at, "tmpfs", 0, opts) == 0, "mount tmpfs at %s", at);
    struct statfs sf;
    CHECK(statfs(at, &sf) == 0 && sf.f_type == 0x01021994, "%s f_type %lx", at, (long)sf.f_type);
    struct stat st;
    CHECK(stat(at, &st) == 0 && (st.st_mode & 07777) == want, "%s mode %o want %o", at, st.st_mode & 07777, want);
    char p[256];
    snprintf(p, sizeof p, "%s/shared", at);
    int fd = open(p, O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0 && ftruncate(fd, 4096) == 0, "create %s", p);
    char *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED, "mmap %s", p);
    if (m != MAP_FAILED) {
        memcpy(m, "mapped", 6);
        char b[8] = {0};
        CHECK(pread(fd, b, 6, 0) == 6 && !memcmp(b, "mapped", 6), "%s mapping store not read", at);
        CHECK(pwrite(fd, "WRITE", 5, 100) == 5 && !memcmp(m + 100, "WRITE", 5), "%s write not mapped", at);
        munmap(m, 4096);
    }
    close(fd);
}

int main(void) {
    mkdir("/mnt", 0755);
    check("/mnt/plain", "", 01777);
    check("/mnt/locked", "mode=0700", 0700);
    mkdir("/srv", 0755);
    check("/srv/dev-shm-elsewhere", "mode=1777", 01777);
    printf("done fails=%d\n", fails);
    return fails != 0;
}
