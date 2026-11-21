// walkconf: path walks resolve as Linux's do. ".." after a symlink climbs from
// the link's target, not lexically; a non-directory in the middle of a path is
// ENOTDIR; openat2 RESOLVE_NO_MAGICLINKS refuses a procfs magic link but not
// /proc/self; RESOLVE_IN_ROOT confines "..", absolute symlinks and magic links
// to the starting directory. Prints the first failed check and "done fails=N".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

struct how { uint64_t flags, mode, resolve; };
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_IN_ROOT 0x10

static void put(const char *p, const char *s) {
    int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK(fd >= 0 && write(fd, s, strlen(s)) == (ssize_t)strlen(s), "write %s", p);
    close(fd);
}

static int got(int fd, const char *want) {
    char b[32] = {0};
    if (fd < 0) return 0;
    int r = read(fd, b, sizeof b - 1);
    close(fd);
    return r > 0 && !strcmp(b, want);
}

static int open2(int dirfd, const char *p, uint64_t resolve) {
    struct how h = {O_RDONLY, 0, resolve};
    return syscall(SYS_openat2, dirfd, p, &h, sizeof h);
}

int main(void) {
    mkdir("/w", 0755);
    mkdir("/w/a", 0755);
    mkdir("/w/a/b", 0755);
    put("/w/x", "LEXICAL");
    put("/w/a/x", "TARGET");
    CHECK(symlink("a/b", "/w/l") == 0, "symlink l");
    CHECK(symlink("/x", "/w/abs") == 0, "symlink abs");

    CHECK(got(open("/w/l/../x", O_RDONLY), "TARGET"), "/w/l/../x did not climb from the link target");
    CHECK(chdir("/w") == 0, "chdir /w");
    CHECK(got(open("l/../x", O_RDONLY), "TARGET"), "l/../x did not climb from the link target");
    struct stat st;
    errno = 0;
    CHECK(stat("/w/a/x/y", &st) < 0 && errno == ENOTDIR, "file mid-path is not ENOTDIR");
    errno = 0;
    CHECK(mkdir("/w/a/x/y", 0755) < 0 && errno == ENOTDIR, "mkdir under a file is not ENOTDIR");

    int fd = open("/w/a/x", O_RDONLY);
    char p[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    errno = 0;
    int m = open2(AT_FDCWD, p, RESOLVE_NO_MAGICLINKS);
    CHECK(m < 0 && errno == ELOOP, "NO_MAGICLINKS followed %s", p);
    if (m >= 0) close(m);
    CHECK(got(open2(AT_FDCWD, p, 0), "TARGET"), "%s without flags", p);
    m = open2(AT_FDCWD, "/proc/self/status", RESOLVE_NO_MAGICLINKS);
    CHECK(m >= 0, "NO_MAGICLINKS refused /proc/self/status");
    if (m >= 0) close(m);

    int w = open("/w", O_RDONLY | O_DIRECTORY);
    CHECK(got(open2(w, "../../x", RESOLVE_IN_ROOT), "LEXICAL"), "IN_ROOT .. left the root");
    put("/x", "OUTSIDE");
    mkdir("/w/sub", 0755);
    put("/w/sub/x", "INROOT");
    CHECK(symlink("/sub/x", "/w/inabs") == 0, "symlink inabs");
    CHECK(got(open2(w, "inabs", RESOLVE_IN_ROOT), "INROOT"), "IN_ROOT absolute link did not restart at the root");
    CHECK(got(open2(w, "abs", RESOLVE_IN_ROOT), "LEXICAL"), "IN_ROOT abs reached /x");
    errno = 0;
    m = open2(w, p, RESOLVE_IN_ROOT);
    CHECK(m < 0, "IN_ROOT opened %s", p);
    if (m >= 0) close(m);
    printf("done fails=%d\n", fails);
    return fails != 0;
}
