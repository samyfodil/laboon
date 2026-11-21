// chrootconf: after chroot("/jail") a path cannot climb out of the jail, by
// "..", by an absolute symlink, by a relative symlink, or through openat2 with
// RESOLVE_NO_SYMLINKS; ".." at the new root stays there. A directory opened
// before the chroot still reaches outside it, as on Linux. Prints the first
// failed check and "done fails=N".
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
#define RESOLVE_NO_SYMLINKS 0x04

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

int main(void) {
    mkdir("/jail", 0755);
    mkdir("/jail/sub", 0755);
    put("/secret", "OUT");
    put("/jail/inside", "IN");
    CHECK(symlink("/../secret", "/jail/abs") == 0, "symlink abs");
    CHECK(symlink("../../secret", "/jail/sub/rel") == 0, "symlink rel");
    int outside = open("/", O_RDONLY | O_DIRECTORY);
    CHECK(outside >= 0, "open / before chroot");

    CHECK(chroot("/jail") == 0, "chroot");
    CHECK(chdir("/") == 0, "chdir /");
    const char *esc[] = {"/../secret", "/../../secret", "../secret", "/x/../../secret",
                         "/sub/../../secret", "sub/../../secret", "/abs", "/sub/rel"};
    for (unsigned i = 0; i < sizeof esc / sizeof *esc; i++) {
        errno = 0;
        int fd = open(esc[i], O_RDONLY);
        CHECK(fd < 0 && errno == ENOENT, "%s escaped the jail", esc[i]);
        if (fd >= 0) close(fd);
    }
    struct how h = {O_RDONLY, 0, RESOLVE_NO_SYMLINKS};
    errno = 0;
    int fd = syscall(SYS_openat2, AT_FDCWD, "/../secret", &h, sizeof h);
    CHECK(fd < 0 && errno == ENOENT, "openat2 /../secret escaped the jail");
    CHECK(got(open("/inside", O_RDONLY), "IN"), "/inside");
    CHECK(got(open("/sub/../inside", O_RDONLY), "IN"), "/sub/../inside");
    CHECK(chdir("../..") == 0, "chdir ../..");
    char cwd[64] = {0};
    CHECK(getcwd(cwd, sizeof cwd) && !strcmp(cwd, "/"), "cwd after .. is %s", cwd);
    CHECK(got(open("inside", O_RDONLY), "IN"), "inside after ..");
    CHECK(got(openat(outside, "secret", O_RDONLY), "OUT"), "pre-chroot fd lost the outside");
    printf("done fails=%d\n", fails);
    return fails != 0;
}
