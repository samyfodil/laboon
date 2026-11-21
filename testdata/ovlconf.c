// ovlconf: a guest `mount -t overlay` over layers inside the guest's own tree.
// The lower layer is named through a relative symlink, as podman names its
// layers; a lower file shows through, the upper wins, a write lands in the
// upper, and an unlinked lower file is gone from both lookup and readdir while
// the lower layer keeps it. A layer named with ".." or through a symlink to an
// absolute path resolves inside the guest's root, never the host's: with no
// /etc in the guest, the mount fails rather than exposing the host's /etc.
// Prints the first failed check and "done fails=N".
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

static void put(const char *p, const char *s) {
    int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK(fd >= 0 && write(fd, s, strlen(s)) == (ssize_t)strlen(s), "write %s", p);
    close(fd);
}

static int is(const char *p, const char *want) {
    char b[32] = {0};
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0;
    int r = read(fd, b, sizeof b - 1);
    close(fd);
    return r > 0 && !strcmp(b, want);
}

static int listed(const char *dir, const char *name) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) found |= !strcmp(e->d_name, name);
    closedir(d);
    return found;
}

int main(void) {
    CHECK(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0, "unshare");
    const char *dirs[] = {"/t", "/t/l1", "/t/l2", "/t/u", "/t/w", "/t/m", "/t/e"};
    for (unsigned i = 0; i < sizeof dirs / sizeof *dirs; i++) mkdir(dirs[i], 0755);
    put("/t/l1/a", "L1");
    put("/t/l1/gone", "G");
    put("/t/l2/a", "L2");
    CHECK(symlink("l1", "/t/link") == 0, "symlink layer");
    CHECK(symlink("/../../../../etc", "/t/evil") == 0, "symlink out");

    CHECK(mount("overlay", "/t/m", "overlay", 0, "lowerdir=/t/l2:/t/link,upperdir=/t/u,workdir=/t/w") == 0, "mount");
    CHECK(is("/t/m/a", "L2"), "upper lower wins");
    CHECK(is("/t/m/gone", "G"), "lower file shows");
    put("/t/m/new", "N");
    CHECK(is("/t/u/new", "N"), "write lands in the upper");
    CHECK(unlink("/t/m/gone") == 0, "unlink lower file");
    struct stat st;
    CHECK(stat("/t/m/gone", &st) < 0 && errno == ENOENT, "unlinked file still looks up");
    CHECK(listed("/t/m", "gone") == 0, "unlinked file still listed");
    CHECK(listed("/t/m", "new") == 1 && listed("/t/m", "a") == 1, "merged listing");
    CHECK(is("/t/l1/gone", "G"), "lower layer lost its file");

    const char *escapes[] = {"lowerdir=/../../../../../etc", "lowerdir=/t/evil", "lowerdir=/t/../../../etc"};
    for (unsigned i = 0; i < sizeof escapes / sizeof *escapes; i++) {
        errno = 0;
        int r = mount("overlay", "/t/e", "overlay", 0, escapes[i]);
        CHECK(r < 0 && errno == ENOENT, "%s mounted", escapes[i]);
        if (r == 0) umount("/t/e");
    }
    CHECK(access("/t/e/hostname", F_OK) < 0, "host /etc reachable");
    printf("done fails=%d\n", fails);
    return fails != 0;
}
