// ptyfs: terminals are the devices their paths resolve to. A pty slave opened
// by its name is the same file ttyname names; /dev/pts lists ptmx and the
// slave; /dev/pts/ptmx and a symlink to it open a master; a devpts mounted
// elsewhere serves the same terminals; an unknown slave is ENOENT. Prints the
// first failed check and "done fails=N".
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

static int listed(const char *dir, const char *name) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) found |= !strcmp(e->d_name, name);
    closedir(d);
    return found;
}

static int master(const char *p) {
    int m = open(p, O_RDWR | O_NOCTTY);
    if (m < 0) return -1;
    if (grantpt(m) || unlockpt(m)) { close(m); return -1; }
    return m;
}

int main(void) {
    int m = master("/dev/ptmx");
    CHECK(m >= 0, "open /dev/ptmx");
    char name[64] = {0};
    CHECK(ptsname_r(m, name, sizeof name) == 0 && !strncmp(name, "/dev/pts/", 9), "ptsname %s", name);
    int s = open(name, O_RDWR | O_NOCTTY);
    CHECK(s >= 0, "open %s", name);
    char *tn = ttyname(s);
    CHECK(tn && !strcmp(tn, name), "ttyname %s, want %s", tn ? tn : "(null)", name);
    CHECK(listed("/dev/pts", name + 9) == 1, "/dev/pts lists %s", name + 9);
    CHECK(listed("/dev/pts", "ptmx") == 1, "/dev/pts lists ptmx");
    struct stat st;
    CHECK(stat("/dev/pts/ptmx", &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 5 && minor(st.st_rdev) == 2, "/dev/pts/ptmx is 5:2");
    errno = 0;
    CHECK(open("/dev/pts/9999", O_RDWR | O_NOCTTY) < 0 && errno == ENOENT, "/dev/pts/9999");

    mkdir("/t", 0755);
    CHECK(symlink("/dev/pts/ptmx", "/t/ptmx") == 0, "symlink");
    int m2 = master("/t/ptmx");
    CHECK(m2 >= 0, "master through a symlink to /dev/pts/ptmx");

    CHECK(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0, "unshare");
    mkdir("/t/pts", 0755);
    CHECK(mount("devpts", "/t/pts", "devpts", 0, "") == 0, "mount devpts");
    struct statfs sf;
    CHECK(statfs("/t/pts", &sf) == 0 && (unsigned long)sf.f_type == 0x1cd1, "devpts f_type");
    int m3 = master("/t/pts/ptmx");
    CHECK(m3 >= 0, "master from the mounted devpts");
    char n3[64] = {0}, p3[80];
    CHECK(m3 >= 0 && ptsname_r(m3, n3, sizeof n3) == 0, "ptsname of the new master");
    snprintf(p3, sizeof p3, "/t/pts/%s", n3 + 9);
    int s3 = open(p3, O_RDWR | O_NOCTTY);
    CHECK(s3 >= 0, "open %s", p3);
    CHECK(s3 >= 0 && write(m3, "hi\n", 3) == 3, "write master");
    char b[8] = {0};
    CHECK(s3 >= 0 && read(s3, b, sizeof b) == 3 && !strcmp(b, "hi\n"), "line through %s", p3);
    printf("done fails=%d\n", fails);
    return fails != 0;
}
