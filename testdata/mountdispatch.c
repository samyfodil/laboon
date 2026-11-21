// mountdispatch: /proc, /sys, /dev and cgroup2 are served by the mount that
// covers a path, not by its name. A tmpfs mounted over /proc hides the
// synthetic tree until it is unmounted; a cgroup2 mounted at another path
// takes mkdir and rmdir like /sys/fs/cgroup; /dev/shm and a guest tmpfs report
// tmpfs to statfs. Prints the first failed check and "done fails=N".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

static unsigned long fstype(const char *p) {
    struct statfs s;
    return statfs(p, &s) == 0 ? (unsigned long)s.f_type : 0;
}

int main(void) {
    CHECK(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0, "unshare");
    CHECK(fstype("/dev/shm") == 0x01021994, "/dev/shm f_type %#lx", fstype("/dev/shm"));
    CHECK(fstype("/proc") == 0x9fa0, "/proc f_type %#lx", fstype("/proc"));

    CHECK(access("/proc/self/status", F_OK) == 0, "/proc/self/status");
    CHECK(mount("tmpfs", "/proc", "tmpfs", 0, "") == 0, "mount tmpfs on /proc");
    errno = 0;
    CHECK(access("/proc/self", F_OK) < 0 && errno == ENOENT, "/proc/self under a tmpfs");
    CHECK(mkdir("/proc/mine", 0755) == 0, "mkdir in the tmpfs over /proc");
    CHECK(umount("/proc") == 0, "umount /proc");
    CHECK(access("/proc/self/status", F_OK) == 0, "/proc/self/status after umount");
    errno = 0;
    CHECK(access("/proc/mine", F_OK) < 0 && errno == ENOENT, "tmpfs entry outlived its mount");

    mkdir("/cg", 0755);
    CHECK(mount("cgroup2", "/cg", "cgroup2", 0, "") == 0, "mount cgroup2");
    CHECK(fstype("/cg") == 0x63677270, "/cg f_type %#lx", fstype("/cg"));
    CHECK(mkdir("/cg/sub", 0755) == 0, "mkdir in a relocated cgroup2");
    CHECK(access("/cg/sub/cgroup.procs", F_OK) == 0, "new cgroup has cgroup.procs");
    CHECK(rmdir("/cg/sub") == 0, "rmdir in a relocated cgroup2");

    mkdir("/shm2", 0755);
    CHECK(mount("tmpfs", "/shm2", "tmpfs", 0, "") == 0, "mount tmpfs");
    CHECK(fstype("/shm2") == 0x01021994, "tmpfs f_type %#lx", fstype("/shm2"));
    printf("done fails=%d\n", fails);
    return fails != 0;
}
