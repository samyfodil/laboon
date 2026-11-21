// noroot: run with no root filesystem, the guest sees none of the host's. argv[1]
// is a host file and argv[2] a host directory; neither may be reachable, and a
// file the guest creates must not land on the host. Prints the first failed
// check and "done fails=N".
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    char p[4096];
    struct stat st;
    errno = 0;
    CHECK(stat(argv[1], &st) < 0, "host file %s is visible", argv[1]);
    errno = 0;
    CHECK(open(argv[1], O_RDONLY) < 0, "host file %s opens", argv[1]);
    errno = 0;
    CHECK(stat("/etc/passwd", &st) < 0, "host /etc/passwd is visible");
    snprintf(p, sizeof p, "%s/made-by-guest", argv[2]);
    int fd = open(p, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
    // The program is bound at its own host path (on Windows /C:/...), so each
    // directory on its path holds exactly the next component; / also has the
    // run's pseudo filesystems and /tmp.
    char self[4096];
    ssize_t sn = readlink("/proc/self/exe", self, sizeof self - 1);
    CHECK(sn > 1 && self[0] == '/', "readlink /proc/self/exe");
    if (sn <= 1) return 1;
    self[sn] = 0;
    char dir[4096] = "/";
    const char *rest = self + 1;
    for (;;) {
        const char *slash = strchr(rest, '/');
        size_t n = slash ? (size_t)(slash - rest) : strlen(rest);
        char want[256];
        snprintf(want, sizeof want, "%.*s", (int)n, rest);
        DIR *d = opendir(dir);
        CHECK(d != NULL, "opendir %s", dir);
        if (!d)
            break;
        struct dirent *e;
        while ((e = readdir(d))) {
            const char *nm = e->d_name;
            if (!strcmp(nm, ".") || !strcmp(nm, "..") || !strcmp(nm, want))
                continue;
            if (!strcmp(dir, "/") && (!strcmp(nm, "proc") || !strcmp(nm, "sys") || !strcmp(nm, "dev") ||
                                      !strcmp(nm, "tmp")))
                continue;
            CHECK(0, "%s lists host entry %s", dir, nm);
        }
        closedir(d);
        if (!slash)
            break;
        snprintf(dir + strlen(dir), sizeof dir - strlen(dir), "%s%s", strcmp(dir, "/") ? "/" : "", want);
        rest = slash + 1;
    }
    printf("done fails=%d\n", fails);
    return fails != 0;
}
