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
    DIR *d = opendir("/");
    CHECK(d != NULL, "opendir /");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            const char *n = e->d_name;
            if (!strcmp(n, ".") || !strcmp(n, "..") || !strcmp(n, "proc") || !strcmp(n, "sys") ||
                !strcmp(n, "dev") || !strcmp(n, "tmp"))
                continue;
            CHECK(0, "/ lists host entry %s", n);
        }
        closedir(d);
    }
    printf("done fails=%d\n", fails);
    return fails != 0;
}
