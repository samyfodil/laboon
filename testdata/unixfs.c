// unixfs DIR...: AF_UNIX sockets named in each DIR, whatever filesystem holds
// it (an overlay upper, an in-memory mount, /dev). In each: a stream socket
// is reached by its path and reports it; datagram senders bound at the same
// name in two directories are told apart by recvfrom; a second bind of a name
// is EADDRINUSE; a regular file refuses a connect; an unlinked name is gone.
// A name in a directory with a long path is bound and reached too. Prints the
// first failed check and "done fails=N".
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

static socklen_t addr(struct sockaddr_un *a, const char *p) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    strncpy(a->sun_path, p, sizeof a->sun_path - 1);
    return offsetof(struct sockaddr_un, sun_path) + strlen(p) + 1;
}

static int bound(int type, const char *p) {
    struct sockaddr_un a;
    int s = socket(AF_UNIX, type, 0);
    if (s < 0) return -1;
    if (bind(s, (struct sockaddr *)&a, addr(&a, p)) != 0) { close(s); return -1; }
    return s;
}

static void stream(const char *dir) {
    char p[108];
    struct sockaddr_un a, got;
    snprintf(p, sizeof p, "%s/s.sock", dir);
    int l = bound(SOCK_STREAM, p);
    CHECK(l >= 0 && listen(l, 4) == 0, "%s: bind+listen", p);
    struct stat st;
    CHECK(stat(p, &st) == 0 && S_ISSOCK(st.st_mode), "%s: stat as socket", p);
    socklen_t gl = sizeof got;
    CHECK(getsockname(l, (struct sockaddr *)&got, &gl) == 0 && !strcmp(got.sun_path, p), "%s: getsockname %s", p, got.sun_path);
    CHECK(bound(SOCK_STREAM, p) < 0 && errno == EADDRINUSE, "%s: rebind EADDRINUSE", p);
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(c, (struct sockaddr *)&a, addr(&a, p)) == 0, "%s: connect", p);
    int x = accept(l, 0, 0);
    CHECK(x >= 0, "%s: accept", p);
    gl = sizeof got;
    CHECK(getpeername(c, (struct sockaddr *)&got, &gl) == 0 && !strcmp(got.sun_path, p), "%s: getpeername %s", p, got.sun_path);
    char b[4] = {0};
    CHECK(write(c, "hi", 2) == 2 && read(x, b, sizeof b) == 2 && !strcmp(b, "hi"), "%s: data", p);
    close(x);
    close(c);
    close(l);
    CHECK(unlink(p) == 0, "%s: unlink", p);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(c, (struct sockaddr *)&a, addr(&a, p)) < 0 && errno == ENOENT, "%s: connect after unlink ENOENT", p);
    snprintf(p, sizeof p, "%s/plain", dir);
    int f = open(p, O_CREAT | O_WRONLY, 0644);
    close(f);
    CHECK(connect(c, (struct sockaddr *)&a, addr(&a, p)) < 0 && errno == ECONNREFUSED, "%s: connect to a file ECONNREFUSED", p);
    close(c);
    unlink(p);
}

static void dgram(const char *dir) {
    char r[108], d[2][108], sub[108];
    struct sockaddr_un a, from;
    snprintf(r, sizeof r, "%s/r.sock", dir);
    int rs = bound(SOCK_DGRAM, r);
    CHECK(rs >= 0, "%s: bind", r);
    int ss[2];
    for (int i = 0; i < 2; i++) {
        snprintf(sub, sizeof sub, "%s/%c", dir, 'a' + i);
        mkdir(sub, 0755);
        snprintf(d[i], sizeof d[i], "%s/d.sock", sub);
        ss[i] = bound(SOCK_DGRAM, d[i]);
        CHECK(ss[i] >= 0, "%s: bind", d[i]);
    }
    for (int i = 0; i < 2; i++) {
        char m = '0' + i;
        CHECK(sendto(ss[i], &m, 1, 0, (struct sockaddr *)&a, addr(&a, r)) == 1, "%s: sendto %s", d[i], r);
    }
    for (int i = 0; i < 2; i++) {
        char m = 0;
        socklen_t fl = sizeof from;
        memset(&from, 0, sizeof from);
        CHECK(recvfrom(rs, &m, 1, 0, (struct sockaddr *)&from, &fl) == 1, "%s: recvfrom", r);
        int who = m - '0';
        CHECK(who >= 0 && who < 2 && !strcmp(from.sun_path, d[who]), "%s: sender of %c is %s, got %s", r, m, who >= 0 && who < 2 ? d[who] : "?", from.sun_path);
    }
    for (int i = 0; i < 2; i++) {
        close(ss[i]);
        unlink(d[i]);
    }
    close(rs);
    unlink(r);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        stream(argv[i]);
        dgram(argv[i]);
    }
    char deep[108];
    snprintf(deep, sizeof deep, "%s/%s", argv[1], "a-directory-name-long-enough-that-the-host-path-overruns-sun_path");
    CHECK(mkdir(deep, 0755) == 0, "mkdir %s", deep);
    stream(deep);
    printf("done fails=%d\n", fails);
    return fails != 0;
}
