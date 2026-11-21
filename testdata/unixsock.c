// unixsock DIR HOSTSOCK HOSTABS: AF_UNIX addresses stay within the guest.
// DIR is a host directory, HOSTSOCK a socket and HOSTABS an abstract name
// the host listens on. Run with the host as the image, the guest may bind in
// DIR (its own view of it) but reaches neither host socket, while its own
// sockets work by path and abstract name. The exit status is the line of the
// first failed check, 0 if none failed.
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int first;
#define CHECK(c) do { if (!(c) && !first) first = __LINE__; } while (0)

static socklen_t addr(struct sockaddr_un *a, const char *p, int abstract) {
	memset(a, 0, sizeof *a);
	a->sun_family = AF_UNIX;
	size_t n = strlen(p);
	memcpy(a->sun_path + abstract, p, n);
	return offsetof(struct sockaddr_un, sun_path) + abstract + n + !abstract;
}

int main(int argc, char **argv) {
	if (argc != 4) return 1;
	struct sockaddr_un a, got;
	socklen_t len, glen;
	char path[200];

	// A socket bound in DIR is the guest's, with the guest's name.
	snprintf(path, sizeof path, "%s/guest.sock", argv[1]);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(s >= 0);
	len = addr(&a, path, 0);
	CHECK(bind(s, (struct sockaddr *)&a, len) == 0 && listen(s, 4) == 0);
	struct stat st;
	CHECK(stat(path, &st) == 0 && S_ISSOCK(st.st_mode));
	glen = sizeof got;
	CHECK(getsockname(s, (struct sockaddr *)&got, &glen) == 0 && strcmp(got.sun_path, path) == 0);
	CHECK(bind(socket(AF_UNIX, SOCK_STREAM, 0), (struct sockaddr *)&a, len) < 0 && errno == EADDRINUSE);
	int c = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(connect(c, (struct sockaddr *)&a, len) == 0);
	int acc = accept(s, 0, 0);
	char b[4] = {0};
	CHECK(acc >= 0 && write(c, "hi", 2) == 2 && read(acc, b, 2) == 2 && strcmp(b, "hi") == 0);
	glen = sizeof got;
	CHECK(getpeername(c, (struct sockaddr *)&got, &glen) == 0 && strcmp(got.sun_path, path) == 0);

	// Datagrams carry the sender's guest name.
	char p1[200], p2[200];
	snprintf(p1, sizeof p1, "%s/d1", argv[1]);
	snprintf(p2, sizeof p2, "%s/d2", argv[1]);
	int d1 = socket(AF_UNIX, SOCK_DGRAM, 0), d2 = socket(AF_UNIX, SOCK_DGRAM, 0);
	struct sockaddr_un a1, a2;
	socklen_t l1 = addr(&a1, p1, 0), l2 = addr(&a2, p2, 0);
	CHECK(bind(d1, (struct sockaddr *)&a1, l1) == 0 && bind(d2, (struct sockaddr *)&a2, l2) == 0);
	CHECK(sendto(d2, "yo", 2, 0, (struct sockaddr *)&a1, l1) == 2);
	glen = sizeof got;
	CHECK(recvfrom(d1, b, sizeof b, 0, (struct sockaddr *)&got, &glen) == 2 && strcmp(got.sun_path, p2) == 0);

	// The guest's abstract names work among its sockets.
	int ab = socket(AF_UNIX, SOCK_STREAM, 0);
	len = addr(&a, "lc-guest-abstract", 1);
	CHECK(bind(ab, (struct sockaddr *)&a, len) == 0 && listen(ab, 4) == 0);
	glen = sizeof got;
	CHECK(getsockname(ab, (struct sockaddr *)&got, &glen) == 0 && glen == len && memcmp(&got, &a, len) == 0);
	CHECK(connect(socket(AF_UNIX, SOCK_STREAM, 0), (struct sockaddr *)&a, len) == 0);

	// Neither host socket is reachable.
	len = addr(&a, argv[2], 0);
	CHECK(connect(socket(AF_UNIX, SOCK_STREAM, 0), (struct sockaddr *)&a, len) < 0);
	len = addr(&a, argv[3], 1);
	CHECK(connect(socket(AF_UNIX, SOCK_STREAM, 0), (struct sockaddr *)&a, len) < 0);

	// A symlink to the host's directory leads to the guest's view of it.
	char link[200];
	snprintf(link, sizeof link, "%s/link", argv[1]);
	CHECK(symlink("/", link) == 0);
	snprintf(path, sizeof path, "%s/link%s/via-link.sock", argv[1], argv[1]);
	len = addr(&a, path, 0);
	CHECK(bind(socket(AF_UNIX, SOCK_STREAM, 0), (struct sockaddr *)&a, len) == 0);
	return first;
}
