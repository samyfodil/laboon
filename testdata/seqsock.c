#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s errno=%d\n", __FILE__, __LINE__, #c, errno); return 1; } } while (0)

// AF_UNIX SOCK_SEQPACKET sockets from socket(): bind, listen, connect and
// accept across fork, messages sent before the accept, boundaries kept both
// ways, the end of the stream once the peer closes and EPIPE after.
int main(void) {
	signal(SIGPIPE, SIG_IGN);
	struct sockaddr_un sa = {.sun_family = AF_UNIX};
	strcpy(sa.sun_path, "/tmp/seq.sock");
	int ls = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	CHECK(ls >= 0);
	CHECK(bind(ls, (void *)&sa, sizeof sa) == 0 && listen(ls, 4) == 0);
	int ty = 0;
	socklen_t tl = sizeof ty;
	CHECK(getsockopt(ls, SOL_SOCKET, SO_TYPE, &ty, &tl) == 0 && ty == SOCK_SEQPACKET);

	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		int c = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		CHECK(c >= 0 && connect(c, (void *)&sa, sizeof sa) == 0);
		CHECK(send(c, "ab", 2, 0) == 2 && send(c, "cde", 3, 0) == 3);
		char buf[16];
		CHECK(recv(c, buf, sizeof buf, 0) == 4 && memcmp(buf, "pong", 4) == 0);
		_exit(0);
	}
	int s = accept(ls, 0, 0);
	CHECK(s >= 0);
	CHECK(getsockopt(s, SOL_SOCKET, SO_TYPE, &ty, &tl) == 0 && ty == SOCK_SEQPACKET);
	char buf[16];
	CHECK(recv(s, buf, sizeof buf, 0) == 2 && memcmp(buf, "ab", 2) == 0);
	CHECK(recv(s, buf, 1, 0) == 1 && buf[0] == 'c');
	CHECK(send(s, "pong", 4, 0) == 4);
	int st;
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(recv(s, buf, sizeof buf, 0) == 0);
	CHECK(send(s, "x", 1, 0) < 0 && errno == EPIPE);
	close(s);

	int c = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	CHECK(c >= 0 && connect(c, (void *)&sa, sizeof sa) == 0);
	CHECK(send(c, "early", 5, 0) == 5);
	struct sockaddr_un pa;
	socklen_t pl = sizeof pa;
	CHECK(getpeername(c, (void *)&pa, &pl) == 0 && strcmp(pa.sun_path, sa.sun_path) == 0);
	s = accept(ls, 0, 0);
	CHECK(s >= 0);
	CHECK(recv(s, buf, sizeof buf, 0) == 5 && memcmp(buf, "early", 5) == 0);
	close(c);
	CHECK(recv(s, buf, sizeof buf, 0) == 0);
	printf("SEQSOCK-OK\n");
	return 0;
}
