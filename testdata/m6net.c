// libc: musl
// M6 network tests: a local TCP server and client (blocking and nonblocking
// connect, poll, epoll level- and edge-triggered, shutdown, a bulk transfer),
// signals interrupting network waits, AF_UNIX stream sockets with
// SCM_RIGHTS, socketpair across fork, UDP, eventfd, and name resolution. One
// case per argv[1]; each prints "<case> OK" on success.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                      \
	do {                                                                          \
		if (!(c)) {                                                           \
			printf("FAIL %s:%d: %s (errno %d)\n", __FILE__, __LINE__, #c, errno); \
			fflush(stdout);                                               \
			exit(1);                                                      \
		}                                                                     \
	} while (0)

static void msleep(int ms)
{
	struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

// listener returns a socket listening on 127.0.0.1 and its port.
static int listener(int *port)
{
	int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	CHECK(s >= 0);
	int one = 1;
	CHECK(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	CHECK(bind(s, (void *)&a, sizeof a) == 0);
	socklen_t l = sizeof a;
	CHECK(getsockname(s, (void *)&a, &l) == 0 && l == sizeof a && a.sin_port != 0);
	CHECK(listen(s, 8) == 0);
	*port = ntohs(a.sin_port);
	return s;
}

static struct sockaddr_in loop_addr(int port)
{
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	return a;
}

static void set_nonblock(int fd)
{
	CHECK(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0);
}

static int ep_wait(int ep, struct epoll_event *ev, int ms)
{
	int n;
	while ((n = epoll_wait(ep, ev, 8, ms)) < 0 && errno == EINTR)
		;
	return n;
}

static int t_tcp(void)
{
	int port, ls = listener(&port);
	int one = 1, v;
	socklen_t l = sizeof v;
	CHECK(getsockopt(ls, SOL_SOCKET, SO_ACCEPTCONN, &v, &l) == 0 && v == 1);
	CHECK(getsockopt(ls, SOL_SOCKET, SO_TYPE, &v, &l) == 0 && v == SOCK_STREAM);

	// nonblocking connect, completed through poll and SO_ERROR
	int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	CHECK(c >= 0);
	struct sockaddr_in a = loop_addr(port);
	int r = connect(c, (void *)&a, sizeof a);
	CHECK(r == 0 || errno == EINPROGRESS);
	struct pollfd pf = {c, POLLOUT, 0};
	CHECK(poll(&pf, 1, 5000) == 1 && (pf.revents & POLLOUT));
	l = sizeof v;
	CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, &v, &l) == 0 && v == 0);
	CHECK(setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0);

	struct sockaddr_in pa;
	l = sizeof pa;
	int s = accept4(ls, (void *)&pa, &l, SOCK_NONBLOCK | SOCK_CLOEXEC);
	CHECK(s >= 0 && pa.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
	CHECK(fcntl(s, F_GETFD) == FD_CLOEXEC && (fcntl(s, F_GETFL) & O_NONBLOCK));
	struct sockaddr_in ca, sp;
	l = sizeof ca;
	CHECK(getsockname(c, (void *)&ca, &l) == 0);
	CHECK(ca.sin_port == pa.sin_port);
	l = sizeof sp;
	CHECK(getpeername(c, (void *)&sp, &l) == 0 && ntohs(sp.sin_port) == port);
	struct stat st;
	CHECK(fstat(s, &st) == 0 && S_ISSOCK(st.st_mode));

	// poll: nothing yet, then data
	char buf[256];
	pf = (struct pollfd){s, POLLIN, 0};
	CHECK(poll(&pf, 1, 100) == 0);
	CHECK(recv(s, buf, sizeof buf, 0) < 0 && errno == EAGAIN);
	CHECK(send(c, "hello", 5, 0) == 5);
	CHECK(poll(&pf, 1, 5000) == 1 && pf.revents == POLLIN);
	CHECK(recv(s, buf, 2, MSG_PEEK) == 2 && memcmp(buf, "he", 2) == 0);
	CHECK(recv(s, buf, sizeof buf, 0) == 5 && memcmp(buf, "hello", 5) == 0);

	// epoll, level-triggered: reported until read
	int ep = epoll_create1(EPOLL_CLOEXEC);
	CHECK(ep >= 0);
	struct epoll_event ev = {.events = EPOLLIN, .data.u64 = 0x1122334455667788ull}, out[8];
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev) == 0);
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev) < 0 && errno == EEXIST);
	CHECK(ep_wait(ep, out, 50) == 0);
	CHECK(send(c, "abc", 3, 0) == 3);
	CHECK(ep_wait(ep, out, 5000) == 1 && out[0].events == EPOLLIN && out[0].data.u64 == 0x1122334455667788ull);
	CHECK(ep_wait(ep, out, 50) == 1);

	// edge-triggered: once per arrival
	ev.events = EPOLLIN | EPOLLET;
	CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, s, &ev) == 0);
	CHECK(ep_wait(ep, out, 5000) == 1);
	CHECK(ep_wait(ep, out, 100) == 0);
	CHECK(send(c, "de", 2, 0) == 2);
	CHECK(ep_wait(ep, out, 5000) == 1);
	CHECK(ep_wait(ep, out, 100) == 0);
	CHECK(recv(s, buf, sizeof buf, 0) == 5 && memcmp(buf, "abcde", 5) == 0);
	CHECK(recv(s, buf, sizeof buf, 0) < 0 && errno == EAGAIN);
	CHECK(ep_wait(ep, out, 100) == 0);

	// edge-triggered writability, and EPOLLONESHOT
	ev.events = EPOLLOUT | EPOLLET;
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, c, &ev) == 0);
	CHECK(ep_wait(ep, out, 5000) == 1 && out[0].events == EPOLLOUT);
	CHECK(ep_wait(ep, out, 100) == 0);
	ev.events = EPOLLIN | EPOLLONESHOT;
	CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, s, &ev) == 0);
	CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, c, 0) == 0);
	CHECK(send(c, "x", 1, 0) == 1);
	CHECK(ep_wait(ep, out, 5000) == 1);
	CHECK(ep_wait(ep, out, 100) == 0);
	CHECK(recv(s, buf, 1, 0) == 1);

	// bulk: 4 MiB each way through nonblocking sockets and poll
	enum { N = 4 << 20 };
	static char big[N], got[N];
	for (int i = 0; i < N; i++)
		big[i] = (char)(i * 7 + (i >> 11));
	set_nonblock(c);
	size_t sent = 0, rcvd = 0;
	while (rcvd < N) {
		struct pollfd p2[2] = {{c, sent < N ? POLLOUT : 0, 0}, {s, POLLIN, 0}};
		CHECK(poll(p2, 2, 5000) > 0);
		if (p2[0].revents & POLLOUT) {
			ssize_t w = send(c, big + sent, N - sent, 0);
			CHECK(w > 0 || errno == EAGAIN);
			if (w > 0)
				sent += w;
		}
		if (p2[1].revents & POLLIN) {
			ssize_t g = recv(s, got + rcvd, N - rcvd, 0);
			CHECK(g > 0 || errno == EAGAIN);
			if (g > 0)
				rcvd += g;
		}
	}
	CHECK(memcmp(big, got, N) == 0);

	// half close: the server reads EOF and can still answer
	CHECK(shutdown(c, SHUT_WR) == 0);
	pf = (struct pollfd){s, POLLIN | POLLRDHUP, 0};
	CHECK(poll(&pf, 1, 5000) == 1 && (pf.revents & POLLRDHUP));
	CHECK(recv(s, buf, sizeof buf, 0) == 0);
	CHECK(send(s, "bye", 3, 0) == 3);
	pf = (struct pollfd){c, POLLIN, 0};
	CHECK(poll(&pf, 1, 5000) == 1);
	CHECK(recv(c, buf, sizeof buf, 0) == 3);
	CHECK(send(c, "z", 1, MSG_NOSIGNAL) < 0 && errno == EPIPE);
	close(s);
	pf = (struct pollfd){c, POLLIN, 0};
	CHECK(poll(&pf, 1, 5000) == 1);
	CHECK(recv(c, buf, sizeof buf, 0) == 0);
	close(c);

	// blocking connect and accept across a fork, MSG_WAITALL
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		int k = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in b = loop_addr(port);
		CHECK(connect(k, (void *)&b, sizeof b) == 0);
		for (int i = 0; i < 4; i++) {
			CHECK(send(k, "ab", 2, 0) == 2);
			msleep(20);
		}
		CHECK(send(k, big, 1 << 20, 0) == 1 << 20);
		_exit(0);
	}
	s = accept(ls, 0, 0);
	CHECK(s >= 0);
	CHECK(recv(s, buf, 8, MSG_WAITALL) == 8 && memcmp(buf, "abababab", 8) == 0);
	CHECK(recv(s, got, 1 << 20, MSG_WAITALL) == 1 << 20 && memcmp(got, big, 1 << 20) == 0);
	int stt;
	CHECK(waitpid(p, &stt, 0) == p && WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
	CHECK(recv(s, buf, 8, 0) == 0);
	close(s);
	close(ls);

	// refused: blocking, and nonblocking through SO_ERROR
	c = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(connect(c, (void *)&a, sizeof a) < 0 && errno == ECONNREFUSED);
	close(c);
	c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	r = connect(c, (void *)&a, sizeof a);
	CHECK(r < 0 && (errno == EINPROGRESS || errno == ECONNREFUSED));
	if (errno == EINPROGRESS) {
		pf = (struct pollfd){c, POLLOUT, 0};
		CHECK(poll(&pf, 1, 5000) == 1 && (pf.revents & (POLLERR | POLLHUP)));
		l = sizeof v;
		CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, &v, &l) == 0 && v == ECONNREFUSED);
	}
	close(c);

	// IPv6 loopback
	int s6 = socket(AF_INET6, SOCK_STREAM, 0);
	CHECK(s6 >= 0);
	struct sockaddr_in6 a6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
	CHECK(bind(s6, (void *)&a6, sizeof a6) == 0 && listen(s6, 1) == 0);
	l = sizeof a6;
	CHECK(getsockname(s6, (void *)&a6, &l) == 0 && l == sizeof a6);
	int c6 = socket(AF_INET6, SOCK_STREAM, 0);
	CHECK(connect(c6, (void *)&a6, sizeof a6) == 0);
	int k6 = accept(s6, 0, 0);
	CHECK(k6 >= 0 && write(c6, "v6", 2) == 2 && read(k6, buf, 2) == 2 && memcmp(buf, "v6", 2) == 0);
	close(k6);
	close(c6);
	close(s6);
	puts("tcp OK");
	return 0;
}

static volatile int hits;
static void on_alarm(int sig) { hits++; }

static void arm(int ms, int restart)
{
	struct sigaction sa = {.sa_handler = on_alarm, .sa_flags = restart ? SA_RESTART : 0};
	sigemptyset(&sa.sa_mask);
	CHECK(sigaction(SIGALRM, &sa, 0) == 0);
	struct itimerval it = {.it_value = {ms / 1000, (ms % 1000) * 1000}};
	CHECK(setitimer(ITIMER_REAL, &it, 0) == 0);
}

// t_eintr: a handled signal ends each kind of blocking network wait with
// EINTR; with SA_RESTART a recv goes on and completes.
static int t_eintr(void)
{
	int port, ls = listener(&port);
	double t0;

	arm(150, 0);
	t0 = now_ms();
	CHECK(accept(ls, 0, 0) < 0 && errno == EINTR && hits == 1);
	CHECK(now_ms() - t0 < 3000);

	int c = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = loop_addr(port);
	CHECK(connect(c, (void *)&a, sizeof a) == 0);
	int s = accept(ls, 0, 0);
	CHECK(s >= 0);
	char buf[16];

	arm(150, 0);
	CHECK(recv(s, buf, sizeof buf, 0) < 0 && errno == EINTR && hits == 2);
	arm(150, 0);
	struct pollfd pf = {s, POLLIN, 0};
	CHECK(poll(&pf, 1, -1) < 0 && errno == EINTR && hits == 3);
	arm(150, 0);
	fd_set rs;
	FD_ZERO(&rs);
	FD_SET(s, &rs);
	CHECK(select(s + 1, &rs, 0, 0, 0) < 0 && errno == EINTR && hits == 4);
	int ep = epoll_create1(0);
	struct epoll_event ev = {.events = EPOLLIN}, out[2];
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev) == 0);
	arm(150, 1);
	CHECK(epoll_wait(ep, out, 2, -1) < 0 && errno == EINTR && hits == 5);
	arm(150, 0);
	CHECK(pause() < 0 && errno == EINTR && hits == 6);

	// SA_RESTART: the recv outlives the signal and gets the child's data.
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		msleep(500);
		CHECK(send(c, "late", 4, 0) == 4);
		_exit(0);
	}
	arm(150, 1);
	t0 = now_ms();
	CHECK(recv(s, buf, sizeof buf, 0) == 4 && memcmp(buf, "late", 4) == 0 && hits == 7);
	CHECK(now_ms() - t0 >= 300);
	int st;
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);

	// SO_RCVTIMEO: EAGAIN after the timeout
	struct timeval tv = {0, 200000};
	CHECK(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0);
	t0 = now_ms();
	CHECK(recv(s, buf, sizeof buf, 0) < 0 && errno == EAGAIN);
	CHECK(now_ms() - t0 >= 150);
	puts("eintr OK");
	return 0;
}

static void send_fd(int sock, int fd)
{
	char c = 'F';
	struct iovec iov = {&c, 1};
	union {
		char b[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.b, .msg_controllen = sizeof u.b};
	struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof fd);
	CHECK(sendmsg(sock, &m, 0) == 1);
}

static int recv_fd(int sock)
{
	char c;
	struct iovec iov = {&c, 1};
	union {
		char b[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.b, .msg_controllen = sizeof u.b};
	CHECK(recvmsg(sock, &m, MSG_CMSG_CLOEXEC) == 1 && c == 'F');
	struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
	CHECK(cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS && cm->cmsg_len == CMSG_LEN(sizeof(int)));
	int fd;
	memcpy(&fd, CMSG_DATA(cm), sizeof fd);
	CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC);
	return fd;
}

// t_unix: a named AF_UNIX stream server and a forked client, peer
// credentials, an abstract name, and a pipe passed over SCM_RIGHTS.
static int t_unix(void)
{
	const char *path = "/tmp/m6.sock";
	unlink(path);
	int ls = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(ls >= 0);
	struct sockaddr_un a = {.sun_family = AF_UNIX};
	strcpy(a.sun_path, path);
	CHECK(bind(ls, (void *)&a, sizeof a) == 0);
	CHECK(bind(socket(AF_UNIX, SOCK_STREAM, 0), (void *)&a, sizeof a) < 0 && errno == EADDRINUSE);
	struct stat st;
	CHECK(stat(path, &st) == 0 && S_ISSOCK(st.st_mode));
	CHECK(listen(ls, 4) == 0);

	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		int c = socket(AF_UNIX, SOCK_STREAM, 0);
		CHECK(connect(c, (void *)&a, sizeof a) == 0);
		char buf[16];
		CHECK(write(c, "ping", 4) == 4);
		CHECK(read(c, buf, 4) == 4 && memcmp(buf, "pong", 4) == 0);
		int fd = recv_fd(c);
		CHECK(write(fd, "via-fd", 6) == 6);
		_exit(0);
	}
	struct sockaddr_un pa;
	socklen_t l = sizeof pa;
	int s = accept(ls, (void *)&pa, &l);
	CHECK(s >= 0 && pa.sun_family == AF_UNIX);
	struct ucred cr;
	l = sizeof cr;
	CHECK(getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &l) == 0 && cr.pid == p);
	struct sockaddr_un na;
	l = sizeof na;
	CHECK(getsockname(s, (void *)&na, &l) == 0 && strcmp(na.sun_path, path) == 0);
	char buf[16];
	CHECK(read(s, buf, sizeof buf) == 4 && memcmp(buf, "ping", 4) == 0);
	CHECK(write(s, "pong", 4) == 4);
	int pp[2];
	CHECK(pipe(pp) == 0);
	send_fd(s, pp[1]);
	close(pp[1]);
	CHECK(read(pp[0], buf, sizeof buf) == 6 && memcmp(buf, "via-fd", 6) == 0);
	int stt;
	CHECK(waitpid(p, &stt, 0) == p && WIFEXITED(stt) && WEXITSTATUS(stt) == 0);
	CHECK(read(s, buf, sizeof buf) == 0);
	close(s);
	close(ls);
	CHECK(unlink(path) == 0);
	struct sockaddr_un g = {.sun_family = AF_UNIX};
	strcpy(g.sun_path, path);
	int c = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(connect(c, (void *)&g, sizeof g) < 0 && errno == ENOENT);
	close(c);

	// abstract name, nonblocking accept
	struct sockaddr_un ab = {.sun_family = AF_UNIX};
	memcpy(ab.sun_path, "\0m6-abstract", 12);
	socklen_t al = offsetof(struct sockaddr_un, sun_path) + 12;
	ls = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	CHECK(bind(ls, (void *)&ab, al) == 0 && listen(ls, 1) == 0);
	CHECK(accept(ls, 0, 0) < 0 && errno == EAGAIN);
	c = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(connect(c, (void *)&ab, al) == 0);
	struct pollfd pf = {ls, POLLIN, 0};
	CHECK(poll(&pf, 1, 1000) == 1);
	s = accept(ls, 0, 0);
	CHECK(s >= 0);
	CHECK(send(c, "abs", 3, 0) == 3 && recv(s, buf, sizeof buf, 0) == 3);
	puts("unix OK");
	return 0;
}

// t_pair: socketpairs across fork: a stream with EOF and EPIPE once the peer
// is gone, datagram and seqpacket pairs keeping message boundaries.
static int t_pair(void)
{
	signal(SIGPIPE, SIG_IGN);
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		close(sv[0]);
		char buf[16];
		CHECK(read(sv[1], buf, sizeof buf) == 5 && memcmp(buf, "hello", 5) == 0);
		CHECK(write(sv[1], "world!", 6) == 6);
		_exit(0);
	}
	close(sv[1]);
	CHECK(write(sv[0], "hello", 5) == 5);
	char buf[64];
	CHECK(read(sv[0], buf, sizeof buf) == 6 && memcmp(buf, "world!", 6) == 0);
	int st;
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(read(sv[0], buf, sizeof buf) == 0);
	CHECK(write(sv[0], "x", 1) < 0 && errno == EPIPE);
	struct pollfd pf = {sv[0], POLLIN, 0};
	CHECK(poll(&pf, 1, 0) == 1 && (pf.revents & POLLHUP));
	close(sv[0]);

	CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	CHECK(send(sv[0], "one", 3, 0) == 3 && send(sv[0], "three", 5, 0) == 5);
	CHECK(recv(sv[1], buf, sizeof buf, 0) == 3);
	CHECK(recv(sv[1], buf, 2, MSG_TRUNC) == 5);
	CHECK(recv(sv[1], buf, sizeof buf, MSG_DONTWAIT) < 0 && errno == EAGAIN);
	close(sv[0]);
	close(sv[1]);

	CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		CHECK(send(sv[1], "ab", 2, 0) == 2 && send(sv[1], "cde", 3, 0) == 3);
		_exit(0);
	}
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(recv(sv[0], buf, sizeof buf, 0) == 2 && recv(sv[0], buf, sizeof buf, 0) == 3);
	puts("pair OK");
	return 0;
}

// t_udp: datagrams on loopback, the sender's address, a connected socket.
static int t_udp(void)
{
	int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(a >= 0 && b >= 0);
	struct sockaddr_in sa = loop_addr(0);
	CHECK(bind(a, (void *)&sa, sizeof sa) == 0);
	socklen_t l = sizeof sa;
	CHECK(getsockname(a, (void *)&sa, &l) == 0 && sa.sin_port != 0);
	CHECK(sendto(b, "dgram", 5, 0, (void *)&sa, sizeof sa) == 5);
	struct pollfd pf = {a, POLLIN, 0};
	CHECK(poll(&pf, 1, 5000) == 1);
	char buf[64];
	struct sockaddr_in from;
	l = sizeof from;
	CHECK(recvfrom(a, buf, sizeof buf, 0, (void *)&from, &l) == 5 && memcmp(buf, "dgram", 5) == 0);
	CHECK(l == sizeof from && from.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
	CHECK(connect(a, (void *)&from, sizeof from) == 0);
	CHECK(send(a, "back", 4, 0) == 4);
	CHECK(recv(b, buf, sizeof buf, 0) == 4 && memcmp(buf, "back", 4) == 0);
	puts("udp OK");
	return 0;
}

// t_eventfd: an eventfd counter with poll and epoll, written from a child.
static int t_eventfd(void)
{
	int e = eventfd(0, EFD_NONBLOCK);
	CHECK(e >= 0);
	uint64_t v;
	CHECK(read(e, &v, 8) < 0 && errno == EAGAIN);
	int ep = epoll_create1(0);
	struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = e}, out[2];
	CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, e, &ev) == 0);
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		msleep(100);
		v = 3;
		CHECK(write(e, &v, 8) == 8);
		_exit(0);
	}
	CHECK(epoll_wait(ep, out, 2, 5000) == 1 && out[0].data.fd == e);
	CHECK(read(e, &v, 8) == 8 && v == 3);
	int st;
	CHECK(waitpid(p, &st, 0) == p);
	puts("eventfd OK");
	return 0;
}

// t_dns: names resolve through the supervisor's DNS proxy; with an
// allowlist, a name outside it does not.
static int t_dns(const char *host, int want)
{
	struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *res;
	int r = getaddrinfo(host, "80", &hints, &res);
	if (!want) {
		CHECK(r != 0);
		printf("%s: %s\n", host, gai_strerror(r));
		puts("dns OK");
		return 0;
	}
	CHECK(r == 0);
	char ip[64];
	inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof ip);
	printf("%s -> %s\n", host, ip);
	puts("dns OK");
	return 0;
}

/* getifaddrs and if_nameindex, which musl builds from netlink dumps: lo
 * with 127.0.0.1, and with the network on, another interface. */
static int t_ifaddrs(int want_other)
{
	struct ifaddrs *ia;
	if (getifaddrs(&ia)) {
		perror("getifaddrs");
		return 1;
	}
	int lo4 = 0, other = 0;
	for (struct ifaddrs *p = ia; p; p = p->ifa_next) {
		if (!p->ifa_addr)
			continue;
		if (!strcmp(p->ifa_name, "lo")) {
			struct sockaddr_in *in = (struct sockaddr_in *)p->ifa_addr;
			lo4 |= p->ifa_addr->sa_family == AF_INET && in->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
		} else {
			other = 1;
		}
	}
	freeifaddrs(ia);
	int n = 0;
	struct if_nameindex *ni = if_nameindex();
	if (ni) {
		for (struct if_nameindex *q = ni; q->if_index; q++)
			n++;
		if_freenameindex(ni);
	}
	if (!lo4 || !n || (want_other && !other)) {
		printf("ifaddrs: lo4=%d names=%d other=%d\n", lo4, n, other);
		return 1;
	}
	printf("ifaddrs OK\n");
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, 0, _IONBF, 0);
	if (argc < 2)
		return 2;
	const char *c = argv[1];
	if (!strcmp(c, "tcp"))
		return t_tcp();
	if (!strcmp(c, "eintr"))
		return t_eintr();
	if (!strcmp(c, "unix"))
		return t_unix();
	if (!strcmp(c, "pair"))
		return t_pair();
	if (!strcmp(c, "udp"))
		return t_udp();
	if (!strcmp(c, "eventfd"))
		return t_eventfd();
	if (!strcmp(c, "ifaddrs"))
		return t_ifaddrs(argc >= 3 && !strcmp(argv[2], "net"));
	if (!strcmp(c, "dns") && argc >= 3)
		return t_dns(argv[2], argc < 4 || strcmp(argv[3], "denied") != 0);
	return 2;
}
