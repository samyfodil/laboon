// m3io: signal-delivery cases the in-process signal battery (sigbasic) does not
// cover -- delivery to a thread blocked in read, EINTR vs SA_RESTART, and the
// default-action exit codes. argv[1] selects one; build static-PIE for
// x86_64-linux-musl. Prints one line and exits 0 on success, or exits with the
// signal-coded status the harness checks.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t hits;
static void on_alrm(int s) { (void)s; hits++; }

static sigjmp_buf segvh_jb;
static volatile void *segvh_addr;
static void segvh_handler(int s, siginfo_t *si, void *uc) {
	(void)s;
	(void)uc;
	segvh_addr = si->si_addr;
	siglongjmp(segvh_jb, 1);
}

static int pfd[2];

// writer sleeps, interrupts the reader with SIGUSR1, then feeds it a byte, so
// the read is first broken by a signal and (under SA_RESTART) completes after.
static void *writer(void *arg) {
	pthread_t main_th = *(pthread_t *)arg;
	struct timespec ts = {0, 80 * 1000 * 1000};
	nanosleep(&ts, NULL);
	pthread_kill(main_th, SIGUSR1);
	nanosleep(&ts, NULL);
	ssize_t n = write(pfd[1], "x", 1);
	(void)n;
	return NULL;
}

static int run_read(int restart) {
	if (pipe(pfd) != 0) return 1;
	struct sigaction sa = {0};
	sa.sa_handler = on_alrm;
	sa.sa_flags = restart ? SA_RESTART : 0;
	sigaction(SIGUSR1, &sa, NULL);
	hits = 0;
	pthread_t self = pthread_self(), w;
	pthread_create(&w, NULL, writer, &self);
	char b = 0;
	ssize_t n = read(pfd[0], &b, 1);
	int e = errno;
	pthread_join(w, NULL);
	if (restart) {
		if (n == 1 && b == 'x' && hits == 1) {
			printf("restart ok\n");
			return 0;
		}
		printf("restart FAIL n=%zd b=%d hits=%d\n", n, b, hits);
		return 1;
	}
	if (n == -1 && e == EINTR && hits == 1) {
		printf("eintr ok\n");
		return 0;
	}
	printf("eintr FAIL n=%zd errno=%d hits=%d\n", n, e, hits);
	return 1;
}

// No data or room is supplied after the signal: an uninterruptible wait
// cannot accidentally pass when a helper later unblocks the pipe.
static void *interrupt_only(void *arg) {
	struct timespec ts = {0, 80 * 1000 * 1000};
	nanosleep(&ts, NULL);
	pthread_kill(*(pthread_t *)arg, SIGUSR1);
	return NULL;
}

static void *kill_blocked(void *arg) {
	(void)arg;
	struct timespec ts = {0, 80 * 1000 * 1000};
	nanosleep(&ts, NULL);
	kill(getpid(), SIGKILL);
	return NULL;
}

static int pipe_intr(int writing, int killing) {
	int p[2], used = 0, after = -1;
	char b[4096];
	memset(b, 'p', sizeof b);
	if (pipe2(p, O_NONBLOCK)) return 1;
	if (writing) {
		ssize_t n;
		while ((n = write(p[1], b, sizeof b)) > 0) used += n;
		if (n != -1 || errno != EAGAIN || used == 0) return 1;
	}
	if (fcntl(p[writing ? 1 : 0], F_SETFL, 0)) return 1;
	struct sigaction sa = {.sa_handler = on_alrm};
	sigaction(SIGUSR1, &sa, NULL);
	hits = 0;
	pthread_t self = pthread_self(), t;
	alarm(5);
	if (pthread_create(&t, NULL, killing ? kill_blocked : interrupt_only, &self)) return 1;
	ssize_t n = writing ? write(p[1], b, sizeof b) : read(p[0], b, 1);
	int e = errno;
	pthread_join(t, NULL);
	alarm(0);
	ioctl(p[0], FIONREAD, &after);
	close(p[0]); close(p[1]);
	int ok = n == -1 && e == EINTR && hits == 1 && after == used;
	printf("pipe-%s-intr %s\n", writing ? "write" : "read", ok ? "ok" : "FAIL");
	return !ok;
}

// stdout_intr: fd 1 is a host pipe of PIPE_BUF bytes the harness reads only
// once the run is over. The first write fills it; the second blocks until a
// signal ends it with EINTR, having written nothing. Reports on stderr.
static int stdout_intr(void) {
	char b[4096];
	memset(b, 's', sizeof b);
	if (write(1, b, sizeof b) != sizeof b) return 1;
	struct sigaction sa = {.sa_handler = on_alrm};
	sigaction(SIGUSR1, &sa, NULL);
	hits = 0;
	pthread_t self = pthread_self(), t;
	alarm(5);
	if (pthread_create(&t, NULL, interrupt_only, &self)) return 1;
	ssize_t n = write(1, b, sizeof b);
	int e = errno;
	pthread_join(t, NULL);
	alarm(0);
	int ok = n == -1 && e == EINTR && hits == 1;
	fprintf(stderr, "stdout-write-intr %s\n", ok ? "ok" : "FAIL");
	return !ok;
}

// stdin_intr: fd 0 is a host pipe nothing writes. A read of it blocks until a
// signal ends it with EINTR, and a poll then still finds nothing to read.
static int stdin_intr(void) {
	char b[16];
	struct sigaction sa = {.sa_handler = on_alrm};
	sigaction(SIGUSR1, &sa, NULL);
	hits = 0;
	pthread_t self = pthread_self(), t;
	alarm(5);
	if (pthread_create(&t, NULL, interrupt_only, &self)) return 1;
	ssize_t n = read(0, b, sizeof b);
	int e = errno;
	pthread_join(t, NULL);
	alarm(0);
	struct pollfd f = {.fd = 0, .events = POLLIN};
	int ok = n == -1 && e == EINTR && hits == 1 && poll(&f, 1, 50) == 0;
	printf("stdin-read-intr %s\n", ok ? "ok" : "FAIL");
	return !ok;
}

// stdin_poll: fd 0 is a host pipe the harness writes "x" to, and then
// closes, once this has said on stderr that it polls. The poll wakes with the
// data, FIONREAD counts it, a read takes it and the next is end of file.
static int stdin_poll(void) {
	fprintf(stderr, "polling\n");
	struct pollfd f = {.fd = 0, .events = POLLIN};
	alarm(5);
	int r = poll(&f, 1, -1);
	int avail = -1;
	ioctl(0, FIONREAD, &avail);
	char b[4];
	ssize_t n = read(0, b, sizeof b);
	ssize_t end = read(0, b, sizeof b);
	alarm(0);
	int ok = r == 1 && (f.revents & POLLIN) && avail == 1 && n == 1 && b[0] == 'x' && end == 0;
	printf("stdin-poll %s\n", ok ? "ok" : "FAIL");
	if (!ok) printf("poll %d revents %#x avail %d read %zd end %zd\n", r, f.revents, avail, n, end);
	return !ok;
}

// stdin_poll0: fd 0 is a host pipe the harness keeps a read of its own
// pending on, from once this has filled fd 1 (a pipe of PIPE_BUF bytes) until
// it drains it. Then a zero-timeout poll finds stdin empty (as Rust's runtime
// checks its stdio), and the run still ends once this exits.
static int stdin_poll0(void) {
	char b[8192];
	memset(b, 'p', sizeof b);
	ssize_t w = write(1, b, sizeof b);
	struct pollfd f = {.fd = 0, .events = POLLIN};
	int r = poll(&f, 1, 0);
	int ok = w == sizeof b && r == 0;
	fprintf(stderr, "stdin-poll0 %s\n", ok ? "ok" : "FAIL");
	if (!ok) fprintf(stderr, "write %zd poll %d revents %#x\n", w, r, f.revents);
	return !ok;
}

// stdout_nonblock: fd 1 is a host pipe of PIPE_BUF bytes the harness reads
// only once this has said "drain" on stderr. Non-blocking, the first write
// fills the pipe and the second is taken while the pipe is full; the third
// fails with EAGAIN, and POLLOUT stays clear until the harness reads.
static int stdout_nonblock(void) {
	char b[4096];
	memset(b, 'n', sizeof b);
	if (fcntl(1, F_SETFL, O_NONBLOCK)) return 1;
	ssize_t w1 = write(1, b, sizeof b);
	ssize_t w2 = write(1, b, sizeof b);
	ssize_t w3 = write(1, b, sizeof b);
	int e3 = errno;
	struct pollfd f = {.fd = 1, .events = POLLOUT};
	int p0 = poll(&f, 1, 0);
	fprintf(stderr, "drain\n");
	alarm(5);
	int p1 = poll(&f, 1, -1);
	alarm(0);
	int ok = w1 == 4096 && w2 == 4096 && w3 == -1 && e3 == EAGAIN && p0 == 0 && p1 == 1 && (f.revents & POLLOUT);
	fprintf(stderr, "stdout-nonblock %s\n", ok ? "ok" : "FAIL");
	if (!ok) fprintf(stderr, "writes %zd %zd %zd (errno %d) polls %d %d\n", w1, w2, w3, e3, p0, p1);
	return !ok;
}

struct pipe_change { int fd, action; };
static void *change_pipe(void *arg) {
	struct pipe_change *c = arg;
	struct timespec ts = {0, 50 * 1000 * 1000};
	char b[4096];
	nanosleep(&ts, NULL);
	if (c->action == 0) write(c->fd, "x", 1);
	else if (c->action == 1) read(c->fd, b, sizeof b);
	else close(c->fd);
	return NULL;
}

static int pipe_waits(void) {
	int p[2], ep = epoll_create1(0);
	char b[4096] = {0};
	if (ep < 0 || pipe2(p, O_NONBLOCK)) return 1;
	struct epoll_event ev = {.events = EPOLLIN}, out;
	if (epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev)) return 1;
	alarm(10);
	for (int i = 0; i < 5; i++) {
		int writing = i == 3;
		if (writing && (fcntl(p[1], F_SETPIPE_SZ, 4096) != 4096 || write(p[1], b, sizeof b) != 4096)) return 1;
		struct pipe_change c = {writing ? p[0] : p[1], writing ? 1 : i == 4 ? 2 : 0};
		pthread_t t;
		if (pthread_create(&t, NULL, change_pipe, &c)) return 1;
		struct pollfd f = {.fd = writing ? p[1] : p[0], .events = writing ? POLLOUT : POLLIN};
		int r;
		if (i == 1) r = epoll_wait(ep, &out, 1, -1);
		else if (i == 2) {
			fd_set set;
			FD_ZERO(&set); FD_SET(p[0], &set);
			r = pselect(p[0] + 1, &set, NULL, NULL, NULL, NULL);
		} else r = ppoll(&f, 1, NULL, NULL);
		pthread_join(t, NULL);
		if (r != 1) return 1;
		if (i < 3 && read(p[0], b, 1) != 1) return 1;
		if (i == 4 && (!(f.revents & POLLHUP) || read(p[0], b, 1) != 0)) return 1;
	}
	alarm(0);
	close(p[0]); close(ep);
	puts("pipe-waits ok");
	return 0;
}

static int pipe_state(void) {
	int p[2], n = -1, ep;
	char b[4096] = {0};
	struct iovec v[2] = {{b, 2048}, {b + 2048, 2048}};
	if (pipe2(p, O_NONBLOCK) || fcntl(p[1], F_SETPIPE_SZ, 4096) != 4096) return 1;
	if (write(p[1], b, 1) != 1 || writev(p[1], v, 2) != -1 || errno != EAGAIN) return 1;
	if (ioctl(p[0], FIONREAD, &n) || n != 1) return 1; // no partial atomic writev
	if (read(p[0], b, 1) != 1) return 1;
	ep = epoll_create1(0);
	struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = p[0]}, out;
	if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev)) return 1;
	if (writev(p[1], v, 2) != 4096 || epoll_wait(ep, &out, 1, 0) != 1) return 1;
	if (epoll_wait(ep, &out, 1, 0) != 0) return 1;
	struct pollfd f = {.fd = p[1], .events = POLLOUT};
	if (poll(&f, 1, 0) != 0 || read(p[0], b, 1) != 1) return 1;
	if (epoll_wait(ep, &out, 1, 0) != 0) return 1; // drain is not a new read edge
	if (read(p[0], b, sizeof b) != 4095) return 1;
	if (poll(&f, 1, 0) != 1 || !(f.revents & POLLOUT)) return 1;
	if (writev(p[1], v, 2) != 4096 || epoll_wait(ep, &out, 1, 0) != 1) return 1;
	if (read(p[0], b, sizeof b) != 4096) return 1; // wrapped ring
	char name[64];
	snprintf(name, sizeof name, "/proc/self/fd/%d", p[0]);
	int r2 = open(name, O_RDONLY | O_NONBLOCK), w2 = open(name, O_WRONLY);
	if (r2 < 0 || w2 < 0 || fcntl(r2, F_SETFL, 0)) return 1;
	if (!(fcntl(p[0], F_GETFL) & O_NONBLOCK)) return 1; // reopen has its own flags
	if (write(w2, "r", 1) != 1 || read(r2, b, 1) != 1 || b[0] != 'r') return 1;
	close(r2); close(w2);
	int w = dup(p[1]);
	close(p[1]);
	if (read(p[0], b, 1) != -1 || errno != EAGAIN) return 1;
	close(w);
	f.fd = p[0]; f.events = POLLIN;
	if (poll(&f, 1, 0) != 1 || !(f.revents & POLLHUP) || read(p[0], b, 1) != 0) return 1;
	close(ep); close(p[0]);
	if (pipe2(p, O_NONBLOCK)) return 1;
	close(p[0]);
	signal(SIGPIPE, SIG_IGN);
	f.fd = p[1]; f.events = POLLOUT;
	if (poll(&f, 1, 0) != 1 || !(f.revents & POLLERR)) return 1;
	if (write(p[1], b, 1) != -1 || errno != EPIPE) return 1;
	close(p[1]);
	puts("pipe-state ok");
	return 0;
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "";
	if (!strcmp(mode, "pipe-read-intr")) return pipe_intr(0, 0);
	if (!strcmp(mode, "pipe-write-intr")) return pipe_intr(1, 0);
	if (!strcmp(mode, "stdout-write-intr")) return stdout_intr();
	if (!strcmp(mode, "stdout-nonblock")) return stdout_nonblock();
	if (!strcmp(mode, "stdin-read-intr")) return stdin_intr();
	if (!strcmp(mode, "stdin-poll")) return stdin_poll();
	if (!strcmp(mode, "stdin-poll0")) return stdin_poll0();
	if (!strcmp(mode, "pipe-read-kill")) return pipe_intr(0, 1);
	if (!strcmp(mode, "pipe-write-kill")) return pipe_intr(1, 1);
	if (!strcmp(mode, "pipe-waits")) return pipe_waits();
	if (!strcmp(mode, "pipe-state")) return pipe_state();
	if (!strcmp(mode, "eintr")) return run_read(0);
	if (!strcmp(mode, "restart")) return run_read(1);
	if (!strcmp(mode, "kill9")) {
		kill(getpid(), SIGKILL);
		printf("not killed\n");
		return 1;
	}
	if (!strcmp(mode, "term")) {
		raise(SIGTERM); // default action: terminate -> 128+15
		printf("not terminated\n");
		return 1;
	}
	if (!strcmp(mode, "segv")) {
		volatile int *p = (int *)16;
		*p = 1; // no handler: default SIGSEGV -> 128+11
		printf("no fault\n");
		return 1;
	}
	if (!strcmp(mode, "segvh")) {
		struct sigaction sa = {0};
		sa.sa_flags = SA_SIGINFO;
		sa.sa_sigaction = segvh_handler;
		sigaction(SIGSEGV, &sa, NULL);
		if (sigsetjmp(segvh_jb, 1) == 0) {
			*(volatile int *)16 = 1;
			printf("no fault\n");
			return 1;
		}
		printf("segvh %s\n", segvh_addr == (void *)16 ? "ok" : "FAIL");
		return segvh_addr == (void *)16 ? 0 : 1;
	}
	fprintf(stderr, "usage: m3io eintr|restart|kill9|term|segv\n");
	return 2;
}
