// A thread's blocking epoll_waits, on one epoll after another: each times out,
// is woken by another thread's write, returns at once for an fd ready before
// it began, or ends with EINTR for a signal, whichever epoll it waited on
// last and also once the epolls it waited on are closed and their numbers
// reused. Waiting does not change how deep epolls nest under the one waited
// on. Returns 0 on success, else the line number of the failed check.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)

static double now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void *kick(void *arg) {
	uint64_t v = 1;
	write((int)(intptr_t)arg, &v, sizeof v);
	return 0;
}

static volatile sig_atomic_t hits;
static void onalrm(int s) { hits++; }

static int watch(int fd) {
	int ep = epoll_create1(0);
	struct epoll_event e = {.events = EPOLLIN, .data.fd = fd};
	if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e)) return -1;
	return ep;
}

// round waits on a fresh epoll of a fresh eventfd: a timeout, a wake from
// another thread, then an fd already ready.
static int round(void) {
	struct epoll_event out[4];
	uint64_t v;
	int e = eventfd(0, 0), ep = watch(e);
	CHECK(ep >= 0);
	double t0 = now_ms();
	CHECK(epoll_wait(ep, out, 4, 30) == 0);
	CHECK(now_ms() - t0 >= 29);
	pthread_t t;
	CHECK(pthread_create(&t, 0, kick, (void *)(intptr_t)e) == 0);
	CHECK(epoll_wait(ep, out, 4, -1) == 1 && out[0].data.fd == e);
	pthread_join(t, 0);
	CHECK(epoll_wait(ep, out, 4, -1) == 1 && out[0].data.fd == e);
	CHECK(read(e, &v, sizeof v) == sizeof v && v == 1);
	CHECK(epoll_wait(ep, out, 4, 0) == 0);
	close(ep);
	close(e);
	return 0;
}

int main(void) {
	for (int i = 0; i < 4; i++) {
		int r = round();
		if (r) return r;
	}
	int a = eventfd(0, 0), b = eventfd(0, 0);
	int epa = watch(a), epb = watch(b);
	struct epoll_event out[2];
	CHECK(epa >= 0 && epb >= 0);
	CHECK(epoll_wait(epa, out, 2, 10) == 0);
	CHECK(epoll_wait(epb, out, 2, 10) == 0);
	pthread_t t;
	CHECK(pthread_create(&t, 0, kick, (void *)(intptr_t)a) == 0);
	CHECK(epoll_wait(epa, out, 2, -1) == 1 && out[0].data.fd == a);
	pthread_join(t, 0);

	struct sigaction sa = {.sa_handler = onalrm};
	CHECK(sigaction(SIGALRM, &sa, 0) == 0);
	struct itimerval it = {.it_value = {.tv_usec = 100000}};
	CHECK(setitimer(ITIMER_REAL, &it, 0) == 0);
	CHECK(epoll_wait(epb, out, 2, -1) < 0 && errno == EINTR && hits == 1);

	// Waiting leaves the epoll as it was: a chain of epolls as deep as Linux
	// allows still builds under it.
	int up = epb;
	for (int i = 0; i < 4; i++) {
		int down = epoll_create1(0);
		struct epoll_event e = {.events = EPOLLIN, .data.fd = down};
		CHECK(down >= 0 && epoll_ctl(up, EPOLL_CTL_ADD, down, &e) == 0);
		up = down;
	}
	return 0;
}
