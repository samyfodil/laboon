// Times epoll_wait: epollbench ready <nfds> <maxevents> <calls> waits on an
// epoll of nfds eventfds, one of them always ready; epollbench wake <calls>
// ping-pongs two threads, each blocked in epoll_wait until the other writes
// its eventfd. Prints "ns/call <n>" (per wait, or per round trip).
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

static long long now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int watch(int fd) {
	int ep = epoll_create1(0);
	struct epoll_event e = {.events = EPOLLIN, .data.fd = fd};
	if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e)) exit(3);
	return ep;
}

static void await(int ep, int fd) {
	struct epoll_event e;
	uint64_t v;
	if (epoll_wait(ep, &e, 1, -1) != 1 || e.data.fd != fd) exit(4);
	if (read(fd, &v, sizeof v) != sizeof v) exit(5);
}

static void kick(int fd) {
	uint64_t v = 1;
	if (write(fd, &v, sizeof v) != sizeof v) exit(6);
}

static int a, b, epa, epb;
static long calls;

static void *peer(void *arg) {
	for (long i = 0; i < calls; i++) {
		await(epa, a);
		kick(b);
	}
	return arg;
}

int main(int argc, char **argv) {
	long long t0, dt;
	if (argc == 3 && !strcmp(argv[1], "wake")) {
		calls = atol(argv[2]);
		a = eventfd(0, 0), b = eventfd(0, 0);
		epa = watch(a), epb = watch(b);
		pthread_t t;
		pthread_create(&t, 0, peer, 0);
		t0 = now();
		for (long i = 0; i < calls; i++) {
			kick(a);
			await(epb, b);
		}
		dt = now() - t0;
		pthread_join(t, 0);
	} else if (argc == 5 && !strcmp(argv[1], "ready")) {
		int nfds = atoi(argv[2]), max = atoi(argv[3]);
		calls = atol(argv[4]);
		struct epoll_event *evs = calloc(max, sizeof *evs);
		int ep = epoll_create1(0);
		for (int i = 0; i < nfds; i++) {
			int fd = eventfd(i == 0, 0);
			struct epoll_event e = {.events = EPOLLIN, .data.fd = fd};
			if (fd < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e)) return 3;
		}
		t0 = now();
		for (long i = 0; i < calls; i++)
			if (epoll_wait(ep, evs, max, -1) != 1) return 4;
		dt = now() - t0;
	} else {
		return 2;
	}
	printf("ns/call %lld\n", calls ? dt / calls : 0);
	return 0;
}
