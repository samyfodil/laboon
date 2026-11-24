// Holds far more threads, and more child processes, alive at once than a
// fixed slot table of a few hundred would allow: the sandbox imposes no limit
// of its own, as Linux imposes none below the host's. The children are forked
// first, while the parent is small: a Windows host charges each one commit
// for the parent's private memory.
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREADS 1000
#define CHILDREN 300

static pthread_barrier_t all;

static void *wait_all(void *a) {
	pthread_barrier_wait(&all);
	return a;
}

int main(void) {
	int fds[2], n = 0;
	pipe(fds);
	for (; n < CHILDREN; n++) {
		pid_t p = fork();
		if (p < 0) {
			printf("fork %d failed\n", n);
			return 1;
		}
		if (p == 0) {
			char c;
			close(fds[1]);
			read(fds[0], &c, 1);
			_exit(0);
		}
	}

	static pthread_t t[THREADS];
	pthread_attr_t at;
	pthread_attr_init(&at);
	pthread_attr_setstacksize(&at, 128 << 10); // PTHREAD_STACK_MIN on arm64
	pthread_barrier_init(&all, 0, THREADS + 1);
	for (int i = 0; i < THREADS; i++) {
		int e = pthread_create(&t[i], &at, wait_all, 0);
		if (e) {
			printf("thread %d: error %d\n", i, e);
			return 1;
		}
	}
	pthread_barrier_wait(&all);
	for (int i = 0; i < THREADS; i++) pthread_join(t[i], 0);
	printf("threads %d\n", THREADS);

	close(fds[1]);
	int reaped = 0;
	while (wait(0) > 0) reaped++;
	printf("children %d reaped %d\n", n, reaped);
	printf("manythreads ok\n");
	return reaped == CHILDREN ? 0 : 1;
}
