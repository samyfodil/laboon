// libc: musl
// Detached threads exiting: musl's exit of a detached thread unmaps the
// thread's own stack (__unmapself) and then exits. Prints "detach ok".
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

static atomic_int done;

static void *run(void *a) {
	(void)a;
	atomic_fetch_add(&done, 1);
	return 0;
}

int main(void) {
	for (int round = 0; round < 20; round++) {
		for (int i = 0; i < 10; i++) {
			pthread_t t;
			pthread_attr_t at;
			pthread_attr_init(&at);
			pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
			if (pthread_create(&t, &at, run, 0)) {
				puts("FAIL pthread_create");
				return 1;
			}
			pthread_attr_destroy(&at);
		}
		pthread_t t;
		pthread_create(&t, 0, run, 0);
		pthread_detach(t);
	}
	for (int i = 0; i < 500 && atomic_load(&done) < 220; i++) usleep(10000);
	usleep(100000);
	printf("detach %s %d\n", atomic_load(&done) == 220 ? "ok" : "FAIL", atomic_load(&done));
	return 0;
}
