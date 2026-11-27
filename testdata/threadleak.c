// Creates and joins threads, and vforks children that exit or exec, in two
// rounds, stopping after each until a byte arrives on stdin, so the host can
// compare the stub process's memory between them.
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static void *nop(void *a) { return a; }

static int round_(char *self, int threads, int vforks, int execs) {
	for (int i = 0; i < threads; i++) {
		pthread_t t;
		if (pthread_create(&t, 0, nop, 0)) { printf("thread %d failed\n", i); return 1; }
		pthread_join(t, 0);
	}
	for (int i = 0; i < vforks + execs; i++) {
		int st;
		pid_t p = vfork();
		if (p < 0) { printf("vfork %d failed\n", i); return 1; }
		if (p == 0) {
			if (i >= vforks) execl(self, self, "leaf", (char *)0);
			_exit(0);
		}
		if (waitpid(p, &st, 0) != p || st != 0) { printf("child %d: %x\n", i, st); return 1; }
	}
	printf("ready\n");
	fflush(stdout);
	char c;
	return read(0, &c, 1) != 1;
}

int main(int argc, char **argv) {
	if (argc > 1) return 0;
	if (round_(argv[0], 20, 5, 2) || round_(argv[0], 4000, 200, 40)) return 1;
	printf("threadleak ok\n");
	return 0;
}
