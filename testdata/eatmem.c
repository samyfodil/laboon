// "eat" allocates 1 MiB at a time until malloc fails or 2000 MiB are taken.
// "fork" takes 40 MiB, forks, and has the child (holding its copy) try 40
// MiB more: under a 64 MiB cap for the whole run it cannot.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t eat(size_t mib) {
	size_t total = 0;
	for (size_t i = 0; i < mib; i++) {
		void *p = malloc(1 << 20);
		if (!p) break;
		memset(p, 1, 1 << 20);
		total++;
	}
	return total;
}

int main(int argc, char **argv) {
	if (argc > 1 && !strcmp(argv[1], "fork")) {
		if (eat(40) != 40) {
			printf("parent malloc failed\n");
			return 1;
		}
		fflush(stdout);
		pid_t p = fork();
		if (p < 0) {
			printf("fork failed\n");
			return 0;
		}
		if (p == 0) {
			size_t got = eat(40);
			printf(got < 40 ? "child malloc failed after %zu MiB\n" : "child allocated %zu MiB\n", got);
			return 0;
		}
		waitpid(p, 0, 0);
		return 0;
	}
	size_t total = eat(2000);
	if (total < 2000) {
		printf("malloc failed after %zu MiB\n", total);
		return 0;
	}
	printf("allocated %zu MiB\n", total);
	return 0;
}
