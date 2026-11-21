// Forks two children that exit, so the supervisor's stub pool fills, then two
// that exec this program again to block, and waits for them. With argv[1]
// "child" it blocks until killed.
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc > 1 && !strcmp(argv[1], "child")) {
		pause();
		return 0;
	}
	for (int i = 0; i < 2; i++) {
		pid_t p = fork();
		if (p == 0) _exit(0);
		waitpid(p, 0, 0);
	}
	for (int i = 0; i < 2; i++) {
		if (fork() == 0) {
			char *av[] = {argv[0], "child", 0};
			execv(argv[0], av);
			_exit(1);
		}
	}
	while (wait(0) > 0) {
	}
	return 0;
}
