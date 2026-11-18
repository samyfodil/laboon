// mmapfork: a MAP_SHARED mapping of a non-host file stays coherent across fork
// and its backing survives while both processes map it. The parent writes and
// forks; the child sees the write through the shared backing and writes back;
// the parent sees the child's write. Prints MMAP-FORK-OK.
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
	int fd = open("/data/f", O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	char *p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return 2;
	}
	memcpy(p, "PARENT", 6);
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return 3;
	}
	if (pid == 0) {
		if (memcmp(p, "PARENT", 6) != 0) {
			_exit(10); // did not see the parent's store
		}
		memcpy(p + 100, "CHILD", 5);
		_exit(0);
	}
	int st;
	waitpid(pid, &st, 0);
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		printf("CHILD-FAIL %d\n", st);
		return 4;
	}
	if (memcmp(p + 100, "CHILD", 5) != 0) {
		printf("PARENT-STALE\n");
		return 5;
	}
	printf("MMAP-FORK-OK\n");
	return 0;
}
