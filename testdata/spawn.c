// libc: musl
/* posix_spawn, which libcs issue as clone(CLONE_VM|CLONE_VFORK) on a stack
   of the child's own. argv[1] is a program that exits 7 (hello.c). A
   missing program must fail posix_spawn itself, which glibc reports through
   memory the child shares with the parent. */
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

extern char **environ;

int main(int argc, char **argv) {
	pid_t pid;
	int st, r;
	char *args[] = {argv[1], "spawned", NULL};
	if ((r = posix_spawn(&pid, argv[1], NULL, NULL, args, environ))) {
		printf("spawn: %s\n", strerror(r));
		return 1;
	}
	if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) {
		printf("waitpid: %s\n", strerror(errno));
		return 2;
	}
	printf("child exit %d\n", WEXITSTATUS(st));
	r = posix_spawn(&pid, "/nonexistent", NULL, NULL, args, environ);
	if (!r)
		waitpid(pid, &st, 0);
	printf("missing: %s\n", r ? strerror(r) : "spawned");
	return 0;
}
