#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
extern char **environ;

// An exec names the task after the last part of the path the caller gave, not
// the file it resolves to: a symlink's own name and a /proc/self/fd/<n> link's
// n. Only execveat AT_EMPTY_PATH, which names no path, takes the file's name.
static int comm_is(const char *want)
{
	char b[32] = {0};
	int fd = open("/proc/self/comm", O_RDONLY);
	ssize_t n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
	if (n > 0 && b[n - 1] == '\n')
		b[n - 1] = 0;
	if (strcmp(b, want)) {
		printf("comm %s, want %s\n", b, want);
		return 0;
	}
	return 1;
}

int main(int argc, char **argv)
{
	char n[16];
	char *av[] = {"execcomm", "", n, 0};
	if (argc < 2) {
		int self = open("/proc/self/exe", O_RDONLY);
		int out = open("/tmp/ec-real", O_RDWR | O_CREAT | O_TRUNC, 0755);
		char buf[65536];
		ssize_t r;
		while (self >= 0 && out >= 0 && (r = read(self, buf, sizeof buf)) > 0)
			write(out, buf, r);
		close(self);
		close(out);
		unlink("/tmp/ec-link");
		if (symlink("ec-real", "/tmp/ec-link")) {
			perror("symlink");
			return 1;
		}
		av[1] = "link";
		execve("/tmp/ec-link", av, environ);
		perror("execve");
		return 2;
	}
	char p[64];
	int fd;
	if (!strcmp(argv[1], "link")) {
		if (!comm_is("ec-link"))
			return 3;
		fd = open("/tmp/ec-real", O_RDONLY);
		snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
		snprintf(n, sizeof n, "%d", fd);
		av[1] = "procfd";
		execve(p, av, environ);
		perror("execve procfd");
		return 4;
	}
	if (!strcmp(argv[1], "procfd")) {
		if (!comm_is(argv[2]))
			return 5;
		fd = open("/tmp/ec-real", O_RDONLY);
		av[1] = "empty";
		execveat(fd, "", av, environ, AT_EMPTY_PATH);
		perror("execveat");
		return 6;
	}
	if (!comm_is("ec-real"))
		return 7;
	unlink("/tmp/ec-link");
	unlink("/tmp/ec-real");
	printf("EXECCOMM-OK\n");
	return 0;
}
