// ptyrun: runs a command on a new pseudo-terminal, as script(1) would, types
// INPUT and a carriage return into it once the command has printed something, and copies what the
// terminal shows to stdout. Exits with the command's status.
//
//   ptyrun INPUT command [args...]
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: ptyrun INPUT command [args...]\n");
		return 2;
	}
	int m = posix_openpt(O_RDWR | O_NOCTTY);
	if (m < 0 || grantpt(m) || unlockpt(m)) {
		perror("ptmx");
		return 1;
	}
	char *name = ptsname(m);
	pid_t pid = fork();
	if (pid == 0) {
		setsid();
		int s = open(name, O_RDWR);
		if (s < 0) {
			perror(name);
			_exit(127);
		}
		ioctl(s, TIOCSCTTY, 0);
		dup2(s, 0);
		dup2(s, 1);
		dup2(s, 2);
		if (s > 2) close(s);
		close(m);
		execvp(argv[2], argv + 2);
		perror(argv[2]);
		_exit(127);
	}
	int typed = 0, status = 0;
	char buf[4096];
	for (;;) {
		struct pollfd p = {m, POLLIN, 0};
		int r = poll(&p, 1, 200);
		if (r > 0 && (p.revents & POLLIN)) {
			ssize_t n = read(m, buf, sizeof buf);
			if (n <= 0) break;
			fwrite(buf, 1, n, stdout);
			fflush(stdout);
			if (!typed) {
				usleep(200000);
				write(m, argv[1], strlen(argv[1]));
				write(m, "\r", 1);
				typed = 1;
			}
		} else if (r > 0 && (p.revents & (POLLHUP | POLLERR))) {
			break;
		}
		if (waitpid(pid, &status, WNOHANG) == pid) {
			while ((r = read(m, buf, sizeof buf)) > 0) fwrite(buf, 1, r, stdout);
			pid = 0;
			break;
		}
	}
	if (pid) waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
