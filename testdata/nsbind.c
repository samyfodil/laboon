#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sched.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// A persisted network-namespace bind-mount must behave like the kernel's: the
// file cannot be unlinked while bound (EBUSY), umount releases it, and setns
// through it rejoins the SAME namespace it pinned — proven here by a listener
// that lives in that namespace becoming reachable over loopback only after the
// join. NST is a writable target (not /run/netns, so the test needs no root fs).
#define NST "/tmp/laboon-nsbind"
#define PORT 9100
static void a4(struct sockaddr_in *s) {
	memset(s, 0, sizeof *s); s->sin_family = AF_INET; s->sin_port = htons(PORT);
	inet_pton(AF_INET, "127.0.0.1", &s->sin_addr);
}
int main(void) {
	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) { perror("unshare user/ns"); return 10; }
	mkdir(NST, 0755);
	int rdy[2]; if (pipe(rdy) != 0) return 11;

	pid_t a = fork();
	if (a == 0) { // listener, in its own pinned netns
		close(rdy[0]);
		if (unshare(CLONE_NEWNET) != 0) { perror("A unshare net"); _exit(31); }
		int f = open(NST "/x", O_RDONLY | O_CREAT | O_EXCL, 0); if (f < 0) { perror("A create"); _exit(32); }
		close(f);
		if (mount("/proc/self/ns/net", NST "/x", NULL, MS_BIND, NULL) != 0) { perror("A bind"); _exit(33); }
		int ls = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in s; a4(&s);
		if (bind(ls, (void *)&s, sizeof s) != 0) { perror("A bind lo"); _exit(34); }
		if (listen(ls, 8) != 0) { perror("A listen"); _exit(35); }
		char one = 1; write(rdy[1], &one, 1); close(rdy[1]);
		int c = accept(ls, NULL, NULL); if (c < 0) _exit(36);
		char b[8] = {0};
		if (read(c, b, 8) != 4 || memcmp(b, "ping", 4)) _exit(37);
		write(c, "pong", 4);
		_exit(0);
	}
	close(rdy[1]); char one; read(rdy[0], &one, 1); // A is listening + bound

	// (1) the bound file cannot be removed.
	if (unlink(NST "/x") == 0 || errno != EBUSY) { fprintf(stderr, "unlink not EBUSY: %s\n", strerror(errno)); return 1; }

	// (2) setns through the bind rejoins A's netns; (3) its loopback listener is then reachable.
	int nf = open(NST "/x", O_RDONLY | O_CLOEXEC); if (nf < 0) { perror("open bind"); return 2; }
	if (setns(nf, CLONE_NEWNET) != 0) { perror("setns"); return 3; }
	int cs = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in d; a4(&d);
	int ok = -1; for (int i = 0; i < 200 && ok != 0; i++) ok = connect(cs, (void *)&d, sizeof d);
	if (ok != 0) { fprintf(stderr, "connect after setns: %s (fresh netns?)\n", strerror(errno)); return 4; }
	if (write(cs, "ping", 4) != 4) return 5;
	char r[8] = {0}; if (read(cs, r, 8) != 4 || memcmp(r, "pong", 4)) return 6;

	// (4) umount releases the pin, then the file can be removed.
	if (umount2(NST "/x", MNT_DETACH) != 0) { perror("umount"); return 7; }
	if (unlink(NST "/x") != 0) { perror("unlink after umount"); return 8; }

	int ws = 0; waitpid(a, &ws, 0);
	if (!WIFEXITED(ws) || WEXITSTATUS(ws)) { fprintf(stderr, "A exit %d\n", ws); return 9; }
	printf("NSBIND-OK\n");
	return 0;
}
