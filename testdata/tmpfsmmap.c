#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// An in-memory tmpfs file must support a private mmap (its bytes read back
// through the mapping) and its directory must fstat as a directory.
int main(void) {
	unshare(CLONE_NEWUSER | CLONE_NEWNS);
	mkdir("/mnt/t", 0755);
	if (mount("none", "/mnt/t", "tmpfs", 0, "") != 0) { perror("mount"); return 1; }

	const char *msg = "hello-mmap-tmpfs";
	size_t len = strlen(msg);
	int fd = open("/mnt/t/f", O_CREAT | O_RDWR, 0644);
	if (fd < 0) { perror("open"); return 2; }
	if (write(fd, msg, len) != (ssize_t)len) { perror("write"); return 3; }

	char *p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) { perror("mmap"); return 4; }
	if (memcmp(p, msg, len) != 0) { printf("mmap-content=%.*s\n", (int)len, p); return 5; }
	munmap(p, len);
	close(fd);

	int dfd = open("/mnt/t", O_RDONLY | O_DIRECTORY);
	if (dfd < 0) { perror("opendir"); return 6; }
	struct stat st;
	if (fstat(dfd, &st) != 0) { perror("fstat"); return 7; }
	if (!S_ISDIR(st.st_mode)) { printf("dir-mode=%o\n", (unsigned)st.st_mode); return 8; }
	close(dfd);

	printf("TMPFSMMAP-OK\n");
	return 0;
}
