// mmapcache: proves the per-vnode shared backing is the file's authoritative
// copy. A store through a MAP_SHARED mapping is visible to a plain read() with
// no msync, and a write() is visible through the mapping. Prints MMAP-CACHE-OK.
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
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

	// A store through the mapping is visible to read() without any msync.
	memcpy(p, "MMAP-STORE", 10);
	int fd2 = open("/data/f", O_RDWR); // an independent open
	if (fd2 < 0) {
		perror("open fd2");
		return 10;
	}
	char buf[32] = {0};
	if (pread(fd2, buf, 10, 0) != 10 || memcmp(buf, "MMAP-STORE", 10) != 0) {
		printf("READ-STALE: %.10s\n", buf);
		return 3;
	}

	// A write() is visible through the mapping (not clobbered, not stale).
	if (pwrite(fd2, "WRITE-DATA", 10, 100) != 10) {
		perror("pwrite");
		return 4;
	}
	if (memcmp(p + 100, "WRITE-DATA", 10) != 0) {
		printf("MMAP-STALE\n");
		return 5;
	}
	printf("MMAP-CACHE-OK\n");
	return 0;
}
