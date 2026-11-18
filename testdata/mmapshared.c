// mmapshared: opens /data/f (a non-host, in-memory file) twice, maps each
// MAP_SHARED, writes through one mapping and checks the other independent open
// sees it (cross-open coherence through the shared backing), then msyncs so the
// content is written back to the filesystem. Prints MMAP-SHARED-OK on success.
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
	int fd1 = open("/data/f", O_RDWR);
	int fd2 = open("/data/f", O_RDWR); // an independent open of the same file
	if (fd1 < 0 || fd2 < 0) {
		perror("open");
		return 1;
	}
	char *p1 = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
	char *p2 = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
	if (p1 == MAP_FAILED || p2 == MAP_FAILED) {
		perror("mmap");
		return 2;
	}
	memcpy(p1, "SHARED-WRITTEN", 14);
	if (memcmp(p2, "SHARED-WRITTEN", 14) != 0) {
		printf("INCOHERENT\n");
		return 3;
	}
	if (msync(p1, 4096, MS_SYNC) != 0) {
		perror("msync");
		return 4;
	}
	printf("MMAP-SHARED-OK\n");
	return 0;
}
