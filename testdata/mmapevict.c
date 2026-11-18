// mmapevict: writes through a MAP_SHARED mapping of a non-host file, then
// munmaps it with no msync. On the last unmap the supervisor writes the backing
// back to the filesystem and releases it, so the stores must still reach the
// composed filesystem. Prints MMAP-EVICT-OK.
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
	memcpy(p, "EVICT-WRITE", 11);
	if (munmap(p, 4096) != 0) { // the last unmap: write-back + release
		perror("munmap");
		return 3;
	}
	printf("MMAP-EVICT-OK\n");
	return 0;
}
