// mmapeof: a MAP_SHARED mapping that runs past the end of a short file must not
// grow the file when its stores are written back. Stores within and past the
// end, msyncs, prints MMAP-EOF-OK; the supervisor checks the file stays short.
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
	int fd = open("/data/f", O_RDWR); // a 100-byte file
	if (fd < 0) {
		perror("open");
		return 1;
	}
	char *p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return 2;
	}
	memcpy(p, "IN", 2);         // within the file
	memcpy(p + 200, "PAST", 4); // past the end, same page: not written back
	if (msync(p, 4096, MS_SYNC) != 0) {
		perror("msync");
		return 3;
	}
	printf("MMAP-EOF-OK\n");
	return 0;
}
