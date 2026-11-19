// mmaptarfs: maps a read-only file served by a tarfs mount through the vfs
// (its content comes from tarFile.ReadAt, its size from tarNode.Stat) and
// verifies the content is readable through the mapping across a page boundary,
// and that read() agrees. Prints TARFS-MMAP-OK.
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
	int fd = open("/data/f", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	char *p = mmap(0, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return 2;
	}
	if (memcmp(p, "TARFS-PAGE0", 11) != 0) {
		fprintf(stderr, "page0 = %.11s\n", p);
		return 3;
	}
	if (memcmp(p + 4096, "TARFS-PAGE1", 11) != 0) {
		fprintf(stderr, "page1 = %.11s\n", p + 4096);
		return 4;
	}
	char buf[11];
	if (pread(fd, buf, 11, 4096) != 11 || memcmp(buf, "TARFS-PAGE1", 11) != 0) {
		fprintf(stderr, "pread mismatch\n");
		return 5;
	}
	printf("TARFS-MMAP-OK\n");
	return 0;
}
