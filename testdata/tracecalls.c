// A few calls for the syscall trace to show: an open and an exec that fail, a
// file written and read back, and an exit status.
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(void) {
	char b[16];
	if (open("/no/such/file", O_RDONLY) >= 0)
		return 2;
	int fd = open("/tmp/traced", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0 || write(fd, "trace-data", 10) != 10)
		return 3;
	if (lseek(fd, 0, SEEK_SET) != 0 || read(fd, b, sizeof b) != 10 || memcmp(b, "trace-data", 10))
		return 4;
	close(fd);
	char *argv[] = {"nope", 0};
	execve("/no/such/prog", argv, argv + 1);
	return 7;
}
