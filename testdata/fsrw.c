#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// Write and read back a file under /data, wherever /data's filesystem comes
// from. With a filesystem mounted there by the host (WithFS), this exercises
// that backend through the guest's open/write/read/stat path.
int main(void) {
	int fd = open("/data/f", O_CREAT | O_RDWR, 0644);
	if (fd < 0) { perror("open"); return 1; }
	if (write(fd, "hi", 2) != 2) { perror("write"); return 2; }
	close(fd);

	char b[8] = {0};
	fd = open("/data/f", O_RDONLY);
	if (fd < 0 || read(fd, b, 2) != 2 || strcmp(b, "hi") != 0) { printf("readback=%s\n", b); return 3; }
	close(fd);

	struct stat st;
	if (stat("/data/f", &st) != 0 || st.st_size != 2) { perror("stat"); return 4; }

	printf("FSRW-OK\n");
	return 0;
}
