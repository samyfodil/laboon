// Reads 5 bytes of stdin the way a program using stdio or readv does, and
// prints them: "fstat" fstats fd 0 first, "getc" uses getchar, "readv" one
// readv of a 2 and a 3 byte part.
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "";
	char buf[5];
	int got = 0;
	if (!strcmp(mode, "fstat")) {
		struct stat st;
		if (fstat(0, &st) != 0)
			return 1;
		while (got < 5) {
			ssize_t n = read(0, buf + got, 5 - got);
			if (n <= 0)
				break;
			got += n;
		}
	} else if (!strcmp(mode, "getc")) {
		int c;
		while (got < 5 && (c = getchar()) != EOF)
			buf[got++] = c;
	} else if (!strcmp(mode, "readv")) {
		struct iovec v[2] = {{buf, 2}, {buf + 2, 3}};
		ssize_t n = readv(0, v, 2);
		if (n > 0)
			got = n;
	}
	printf("%s %d: %.*s\n", mode, got, got, buf);
	return 0;
}
