// Reads exactly argv[1] bytes of stdin with read(2), asking for no more than
// it still needs, and prints them.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
	int want = argc > 1 ? atoi(argv[1]) : 0;
	char buf[256];
	int got = 0;
	while (got < want && got < (int)sizeof buf) {
		ssize_t n = read(0, buf + got, want - got);
		if (n <= 0)
			break;
		got += n;
	}
	printf("read %d: %.*s\n", got, got, buf);
	return 0;
}
