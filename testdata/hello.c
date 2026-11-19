#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>

int main(int argc, char **argv) {
	struct utsname u;
	uname(&u);
	char *p = malloc(1 << 20); // exercises brk/mmap
	p[0] = 'x';
	printf("hello from %s on %s %s, argv[1]=%s\n", argv[0], u.sysname, u.nodename,
	       argc > 1 ? argv[1] : "(none)");
	return 7;
}
