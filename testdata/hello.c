// hello: a minimal startup-only guest, to isolate libc init (static-PIE
// self-relocation, TLS setup) from any syscall behavior. Prints HELLO and
// exits 0. Built both glibc-static-PIE and musl-static-PIE to compare.
#include <unistd.h>

int main(void) {
	write(1, "HELLO\n", 6);
	return 0;
}
