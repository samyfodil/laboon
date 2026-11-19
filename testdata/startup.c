// startup: a minimal startup-only guest, to isolate libc init (static-PIE
// self-relocation, TLS setup) and a clean exit from any syscall behavior. Writes
// a marker and returns 0. Built both glibc-static-PIE and musl-static-PIE so the
// cross-platform matrix exercises each libc's _start/exit path.
#include <unistd.h>

int main(void) {
	write(1, "STARTUP-OK\n", 11);
	return 0;
}
