// mmapguest: a guest program for the writable MAP_SHARED test of a non-host
// file. Checks cross-open coherence, that a mapping store is visible to read()
// with no msync, and that a write() is visible through the mapping; writes
// MMAP-OK. Built -static-pie so it needs no dynamic loader and runs on the
// rewriter backend (a non-PIE ET_EXEC forces the hypervisor backend on arm64
// macOS, which copies file mappings into VM RAM instead of sharing them).
//
// Output is via write(2) and the program ends with _exit(2): a static-PIE glibc
// binary's normal exit cleanup faults under laboon's rewriter (the gate runs
// musl binaries), which would discard buffered stdout and mask the result.
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void say(const char *s) { write(1, s, strlen(s)); }

int main(void) {
	int fd1 = open("/data/f", O_RDWR);
	int fd2 = open("/data/f", O_RDWR); // an independent open
	if (fd1 < 0 || fd2 < 0) {
		say("OPEN-FAIL\n");
		_exit(1);
	}
	char *p1 = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
	char *p2 = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
	if (p1 == MAP_FAILED || p2 == MAP_FAILED) {
		say("MMAP-FAIL\n");
		_exit(2);
	}

	// Cross-open coherence: a store through one mapping is seen by the other.
	memcpy(p1, "SHARED-WRITTEN", 14);
	if (memcmp(p2, "SHARED-WRITTEN", 14) != 0) {
		say("INCOHERENT\n");
		_exit(3);
	}

	// The store is visible to a plain read() with no msync.
	char buf[14];
	if (pread(fd2, buf, 14, 0) != 14 || memcmp(buf, "SHARED-WRITTEN", 14) != 0) {
		say("READ-STALE\n");
		_exit(4);
	}

	// A write() is visible through the mapping.
	if (pwrite(fd2, "WROTE", 5, 100) != 5 || memcmp(p1 + 100, "WROTE", 5) != 0) {
		say("MMAP-STALE\n");
		_exit(5);
	}

	// msync writes the stores back to the composed filesystem now, not just at
	// teardown (the supervisor counts the write-back).
	if (msync(p1, 4096, MS_SYNC) != 0) {
		say("MSYNC-FAIL\n");
		_exit(6);
	}

	say("MMAP-OK\n");
	_exit(0);
}
