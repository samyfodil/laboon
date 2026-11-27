// Times one thread's cheap syscalls while other threads churn memory:
// syscontend <getppid|pread> <churners> <calls>. Each churner loops mmap,
// write, madvise(DONTNEED), mprotect and munmap, as an allocator giving
// memory back does. Prints "ns/call <n>" for the timed thread.
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static atomic_int stop, started;

static void *churn(void *a) {
	atomic_fetch_add(&started, 1);
	while (!atomic_load(&stop)) {
		char *p = mmap(0, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) abort();
		p[0] = 1;
		madvise(p, 1 << 16, MADV_DONTNEED);
		mprotect(p, 1 << 16, PROT_READ);
		munmap(p, 1 << 16);
	}
	return a;
}

static long long now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv) {
	if (argc != 4) return 2;
	int pread_mode = !strcmp(argv[1], "pread");
	int n = atoi(argv[2]);
	long calls = atol(argv[3]);
	int fd = -1;
	char buf[64];
	if (pread_mode) {
		fd = open("/tmp/syscontend", O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (fd < 0 || write(fd, buf, sizeof buf) != sizeof buf) return 3;
	}
	pthread_t t[64];
	for (int i = 0; i < n && i < 64; i++) pthread_create(&t[i], 0, churn, 0);
	while (atomic_load(&started) < n) ;
	long long t0 = now();
	for (long i = 0; i < calls; i++) {
		if (pread_mode) {
			if (pread(fd, buf, sizeof buf, 0) != sizeof buf) return 4;
		} else {
			syscall(SYS_getppid);
		}
	}
	long long dt = now() - t0;
	atomic_store(&stop, 1);
	for (int i = 0; i < n && i < 64; i++) pthread_join(t[i], 0);
	printf("ns/call %lld\n", dt / calls);
	return 0;
}
