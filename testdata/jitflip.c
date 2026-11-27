// jitflip: a JIT that keeps W^X writes new code into one page and flips it
// between writable and executable argv[1] times, running a raw syscall
// (lseek, whose result is the offset it is given) from each version. With
// argv[2] "memfd" each version is instead a new memfd mapped executable.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__x86_64__)
// mov eax, 8 (lseek); syscall; ret
static const unsigned char seekFn[] = {0xb8, 0x08, 0, 0, 0, 0x0f, 0x05, 0xc3};
#elif defined(__aarch64__)
// mov x8, #62 (lseek); svc #0; ret
static const unsigned int seekFn[] = {0xd28007c8, 0xd4000001, 0xd65f03c0};
#endif

typedef long (*fn)(long, long, long);

static void syncCode(void *p, size_t n) {
#if defined(__aarch64__)
	__builtin___clear_cache((char *)p, (char *)p + n);
	__asm__ volatile("dsb ish\n\tisb" ::: "memory");
#else
	(void)p, (void)n;
#endif
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	int n = argc > 1 ? atoi(argv[1]) : 100, fails = 0;
	long pg = sysconf(_SC_PAGESIZE);
	char path[] = "/tmp/jitflipXXXXXX";
	int fd = mkstemp(path);
	unlink(path);
	unsigned char *m = mmap(0, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (fd < 0 || m == MAP_FAILED) {
		printf("jitflip setup failed\n");
		return 1;
	}
	int memfd = argc > 2 && strcmp(argv[2], "memfd") == 0;
	for (int i = 0; memfd && i < n; i++) {
		memcpy(m, seekFn, sizeof seekFn);
		memcpy(m + pg - sizeof i, &i, sizeof i);
		int mfd = memfd_create("jit", 0);
		if (mfd < 0 || write(mfd, m, pg) != pg) {
			fails++;
			break;
		}
		void *x = mmap(0, pg, PROT_READ | PROT_EXEC, MAP_PRIVATE, mfd, 0);
		close(mfd);
		if (x == MAP_FAILED) {
			fails++;
			break;
		}
		long off = (i + 1) * 4096L + 7;
		if (((fn)x)(fd, off, SEEK_SET) != off)
			fails++;
		munmap(x, pg);
	}
	for (int i = 0; !memfd && i < n; i++) {
		memcpy(m, seekFn, sizeof seekFn);
		memcpy(m + pg - sizeof i, &i, sizeof i); // new bytes each time
		syncCode(m, pg);
		if (mprotect(m, pg, PROT_READ | PROT_EXEC) != 0) {
			fails++;
			break;
		}
		long off = (i + 1) * 4096L + 7;
		if (((fn)m)(fd, off, SEEK_SET) != off || lseek(fd, 0, SEEK_CUR) != off)
			fails++;
		if (mprotect(m, pg, PROT_READ | PROT_WRITE) != 0) {
			fails++;
			break;
		}
	}
	printf("jitflip fails=%d\n", fails);
	return fails != 0;
}
