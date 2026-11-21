// memtest: a static-PIE musl program for the Windows M2 milestone. It drives
// the stub's memory (brk, anonymous and file mappings, partial munmap,
// mprotect, mremap) and the overlay's file calls, printing one line per
// failed check and exiting with the failure count.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fails;
static sigjmp_buf jb;

static void onsig(int sig) {
	siglongjmp(jb, sig);
}

// touch writes to p and returns the signal that stopped it, or 0; peek reads.
static int touch(volatile char *p) {
	int sig = sigsetjmp(jb, 1);
	if (sig == 0)
		*p = 1;
	return sig;
}

static int peek(volatile char *p) {
	int sig = sigsetjmp(jb, 1);
	if (sig == 0)
		(void)*p;
	return sig;
}

#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(int argc, char **argv) {
	const char *dir = argc > 1 ? argv[1] : "/tmp";
	long pg = sysconf(_SC_PAGESIZE);
	CHECK(pg == (argc > 2 ? atol(argv[2]) : 4096));

	// brk (musl's sbrk only reports the break; move it with the syscall)
	char *b0 = (char *)syscall(SYS_brk, 0);
	CHECK((char *)syscall(SYS_brk, b0 + 3 * pg) == b0 + 3 * pg);
	memset(b0, 7, 3 * pg);
	CHECK(b0[3 * pg - 1] == 7);
	CHECK((char *)syscall(SYS_brk, b0 + 2 * pg) == b0 + 2 * pg && b0[pg] == 7);

	// malloc, small and large
	char *s = malloc(100), *l = malloc(1 << 20);
	CHECK(s && l);
	memset(l, 1, 1 << 20);
	free(s);
	free(l);

	// anonymous mappings, partial munmap, MAP_FIXED, mprotect
	char *m = mmap(0, 8 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(m != MAP_FAILED);
	CHECK(m[5 * pg] == 0);
	memset(m, 3, 8 * pg);
	CHECK(munmap(m + 2 * pg, 2 * pg) == 0);
	CHECK(m[pg] == 3 && m[4 * pg] == 3);
	char *f = mmap(m + 2 * pg, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	CHECK(f == m + 2 * pg && f[0] == 0);
	char *o = mmap(m + 5 * pg, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	CHECK(o == m + 5 * pg && o[0] == 0 && m[6 * pg] == 3);
	CHECK(mprotect(m, pg, PROT_READ) == 0);
	CHECK(m[0] == 3);
	CHECK(mprotect(m, pg, PROT_READ | PROT_WRITE) == 0);
	m[0] = 9;
	CHECK(munmap(m, 8 * pg) == 0);
	char *n = mmap(0, 2 * pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(n != MAP_FAILED && mprotect(n, pg, PROT_READ | PROT_WRITE) == 0);
	n[1] = 1;
	CHECK(munmap(n, 2 * pg) == 0);

	// mremap: grow (in place or moved), shrink
	char *r = mmap(0, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	r[10] = 42;
	char *r2 = mremap(r, pg, 64 * pg, MREMAP_MAYMOVE);
	CHECK(r2 != MAP_FAILED && r2[10] == 42 && r2[63 * pg] == 0);
	char *r3 = mremap(r2, 64 * pg, 2 * pg, 0);
	CHECK(r3 == r2 && r3[10] == 42);
	CHECK(munmap(r3, 2 * pg) == 0);

	// files
	char p[256], q[256];
	snprintf(p, sizeof p, "%s/mt.dat", dir);
	snprintf(q, sizeof q, "%s/mt2.dat", dir);
	int fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0640);
	CHECK(fd >= 0);
	long nbuf = 3 * pg;
	char *buf = malloc(nbuf);
	for (long i = 0; i < nbuf; i++)
		buf[i] = 'a' + i % 26;
	CHECK(write(fd, buf, nbuf) == nbuf);
	struct stat st;
	CHECK(fstat(fd, &st) == 0 && st.st_size == nbuf && (st.st_mode & 07777) == 0640 && S_ISREG(st.st_mode));

	// a private file mapping sees the file and keeps its own writes
	char *pm = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, pg);
	CHECK(pm != MAP_FAILED && pm[0] == buf[pg] && pm[pg + 5] == buf[2 * pg + 5]);
	pm[0] = '#';
	char c;
	CHECK(pread(fd, &c, 1, pg) == 1 && c == buf[pg]);
	CHECK(munmap(pm, 2 * pg) == 0);

	// a shared mapping writes through, and survives a partial munmap
	char *sm = mmap(0, 3 * pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(sm != MAP_FAILED && sm[1] == buf[1]);
	sm[2 * pg] = '!';
	CHECK(munmap(sm, pg) == 0);
	CHECK(sm[2 * pg] == '!' && sm[pg + 1] == buf[pg + 1]);
	CHECK(msync(sm + pg, 2 * pg, MS_SYNC) == 0);
	CHECK(pread(fd, &c, 1, 2 * pg) == 1 && c == '!');
	CHECK(munmap(sm + pg, 2 * pg) == 0);

	// a shared mapping may run past the end of the file: the last page is
	// there, the pages past it raise SIGBUS, and a partial munmap keeps both
	signal(SIGBUS, onsig);
	signal(SIGSEGV, onsig);
	CHECK(ftruncate(fd, pg + 100) == 0);
	sm = mmap(0, 3 * pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(sm != MAP_FAILED);
	CHECK(touch(sm + pg + 50) == 0 && touch(sm + 2 * pg - 1) == 0);
	CHECK(touch(sm + 2 * pg) == SIGBUS);
	CHECK(munmap(sm, pg) == 0);
	CHECK(sm[pg + 50] == 1 && touch(sm + pg + 99) == 0 && touch(sm + 2 * pg + 8) == SIGBUS);
	CHECK(mprotect(sm + 2 * pg, pg, PROT_READ) == 0 && peek(sm + 2 * pg) == SIGBUS && touch(sm + 2 * pg) == SIGSEGV);
	CHECK(pread(fd, &c, 1, pg + 50) == 1 && c == 1);
	// the file grown over a page past its end makes it readable; cut short
	// under the mapping, its pages past the new end raise SIGBUS
	CHECK(ftruncate(fd, 2 * pg + 10) == 0 && peek(sm + 2 * pg + 8) == 0 && sm[2 * pg + 20] == 0);
	CHECK(ftruncate(fd, pg) == 0 && peek(sm + pg + 50) == SIGBUS && touch(sm + pg + 50) == SIGBUS);
	CHECK(munmap(sm + pg, 2 * pg) == 0);
	int ef = open(q, O_RDWR | O_CREAT | O_TRUNC, 0600);
	char *em = mmap(0, pg, PROT_READ | PROT_WRITE, MAP_SHARED, ef, 0);
	CHECK(ef >= 0 && em != MAP_FAILED && touch(em) == SIGBUS);
	CHECK(munmap(em, pg) == 0 && close(ef) == 0 && unlink(q) == 0);
	signal(SIGBUS, SIG_DFL);
	signal(SIGSEGV, SIG_DFL);
	close(fd);

	// a hint where nothing is mapped is taken (an unaligned one rounded down), and
	// a fixed mapping goes anywhere free, as on Linux
	char *hint = (char *)0x300000000000UL;
	char *hm = mmap(hint, 4 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(hm == hint);
	char *um = mmap(hint + 16 * pg + 1, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(um == hint + 16 * pg);
	char *fm = mmap(hint + 64 * pg, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	CHECK(fm == hint + 64 * pg);
	if (hm == hint && um == hint + 16 * pg && fm == hint + 64 * pg) {
		hm[0] = um[0] = fm[0] = 7;
		CHECK(hm[0] + um[0] + fm[0] == 21);
	}
	CHECK(munmap(hint, 65 * pg) == 0);

	// address space is reserved as long as there is any: MariaDB takes 8 TiB
	// for its buffer pool's largest size
	size_t big = (size_t)8 << 40;
	char *res = mmap(0, big, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	CHECK(res != MAP_FAILED && munmap(res, big) == 0);

	// fchmod of a socket or a pipe acts on the descriptor, and fstat shows it
	int sk = socket(AF_UNIX, SOCK_STREAM, 0), pp[2];
	CHECK(sk >= 0 && fchmod(sk, 0600) == 0 && fstat(sk, &st) == 0 && S_ISSOCK(st.st_mode) && (st.st_mode & 07777) == 0600);
	CHECK(pipe(pp) == 0 && fchmod(pp[1], 0640) == 0 && fstat(pp[1], &st) == 0 && (st.st_mode & 07777) == 0640);
	close(sk);
	close(pp[0]);
	close(pp[1]);

	// membarrier offers the private expedited barrier, once registered
	long mq = syscall(SYS_membarrier, 0, 0);
	CHECK(mq > 0 && (mq & 8) && (mq & 16));
	CHECK(syscall(SYS_membarrier, 8, 0) == -1 && errno == EPERM);
	CHECK(syscall(SYS_membarrier, 16, 0) == 0 && syscall(SYS_membarrier, 8, 0) == 0);

	// rename, getdents, unlink
	CHECK(rename(p, q) == 0);
	CHECK(stat(p, &st) == -1 && stat(q, &st) == 0);
	DIR *d = opendir(dir);
	int seen = 0;
	struct dirent *e;
	while (d && (e = readdir(d)))
		if (!strcmp(e->d_name, "mt2.dat"))
			seen++;
	if (d)
		closedir(d);
	CHECK(seen == 1);
	CHECK(unlink(q) == 0);

	printf("memtest: %d failures\n", fails);
	return fails;
}
