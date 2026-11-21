// mmapplace: mappings a program leaves unplaced go where Linux puts them:
// top-down below a base drawn anew at each execve (fixed under
// ADDR_NO_RANDOMIZE), a program with no interpreter at the top, a freed gap
// used again, a free hint honoured, a private anonymous mapping a whole number
// of huge pages long huge-page aligned, MAP_32BIT under 2 GiB, and with an
// unlimited stack bottom-up where Linux makes that the legacy layout (arm64,
// not x86-64); mremap grows in place when it can, and the break moves down.
// Build it static-pie.
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

#define MB (1UL << 20)

static char *map(void *hint, size_t n, int flags) {
	return mmap(hint, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
}

// report writes where two consecutive mmaps land and where the program is,
// for the parent.
static int report(void) {
	unsigned long w[3] = {(unsigned long)map(0, MB, 0), (unsigned long)map(0, MB, 0), (unsigned long)&report};
	return write(1, w, sizeof w) != sizeof w;
}

// placed runs report in a fresh exec, with ADDR_NO_RANDOMIZE when norand and
// an unlimited stack when unlimited.
static int placed(unsigned long w[3], int norand, int unlimited) {
	int p[2];
	if (pipe(p) != 0)
		return 0;
	pid_t c = fork();
	if (c == 0) {
		if (norand)
			personality(ADDR_NO_RANDOMIZE);
		if (unlimited) {
			struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
			setrlimit(RLIMIT_STACK, &r);
		}
		dup2(p[1], 1);
		execl("/proc/self/exe", "mmapplace", "report", (char *)0);
		_exit(99);
	}
	close(p[1]);
	ssize_t n = read(p[0], w, 3 * sizeof w[0]);
	close(p[0]);
	waitpid(c, 0, 0);
	return n == 3 * (ssize_t)sizeof w[0];
}

int main(int argc, char **argv) {
	if (argc > 1 && strcmp(argv[1], "report") == 0)
		return report();
	long pg = sysconf(_SC_PAGESIZE);

	// The stack is where Linux's is: within its random reach below the top of
	// the address space (STACK_TOP less STACK_RND_MASK pages), and the
	// mappings top-down below it.
	unsigned long sp = (unsigned long)&pg;
#ifdef __x86_64__
	// STACK_TOP is the task size, 0x7ffffffff000 unless the system keeps the
	// top of the space (Rosetta does): the end of what a fixed mapping may
	// reach, beyond which it fails with ENOMEM.
	unsigned long stop = 0x7ffffffff000UL, reach = 1UL << 34;
	for (;;) {
		void *q = mmap((void *)(stop - pg), pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
		if (q != MAP_FAILED)
			munmap(q, pg);
		if (q != MAP_FAILED || errno != ENOMEM || stop <= sp)
			break;
		stop -= 1UL << 30;
	}
#else
	// STACK_TOP is the task size, one of those an arm64 kernel offers with
	// the page size it runs: the smallest above the stack.
	unsigned long reach = 1UL << 30, stop = 0;
	static const int va4k[] = {39, 48, 0}, va16k[] = {36, 47, 48, 0}, va64k[] = {42, 48, 52, 0};
	const int *va = pg == 4096 ? va4k : pg == 16384 ? va16k : va64k;
	for (; *va && !stop; va++)
		if (sp < 1UL << *va)
			stop = 1UL << *va;
#endif
	CHECK(sp < stop && sp > stop - reach - 64 * MB, "stack at %#lx, not within %#lx below %#lx", sp, reach, stop);
	char *first = map(0, MB, 0);
	CHECK((unsigned long)first < sp && (unsigned long)first > stop / 2, "first mapping %p, the stack at %#lx", first, sp);
	munmap(first, MB);

	// Top-down, and a freed gap is used again.
	char *a = map(0, MB, 0), *b = map(0, MB, 0);
	CHECK(b == a - MB, "second mapping %p not right below the first %p", b, a);
	munmap(b, MB);
	char *c = map(0, MB, 0);
	CHECK(c == b, "freed gap %p not used again (got %p)", b, c);

	// A free hint is honoured; a taken one is not, and nothing is clobbered.
	char *h = a - 64 * MB;
	CHECK(map(h, MB, 0) == h, "free hint %p not honoured", h);
	char *t = map(a, MB, 0);
	CHECK(t != a && (t + MB <= a || t >= a + MB), "taken hint %p gave %p", a, t);

	// A private anonymous mapping a whole number of huge pages long is
	// huge-page aligned: a PMD's worth, a page of page table entries.
	size_t huge = pg * (pg / 8);
	char *g = map(0, 2 * huge, 0);
	CHECK(((uintptr_t)g & (huge - 1)) == 0, "%zu MiB mapping at %p not %zu MiB aligned", 2 * huge / MB, g, huge / MB);

#ifdef __x86_64__
	char *l = map(0, MB, MAP_32BIT);
	CHECK(l != MAP_FAILED && (uintptr_t)l + MB <= 0x80000000UL, "MAP_32BIT mapping at %p", l);
#endif

	// mremap grows in place when the pages above are free.
	char *r = map(0, 2 * MB, 0);
	munmap(r + MB, MB);
	char *rr = mremap(r, MB, 2 * MB, MREMAP_MAYMOVE);
	CHECK(rr == r, "growth into a free range moved %p to %p", r, rr);
	map(r + 2 * MB, MB, MAP_FIXED_NOREPLACE); // taken already, or now
	char *mv = mremap(r, 2 * MB, 3 * MB, MREMAP_MAYMOVE);
	CHECK(mv != MAP_FAILED && mv != r, "growth into a taken range did not move (%p)", mv);

	// The break moves down.
	char *top = sbrk(0);
	CHECK(sbrk(16 * pg) == top && sbrk(0) == top + 16 * pg, "brk up");
	CHECK(sbrk(-8 * pg) == top + 16 * pg && sbrk(0) == top + 8 * pg, "brk down to %p, at %p", top + 8 * pg, sbrk(0));

	// Anew at each execve, the same under ADDR_NO_RANDOMIZE, bottom-up with an
	// unlimited stack.
	unsigned long x[3], y[3];
	CHECK(placed(x, 0, 0) && placed(y, 0, 0) && x[0] != y[0], "mmap base the same after two execs: %#lx", x[0]);
	CHECK(x[2] > x[0] && x[2] - x[0] < 64 * MB, "program at %#lx, not at the top of the mmap area (%#lx)", x[2], x[0]);
	CHECK(placed(x, 1, 0) && placed(y, 1, 0) && x[0] == y[0] && x[2] == y[2], "unrandomized base %#lx then %#lx", x[0], y[0]);
	CHECK(x[1] == x[0] - MB, "exec'd top-down");
#ifdef __x86_64__
	CHECK(placed(x, 0, 1) && x[1] == x[0] - MB, "unlimited stack not top-down: %#lx then %#lx", x[0], x[1]);
#else
	CHECK(placed(x, 0, 1) && x[1] == x[0] + MB, "unlimited stack not bottom-up: %#lx then %#lx", x[0], x[1]);
#endif

	printf("mmapplace fails=%d\n", fails);
	return fails != 0;
}
