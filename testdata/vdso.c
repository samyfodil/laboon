// vdso: the guest has the kernel's vDSO, as a Linux process does: AT_SYSINFO_EHDR
// names an ELF image that /proc/self/maps lists as [vdso], the clocks read
// through it agree with the system calls, the clocks it leaves to the kernel
// (CPU time, another process's or thread's CPU clock) still work and are
// refused as Linux refuses them, sched_getcpu and getcpu
// name a CPU the thread may run on, pinned to one CPU that one, which a fork
// child keeps, a fork keeps the vDSO, and a program that unmapped it (the
// range then free), mapped over it or moved it execs with a fresh one.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static long long ns(struct timespec t) { return t.tv_sec * 1000000000LL + t.tv_nsec; }

// vdsoRange finds [vdso] in /proc/self/maps.
static int vdsoRange(unsigned long *lo, unsigned long *hi) {
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512];
	int found = 0;
	while (f && fgets(line, sizeof line, f))
		if (strstr(line, "[vdso]") && sscanf(line, "%lx-%lx", lo, hi) == 2)
			found = 1;
	if (f)
		fclose(f);
	return found;
}

static void clocks(void) {
	struct timespec a, b, s;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &a) == 0, "CLOCK_MONOTONIC");
	CHECK(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &s) == 0, "the clock_gettime call");
	CHECK(clock_gettime(CLOCK_MONOTONIC, &b) == 0 && ns(a) <= ns(s) && ns(s) <= ns(b), "the vDSO and the call disagree: %lld %lld %lld", ns(a), ns(s), ns(b));
	CHECK(clock_gettime(CLOCK_REALTIME, &a) == 0 && a.tv_sec - time(0) <= 1 && time(0) - a.tv_sec <= 1, "time() and CLOCK_REALTIME");
	CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &a) == 0 && ns(a) > 0, "CLOCK_PROCESS_CPUTIME_ID");
	CHECK(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &a) == 0 && ns(a) > 0, "CLOCK_THREAD_CPUTIME_ID");
}

#define THREAD_CLOCK(tid, which) ((~(clockid_t)(tid) << 3) | (which) | 4)
#define PROCESS_CLOCK(pid, which) ((~(clockid_t)(pid) << 3) | (which))

static int spun, gate[2];

static void *spinner(void *unused) {
	char c;
	for (volatile long i = 0; i < 30000000; i++)
		;
	__atomic_store_n(&spun, 1, __ATOMIC_SEQ_CST);
	return (void *)(long)read(gate[0], &c, 1);
}

static void cpuclocks(void) {
	struct timespec t, u;
	CHECK(clock_gettime(10, &t) == -1 && errno == EINVAL, "clock 10 is not EINVAL");
	CHECK(clock_gettime(12, &t) == -1 && errno == EINVAL, "clock 12 is not EINVAL");
	CHECK(clock_getres(12, &t) == -1 && errno == EINVAL, "clock_getres 12 is not EINVAL");
	CHECK(clock_getres(CLOCK_THREAD_CPUTIME_ID, &t) == 0 && ns(t) > 0, "clock_getres CLOCK_THREAD_CPUTIME_ID");
	clockid_t c;
	CHECK(clock_getcpuclockid(999999, &c) == ESRCH, "clock_getcpuclockid of no process is not ESRCH");
	CHECK(clock_gettime(PROCESS_CLOCK(0, 1), &u) == 0 && clock_gettime(PROCESS_CLOCK(0, 2), &t) == 0 && ns(u) <= ns(t), "user time %lld above the process's total %lld", ns(u), ns(t));
	CHECK(clock_gettime(PROCESS_CLOCK(getpid(), 2), &t) == 0 && ns(t) > 0, "this process's clock by pid");
	CHECK(clock_gettime(PROCESS_CLOCK(0, 3), &t) == -1 && errno == EINVAL, "clock type 3 is not EINVAL");

	pthread_t th;
	CHECK(pipe(gate) == 0, "pipe");
	CHECK(pthread_create(&th, 0, spinner, 0) == 0, "pthread_create");
	while (!__atomic_load_n(&spun, __ATOMIC_SEQ_CST))
		;
	clockid_t tc;
	CHECK(pthread_getcpuclockid(th, &tc) == 0 && clock_gettime(tc, &t) == 0 && ns(t) > 0, "another thread's CPU clock");
	CHECK(clock_gettime(THREAD_CLOCK(gettid(), 2), &u) == 0 && ns(u) > 0, "this thread's clock by tid");
	CHECK(clock_getres(tc, &u) == 0, "clock_getres of another thread's clock");
	CHECK(write(gate[1], "x", 1) == 1, "the go-ahead");
	pthread_join(th, 0);

	pid_t k = fork();
	if (k == 0) {
		char ch;
		_exit(read(gate[0], &ch, 1) != 1);
	}
	CHECK(clock_gettime(THREAD_CLOCK(k, 2), &t) == -1 && errno == EINVAL, "another process's thread clock is not EINVAL");
	CHECK(clock_gettime(PROCESS_CLOCK(k, 2), &t) == 0, "another process's clock by pid");
	CHECK(write(gate[1], "x", 1) == 1, "the go-ahead");
	waitpid(k, 0, 0);
	close(gate[0]);
	close(gate[1]);
}

static void cpu(void) {
	cpu_set_t set;
	CHECK(sched_getaffinity(0, sizeof set, &set) == 0, "sched_getaffinity");
	int c = sched_getcpu();
	CHECK(c >= 0 && CPU_ISSET(c, &set), "sched_getcpu %d is not in the affinity mask", c);
	unsigned sc = 0, node = 0;
	CHECK(syscall(SYS_getcpu, &sc, &node, 0) == 0 && CPU_ISSET(sc, &set), "getcpu %u is not in the affinity mask", sc);

	// Pinned to one CPU, the thread runs there, and a fork child is pinned too.
	int last = -1;
	for (int i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &set))
			last = i;
	cpu_set_t one, got;
	CPU_ZERO(&one);
	CPU_SET(last, &one);
	CHECK(sched_setaffinity(0, sizeof one, &one) == 0, "pinning to CPU %d", last);
	CHECK(sched_getaffinity(0, sizeof got, &got) == 0 && CPU_EQUAL(&got, &one), "the pinned mask");
	CHECK(sched_getcpu() == last, "pinned to CPU %d, sched_getcpu says %d", last, sched_getcpu());
	CHECK(syscall(SYS_getcpu, &sc, &node, 0) == 0 && sc == (unsigned)last, "pinned to CPU %d, getcpu says %u", last, sc);
	int p[2];
	CHECK(pipe(p) == 0, "pipe");
	pid_t k = fork();
	if (k == 0) {
		cpu_set_t kg;
		char ch;
		CHECK(sched_getaffinity(0, sizeof kg, &kg) == 0 && CPU_EQUAL(&kg, &one) && sched_getcpu() == last, "the fork child is not pinned as its parent was");
		fflush(stdout);
		CHECK(read(p[0], &ch, 1) == 1, "the parent's go-ahead");
		_exit(fails != 0);
	}
	CHECK(sched_getaffinity(k, sizeof got, &got) == 0 && CPU_EQUAL(&got, &one), "the fork child's mask, read by pid");
	CHECK(write(p[1], "x", 1) == 1, "the go-ahead");
	siginfo_t si;
	CHECK(waitid(P_PID, k, &si, WEXITED | WNOWAIT) == 0, "waiting for the child, leaving its zombie");
	CHECK(sched_getaffinity(k, sizeof got, &got) == 0 && CPU_EQUAL(&got, &one), "the zombie fork child's mask, read by pid");
	int st;
	waitpid(k, &st, 0);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the fork child is not pinned as its parent was");
	CHECK(sched_setaffinity(0, sizeof set, &set) == 0, "unpinning");
	cpu_set_t none;
	CPU_ZERO(&none);
	CHECK(sched_setaffinity(0, sizeof none, &none) == -1 && errno == EINVAL, "an empty mask");
	CHECK(sched_getaffinity(999999, sizeof got, &got) == -1 && errno == ESRCH, "no such thread");
}

int main(int argc, char **argv) {
	if (argc > 1 && strcmp(argv[1], "novdso") == 0) {
		unsigned long v = getauxval(AT_SYSINFO_EHDR), lo = 0, hi = 0;
		CHECK(v != 0 && vdsoRange(&lo, &hi) && lo == v, "after an unmap, the exec'd vDSO %#lx is not [vdso] at %#lx", v, lo);
		clocks();
		printf("novdso fails=%d\n", fails);
		return fails != 0;
	}
	unsigned long v = getauxval(AT_SYSINFO_EHDR), lo = 0, hi = 0;
	CHECK(v != 0 && memcmp((void *)v, "\177ELF", 4) == 0, "AT_SYSINFO_EHDR %#lx is not an ELF image", v);
	CHECK(vdsoRange(&lo, &hi) && lo == v, "/proc/self/maps lists [vdso] at %#lx, AT_SYSINFO_EHDR is %#lx", lo, v);
	clocks();
	cpuclocks();
	cpu();

	pid_t c = fork();
	if (c == 0) {
		clocks();
		for (volatile long i = 0; i < 10000000; i++)
			;
		fflush(stdout);
		_exit(fails != 0);
	}
	clockid_t cc;
	struct timespec t;
	CHECK(clock_getcpuclockid(c, &cc) == 0 && clock_gettime(cc, &t) == 0, "another process's CPU clock");
	int st;
	waitpid(c, &st, 0);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the clocks in a fork");

	static const char *how[] = {"unmapping", "mapping over", "moving"};
	for (int h = 0; h < 3; h++) {
		c = fork();
		if (c == 0) {
			if (h == 0) {
				if (munmap((void *)lo, hi - lo) != 0)
					_exit(96);
				if (mmap((void *)lo, hi - lo, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) != (void *)lo)
					_exit(98); // the range is free once the vDSO is unmapped
			} else if (h == 1) {
				if (mmap((void *)lo, hi - lo, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != (void *)lo)
					_exit(97);
			} else {
				// Moved (as CRIU moves it), it is [vdso] where it went; nothing
				// calls it there, its [vvar] left behind.
				void *to = mmap(0, hi - lo, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				unsigned long nlo, nhi;
				if (to == MAP_FAILED || mremap((void *)lo, hi - lo, hi - lo, MREMAP_MAYMOVE | MREMAP_FIXED, to) != to)
					_exit(95);
				if (!vdsoRange(&nlo, &nhi) || nlo != (unsigned long)to)
					_exit(94);
			}
			execl("/proc/self/exe", "vdso", "novdso", (char *)0);
			_exit(99);
		}
		waitpid(c, &st, 0);
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "an exec after %s the vDSO: status %#x", how[h], st);
	}

	printf("vdso fails=%d\n", fails);
	return fails != 0;
}
