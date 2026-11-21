// libc: musl
// M4 process tests: fork, execve, posix_spawn, system, waitpid, process
// groups, fork from a multithreaded parent, MAP_SHARED memory and a shared
// futex across fork, and fork+exec timing. One case per argv[1]; each prints
// "<case> OK" on success.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define CHECK(c)                                                              \
	do {                                                                  \
		if (!(c)) {                                                   \
			printf("FAIL %s:%d: %s (errno %d)\n", __FILE__, __LINE__, #c, errno); \
			exit(1);                                              \
		}                                                             \
	} while (0)

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void msleep(int ms)
{
	struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
	nanosleep(&ts, 0);
}

static int t_fork(void)
{
	int st;
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		msleep(200);
		_exit(7);
	}
	CHECK(waitpid(p, &st, WNOHANG) == 0);
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7);
	CHECK(waitpid(-1, &st, WNOHANG) == -1 && errno == ECHILD);

	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		for (;;)
			msleep(1000);
	}
	msleep(100);
	CHECK(kill(p, SIGTERM) == 0);
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);

	// The child's copy of memory is its own.
	static volatile int v = 1;
	p = fork();
	if (p == 0) {
		v = 2;
		_exit(v);
	}
	CHECK(waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 2 && v == 1);
	printf("fork OK\n");
	return 0;
}

static int t_exec(void)
{
	int fd[2], st;
	CHECK(pipe(fd) == 0);
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		dup2(fd[1], 1);
		close(fd[0]);
		close(fd[1]);
		char *argv[] = {"cat", "/etc/os-release", 0};
		execve("/bin/cat", argv, environ);
		_exit(127);
	}
	close(fd[1]);
	char buf[4096];
	int n = 0, k;
	while ((k = read(fd[0], buf + n, sizeof buf - 1 - n)) > 0)
		n += k;
	buf[n] = 0;
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(strstr(buf, "Alpine Linux") != 0);

	// A failed execve returns to the child.
	p = fork();
	if (p == 0) {
		char *argv[] = {"nope", 0};
		execve("/nope", argv, environ);
		_exit(errno == ENOENT ? 9 : 1);
	}
	CHECK(waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 9);
	printf("exec OK\n");
	return 0;
}

static int t_spawn(void)
{
	int st;
	pid_t p;
	char *argv[] = {"sh", "-c", "exit 6", 0};
	CHECK(posix_spawn(&p, "/bin/sh", 0, 0, argv, environ) == 0);
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 6);
	char *bad[] = {"x", 0};
	CHECK(posix_spawn(&p, "/nope", 0, 0, bad, environ) == ENOENT);
	st = system("echo from system; exit 3");
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 3);
	fflush(stdout);

	// vfork: the child runs on our stack until it execs.
	volatile int seen = 0;
	p = vfork();
	if (p == 0) {
		seen = 1;
		char *a[] = {"true", 0};
		execve("/bin/true", a, environ);
		_exit(127);
	}
	CHECK(p > 0 && seen == 1);
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	p = vfork();
	if (p == 0)
		_exit(4);
	CHECK(waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 4);
	printf("spawn OK\n");
	return 0;
}

static int t_pgrp(void)
{
	pid_t kids[3];
	pid_t pg = 0;
	for (int i = 0; i < 3; i++) {
		pid_t p = fork();
		CHECK(p >= 0);
		if (p == 0) {
			for (;;)
				msleep(1000);
		}
		if (i == 0)
			pg = p;
		CHECK(setpgid(p, pg) == 0);
		kids[i] = p;
	}
	CHECK(getpgid(kids[2]) == pg);
	msleep(100);
	CHECK(kill(-pg, SIGTERM) == 0);
	for (int i = 0; i < 3; i++) {
		int st;
		CHECK(waitpid(kids[i], &st, 0) == kids[i]);
		CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
	}
	printf("pgrp OK\n");
	return 0;
}

static volatile int spin_stop;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;

static void *spinner(void *arg)
{
	while (!spin_stop) {
		pthread_mutex_lock(&mu);
		counter++;
		pthread_mutex_unlock(&mu);
	}
	return 0;
}

static int t_mt(void)
{
	pthread_t th[3];
	for (int i = 0; i < 3; i++)
		CHECK(pthread_create(&th[i], 0, spinner, 0) == 0);
	msleep(50);
	for (int round = 0; round < 5; round++) {
		pid_t p = fork();
		CHECK(p >= 0);
		if (p == 0) {
			// Only this thread was copied: the threads' count, then
			// the lock (free, or held by a thread that no longer exists:
			// musl's fork takes it around the clone, as POSIX asks).
			char buf[1024];
			int fd = open("/proc/self/status", O_RDONLY);
			int n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
			if (n <= 0)
				_exit(20);
			buf[n] = 0;
			char *t = strstr(buf, "Threads:");
			if (!t || atoi(t + 8) != 1)
				_exit(21);
			void *m = malloc(1 << 20);
			memset(m, 1, 1 << 20);
			free(m);
			_exit(0);
		}
		int st;
		CHECK(waitpid(p, &st, 0) == p);
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
			printf("FAIL child status %#x\n", st);
			return 1;
		}
	}
	spin_stop = 1;
	for (int i = 0; i < 3; i++)
		pthread_join(th[i], 0);
	CHECK(counter > 0);
	printf("mt OK\n");
	return 0;
}

static int t_shm(void)
{
	struct shared {
		sem_t go, done;
		int val;
	} *s = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK(s != MAP_FAILED);
	CHECK(sem_init(&s->go, 1, 0) == 0 && sem_init(&s->done, 1, 0) == 0);
	s->val = 1;
	pid_t p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		if (sem_wait(&s->go) != 0)
			_exit(2);
		s->val = s->val * 10 + 2;
		sem_post(&s->done);
		_exit(0);
	}
	msleep(100); // the child is parked in a futex wait by now
	s->val = s->val * 10 + 1;
	CHECK(sem_post(&s->go) == 0);
	CHECK(sem_wait(&s->done) == 0);
	int st;
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(s->val == 112);
	printf("shm OK\n");
	return 0;
}

static int t_bench(int n)
{
	char *argv[] = {"true", 0};
	double t0 = now_ms();
	for (int i = 0; i < n; i++) {
		pid_t p = fork();
		if (p == 0) {
			execve("/bin/true", argv, environ);
			_exit(127);
		}
		int st;
		CHECK(waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 0);
	}
	double t1 = now_ms();
	for (int i = 0; i < n; i++) {
		pid_t p;
		int st;
		CHECK(posix_spawn(&p, "/bin/true", 0, 0, argv, environ) == 0);
		CHECK(waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 0);
	}
	double t2 = now_ms();
	for (int i = 0; i < n; i++) {
		pid_t p = fork();
		if (p == 0)
			_exit(0);
		int st;
		CHECK(waitpid(p, &st, 0) == p);
	}
	double t3 = now_ms();
	printf("fork+exec x%d: %.0f ms (%.1f ms each)\n", n, t1 - t0, (t1 - t0) / n);
	printf("posix_spawn x%d: %.0f ms (%.1f ms each)\n", n, t2 - t1, (t2 - t1) / n);
	printf("fork+_exit x%d: %.0f ms (%.1f ms each)\n", n, t3 - t2, (t3 - t2) / n);
	printf("bench OK\n");
	return 0;
}

/* Death while blocked in the supervisor: a process's end must end every wait
 * it has there, at once. Each case gives 2 s; the alarm fails a hang instead
 * of stalling the run. */

/* awaitDeath waits for child c, which must die of sig within 2 s. */
static void awaitDeath(pid_t c, int sig)
{
	double t0 = now_ms();
	int st;
	CHECK(waitpid(c, &st, 0) == c);
	if (!WIFSIGNALED(st) || WTERMSIG(st) != sig) {
		printf("FAIL child status %#x (signalled %d sig %d, exited %d code %d), want signal %d\n",
		       st, WIFSIGNALED(st), WTERMSIG(st), WIFEXITED(st), WEXITSTATUS(st), sig);
		exit(1);
	}
	CHECK(now_ms() - t0 < 2000);
}

/* killread: SIGKILL ends a child blocked reading an empty pipe whose writer
 * stays open. */
static int t_killread(void)
{
	alarm(10);
	int p[2], ready[2];
	CHECK(pipe(p) == 0 && pipe(ready) == 0);
	pid_t c = fork();
	CHECK(c >= 0);
	if (c == 0) {
		char b;
		write(ready[1], "r", 1);
		read(p[0], &b, 1);
		_exit(0);
	}
	char b;
	CHECK(read(ready[0], &b, 1) == 1);
	usleep(300000); /* into the read */
	CHECK(kill(c, SIGKILL) == 0);
	awaitDeath(c, SIGKILL);
	printf("killread OK\n");
	return 0;
}

/* killwrite: SIGKILL ends a child blocked writing a full pipe nobody reads. */
static int t_killwrite(void)
{
	alarm(10);
	int p[2], ready[2];
	CHECK(pipe(p) == 0 && pipe(ready) == 0);
	pid_t c = fork();
	CHECK(c >= 0);
	if (c == 0) {
		static char buf[65536];
		write(ready[1], "r", 1);
		for (;;)
			write(p[1], buf, sizeof buf);
	}
	char b;
	CHECK(read(ready[0], &b, 1) == 1);
	usleep(300000); /* the pipe fills and the write blocks */
	CHECK(kill(c, SIGKILL) == 0);
	awaitDeath(c, SIGKILL);
	printf("killwrite OK\n");
	return 0;
}

/* The sibling thread of the abort cases: it holds ev[1], which the parent
 * reads to EOF, and blocks (in a pipe read, or asleep). */
static int sib_ev[2], sib_pipe[2], sib_sleeps;
static void *sibling(void *arg)
{
	(void)arg;
	char b;
	if (sib_sleeps)
		sleep(30);
	else
		read(sib_pipe[0], &b, 1);
	return 0;
}

/* abortBlocked: a child aborts with a sibling blocked; it must die of SIGABRT
 * within 2 s and its descriptors close with it (EOF on ev). */
static int abortBlocked(const char *name, int sleeps)
{
	alarm(10);
	sib_sleeps = sleeps;
	CHECK(pipe(sib_ev) == 0 && pipe(sib_pipe) == 0);
	pid_t c = fork();
	CHECK(c >= 0);
	if (c == 0) {
		close(sib_ev[0]);
		pthread_t t;
		pthread_create(&t, 0, sibling, 0);
		usleep(200000); /* the sibling blocks */
		abort();
	}
	close(sib_ev[1]);
	double t0 = now_ms();
	char b;
	CHECK(read(sib_ev[0], &b, 1) == 0);
	CHECK(now_ms() - t0 < 2500);
	awaitDeath(c, SIGABRT);
	printf("%s OK\n", name);
	return 0;
}

/* jit writes 1 MiB of functions into RWX memory, each returning its own
 * value, flushes it with __builtin___clear_cache (which steps by CTR_EL0's
 * line size on arm64), runs every one, then rewrites them all in place with
 * other values and does it again: stale instructions would return the old
 * ones. It reports the time the two flushes took. */
#define JIT_FNS (1 << 17)
static void jit_gen(unsigned char *m, unsigned base)
{
	for (unsigned i = 0; i < JIT_FNS; i++) {
		unsigned v = (base + i) & 0xffff;
#if defined(__aarch64__)
		unsigned *p = (unsigned *)(m + 8 * i);
		p[0] = 0x52800000 | v << 5; /* movz w0, #v */
		p[1] = 0xd65f03c0;          /* ret */
#else
		unsigned char *p = m + 8 * i;
		p[0] = 0xb8; /* mov eax, imm32 */
		memcpy(p + 1, &v, 4);
		p[5] = 0xc3; /* ret */
#endif
	}
}

static int jit_check(unsigned char *m, unsigned base)
{
	for (unsigned i = 0; i < JIT_FNS; i++) {
		unsigned (*f)(void) = (unsigned (*)(void))(m + 8 * i);
		if (f() != ((base + i) & 0xffff)) {
			printf("jit: function %u returned %u, want %u\n", i, f(), (base + i) & 0xffff);
			return 0;
		}
	}
	return 1;
}

static int t_jit(void)
{
	size_t n = 8 * JIT_FNS;
	unsigned char *m = mmap(0, n, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED) {
		perror("jit mmap");
		return 1;
	}
	double spent = 0;
	for (unsigned base = 1; base <= 2; base++) {
		jit_gen(m, base * 1000);
		double t0 = now_ms();
		__builtin___clear_cache((char *)m, (char *)m + n);
		spent += now_ms() - t0;
		if (!jit_check(m, base * 1000))
			return 1;
	}
	printf("jit OK flush %.2f ms\n", spent);
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, 0, _IONBF, 0);
	if (argc < 2)
		return 2;
	const char *c = argv[1];
	if (!strcmp(c, "fork"))
		return t_fork();
	if (!strcmp(c, "exec"))
		return t_exec();
	if (!strcmp(c, "spawn"))
		return t_spawn();
	if (!strcmp(c, "pgrp"))
		return t_pgrp();
	if (!strcmp(c, "mt"))
		return t_mt();
	if (!strcmp(c, "shm"))
		return t_shm();
	if (!strcmp(c, "killread"))
		return t_killread();
	if (!strcmp(c, "killwrite"))
		return t_killwrite();
	if (!strcmp(c, "abortpipe"))
		return abortBlocked("abortpipe", 0);
	if (!strcmp(c, "abortsleep"))
		return abortBlocked("abortsleep", 1);
	if (!strcmp(c, "jit"))
		return t_jit();
	if (!strcmp(c, "bench"))
		return t_bench(argc > 2 ? atoi(argv[2]) : 100);
	return 2;
}
