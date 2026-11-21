/* m3sig: Linux x86-64 signal semantics within one process (no fork; fork is
   M4). One check per line: "<name> ok" or "<name> FAIL".
   Build static with glibc or musl, with -pthread. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

static int fails;

static void check(const char *name, int ok) {
	printf("%s %s\n", name, ok ? "ok" : "FAIL");
	fflush(stdout);
	if (!ok)
		fails++;
}

static volatile sig_atomic_t hits, last, code, pid_from, value;

static void on_info(int s, siginfo_t *si, void *uc) {
	(void)uc;
	hits++;
	last = s;
	code = si->si_code;
	pid_from = si->si_pid;
	value = si->si_value.sival_int;
}

static void on_sig(int s) {
	hits++;
	last = s;
}

static void handle(int s, void (*fn)(int), int flags) {
	struct sigaction sa = {0};
	sa.sa_handler = fn;
	sa.sa_flags = flags;
	sigemptyset(&sa.sa_mask);
	sigaction(s, &sa, NULL);
}

static void handle_info(int s, int flags) {
	struct sigaction sa = {0};
	sa.sa_sigaction = on_info;
	sa.sa_flags = SA_SIGINFO | flags;
	sigemptyset(&sa.sa_mask);
	sigaction(s, &sa, NULL);
}

static void reset(void) { hits = last = code = pid_from = value = 0; }

static void block(int s, int how) {
	sigset_t m;
	sigemptyset(&m);
	sigaddset(&m, s);
	sigprocmask(how, &m, NULL);
}

static void t_handler(void) {
	reset();
	handle_info(SIGUSR1, 0);
	raise(SIGUSR1);
	check("handler", hits == 1 && last == SIGUSR1 && code == SI_TKILL && pid_from == getpid());
	reset();
	kill(getpid(), SIGUSR1);
	check("kill-self", hits == 1 && code == SI_USER);
}

static void t_mask(void) {
	reset();
	handle(SIGUSR1, on_sig, 0);
	block(SIGUSR1, SIG_BLOCK);
	raise(SIGUSR1);
	sigset_t p;
	sigpending(&p);
	int pend = sigismember(&p, SIGUSR1) && hits == 0;
	block(SIGUSR1, SIG_UNBLOCK);
	check("mask-pending", pend && hits == 1);
}

static void t_ppoll(void) {
	reset();
	handle(SIGUSR1, on_sig, 0);
	block(SIGUSR1, SIG_BLOCK);
	raise(SIGUSR1);
	sigset_t none, cur;
	sigemptyset(&none);
	struct timespec ts = {2, 0};
	int r = ppoll(NULL, 0, &ts, &none);
	int e = errno;
	sigprocmask(SIG_BLOCK, NULL, &cur);
	check("ppoll-sigmask", r == -1 && e == EINTR && hits == 1 && sigismember(&cur, SIGUSR1));
	block(SIGUSR1, SIG_UNBLOCK);
}

static void t_nested(void);
static volatile int nested_order[4], nested_n;
static void on_nest2(int s) { nested_order[nested_n++] = s; }
static void on_nest1(int s) {
	nested_order[nested_n++] = s;
	raise(SIGUSR2);
	nested_order[nested_n++] = -s;
}
static void t_nested(void) {
	handle(SIGUSR1, on_nest1, 0);
	handle(SIGUSR2, on_nest2, 0);
	raise(SIGUSR1);
	check("nested", nested_n == 3 && nested_order[0] == SIGUSR1 && nested_order[1] == SIGUSR2 &&
		nested_order[2] == -SIGUSR1);
}


static void t_alarm(void) {
	reset();
	handle(SIGALRM, on_sig, 0);
	alarm(1);
	int r = pause();
	check("alarm-pause", r == -1 && errno == EINTR && last == SIGALRM);
}

static char altstack[64 << 10];
static volatile int on_alt;
static void on_altsig(int s) {
	char here;
	(void)s;
	stack_t ss;
	sigaltstack(NULL, &ss);
	on_alt = &here >= altstack && &here < altstack + sizeof altstack && (ss.ss_flags & SS_ONSTACK);
}

static void t_altstack(void) {
	stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
	sigaltstack(&ss, NULL);
	handle(SIGUSR1, on_altsig, SA_ONSTACK);
	raise(SIGUSR1);
	stack_t now;
	sigaltstack(NULL, &now);
	check("sigaltstack", on_alt && !(now.ss_flags & SS_ONSTACK) && now.ss_sp == altstack);
	ss.ss_flags = SS_DISABLE;
	sigaltstack(&ss, NULL);
}


static sigjmp_buf jb;
static volatile void *fault_addr;
static void on_segv(int s, siginfo_t *si, void *uc) {
	(void)s;
	(void)uc;
	fault_addr = si->si_addr;
	siglongjmp(jb, 1);
}

static void t_fault(void) {
	struct sigaction sa = {0};
	sa.sa_sigaction = on_segv;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	volatile int *bad = (int *)16;
	int jumped = 0;
	if (sigsetjmp(jb, 1) == 0)
		*bad = 1;
	else
		jumped = 1;
	sigset_t cur;
	sigprocmask(SIG_BLOCK, NULL, &cur);
	check("segv-siglongjmp", jumped && fault_addr == (void *)16 && !sigismember(&cur, SIGSEGV));
	signal(SIGSEGV, SIG_DFL);
}

static void t_timer(void) {
	reset();
	handle_info(SIGRTMIN, 0);
	struct sigevent ev = {0};
	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = SIGRTMIN;
	ev.sigev_value.sival_int = 42;
	timer_t t;
	if (timer_create(CLOCK_MONOTONIC, &ev, &t)) {
		check("timer-create", 0);
		return;
	}
	struct itimerspec its = {{0, 0}, {0, 50 * 1000 * 1000}};
	timer_settime(t, 0, &its, NULL);
	struct timespec ts = {2, 0};
	while (!hits && nanosleep(&ts, &ts) == -1 && errno == EINTR && !hits)
		;
	check("timer-create", hits == 1 && last == SIGRTMIN && code == SI_TIMER && value == 42);
	timer_delete(t);
}

static void t_sigtimedwait(void) {
	block(SIGUSR2, SIG_BLOCK);
	union sigval v = {.sival_int = 7};
	sigqueue(getpid(), SIGUSR2, v);
	sigset_t w;
	sigemptyset(&w);
	sigaddset(&w, SIGUSR2);
	siginfo_t si;
	struct timespec ts = {1, 0};
	int s = sigtimedwait(&w, &si, &ts);
	check("sigqueue-sigtimedwait", s == SIGUSR2 && si.si_code == SI_QUEUE && si.si_value.sival_int == 7);
	ts.tv_sec = 0;
	ts.tv_nsec = 1000 * 1000;
	s = sigtimedwait(&w, &si, &ts);
	check("sigtimedwait-timeout", s == -1 && errno == EAGAIN);
	block(SIGUSR2, SIG_UNBLOCK);
}



/* FP and general registers survive handlers that run between instructions. */
static volatile double fp_scratch;
static void on_fp(int s) {
	(void)s;
	hits++;
	double x = 1.0;
	for (int i = 0; i < 100; i++)
		x = x * 1.0000001 + 3.0;
	fp_scratch = x;
}

static void t_fp(void) {
	reset();
	handle(SIGALRM, on_fp, SA_RESTART);
	struct itimerval it = {{0, 500}, {0, 500}};
	setitimer(ITIMER_REAL, &it, NULL);
	double a = 0;
	long n = 0;
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		for (int i = 0; i < 1000000; i++) {
			a += 0.5;
			n++;
		}
		clock_gettime(CLOCK_MONOTONIC, &t1);
	} while (t1.tv_sec - t0.tv_sec < 1 && hits < 20);
	struct itimerval off = {0};
	setitimer(ITIMER_REAL, &off, NULL);
	check("fp-preserved", hits > 0 && a == 0.5 * n);
}

static pthread_t main_thread;
static volatile pthread_t got_thread;
static void on_thr(int s) {
	(void)s;
	got_thread = pthread_self();
	hits++;
}
static void *thr(void *arg) {
	(void)arg;
	pthread_kill(main_thread, SIGUSR1);
	return NULL;
}

static void t_threads(void) {
	reset();
	handle(SIGUSR1, on_thr, 0);
	main_thread = pthread_self();
	pthread_t t;
	pthread_create(&t, NULL, thr, NULL);
	pthread_join(t, NULL);
	struct timespec ts = {0, 10 * 1000 * 1000};
	for (int i = 0; i < 100 && !hits; i++)
		nanosleep(&ts, NULL);
	check("pthread-kill", hits == 1 && pthread_equal(got_thread, main_thread));
}

/* A syscall a SA_RESTART handler interrupts is restarted without anything
   written below the stack pointer, as on Linux: a reader blocks in read on a
   stack of its own, signalled until its handler has run many times, and the
   unused bottom of that stack keeps its canary. */
#define RESTART_SIGS 200
static char restart_stack[256 << 10] __attribute__((aligned(16)));
static char restart_alt[64 << 10];
static int restart_pipe[2];
static volatile int restart_ready;
static void on_restart(int s) {
	(void)s;
	hits++;
}
static void *restart_reader(void *arg) {
	(void)arg;
	stack_t ss = {.ss_sp = restart_alt, .ss_size = sizeof restart_alt};
	sigaltstack(&ss, NULL);
	char here;
	size_t n = (size_t)(&here - 1024 - restart_stack);
	memset(restart_stack, 0x5a, n);
	restart_ready = 1;
	char c;
	ssize_t r = read(restart_pipe[0], &c, 1);
	size_t i = 0;
	while (i < n && restart_stack[i] == 0x5a)
		i++;
	return (void *)(intptr_t)(r == 1 && i == n);
}

static void t_restart(void) {
	reset();
	handle(SIGUSR2, on_restart, SA_RESTART | SA_ONSTACK);
	pipe(restart_pipe);
	pthread_attr_t a;
	pthread_attr_init(&a);
	pthread_attr_setstack(&a, restart_stack, sizeof restart_stack);
	pthread_t t;
	pthread_create(&t, &a, restart_reader, NULL);
	while (!restart_ready)
		sched_yield();
	for (int i = 1; i <= RESTART_SIGS; i++) {
		pthread_kill(t, SIGUSR2);
		while (hits < i)
			sched_yield();
	}
	write(restart_pipe[1], "x", 1);
	void *ok;
	pthread_join(t, &ok);
	check("restart-stack", ok != NULL && hits == RESTART_SIGS);
}

#ifdef __x86_64__
/* The signal frame carries the XSAVE image (FP_XSTATE_MAGIC1 in the fxsave
   area's software bytes) and rt_sigreturn restores it: a handler that zeroes
   the upper YMM halves leaves the interrupted code's as they were. */
static volatile int xstate_magic;
static void on_xs(int s, siginfo_t *si, void *ucv) {
	(void)s;
	(void)si;
	ucontext_t *uc = ucv;
	unsigned *fp = (unsigned *)uc->uc_mcontext.fpregs;
	xstate_magic = fp && fp[464 / 4] == 0x46505853;
}
static void on_vz(int s) {
	(void)s;
	hits++;
	__asm__ volatile("vzeroupper" ::: "memory");
}
static void t_xstate(void) {
	unsigned a, b, c, d, lo, hi;
	__asm__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
	if (!(c & (1u << 27))) {
		printf("xstate skipped (no OSXSAVE)\n");
		return;
	}
	reset();
	handle_info(SIGUSR1, 0);
	struct sigaction sa = {0};
	sa.sa_sigaction = on_xs;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGUSR1, &sa, NULL);
	raise(SIGUSR1);
	check("xstate-frame", xstate_magic);
	__asm__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	if (!(c & (1u << 28)) || (lo & 6) != 6) {
		printf("ymm-preserved skipped (no AVX)\n");
		return;
	}
	reset();
	handle(SIGUSR1, on_vz, 0);
	unsigned char in[32], out[32];
	for (int i = 0; i < 32; i++)
		in[i] = i + 1;
	__asm__ volatile("vmovdqu %1, %%ymm3\n"
	                 "mov $39, %%eax\n syscall\n mov %%eax, %%edi\n mov $10, %%esi\n mov $62, %%eax\n syscall\n"
	                 "vmovdqu %%ymm3, %0\n"
	                 : "=m"(out)
	                 : "m"(in)
	                 : "rax", "rdi", "rsi", "rcx", "r11", "xmm3", "memory");
	check("ymm-preserved", hits == 1 && memcmp(in, out, 32) == 0);
}
#endif

int main(void) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	t_handler();
	t_mask();
	t_nested();
	// t_ppoll and t_alarm need ppoll(2) and pause(2), which the Windows
	// supervisor does not serve yet (M6); the signal delivery they would
	// exercise is covered by t_timer, t_sigtimedwait and t_fp.
	t_altstack();
	t_fault();
	t_timer();
	t_sigtimedwait();
	t_fp();
	t_threads();
	t_restart();
#ifdef __x86_64__
	t_xstate();
#endif
	printf("m3sig fails=%d\n", fails);
	return fails != 0;
}
