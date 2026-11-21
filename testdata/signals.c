// libc: musl
/* Linux signal semantics, one check per line: "<name> ok" or "<name> FAIL".
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

static void t_sigsuspend_child(void) {
	reset();
	handle_info(SIGCHLD, 0);
	block(SIGCHLD, SIG_BLOCK);
	pid_t c = fork();
	if (c == 0)
		_exit(3);
	sigset_t none;
	sigemptyset(&none);
	while (!hits)
		sigsuspend(&none);
	sigset_t cur;
	sigprocmask(SIG_BLOCK, NULL, &cur);
	int masked = sigismember(&cur, SIGCHLD);
	int st;
	pid_t w = waitpid(c, &st, 0);
	check("sigchld-sigsuspend", last == SIGCHLD && code == CLD_EXITED && pid_from == c && masked);
	check("wait-status", w == c && WIFEXITED(st) && WEXITSTATUS(st) == 3);
	block(SIGCHLD, SIG_UNBLOCK);
	signal(SIGCHLD, SIG_DFL);
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

static void t_restart(int restart) {
	int p[2];
	pipe(p);
	reset();
	handle(SIGALRM, on_sig, restart ? SA_RESTART : 0);
	pid_t c = fork();
	if (c == 0) {
		struct timespec ts = {0, 300 * 1000 * 1000};
		nanosleep(&ts, NULL);
		write(p[1], "x", 1);
		_exit(0);
	}
	close(p[1]);
	struct itimerval it = {{0, 0}, {0, 100 * 1000}};
	setitimer(ITIMER_REAL, &it, NULL);
	char b;
	ssize_t n = read(p[0], &b, 1);
	int e = errno;
	waitpid(c, NULL, 0);
	close(p[0]);
	if (restart)
		check("sa-restart-read", n == 1 && b == 'x' && hits == 1);
	else
		check("eintr-read", n == -1 && e == EINTR && hits == 1);
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

static void t_kill_child(void) {
	pid_t c = fork();
	if (c == 0) {
		for (;;)
			pause();
	}
	kill(c, SIGTERM);
	int st;
	pid_t w = waitpid(c, &st, 0);
	check("kill-child-term", w == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
	c = fork();
	if (c == 0) {
		for (volatile int i = 0;; i++)
			;
	}
	kill(c, SIGKILL);
	w = waitpid(c, &st, 0);
	check("kill-child-spin", w == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
}

/* A CLONE_VM child (it runs on its parent's stub until it execs) that dies of
   a pending signal's default action reports the signal, not an exit with
   128+sig. */
static int vm_die(void *arg) {
	(void)arg;
	sigset_t term;
	sigemptyset(&term);
	sigaddset(&term, SIGTERM);
	kill(getpid(), SIGTERM);
	sigprocmask(SIG_UNBLOCK, &term, NULL);
	return 1;
}

static void t_vm_die(void) {
	static char stack[64 << 10];
	sigset_t term, old;
	sigemptyset(&term);
	sigaddset(&term, SIGTERM);
	sigprocmask(SIG_BLOCK, &term, &old);
	pid_t c = clone(vm_die, stack + sizeof stack, CLONE_VM | SIGCHLD, NULL);
	sigprocmask(SIG_SETMASK, &old, NULL);
	int st;
	pid_t w = waitpid(c, &st, 0);
	check("vm-die-term", c > 0 && w == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
}

/* termed waits up to 2 s for child c to die of SIGTERM, killing it if not. */
static int termed(pid_t c) {
	int st;
	for (int i = 0; i < 200; i++) {
		if (waitpid(c, &st, WNOHANG) == c)
			return WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM;
		usleep(10000);
	}
	kill(c, SIGKILL);
	waitpid(c, &st, 0);
	return 0;
}

/* kill(-pgid) reaches the group, not the descendants of its number. */
static void t_kill_pgrp(void) {
	pid_t a = fork();
	if (a == 0) {
		setpgid(0, 0);
		pause();
		_exit(0);
	}
	setpgid(a, a);
	pid_t b = fork();
	if (b == 0) {
		pause();
		_exit(0);
	}
	pid_t a2 = fork(); /* a second member of a's group, not a's child */
	if (a2 == 0) {
		setpgid(0, a);
		pause();
		_exit(0);
	}
	setpgid(a2, a);
	int ok = kill(-a, SIGTERM) == 0;
	ok = termed(a) && ok;
	ok = termed(a2) && ok;
	int sb;
	ok = ok && waitpid(b, &sb, WNOHANG) == 0; /* b, in our group, is untouched */
	kill(b, SIGKILL);
	waitpid(b, &sb, 0);
	check("kill-pgrp", ok && kill(-a, 0) == -1 && errno == ESRCH);
}

static void t_sigpipe(void) {
	int p[2];
	pipe(p);
	close(p[0]);
	signal(SIGPIPE, SIG_IGN);
	ssize_t n = write(p[1], "x", 1);
	check("epipe-ignored", n == -1 && errno == EPIPE);
	signal(SIGPIPE, SIG_DFL);
	pid_t c = fork();
	if (c == 0) {
		write(p[1], "x", 1);
		_exit(0);
	}
	int st;
	waitpid(c, &st, 0);
	check("sigpipe-default", WIFSIGNALED(st) && WTERMSIG(st) == SIGPIPE);
	close(p[1]);
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

int main(void) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	t_handler();
	t_mask();
	t_nested();
	t_ppoll();
	t_sigsuspend_child();
	t_kill_pgrp();
	t_alarm();
	t_altstack();
	t_restart(1);
	t_restart(0);
	t_fault();
	t_timer();
	t_sigtimedwait();
	t_kill_child();
	t_vm_die();
	t_sigpipe();
	t_fp();
	t_threads();
	printf("done fails=%d\n", fails);
	return fails != 0;
}
