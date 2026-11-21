// seccomp_kill.c — SECCOMP_RET_KILL_PROCESS ends the process with SIGSYS even
// when the guest has a SIGSYS handler installed and SIGSYS blocked: the kill
// is not a catchable signal.
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static void h(int s) { (void)s; _exit(7); }
int main(void) {
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {.len = 4, .filter = f};
	pid_t k = fork();
	if (k == 0) {
		signal(SIGSYS, h);
		sigset_t s; sigemptyset(&s); sigaddset(&s, SIGSYS); sigprocmask(SIG_BLOCK, &s, 0);
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
		syscall(__NR_getuid);
		_exit(3);
	}
	int st; waitpid(k, &st, 0);
	if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGSYS) { printf("FAIL status %#x\n", st); return 1; }
	printf("SECKILL-OK\n");
	return 0;
}
