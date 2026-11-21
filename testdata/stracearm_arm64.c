// stracearm_arm64.c -- a minimal arm64 ptrace tracer: it traces a child, steps it to
// a distinctive syscall (write to fd 42), and reads the child's registers with
// PTRACE_GETREGSET(NT_PRSTATUS), checking the syscall number (write = 64) and
// its first argument (the fd) came through. This exercises the syscall-entry
// stop, register publishing and PTRACE_CONT without single-step or breakpoints
// (which arm64 cannot do from EL0). Prints STRACE-OK on success.
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <elf.h>

// The arm64 NT_PRSTATUS register set: x0..x30, sp, pc, pstate.
struct a64regs {
    unsigned long long regs[31];
    unsigned long long sp, pc, pstate;
};

#define NR_write 64
#define FD 42

int main(void) {
    pid_t c = fork();
    if (c == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP); // sync: the tracer attaches at this stop
        write(FD, "x", 1);       // the distinctive syscall to catch
        _exit(0);
    }
    int st;
    if (waitpid(c, &st, 0) < 0 || !WIFSTOPPED(st)) { printf("FAIL initial stop\n"); return 1; }
    ptrace(PTRACE_SETOPTIONS, c, 0, PTRACE_O_TRACESYSGOOD);

    for (int i = 0; i < 200; i++) {
        if (ptrace(PTRACE_SYSCALL, c, 0, 0) != 0) { printf("FAIL cont\n"); return 1; }
        if (waitpid(c, &st, 0) < 0) { printf("FAIL wait\n"); return 1; }
        if (WIFEXITED(st)) { printf("FAIL exited before write\n"); return 1; }
        if (!WIFSTOPPED(st)) continue;
        struct a64regs r;
        struct iovec iov = { &r, sizeof(r) };
        if (ptrace(PTRACE_GETREGSET, c, NT_PRSTATUS, &iov) != 0) { printf("FAIL getregset\n"); return 1; }
        if (r.regs[8] == NR_write && r.regs[0] == FD) {
            printf("STRACE-OK nr=%llu fd=%llu\n", r.regs[8], r.regs[0]);
            ptrace(PTRACE_CONT, c, 0, 0);
            waitpid(c, &st, 0);
            return 0;
        }
    }
    printf("FAIL never saw write(42)\n");
    return 1;
}
