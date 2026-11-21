// stracelocal_arm64.c -- an arm64 ptrace tracer that catches a syscall the sandbox
// serves in-guest (getrandom) rather than posting to the supervisor. Without
// in-guest-served syscalls being reported for their ptrace stops, this call
// would be invisible to a tracer; this checks it shows up at a syscall-entry
// stop with the right number and argument. Prints LOCALTRACE-OK on success.
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <elf.h>

// The arm64 NT_PRSTATUS register set: x0..x30, sp, pc, pstate.
struct a64regs {
    unsigned long long regs[31];
    unsigned long long sp, pc, pstate;
};

#define NR_getrandom 278
#define LEN 1337

int main(void) {
    pid_t c = fork();
    if (c == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP); // sync: the tracer attaches at this stop
        char buf[LEN];
        syscall(NR_getrandom, buf, (long)LEN, 0L); // in-guest-served; distinctive length
        _exit(0);
    }
    int st;
    if (waitpid(c, &st, 0) < 0 || !WIFSTOPPED(st)) { printf("FAIL initial stop\n"); return 1; }
    ptrace(PTRACE_SETOPTIONS, c, 0, PTRACE_O_TRACESYSGOOD);

    for (int i = 0; i < 400; i++) {
        if (ptrace(PTRACE_SYSCALL, c, 0, 0) != 0) { printf("FAIL cont\n"); return 1; }
        if (waitpid(c, &st, 0) < 0) { printf("FAIL wait\n"); return 1; }
        if (WIFEXITED(st)) { printf("FAIL exited before getrandom\n"); return 1; }
        if (!WIFSTOPPED(st)) continue;
        struct a64regs r;
        struct iovec iov = { &r, sizeof(r) };
        if (ptrace(PTRACE_GETREGSET, c, NT_PRSTATUS, &iov) != 0) { printf("FAIL getregset\n"); return 1; }
        if (r.regs[8] == NR_getrandom && r.regs[1] == LEN) {
            printf("LOCALTRACE-OK nr=%llu len=%llu\n", r.regs[8], r.regs[1]);
            ptrace(PTRACE_CONT, c, 0, 0);
            waitpid(c, &st, 0);
            return 0;
        }
    }
    printf("FAIL getrandom not seen\n");
    return 1;
}
