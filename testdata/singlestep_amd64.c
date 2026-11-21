// build: -O0 -static
// singlestep_amd64.c -- PTRACE_SINGLESTEP: advance the child to a syscall stop, then
// single-step instruction by instruction until a one-byte step (a NOP) is seen,
// each with a TRAP_TRACE SIGTRAP and rip advancing by one instruction. Prints
// SINGLESTEP-OK. Stepping from a syscall stop exercises the stub's syscall-return
// and #DB resume paths. x86-64.
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

int main(void) {
    pid_t c = fork();
    if (c == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);
        getpid();
        __asm__ volatile("nop; nop; nop; nop");
        _exit(0);
    }
    int st;
    if (waitpid(c, &st, 0) < 0 || !WIFSTOPPED(st)) { printf("FAIL initial stop\n"); return 1; }
    ptrace(PTRACE_SETOPTIONS, c, 0, PTRACE_O_TRACESYSGOOD);
    // Reach a syscall stop (entry, then exit) to step from.
    for (int k = 0; k < 2; k++) {
        if (ptrace(PTRACE_SYSCALL, c, 0, 0) != 0) { printf("FAIL syscall cont\n"); return 1; }
        if (waitpid(c, &st, 0) < 0 || !WIFSTOPPED(st)) { printf("FAIL syscall stop\n"); return 1; }
    }
    struct user_regs_struct r;
    unsigned long long last = 0;
    for (int i = 0; i < 120; i++) {
        if (ptrace(PTRACE_SINGLESTEP, c, 0, 0) != 0) { printf("FAIL singlestep errno\n"); return 1; }
        if (waitpid(c, &st, 0) < 0) { printf("FAIL wait\n"); return 1; }
        if (WIFEXITED(st)) { printf("FAIL exited before NOP\n"); return 1; }
        if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP) { printf("FAIL not SIGTRAP sig=%d\n", WSTOPSIG(st)); return 1; }
        if (ptrace(PTRACE_GETREGS, c, 0, &r) != 0) { printf("FAIL getregs\n"); return 1; }
        if (last && r.rip == last + 1) {
            printf("SINGLESTEP-OK rip=%llx\n", r.rip);
            ptrace(PTRACE_CONT, c, 0, 0);
            waitpid(c, &st, 0);
            return 0;
        }
        last = r.rip;
    }
    printf("FAIL no single-byte step\n");
    return 1;
}
