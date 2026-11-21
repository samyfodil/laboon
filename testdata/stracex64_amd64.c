// stracex64_amd64.c -- the x86-64 counterpart of stracearm_arm64.c: trace a child to a
// distinctive write(42) syscall and read its registers with
// PTRACE_GETREGSET(NT_PRSTATUS), checking the syscall number (write = 1) and
// the fd argument came through. Covers the syscall-entry stop, register
// publishing and PTRACE_CONT without single-step. Prints STRACE-OK on success.
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <elf.h>

// x86-64 NT_PRSTATUS (user_regs_struct) as a flat array; orig_rax is index 15,
// rdi is index 14.
struct x64regs {
    unsigned long long r[27];
};
#define ORIG_RAX 15
#define RDI 14

#define NR_write 1
#define FD 42

int main(void) {
    pid_t c = fork();
    if (c == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);
        write(FD, "x", 1);
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
        struct x64regs r;
        struct iovec iov = { &r, sizeof(r) };
        if (ptrace(PTRACE_GETREGSET, c, NT_PRSTATUS, &iov) != 0) { printf("FAIL getregset\n"); return 1; }
        if (r.r[ORIG_RAX] == NR_write && r.r[RDI] == FD) {
            printf("STRACE-OK nr=%llu fd=%llu\n", r.r[ORIG_RAX], r.r[RDI]);
            ptrace(PTRACE_CONT, c, 0, 0);
            waitpid(c, &st, 0);
            return 0;
        }
    }
    printf("FAIL never saw write(42)\n");
    return 1;
}
