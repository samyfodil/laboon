// stracelocalx64_amd64.c -- the x86-64 counterpart of stracelocal_arm64.c: trace a child to
// a syscall the sandbox serves in-guest (getrandom) rather than posting to the
// supervisor, and confirm it still appears at a ptrace syscall-entry stop.
// Prints LOCALTRACE-OK on success.
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <elf.h>

// x86-64 NT_PRSTATUS (user_regs_struct) as a flat array; orig_rax is index 15,
// rsi (getrandom's length arg) index 13.
struct x64regs {
    unsigned long long r[27];
};
#define ORIG_RAX 15
#define RSI 13

#define NR_getrandom 318
#define LEN 1337

int main(void) {
    pid_t c = fork();
    if (c == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);
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
        struct x64regs r;
        struct iovec iov = { &r, sizeof(r) };
        if (ptrace(PTRACE_GETREGSET, c, NT_PRSTATUS, &iov) != 0) { printf("FAIL getregset\n"); return 1; }
        if (r.r[ORIG_RAX] == NR_getrandom && r.r[RSI] == LEN) {
            printf("LOCALTRACE-OK nr=%llu len=%llu\n", r.r[ORIG_RAX], r.r[RSI]);
            ptrace(PTRACE_CONT, c, 0, 0);
            waitpid(c, &st, 0);
            return 0;
        }
    }
    printf("FAIL getrandom not seen\n");
    return 1;
}
