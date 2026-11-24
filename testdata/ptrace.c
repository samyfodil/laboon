// build: -static
// (the tracer reads its re-exec'd child's memory at its own address of
// mem_area, which only a fixed-address build shares)
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <sched.h>
#include <sys/stat.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s errno=%d\n", __LINE__, #x, errno); exit(1); } } while (0)
static volatile sig_atomic_t caught;
__attribute__((noinline, aligned(16))) static void breakpoint(void) { __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop"); }
static void tracer_death(int exitkill) {
    int p[2];
    CHECK(pipe(p) == 0);
    pid_t tracer = fork();
    CHECK(tracer >= 0);
    if (!tracer) {
        close(p[0]);
        pid_t tracee = fork();
        CHECK(tracee >= 0);
        if (!tracee) {
            CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
            raise(SIGSTOP);
            char c = 'x';
            CHECK(write(p[1], &c, 1) == 1);
            _exit(0);
        }
        int st;
        CHECK(waitpid(tracee, &st, 0) == tracee && WIFSTOPPED(st));
        if (exitkill) CHECK(ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_EXITKILL) == 0);
        _exit(0);
    }
    close(p[1]);
    int st;
    CHECK(waitpid(tracer, &st, 0) == tracer && st == 0);
    char c;
    CHECK(read(p[0], &c, 1) == (exitkill ? 0 : 1));
    CHECK(waitpid(-1, &st, 0) > 0);
    CHECK(exitkill ? WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL : st == 0);
    puts("OK");
}
static void handler(int sig) { caught = sig; }
static void *thread(void *p) { syscall(SYS_getpid); return p; }

static void workload(const char *mode) {
    CHECK(syscall(SYS_getpid) == getpid());
    struct timespec ts;
    CHECK(syscall(SYS_clock_gettime, 1, &ts) == 0);
    CHECK(syscall(SYS_close, -1) == -1 && errno == EBADF);
    char word[8] = "before";
    CHECK(syscall(SYS_write, 1, word, sizeof(word)) == sizeof(word));
    CHECK(strcmp(word, "after") == 0);
    if (!strcmp(mode, "signals")) {
        signal(SIGUSR1, handler);
        signal(SIGUSR2, handler);
        breakpoint();
        raise(SIGUSR1);
        CHECK(caught == 0);
        raise(SIGUSR2);
        CHECK(caught == SIGUSR1);
#if defined(__x86_64__)
        __asm__ volatile("int3");
#elif defined(__aarch64__)
        /* Suppressing BRK without advancing PC would execute it again. */
        raise(SIGTRAP);
#endif
    }
    if (!strcmp(mode, "events")) {
        pid_t p = fork();
        CHECK(p >= 0);
        if (!p) _exit(7);
        int st;
        CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 7);
        p = vfork();
        CHECK(p >= 0);
        if (!p) _exit(8);
        CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 8);
        pthread_t th;
        CHECK(pthread_create(&th, NULL, thread, NULL) == 0);
        CHECK(pthread_join(th, NULL) == 0);
    }
    _exit(23);
}


static unsigned char mem_area[32768];
#if defined(__x86_64__)
__attribute__((naked, noinline)) static int debug_add(int a, int b) {
    __asm__ volatile("nop; nop; lea (%rdi,%rsi), %eax; ret");
}
#elif defined(__aarch64__)
extern int debug_add(int a, int b);
__asm__(".text\n.align 4\ndebug_add: nop; nop; add w0,w0,w1; ret");
#endif

static void debug_child(void) {
#if defined(__x86_64__)
    int result;
    unsigned long saved;
    __asm__ volatile("mov $0x12345678, %%r12; call *%3; mov %%r12, %1"
        : "=a"(result), "=m"(saved) : "D"(2), "r"(debug_add), "S"(3)
        : "r12", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc");
    CHECK(result == 7 && saved == 0x87654321);
#elif defined(__aarch64__)
    register long result __asm__("x0") = 2;
    register long arg __asm__("x1") = 3;
    long saved;
    __asm__ volatile("mov x19,#0x1234; bl debug_add; mov %1,x19"
        : "+r"(result), "=r"(saved), "+r"(arg) :: "x19", "x30", "memory", "cc");
    CHECK(result == 7 && saved == 0x5678);
#endif
    CHECK(mem_area[0] == 0x5a && mem_area[sizeof(mem_area)-1] == 0xa5);
    _exit(0);
}

static void check_ids(pid_t child, int different_ns) {
    char name[80], b[8192];
    struct stat me, target, task;
    CHECK(stat("/proc/self/ns/pid", &me) == 0);
    snprintf(name, sizeof(name), "/proc/%d/ns/pid", child);
    CHECK(stat(name, &target) == 0);
    CHECK((me.st_ino != target.st_ino) == different_ns);
    snprintf(name, sizeof(name), "/proc/%d/task/%d/ns/pid", child, child);
    CHECK(stat(name, &task) == 0 && target.st_ino == task.st_ino);
    snprintf(name, sizeof(name), "/proc/%d/status", child);
    int fd = open(name, O_RDONLY);
    CHECK(fd >= 0);
    ssize_t n = read(fd, b, sizeof(b)-1);
    CHECK(n > 0);
    b[n] = 0;
    close(fd);
    CHECK(atoi(strstr(b, "\nPid:") + 5) == child);
    CHECK(atoi(strstr(b, "\nTgid:") + 6) == child);
    CHECK(atoi(strstr(b, "\nNSpid:") + 7) == child);
    CHECK(atoi(strstr(b, "\nTracerPid:") + 11) == getpid());
    snprintf(name, sizeof(name), "/proc/%d/stat", child);
    fd = open(name, O_RDONLY);
    CHECK(fd >= 0 && read(fd, b, sizeof(b)-1) > 0);
    CHECK(atoi(b) == child);
    close(fd);
    n = readlink("/proc/self", b, sizeof(b)-1);
    CHECK(n > 0);
    b[n] = 0;
    CHECK(atoi(b) == getpid());
}

static void debugger(pid_t child, int use_mem, int different_ns) {
    check_ids(child, different_ns);
    char name[80];
    snprintf(name, sizeof(name), "/proc/%d/mem", child);
    int fd = open(name, O_RDWR);
    CHECK(fd >= 0);
    unsigned char b[sizeof(mem_area)];
    CHECK(pread(fd, b, sizeof(b), (uintptr_t)mem_area) == sizeof(b));
    for (size_t i = 0; i < sizeof(b); i++) CHECK(b[i] == 0);
    b[0] = 0x5a;
    b[sizeof(b)-1] = 0xa5;
    CHECK(pwrite(fd, b, sizeof(b), (uintptr_t)mem_area) == sizeof(b));
    memset(b, 0, sizeof(b));
    CHECK(lseek(fd, (uintptr_t)mem_area, SEEK_SET) == (uintptr_t)mem_area);
    CHECK(read(fd, b, sizeof(b)) == sizeof(b));
    CHECK(b[0] == 0x5a && b[sizeof(b)-1] == 0xa5);
    CHECK(lseek(fd, (uintptr_t)mem_area, SEEK_SET) == (uintptr_t)mem_area);
    CHECK(write(fd, b, sizeof(b)) == sizeof(b));
    errno = 0;
    CHECK(pread(fd, b, 8, 0x6c0000000000UL) == -1 && errno == EIO);
    CHECK(pwrite(fd, b, 8, 0x6c1000000000UL) == -1 && errno == EIO);
#if defined(__x86_64__)
    void *pc = (void *)debug_add;
    errno = 0;
    long orig = ptrace(PTRACE_PEEKTEXT, child, pc, 0);
    CHECK(errno == 0);
    if ((uint32_t)orig == 0xfa1e0ff3U) pc = (char *)pc + 4;
    orig = ptrace(PTRACE_PEEKTEXT, child, pc, 0);
    CHECK((orig & 0xff) == 0x90);
    long trap = (orig & ~0xffL) | 0xcc;
    if (use_mem) CHECK(pwrite(fd, &trap, sizeof(trap), (uintptr_t)pc) == sizeof(trap));
    else CHECK(ptrace(PTRACE_POKETEXT, child, pc, trap) == 0);
    CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    int st;
    CHECK(waitpid(child, &st, 0) == child && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP);
    struct user_regs_struct regs;
    CHECK(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0);
    CHECK(regs.rip == (uintptr_t)pc + 1 && regs.rdi == 2 && regs.rsi == 3 && regs.r12 == 0x12345678);
    CHECK(regs.rsp != 0 && regs.cs == 0x33 && regs.ss == 0x2b && regs.orig_rax == -1UL);
    regs.rip--;
    regs.rdi = 4;
    CHECK(ptrace(PTRACE_SETREGS, child, 0, &regs) == 0);
    CHECK(ptrace(PTRACE_POKEUSER, child, offsetof(struct user_regs_struct, r12), 0x87654321) == 0);
    struct iovec iov = {&regs, sizeof(regs)};
    CHECK(ptrace(PTRACE_GETREGSET, child, 1, &iov) == 0 && regs.r12 == 0x87654321);
    CHECK(ptrace(PTRACE_SETREGSET, child, 1, &iov) == 0);
    if (use_mem) CHECK(pwrite(fd, &orig, sizeof(orig), (uintptr_t)pc) == sizeof(orig));
    else CHECK(ptrace(PTRACE_POKETEXT, child, pc, orig) == 0);
    CHECK(ptrace(PTRACE_SINGLESTEP, child, 0, 0) == 0);
    CHECK(waitpid(child, &st, 0) == child && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP);
    CHECK(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0 && regs.rip == (uintptr_t)pc + 1);
    siginfo_t si;
    CHECK(ptrace(PTRACE_GETSIGINFO, child, 0, &si) == 0 && si.si_code == TRAP_TRACE);
#elif defined(__aarch64__)
    void *pc = (void *)debug_add;
    errno = 0;
    long orig = ptrace(PTRACE_PEEKTEXT, child, pc, 0);
    CHECK(errno == 0 && (uint32_t)orig == 0xd503201fU);
    long trap = (orig & ~0xffffffffL) | 0xd4200000U;
    if (use_mem) CHECK(pwrite(fd, &trap, sizeof(trap), (uintptr_t)pc) == sizeof(trap));
    else CHECK(ptrace(PTRACE_POKETEXT, child, pc, trap) == 0);
    CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    int st;
    CHECK(waitpid(child, &st, 0) == child && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP);
    unsigned long regs[34];
    struct iovec iov = {regs, sizeof(regs)};
    CHECK(ptrace(PTRACE_GETREGSET, child, 1, &iov) == 0);
    CHECK(regs[32] == (uintptr_t)pc && regs[0] == 2 && regs[1] == 3 && regs[19] == 0x1234);
    regs[0] = 4;
    regs[19] = 0x5678;
    CHECK(ptrace(PTRACE_SETREGSET, child, 1, &iov) == 0);
    if (use_mem) CHECK(pwrite(fd, &orig, sizeof(orig), (uintptr_t)pc) == sizeof(orig));
    else CHECK(ptrace(PTRACE_POKETEXT, child, pc, orig) == 0);
    CHECK(ptrace(PTRACE_SINGLESTEP, child, 0, 0) == 0);
    CHECK(waitpid(child, &st, 0) == child && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP);
    CHECK(ptrace(PTRACE_GETREGSET, child, 1, &iov) == 0 && regs[32] == (uintptr_t)pc + 4);
    siginfo_t si;
    CHECK(ptrace(PTRACE_GETSIGINFO, child, 0, &si) == 0 && si.si_code == TRAP_TRACE);
#endif
    close(fd);
    CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("OK");
}

static void self_mem(void) {
    int fd = open("/proc/self/mem", O_RDWR);
    CHECK(fd >= 0);
    unsigned long value = 0x12345678, b = 0;
    CHECK(pread(fd, &b, sizeof(b), (uintptr_t)&value) == sizeof(b) && b == value);
    b++;
    CHECK(pwrite(fd, &b, sizeof(b), (uintptr_t)&value) == sizeof(b) && value == b);
    close(fd);
}


static void mem_access(void) {
    int ready[2], done[2];
    CHECK(pipe(ready) == 0 && pipe(done) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setuid(1000) == 0);
        self_mem();
        CHECK(write(ready[1], "x", 1) == 1);
        char c;
        CHECK(read(done[0], &c, 1) == 1);
        _exit(0);
    }
    char c, name[80];
    CHECK(read(ready[0], &c, 1) == 1);
    CHECK(setuid(1001) == 0);
    self_mem();
    snprintf(name, sizeof(name), "/proc/%d/mem", child);
    CHECK(open(name, O_RDWR) == -1 && errno == EACCES);
    CHECK(write(done[1], "x", 1) == 1);
    int st;
    CHECK(waitpid(child, &st, 0) == child && st == 0);
    puts("OK");
}

static void register_child(void) {
#if defined(__x86_64__)
    long result, saved;
    __asm__ volatile("mov $0x12345678, %%r12; syscall; mov %%r12, %1"
        : "=a"(result), "=r"(saved) : "a"(SYS_close), "D"(-1L)
        : "r12", "rcx", "r11", "memory");
    CHECK(result == 321 && saved == 0x87654321);
    long pid = getpid(), tid = syscall(SYS_gettid);
    __asm__ volatile("mov $0x12345678, %%r13; syscall; mov %%r13, %1"
        : "=a"(result), "=r"(saved) : "a"(SYS_tgkill), "D"(pid), "S"(tid), "d"(SIGUSR1)
        : "r13", "rcx", "r11", "memory");
    CHECK(saved == 0x87654321);
#endif
    CHECK(syscall(SYS_getppid) == getppid());
    _exit(0);
}

static void register_tracer(pid_t child) {
    CHECK(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD) == 0);
    CHECK(ptrace(PTRACE_SYSCALL, child, 0, 0) == 0);
    int st, changed = 0, returned = 0, delivered = 0, stepped = 0;
    while (1) {
        CHECK(waitpid(child, &st, 0) == child);
        if (WIFEXITED(st)) { CHECK(WEXITSTATUS(st) == 0); break; }
        CHECK(WIFSTOPPED(st));
        if (WSTOPSIG(st) == (SIGTRAP | 0x80)) {
            // A single-step from a syscall-entry stop runs the call, then
            // traps with its result in place.
            struct ptrace_syscall_info info;
            CHECK(ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info) >= 24);
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == SYS_getppid && !stepped) {
                CHECK(ptrace(PTRACE_SINGLESTEP, child, 0, 0) == 0);
                CHECK(waitpid(child, &st, 0) == child && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP);
                siginfo_t si;
                CHECK(ptrace(PTRACE_GETSIGINFO, child, 0, &si) == 0 && si.si_signo == SIGTRAP);
                unsigned long rv[34];
                struct iovec iov = {rv, sizeof(rv)};
                CHECK(ptrace(PTRACE_GETREGSET, child, 1, &iov) == 0);
#if defined(__x86_64__)
                CHECK(si.si_code == TRAP_BRKPT && rv[offsetof(struct user_regs_struct, rax) / 8] == (unsigned long)getpid());
#else
                CHECK(si.si_code == SI_USER && rv[0] == (unsigned long)getpid());
#endif
                stepped++;
                CHECK(ptrace(PTRACE_SYSCALL, child, 0, 0) == 0);
                continue;
            }
        }
#if defined(__x86_64__)
        struct user_regs_struct regs;
        CHECK(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0);
        if (WSTOPSIG(st) == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info info;
            CHECK(ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info) >= 24);
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == SYS_close && info.entry.args[0] == -1UL) {
                CHECK(!changed && regs.r12 == 0x12345678 && regs.rsp != 0 && regs.rax == -ENOSYS);
                struct iovec bad = {&regs, 9};
                errno = 0;
                CHECK(ptrace(PTRACE_SETREGSET, child, 1, &bad) == -1 && errno == EINVAL);
                unsigned long fs = regs.fs_base;
                regs.fs_base = 1UL << 47;
                CHECK(ptrace(PTRACE_SETREGS, child, 0, &regs) == -1 && errno == EIO);
                regs.fs_base = fs;
                regs.orig_rax = SYS_getpid;
                regs.r12 = 0x87654321;
                CHECK(ptrace(PTRACE_SETREGS, child, 0, &regs) == 0);
                changed++;
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && changed && !returned) {
                CHECK(regs.rax == child && regs.r12 == 0x87654321);
                regs.rax = 321;
                CHECK(ptrace(PTRACE_SETREGS, child, 0, &regs) == 0);
                returned++;
            }
        } else {
            CHECK(WSTOPSIG(st) == SIGUSR1 && regs.r13 == 0x12345678);
            regs.r13 = 0x87654321;
            struct iovec iov = {&regs, sizeof(regs)};
            CHECK(ptrace(PTRACE_SETREGSET, child, 1, &iov) == 0);
            delivered++;
        }
#endif
        CHECK(ptrace(PTRACE_SYSCALL, child, 0, 0) == 0);
    }
    CHECK(stepped == 1);
#if defined(__x86_64__)
    CHECK(changed == 1 && returned == 1 && delivered == 1);
#endif
    puts("OK");
}

int main(int argc, char **argv) {
    CHECK(argc >= 2);
    if (!strcmp(argv[1], "memaccess")) { mem_access(); return 0; }
    if (argc == 3 && !strcmp(argv[1], "registers")) register_child();
    if (!strcmp(argv[1], "tracerexit") || !strcmp(argv[1], "exitkill")) { tracer_death(!strcmp(argv[1], "exitkill")); return 0; }
    if (!strcmp(argv[1], "namespace")) CHECK(unshare(CLONE_NEWPID) == 0);
    int debug = !strcmp(argv[1], "breakpoint") || !strcmp(argv[1], "procmem") || !strcmp(argv[1], "namespace");
    if (argc == 3 && debug) debug_child();
    if (argc == 3) workload(argv[1]);
    if (debug) self_mem();
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
        if (!strcmp(argv[1], "events")) raise(SIGSTOP);
        execl(argv[0], argv[0], argv[1], "child", NULL);
        _exit(99);
    }
    int st;
    CHECK(waitpid(child, &st, 0) == child);
    CHECK(WIFSTOPPED(st));
    if (!strcmp(argv[1], "cancel")) {
        CHECK(write(1, "ready\n", 6) == 6);
        for (;;) pause();
    }
    if (debug) { debugger(child, !strcmp(argv[1], "procmem"), !strcmp(argv[1], "namespace")); return 0; }
    if (!strcmp(argv[1], "registers")) { register_tracer(child); return 0; }
    int events = !strcmp(argv[1], "events");
    CHECK(WSTOPSIG(st) == (events ? SIGSTOP : SIGTRAP));
    if (!strcmp(argv[1], "kill") || !strcmp(argv[1], "killexit")) {
        if (!strcmp(argv[1], "killexit")) CHECK(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEEXIT) == 0);
        CHECK(ptrace(PTRACE_KILL, child, 0, 0) == 0);
        if (!strcmp(argv[1], "killexit")) {
            CHECK(waitpid(child, &st, 0) == child && (unsigned)st >> 16 == PTRACE_EVENT_EXIT);
            unsigned long msg;
            CHECK(ptrace(PTRACE_GETEVENTMSG, child, 0, &msg) == 0 && msg == SIGKILL);
            CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0);
        }
        CHECK(waitpid(child, &st, 0) == child && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
        puts("OK");
        return 0;
    }
    if (!strcmp(argv[1], "detach")) {
        CHECK(ptrace(PTRACE_DETACH, child, 0, 0) == 0);
        /* This workload checks the tracer's memory edit, so it exits 1. */
        CHECK(waitpid(child, &st, 0) == child && WIFEXITED(st) && WEXITSTATUS(st) == 1);
        puts("OK");
        return 0;
    }
    unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL;
    if (events) options |= PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORKDONE;
    CHECK(ptrace(PTRACE_SETOPTIONS, child, 0, options) == 0);
    errno = 0;
    CHECK(ptrace(PTRACE_CONT, child, 0, 65) == -1 && errno == EIO);
    CHECK(ptrace(PTRACE_SYSCALL, child, 0, 0) == 0);
    int entries = 0, exits = 0, writes = 0, done = 0, forks = 0, clones = 0, vforks = 0, execs = 0, exit_events = 0, signals = 0;
    int write_pid = 0, error_pid = 0, errors = 0, clocks = 0;
    long saved_text = 0;
    void *break_addr = (void *)breakpoint;
    while (!done) {
        siginfo_t waitinfo;
        memset(&waitinfo, 0, sizeof(waitinfo));
        CHECK(waitid(P_ALL, 0, &waitinfo, WEXITED | WSTOPPED | WNOWAIT | __WALL) == 0);
        CHECK(waitinfo.si_pid > 0);
        pid_t pid = waitpid(waitinfo.si_pid, &st, __WALL);
        CHECK(pid > 0);
        if (WIFEXITED(st)) {
            if (pid == child) { CHECK(WEXITSTATUS(st) == 23); done = 1; }
            continue;
        }
        CHECK(WIFSTOPPED(st));
        int sig = WSTOPSIG(st), inject = 0;
        unsigned event = (unsigned)st >> 16;
        if (event) {
            unsigned long msg = 0;
            CHECK(ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg) == 0);
            if (event == PTRACE_EVENT_FORK) { CHECK(msg > 0); forks++; }
            if (event == PTRACE_EVENT_VFORK) { CHECK(msg > 0); vforks++; }
            if (event == PTRACE_EVENT_CLONE) { CHECK(msg > 0); clones++; }
            if (event == PTRACE_EVENT_EXEC) { CHECK(msg == child); execs++; }
            if (event == PTRACE_EVENT_EXIT) { CHECK((msg & 0xff) == 0); exit_events++; }
        } else if (sig == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info info;
            memset(&info, 0, sizeof(info));
            CHECK(ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) >= 24);
            CHECK(info.op == PTRACE_SYSCALL_INFO_ENTRY || info.op == PTRACE_SYSCALL_INFO_EXIT);
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                entries++;
                if (info.entry.nr == SYS_close && (int)info.entry.args[0] == -1) error_pid = pid;
                if (info.entry.nr == SYS_clock_gettime) clocks++;
                if (info.entry.nr == SYS_write && info.entry.args[0] == 1 && info.entry.args[2] == 8) {
                    errno = 0;
                    long val = ptrace(PTRACE_PEEKDATA, pid, info.entry.args[1], 0);
                    CHECK(errno == 0 && !memcmp(&val, "before", 7));
                    memcpy(&val, "after\0\0", 8);
                    CHECK(ptrace(PTRACE_POKEDATA, pid, info.entry.args[1], val) == 0);
                    write_pid = pid;
                    writes++;
                    errno = 0;
                    long text = ptrace(PTRACE_PEEKTEXT, pid, breakpoint, 0);
                    CHECK(errno == 0);
                    CHECK(ptrace(PTRACE_POKETEXT, pid, breakpoint, text) == 0);
#if defined(__x86_64__)
                    if (!strcmp(argv[1], "signals")) {
                        if ((uint32_t)text == 0xfa1e0ff3U) break_addr = (char *)break_addr + 4;
                        errno = 0;
                        text = ptrace(PTRACE_PEEKTEXT, pid, break_addr, 0);
                        CHECK(errno == 0 && (text & 0xff) == 0x90);
                        saved_text = text;
                        CHECK(ptrace(PTRACE_POKETEXT, pid, break_addr, (text & ~0xffL) | 0xcc) == 0);
                    }
#endif
                    struct ptrace_syscall_info short_info;
                    memset(&short_info, 0xff, sizeof(short_info));
                    CHECK(ptrace(PTRACE_GET_SYSCALL_INFO, pid, 1, &short_info) == 80);
                    CHECK(short_info.op == PTRACE_SYSCALL_INFO_ENTRY && short_info.arch == UINT32_MAX);
                    errno = 0;
                    CHECK(ptrace(PTRACE_SETOPTIONS, pid, 0, 0x80000000UL) == -1 && errno == EINVAL);
                    unsigned long regs[34];
                    struct iovec iov = {regs, sizeof(regs)};
                    CHECK(ptrace(PTRACE_GETREGSET, pid, 1, &iov) == 0);
#if defined(__x86_64__)
                    CHECK(iov.iov_len == sizeof(struct user_regs_struct));
                    CHECK(((struct user_regs_struct *)regs)->orig_rax == SYS_write);
                    CHECK(ptrace(PTRACE_PEEKUSER, pid, 15 * 8, 0) == SYS_write);
#else
                    CHECK(regs[8] == SYS_write);
#endif
                }
            } else {
                exits++;
                if (pid == error_pid) {
                    CHECK(info.exit.rval == -EBADF && info.exit.is_error);
                    error_pid = 0;
                    errors++;
                }
                if (pid == write_pid) { CHECK(info.exit.rval == 8 && !info.exit.is_error); write_pid = 0; }
            }
        } else if (sig == SIGUSR1 || sig == SIGUSR2 || sig == SIGTRAP) {
            siginfo_t si;
            CHECK(ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0 && si.si_signo == sig);
            signals++;
            if (sig == SIGTRAP && saved_text) CHECK(ptrace(PTRACE_POKETEXT, pid, break_addr, saved_text) == 0);
            if (sig == SIGUSR2) inject = SIGUSR1;
        } else CHECK(sig == SIGSTOP || sig == SIGCHLD);
        CHECK(ptrace(PTRACE_SYSCALL, pid, 0, inject) == 0);
    }
    CHECK(entries > 2 && exits > 2 && writes == 1 && errors == 1 && clocks >= 1 && exit_events >= 1);
    if (events) CHECK(forks == 1 && vforks == 1 && clones == 1 && execs == 1);
    if (!strcmp(argv[1], "signals")) {
#if defined(__x86_64__)
        CHECK(signals == 4);
#else
        CHECK(signals == 3);
#endif
    }
    puts("OK");
    return 0;
}
