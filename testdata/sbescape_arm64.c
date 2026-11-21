// Guest code issuing raw Darwin syscalls (svc #0x80, which the rewriter
// leaves alone) must hit the stub's Seatbelt profile: no host file outside
// the rootfs, no host write, no exec, socket, signal, ptrace or sysctl, and
// any syscall off the stub's list (getppid) is denied. Mach traps and kernel
// MIG routines the stub does not use (pid_for_task, task_info on the task port)
// are denied too -- a trap returns an error, a MIG routine comes back
// KERN_DENIED -- fcntl F_GETPATH does not reveal the host path of a stub-held
// descriptor, the core-size hard limit is 0, and a raw fork is denied (a fork
// child is a stub the supervisor starts). A Darwin error other than
// EPERM/EACCES means the call reached the host (an exec of a missing file
// failing with ENOENT was permitted).
// Usage: sbescape [host-file-outside-root]
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static long dsys(long nr, long a0, long a1, long a2, long *carry) {
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x16 __asm__("x16") = nr;
	long c;
	__asm__ volatile("svc #0x80\n\tcset %4, cs"
			 : "+r"(x0), "+r"(x1), "+r"(x16), "+r"(x2), "=r"(c)
			 :
			 : "memory", "cc");
	*carry = c;
	return x0;
}

static long dsys8(long nr, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x3 __asm__("x3") = a3;
	register long x4 __asm__("x4") = a4;
	register long x5 __asm__("x5") = a5;
	register long x6 __asm__("x6") = a6;
	register long x7 __asm__("x7") = a7;
	register long x16 __asm__("x16") = nr;
	__asm__ volatile("svc #0x80"
			 : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7), "+r"(x16)
			 :
			 : "memory", "cc");
	return x0;
}

#define TRAP(n) dsys8(-(n), 0, 0, 0, 0, 0, 0, 0, 0)

// pid_for_task on the task's own port: exit 100 if the kernel answered.
static long pidfortask(void) {
	int pid = 0;
	return dsys8(-46, TRAP(28), (long)&pid, 0, 0, 0, 0, 0, 0) == 0 && pid > 0 ? 100 : 0;
}

// task_info(mach_task_self(), MACH_TASK_BASIC_INFO) sent with mach_msg2_trap
// the way libsystem_kernel's MIG stub does (send+receive, kobject call; each
// register packs two 32-bit header fields): exit 100 if the kernel answered.
static long mig_task_info(void) {
	uint64_t self = TRAP(28);     // task_self_trap
	uint64_t reply = TRAP(26);    // mach_reply_port
	uint32_t m[106] = {19 | 21 << 8, 40, self, reply, 0, 3405, 0, 1, 20, 12}; // NDR int_rep 1: little endian
	long kr = dsys8(-47, (long)m, 0x200000003, 40L << 32 | m[0], reply << 32 | self, 3405L << 32,
			reply << 32, sizeof m, 0);
	// A denied MIG routine returns KERN_DENIED (53) in the reply's RetCode (m[8])
	// over the allowed mach_msg2 transport (kr stays 0), not a kill, so that is a
	// containment, not a host call -- treat it as denied, not "reached the host".
	return kr == 0 && m[5] == 3505 && m[8] == 0 ? 100 : kr ? kr & 0xff : m[8] == 53 ? 0 : 1;
}

// F_GETPATH on every descriptor: exit 100 if one named a host path.
static long getpath(void) {
	char buf[1024];
	long r = 0;
	for (int fd = 0; fd < 256; fd++) {
		long carry;
		if (dsys(92, fd, 50, (long)buf, &carry) == 0 && !carry && buf[0] == '/') {
			printf("fcntl-getpath: fd %d is %s\n", fd, buf);
			fflush(stdout);
			r = 100;
		}
	}
	return r;
}

// The core-size hard limit: exit 100 if a guest could raise it above 0.
static long corelimit(void) {
	uint64_t rl[2];
	long carry;
	if (dsys(194, 4, (long)rl, 0, &carry), carry)
		return 0;
	return rl[1] ? 100 : 0;
}

static const char *hostfile = "/private/etc/hosts";
static char *const shargv[] = {"sh", 0};
static char *const shenv[] = {0};

static long probe(int i, long *carry) {
	switch (i) {
	case 0: return dsys(5, (long)hostfile, 0, 0, carry);
	case 1: return dsys(5, (long)"/private/tmp/lc-sbescape", 0x601, 0644, carry);
	case 2: return dsys(59, (long)"/private/var/empty/lc-sbescape", (long)shargv, (long)shenv, carry);
	case 3: return dsys(97, 2, 1, 0, carry);
	case 4: return dsys(37, 1, 0, 0, carry);
	case 5: return dsys(26, 10, 1, 0, carry);
	case 6: return dsys(202, 0, 0, 0, carry);
	case 7: return dsys(39, 0, 0, 0, carry);
	case 8: *carry = -1; return pidfortask();
	case 9: *carry = -1; return mig_task_info();
	case 10: *carry = -1; return getpath();
	case 11: *carry = -1; return corelimit();
	default: return dsys(2, 0, 0, 0, carry); // fork: if it were allowed, both return here
	}
}

static const char *names[] = {"read-host-file", "write-host-tmp", "execve", "socket",
			      "kill", "ptrace", "sysctl", "getppid", "mach-trap",
			      "mig-task-info", "fcntl-getpath", "core-limit", "raw-fork"};
#define NPROBES (int)(sizeof names / sizeof names[0])

int main(int argc, char **argv) {
	if (argc > 1)
		hostfile = argv[1];
	int fails = 0;
	int hold = open(argv[0], O_RDONLY); // a stub-held host descriptor
	if (hold >= 0)
		mmap(0, 4096, PROT_READ, MAP_PRIVATE, hold, 0);
	for (int i = 0; i < NPROBES; i++) {
		fflush(stdout);
		pid_t pid = fork();
		if (pid == 0) {
			long carry;
			long r = probe(i, &carry);
			_exit(carry < 0 ? r : !carry ? 100 : r == 1 || r == 13 ? 0 : r);
		}
		int st;
		if (waitpid(pid, &st, 0) != pid) {
			printf("%s: waitpid failed\n", names[i]);
			fails++;
		} else if (WIFSIGNALED(st)) {
			printf("%s: denied (signal %d)\n", names[i], WTERMSIG(st));
		} else if (WEXITSTATUS(st) == 0) {
			printf("%s: denied (error)\n", names[i]);
		} else if (WEXITSTATUS(st) == 100) {
			printf("%s: ALLOWED\n", names[i]);
			fails++;
		} else {
			printf("%s: reached the host (errno %d)\n", names[i], WEXITSTATUS(st));
			fails++;
		}
	}
	printf(fails ? "FAIL: %d probes reached the host\n" : "PASS\n", fails);
	return fails != 0;
}
