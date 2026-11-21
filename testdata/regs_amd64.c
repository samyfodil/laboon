// Checks that a syscall preserves every register but rax, rcx and r11, as the
// x86-64 Linux ABI does: rbx, rdx, rsi, rdi, rbp, r8-r10, r12-r15, the flags
// and xmm0-xmm7. With "jit" the check runs from a copy made executable at run
// time, as a JIT's code would.
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned long check(unsigned long *out, unsigned long nr);
extern char check_code[], check_code_end[];
static unsigned long (*checkp)(unsigned long *, unsigned long) = check;

#define CHECK \
	"  push %rbx\n push %rbp\n push %r12\n push %r13\n push %r14\n push %r15\n" \
	"  push %rdi\n" \
	"  mov %rsi, %rax\n" \
	"  mov $0x1111, %rcx\n movq %rcx, %xmm0\n mov $0x2222, %rcx\n movq %rcx, %xmm1\n" \
	"  mov $0x3333, %rcx\n movq %rcx, %xmm2\n mov $0x4444, %rcx\n movq %rcx, %xmm3\n" \
	"  mov $0x5555, %rcx\n movq %rcx, %xmm4\n mov $0x6666, %rcx\n movq %rcx, %xmm5\n" \
	"  mov $0x7777, %rcx\n movq %rcx, %xmm6\n mov $0x8888, %rcx\n movq %rcx, %xmm7\n" \
	"  mov $0x0303, %rbx\n mov $0x0404, %rdx\n mov $0x0505, %rsi\n mov $0x0606, %rdi\n" \
	"  mov $0x0707, %rbp\n mov $0x0808, %r8\n mov $0x0909, %r9\n mov $0x0a0a, %r10\n" \
	"  mov $0x0c0c, %r12\n mov $0x0d0d, %r13\n mov $0x0e0e, %r14\n mov $0x0f0f, %r15\n" \
	"  stc\n" \
	"  syscall\n" \
	"  pushfq\n" \
	"  push %r15\n push %r14\n push %r13\n push %r12\n push %r10\n push %r9\n push %r8\n" \
	"  push %rbp\n push %rdi\n push %rsi\n push %rdx\n push %rbx\n push %rax\n" \
	"  sub $64, %rsp\n" \
	"  movq %xmm0, 0(%rsp)\n movq %xmm1, 8(%rsp)\n movq %xmm2, 16(%rsp)\n movq %xmm3, 24(%rsp)\n" \
	"  movq %xmm4, 32(%rsp)\n movq %xmm5, 40(%rsp)\n movq %xmm6, 48(%rsp)\n movq %xmm7, 56(%rsp)\n" \
	"  mov 176(%rsp), %rdi\n" \
	"  mov %rsp, %rsi\n" \
	"  mov $22, %ecx\n" \
	"  rep movsq\n" \
	"  add $184, %rsp\n" \
	"  pop %r15\n pop %r14\n pop %r13\n pop %r12\n pop %rbp\n pop %rbx\n" \
	"  ret\n"

// The copy run as JIT code comes from data: the image's own code is
// rewritten where it was loaded and does not run anywhere else.
__asm__(".globl check\n"
	".type check, @function\n"
	"check:\n" CHECK
	".section .rodata\n"
	".globl check_code, check_code_end\n"
	"check_code:\n" CHECK
	"check_code_end:\n"
	".text\n");

static const char *names[] = { "rbx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r12", "r13", "r14", "r15" };
static const unsigned long want[] = { 0x0303, 0x0404, 0x0505, 0x0606, 0x0707, 0x0808, 0x0909, 0x0a0a, 0x0c0c, 0x0d0d, 0x0e0e, 0x0f0f };

static int verify(const char *what, unsigned long nr)
{
	unsigned long r[22];
	memset(r, 0, sizeof r);
	checkp(r, nr);
	int bad = 0;
	for (int i = 0; i < 8; i++) {
		if (r[i] != (unsigned long)(i + 1) * 0x1111) {
			printf("%s: xmm%d = %#lx\n", what, i, r[i]);
			bad = 1;
		}
	}
	for (int i = 0; i < 12; i++) {
		if (r[9 + i] != want[i]) {
			printf("%s: %s = %#lx, want %#lx\n", what, names[i], r[9 + i], want[i]);
			bad = 1;
		}
	}
	if (!(r[21] & 1)) {
		printf("%s: flags = %#lx, carry lost\n", what, r[21]);
		bad = 1;
	}
	return bad;
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "jit")) {
		size_t n = check_code_end - check_code;
		void *p = mmap(0, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			return 2;
		memcpy(p, check_code, n);
		if (mprotect(p, 65536, PROT_READ | PROT_EXEC))
			return 2;
		checkp = (unsigned long (*)(unsigned long *, unsigned long))p;
	}
	int bad = verify("getpid", 39) | verify("gettid", 186) | verify("sched_yield", 24);
	puts(bad ? "regs clobbered" : "regs preserved");
	return bad;
}
