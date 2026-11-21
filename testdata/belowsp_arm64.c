// Checks that a syscall leaves memory below sp alone, as Linux does (Go's
// runtime.clone relies on it), then execs itself once so the second image
// starts from whichever path served the first execve. With "jit" the check
// runs from a copy made executable at run time, as a JIT's code would.
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned long belowsp(void);
extern char belowsp_code[], belowsp_code_end[];

#define BELOWSP \
	"  mov x9, #0x111\n stur x9, [sp, #-8]\n" \
	"  mov x9, #0x222\n stur x9, [sp, #-16]\n" \
	"  mov x9, #0x333\n stur x9, [sp, #-24]\n" \
	"  mov x9, #0x444\n stur x9, [sp, #-64]\n" \
	"  mov x9, #0x555\n stur x9, [sp, #-128]\n" \
	"  mov x8, #172\n svc #0\n" \
	"  mov x0, #0\n" \
	"  ldur x9, [sp, #-8]\n cmp x9, #0x111\n cinc x0, x0, ne\n" \
	"  ldur x9, [sp, #-16]\n cmp x9, #0x222\n cinc x0, x0, ne\n" \
	"  ldur x9, [sp, #-24]\n cmp x9, #0x333\n cinc x0, x0, ne\n" \
	"  ldur x9, [sp, #-64]\n cmp x9, #0x444\n cinc x0, x0, ne\n" \
	"  ldur x9, [sp, #-128]\n cmp x9, #0x555\n cinc x0, x0, ne\n" \
	"  ret\n"

// The copy run as JIT code comes from data: the image's own code is
// rewritten where it was loaded and does not run anywhere else.
__asm__(".globl belowsp\n"
	".type belowsp, %function\n"
	"belowsp:\n" BELOWSP
	".section .rodata\n"
	".balign 4\n"
	".globl belowsp_code, belowsp_code_end\n"
	"belowsp_code:\n" BELOWSP
	"belowsp_code_end:\n"
	".text\n");

static unsigned long (*jitted(void))(void)
{
	size_t n = belowsp_code_end - belowsp_code;
	void *p = mmap(0, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 0;
	memcpy(p, belowsp_code, n);
	__builtin___clear_cache(p, (char *)p + n);
	if (mprotect(p, 65536, PROT_READ | PROT_EXEC))
		return 0;
	return (unsigned long (*)(void))p;
}

int main(int argc, char **argv)
{
	int jit = argc > 1 && !strcmp(argv[1], "jit"), second = !strcmp(argv[argc - 1], "again");
	unsigned long (*f)(void) = jit ? jitted() : belowsp;
	if (!f) {
		perror("jit");
		return 2;
	}
	unsigned long bad = f();
	printf("%s: below sp %s\n", second ? "second" : "first", bad ? "clobbered" : "preserved");
	fflush(stdout);
	if (second)
		return bad != 0;
	char *args[] = { argv[0], jit ? "jit" : "again", jit ? "again" : 0, 0 };
	execv(argv[0], args);
	perror("execv");
	return 2;
}
